package state

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/xingjianluo/go-siem-detection-engine-go/internal/alert"
	"github.com/xingjianluo/go-siem-detection-engine-go/internal/engine"
)

const (
	// StoreFormatVersion 是落盘状态格式的当前版本。
	StoreFormatVersion = 1
	// stateMagic 用于识别“这确实是本引擎的状态文件”。
	stateMagic  = "go-siem-state-v1"
	stateSuffix = ".state.json"
)

// envelope 是状态文件的外层包装（带魔数、版本、校验和）。
// 校验和覆盖 payload：磁盘损坏/手工改坏时能与“版本不认识”区分开。
type envelope struct {
	Magic    string `json:"magic"`
	Version  int    `json:"version"`
	SavedAt  int64  `json:"saved_at_unix_nano"`
	Checksum string `json:"checksum"`
	Payload  string `json:"payload"` // PipelineState 的 JSON
}

// PipelineState 是一次落盘的完整状态。
type PipelineState struct {
	Correlator engine.State `json:"correlator"`
	Alerts     alert.State  `json:"alerts"`
	Cursor     CursorState  `json:"cursor"`
}

// Store 把 PipelineState 原子地写到本地目录，并负责读取时的
// 魔数/版本/校验和/保留期限识别。
//
// 同键（同一状态文件）的写入在进程内互斥、跨进程加文件锁，
// 多个来源同时写不会竞态或把状态写丢。
type Store struct {
	dir    string
	policy Policy
	now    func() time.Time

	mmu  sync.Mutex
	keys map[string]*sync.Mutex
}

// NewStore 在指定目录下管理状态文件（目录不存在会创建）。
func NewStore(dir string, p Policy) (*Store, error) {
	if dir == "" {
		return nil, errors.New("NewStore: empty dir")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create state dir %s: %w", dir, err)
	}
	return &Store{dir: dir, policy: p, now: time.Now, keys: map[string]*sync.Mutex{}}, nil
}

// withClock 用给定时钟替换取时函数（主要供测试把 checkpoint 固定在
// 事件所在的时间点，避免墙钟保留期干扰断言）。
func (s *Store) withClock(now func() time.Time) *Store {
	s.now = now
	return s
}

// keyMu 返回进程内同键串行化用的互斥锁。
func (s *Store) keyMu(key string) *sync.Mutex {
	s.mmu.Lock()
	defer s.mmu.Unlock()
	m, ok := s.keys[key]
	if !ok {
		m = &sync.Mutex{}
		s.keys[key] = m
	}
	return m
}

func (s *Store) path(key string) string {
	return filepath.Join(s.dir, safeKey(key)+stateSuffix)
}

// Save 原子落盘指定键的状态。序列化结果超过策略 MaxBytes 时返回
// ErrCapacityExceeded（调用方应先做保留裁剪）。
func (s *Store) Save(key string, st PipelineState) error {
	lock := s.keyMu(key)
	lock.Lock()
	defer lock.Unlock()

	payload, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	if s.policy.MaxBytes > 0 && len(payload) > s.policy.MaxBytes {
		return fmt.Errorf("%w: key=%s payload=%d bytes limit=%d",
			ErrCapacityExceeded, key, len(payload), s.policy.MaxBytes)
	}

	sum := sha256.Sum256(payload)
	env := envelope{
		Magic:    stateMagic,
		Version:  StoreFormatVersion,
		SavedAt:  s.now().UnixNano(),
		Checksum: hex.EncodeToString(sum[:]),
		Payload:  string(payload),
	}
	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}

	fl, err := acquireLock(s.dir, key)
	if err != nil {
		return err
	}
	defer fl.Unlock()
	if err := atomicWriteFile(s.path(key), data); err != nil {
		return err
	}
	return nil
}

// atomicWriteFile 先写同目录临时文件再 rename：读者要么看到完整的旧文件，
// 要么看到完整的新文件，不会读到写了一半的状态。
func atomicWriteFile(path string, data []byte) error {
	tmp := fmt.Sprintf("%s.tmp-%d", path, time.Now().UnixNano())
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create temp state %s: %w", tmp, err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("write temp state %s: %w", tmp, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("fsync temp state %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("close temp state %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename temp state -> %s: %w", path, err)
	}
	return nil
}

// Load 读取指定键的状态。错误可用 errors.Is 区分为：
//   - os.ErrNotExist：从未落过盘（全新现场，不算异常）；
//   - ErrVersionIncompatible：魔数不认识或版本无法理解；
//   - ErrCorrupt：JSON 损坏、校验和不符、内部数据不一致；
//   - ErrExpired：状态时间整体早于保留策略允许的范围。
func (s *Store) Load(key string) (PipelineState, error) {
	path := s.path(key)
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return PipelineState{}, err
		}
		return PipelineState{}, fmt.Errorf("read state %s: %w", path, err)
	}

	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return PipelineState{}, &LoadError{Kind: ErrCorrupt,
			Detail: fmt.Sprintf("%s: envelope not JSON: %v", path, err)}
	}
	if env.Magic != stateMagic {
		return PipelineState{}, &LoadError{Kind: ErrVersionIncompatible,
			Detail: fmt.Sprintf("%s: unknown magic %q", path, env.Magic)}
	}
	if env.Version != StoreFormatVersion {
		return PipelineState{}, &LoadError{Kind: ErrVersionIncompatible,
			Detail: fmt.Sprintf("%s: state version %d, engine supports %d",
				path, env.Version, StoreFormatVersion)}
	}
	sum := sha256.Sum256([]byte(env.Payload))
	want := hex.EncodeToString(sum[:])
	if env.Checksum == "" || env.Checksum != want {
		return PipelineState{}, &LoadError{Kind: ErrCorrupt,
			Detail: fmt.Sprintf("%s: checksum mismatch (content tampered or truncated)", path)}
	}

	var st PipelineState
	if err := json.Unmarshal([]byte(env.Payload), &st); err != nil {
		return PipelineState{}, &LoadError{Kind: ErrCorrupt,
			Detail: fmt.Sprintf("%s: payload not decodable: %v", path, err)}
	}

	savedAt := time.Unix(0, env.SavedAt)
	if s.policy.isExpired(savedAt, s.now()) {
		return PipelineState{}, &LoadError{Kind: ErrExpired,
			Detail: fmt.Sprintf("%s: checkpoint saved at %s older than retention %s",
				path, savedAt.Format(time.RFC3339Nano), s.policy.MaxAge)}
	}
	return st, nil
}

// Exists 报告状态文件是否存在。
func (s *Store) Exists(key string) bool {
	_, err := os.Stat(s.path(key))
	return err == nil
}

// Delete 删除指定键的状态文件（不存在不算错）。
func (s *Store) Delete(key string) error {
	lock := s.keyMu(key)
	lock.Lock()
	defer lock.Unlock()

	fl, err := acquireLock(s.dir, key)
	if err != nil {
		return err
	}
	defer fl.Unlock()
	if err := os.Remove(s.path(key)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("delete state %s: %w", key, err)
	}
	return nil
}

// Sweep 删除目录下所有超出保留期限的状态文件（用于回放键等历史堆积）。
// 非本引擎状态文件与锁文件一律不碰。返回被删除的键名。
func (s *Store) Sweep() ([]string, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("list state dir: %w", err)
	}
	now := s.now()
	var removed []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, stateSuffix) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.dir, name))
		if err != nil {
			continue // 可能正处于原子替换中，下一轮再扫
		}
		var env envelope
		if err := json.Unmarshal(data, &env); err != nil || env.Magic != stateMagic {
			continue // 不归本格式管理，不动它
		}
		if !s.policy.isExpired(time.Unix(0, env.SavedAt), now) {
			continue
		}
		key := strings.TrimSuffix(name, stateSuffix)
		if err := s.Delete(key); err == nil {
			removed = append(removed, key)
		}
	}
	return removed, nil
}
