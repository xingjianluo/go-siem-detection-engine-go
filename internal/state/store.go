// Package state 提供检测引擎判定状态的本地持久化：
//
//   - 快照文件带格式版本与 CRC32 校验和，损坏/版本不兼容/超出保留期
//     分别返回可区分的错误（errors.Is 判定），绝不静默当作无状态；
//   - 写入先落临时文件再 rename，崩溃不会留下半个文件；
//   - 多进程/多 goroutine 同时写通过文件锁串行化，不会竞态或写丢；
//   - 容量策略：最多保留 maxSnapshots 个快照文件，超出轮换删除；
//     保留策略：快照年龄超过 maxAge 时 Load 返回 ErrExpired。
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/xingjianluo/go-siem-detection-engine-go/internal/alert"
	"github.com/xingjianluo/go-siem-detection-engine-go/internal/engine"
)

// FormatVersion 是当前状态文件格式版本。
const FormatVersion = 1

// 可区分的加载失败原因，用 errors.Is 判定。
var (
	// ErrNoState 状态文件不存在（首次运行）。
	ErrNoState = errors.New("no state")
	// ErrIncompatibleVersion 状态文件版本与当前引擎不兼容。
	ErrIncompatibleVersion = errors.New("incompatible state version")
	// ErrCorrupted 状态文件内容损坏（解析失败或校验和不匹配）。
	ErrCorrupted = errors.New("corrupted state")
	// ErrExpired 状态已超出保留期，不再可信。
	ErrExpired = errors.New("state beyond retention")
)

// Checkpoint 是一次完整落盘的判定现场。
type Checkpoint struct {
	RulesFingerprint string
	LatenessNs       int64
	DedupWindowNs    int64
	Processed        int64 // 已从来源消费的事件条数（用于续跑偏移）
	Engine           engine.Snapshot
	Alerts           alert.State
}

// envelope 是磁盘上的文件结构：元信息 + 校验和 + 负载。
type envelope struct {
	Version  int             `json:"version"`
	SavedAt  time.Time       `json:"saved_at"`
	Checksum uint32          `json:"checksum"`
	Payload  json.RawMessage `json:"payload"`
}

// Store 管理本地状态文件的读写、轮换与保留。并发安全。
type Store struct {
	mu           sync.Mutex
	dir          string
	maxSnapshots int
	maxAge       time.Duration
	now          func() time.Time // 可注入时钟，便于测试保留期
}

// NewStore 创建状态仓库。maxSnapshots 为保留的快照文件数上限（含最新），
// maxAge 为快照保留期（加载时超过即视为 ErrExpired）。
func NewStore(dir string, maxSnapshots int, maxAge time.Duration) *Store {
	if maxSnapshots < 1 {
		maxSnapshots = 1
	}
	return &Store{
		dir:          dir,
		maxSnapshots: maxSnapshots,
		maxAge:       maxAge,
		now:          time.Now,
	}
}

const (
	currentFile = "checkpoint.json"
	lockFile    = "checkpoint.lock"
)

// Save 原子地写入一个检查点，并按容量策略轮换旧快照。
// 多来源并发写在文件锁下串行执行，后写覆盖先写，不会写丢或撕裂。
func (s *Store) Save(cp Checkpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()

	payload, err := json.Marshal(cp)
	if err != nil {
		return fmt.Errorf("encode checkpoint: %w", err)
	}
	env := envelope{
		Version:  FormatVersion,
		SavedAt:  s.now().UTC(),
		Checksum: crc32.ChecksumIEEE(payload),
		Payload:  payload,
	}
	data, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("encode envelope: %w", err)
	}

	// 先写临时文件并 fsync，再 rename，保证任何时刻 checkpoint.json
	// 要么是旧版本要么是完整的新版本。
	tmp := filepath.Join(s.dir, currentFile+".tmp")
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("write temp state: %w", err)
	}
	if err := syncFile(tmp); err != nil {
		return fmt.Errorf("fsync temp state: %w", err)
	}

	// 轮换：当前文件先转为历史快照，再换上新文件。
	if _, err := os.Stat(filepath.Join(s.dir, currentFile)); err == nil {
		if err := s.rotateLocked(); err != nil {
			return fmt.Errorf("rotate state: %w", err)
		}
	}
	if err := os.Rename(tmp, filepath.Join(s.dir, currentFile)); err != nil {
		return fmt.Errorf("commit state: %w", err)
	}
	return nil
}

// Load 读取最新检查点。失败原因用 errors.Is 区分：
// ErrNoState / ErrIncompatibleVersion / ErrCorrupted / ErrExpired。
func (s *Store) Load() (Checkpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(filepath.Join(s.dir, currentFile))
	if errors.Is(err, os.ErrNotExist) {
		return Checkpoint{}, ErrNoState
	}
	if err != nil {
		return Checkpoint{}, fmt.Errorf("read state: %w", err)
	}

	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return Checkpoint{}, fmt.Errorf("%w: unparseable envelope: %v", ErrCorrupted, err)
	}
	if env.Version != FormatVersion {
		return Checkpoint{}, fmt.Errorf("%w: file version %d, supported %d",
			ErrIncompatibleVersion, env.Version, FormatVersion)
	}
	if crc32.ChecksumIEEE(env.Payload) != env.Checksum {
		return Checkpoint{}, fmt.Errorf("%w: checksum mismatch", ErrCorrupted)
	}
	if s.maxAge > 0 && s.now().Sub(env.SavedAt) > s.maxAge {
		return Checkpoint{}, fmt.Errorf("%w: saved at %s, retention %s",
			ErrExpired, env.SavedAt.Format(time.RFC3339), s.maxAge)
	}

	var cp Checkpoint
	if err := json.Unmarshal(env.Payload, &cp); err != nil {
		return Checkpoint{}, fmt.Errorf("%w: unparseable payload: %v", ErrCorrupted, err)
	}
	return cp, nil
}

// rotateLocked 把现有快照文件序号顺移一位（checkpoint.json ->
// checkpoint.1.json -> checkpoint.2.json ...），超出容量上限的删除。
// 调用时必须已持有文件锁。
func (s *Store) rotateLocked() error {
	// 容量为 1 时不保留历史快照，直接删除当前文件。
	if s.maxSnapshots == 1 {
		if err := os.Remove(filepath.Join(s.dir, currentFile)); err != nil &&
			!errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	// 删除最老的一份（序号最大）。
	oldest := filepath.Join(s.dir, rotatedName(s.maxSnapshots-1))
	if err := os.Remove(oldest); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	// 序号顺移：n-2 -> n-1, ..., 1 -> 2。
	for i := s.maxSnapshots - 2; i >= 1; i-- {
		from := filepath.Join(s.dir, rotatedName(i))
		to := filepath.Join(s.dir, rotatedName(i+1))
		if err := os.Rename(from, to); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	// 当前文件变为 1 号历史快照。
	return os.Rename(filepath.Join(s.dir, currentFile),
		filepath.Join(s.dir, rotatedName(1)))
}

// rotatedName 返回第 i 份历史快照的文件名。
func rotatedName(i int) string {
	return "checkpoint." + strconv.Itoa(i) + ".json"
}

// SnapshotFiles 返回当前保留的快照文件列表（含最新），按新到旧排序。
// 供测试与运维排查确认容量策略生效。
func (s *Store) SnapshotFiles() ([]string, error) {
	entries, err := os.ReadDir(s.dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var files []string
	for _, e := range entries {
		name := e.Name()
		if name == currentFile || (strings.HasPrefix(name, "checkpoint.") &&
			strings.HasSuffix(name, ".json") && name != currentFile+".tmp") {
			files = append(files, name)
		}
	}
	sort.Strings(files)
	return files, nil
}

// lock 获取仓库级文件锁，返回释放函数。锁文件本身不参与轮换。
func (s *Store) lock() (func(), error) {
	f, err := os.OpenFile(filepath.Join(s.dir, lockFile), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, fmt.Errorf("acquire state lock: %w", err)
	}
	return func() {
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}

func syncFile(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
