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
	"testing"
	"time"

	"github.com/xingjianluo/go-siem-detection-engine-go/internal/engine"
)

// 三类读取问题必须给出互相能区分的结果，且不能静默当“没有状态”从头开始。
func TestLoadDistinguishesVersionCorruptExpired(t *testing.T) {
	dir := t.TempDir()

	// 1) 版本不兼容（魔数不认识）。
	path := filepath.Join(dir, "magic.state.json")
	writeRaw(t, path, `{"magic":"some-other-tool","version":1,"payload":"{}","checksum":""}`)

	// 2) 版本号过高。
	path2 := filepath.Join(dir, "ver.state.json")
	env2, _ := buildEnvelope(t, PipelineState{
		Correlator: engine.State{LatenessNS: int64(time.Minute)},
	}, time.Now())
	env2.Version = 99
	writeRaw(t, path2, mustJSON(t, env2))

	// 3) 校验和损坏（模拟磁盘写坏 / 手工篡改）。
	path3 := filepath.Join(dir, "corrupt.state.json")
	env3, payload3 := buildEnvelope(t, PipelineState{
		Correlator: engine.State{LatenessNS: int64(time.Minute), HasMax: true},
	}, time.Now())
	_ = payload3
	// 改 payload 但不动 checksum。
	env3.Payload = strings.Replace(env3.Payload, `"has_max":true`, `"has_max":false`, 1)
	writeRaw(t, path3, mustJSON(t, env3))

	// 4) 外层 JSON 直接截断。
	path4 := filepath.Join(dir, "truncated.state.json")
	raw4 := mustJSON(t, env3)
	writeRaw(t, path4, raw4[:len(raw4)/2])

	// 5) payload 不是合法的 PipelineState。
	path5 := filepath.Join(dir, "badpayload.state.json")
	env5 := makeEnvelope(t, `{"correlator":"not-an-object"}`, time.Now())
	writeRaw(t, path5, mustJSON(t, env5))

	store, err := NewStore(dir, DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		key  string
		want error
	}{
		{"unknown magic", "magic", ErrVersionIncompatible},
		{"future version", "ver", ErrVersionIncompatible},
		{"tampered checksum", "corrupt", ErrCorrupt},
		{"truncated envelope", "truncated", ErrCorrupt},
		{"undecodable payload", "badpayload", ErrCorrupt},
	}
	for _, c := range cases {
		_, err := store.Load(c.key)
		if !errors.Is(err, c.want) {
			t.Errorf("[compat-scenario] %s: want %v, got %v", c.name, c.want, err)
		} else {
			t.Logf("[compat-scenario] %s -> %v | %v", c.name, c.want, err)
		}
	}
}

// 业务场景：checkpoint 超出保留期（MaxAge）必须被识别为 ErrExpired，
// 不能静默当空状态从头续跑；放宽保留策略后同文件又可正常读取。
func TestExpiredCheckpointRejected(t *testing.T) {
	dir := t.TempDir()
	st := PipelineState{
		Correlator: engine.State{LatenessNS: int64(time.Minute), HasMax: true,
			MaxSeen: tBase},
	}
	strict, err := NewStore(dir, Policy{MaxAge: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	clock := tBase
	strict.withClock(func() time.Time { return clock })
	if err := strict.Save("old", st); err != nil {
		t.Fatal(err)
	}

	clock = tBase.Add(2 * time.Hour)
	_, err = strict.Load("old")
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("[expiry-scenario] want ErrExpired, got %v", err)
	}
	t.Logf("[expiry-scenario] checkpoint older than MaxAge rejected: %v", err)

	// 同样的文件，换一个不设 MaxAge 的 store 读取，应能读出而非损坏。
	loose, err := NewStore(dir, Policy{})
	if err != nil {
		t.Fatal(err)
	}
	got, err := loose.Load("old")
	if err != nil {
		t.Fatalf("[expiry-scenario] loose policy should still read the file: %v", err)
	}
	if !got.Correlator.MaxSeen.Equal(tBase) {
		t.Fatalf("payload mismatch: %s", got.Correlator.MaxSeen)
	}
	t.Logf("[expiry-scenario] file itself intact; expiry is a policy decision, not corruption")
}

// 业务场景：resolved 告警按 MaxAge 清理、状态只降不涨；Sweep 清掉
// 过期的回放状态文件；firing 告警永不被保留策略删除。
func TestRetentionPrunesAndSweeps(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir, Policy{MaxAge: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	clock := tBase
	store.withClock(func() time.Time { return clock })

	p := newTestPipeline()
	p.BindStore(store, RealtimeKey)
	p.BindCursor(filepath.Join(dir, "events.jsonl"))
	// 产生 2 条 firing 告警。
	p.IngestEvent(evt("g1", 0, "web-1"))
	p.IngestEvent(evt("g2", 0, "web-2"))
	p.IngestEvent(evt("g3", 1, "web-1"))
	p.IngestEvent(evt("g4", 1, "web-2"))
	p.IngestEvent(evt("g5", 2, "web-1"))
	p.IngestEvent(evt("g6", 2, "web-2"))
	// 实时链路只有在闭合后才有告警；对账/收尾场景调用 Flush。
	p.Flush()
	if _, err := p.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	// 超 dedup 窗口很久未再命中 -> 全部 resolved。
	closed := p.Expire(tBase.Add(24 * time.Hour))
	if len(closed) != 2 {
		t.Fatalf("want 2 resolved, got %d", len(closed))
	}

	// 再来一组新的 firing 告警（够阈值并 Flush 闭合）。
	p.IngestEvent(evt("h1", 24*60, "web-9"))
	p.IngestEvent(evt("h2", 24*60+1, "web-9"))
	p.IngestEvent(evt("h3", 24*60+2, "web-9"))
	p.Flush()

	clock = tBase.Add(2 * time.Hour) // resolved 告警（LastSeen=10:02）已超 MaxAge
	res, err := p.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	if res.ResolvedPruned != 2 {
		t.Fatalf("want 2 old resolved alerts pruned, got %d", res.ResolvedPruned)
	}
	alerts := p.Alerts()
	if len(alerts) != 1 || alerts[0].GroupKey != "web-9" {
		t.Fatalf("only the new firing alert should remain, got %+v", alerts)
	}
	t.Logf("[retention-scenario] pruned %d aged resolved alerts; firing alert kept (%s)",
		res.ResolvedPruned, alerts[0].ID)

	// Sweep：在清扫时刻 tBase+3h，一个文件保存于 30 分钟前（新鲜，保留），
	// 另一个保存于 tBase（已超 1h 保留期，删除）；实时文件不能被动。
	oldSt := PipelineState{Correlator: engine.State{LatenessNS: int64(time.Minute)}}
	clock = tBase.Add(150 * time.Minute) // 清扫前 30 分钟
	if err := store.Save("replay-keep", oldSt); err != nil {
		t.Fatal(err)
	}
	clock = tBase
	if err := store.Save("replay-ancient", oldSt); err != nil {
		t.Fatal(err)
	}
	clock = tBase.Add(3 * time.Hour)
	swept, err := store.Sweep()
	if err != nil {
		t.Fatal(err)
	}
	sweptSet := map[string]bool{}
	for _, k := range swept {
		sweptSet[k] = true
	}
	if !sweptSet["replay-ancient"] || sweptSet["replay-keep"] || sweptSet[RealtimeKey] {
		t.Fatalf("sweep removed wrong keys: %v", swept)
	}
	t.Logf("[retention-scenario] sweep removed %v (kept fresh replay and realtime)", swept)
}

// 业务场景：最小必要状态超过 MaxBytes 时必须报 ErrCapacityExceeded，
// 不能悄悄删判定状态；正常体积的状态保存成功。
func TestCapacityLimitEnforced(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir, Policy{MaxBytes: 80}) // 极小上限：连一个事件的最小状态都放不下
	if err != nil {
		t.Fatal(err)
	}
	p := newTestPipeline()
	p.BindStore(store, RealtimeKey)
	p.BindCursor(filepath.Join(dir, "events.jsonl"))
	p.IngestEvent(evt("e1", 0, "web-1"))

	if _, err := p.Checkpoint(); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("[capacity-scenario] want ErrCapacityExceeded, got %v", err)
	}
	t.Logf("[capacity-scenario] minimum state above MaxBytes refused: %v", err)

	// 上限放宽后同样的状态可以正常落盘并读回。
	big, err := NewStore(dir, Policy{MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	p.BindStore(big, RealtimeKey)
	if _, err := p.Checkpoint(); err != nil {
		t.Fatalf("[capacity-scenario] state within limit must save: %v", err)
	}
	if _, err := big.Load(RealtimeKey); err != nil {
		t.Fatalf("[capacity-scenario] saved state must load back: %v", err)
	}
	t.Logf("[capacity-scenario] same state saves once limit raised; no judgment state was silently dropped")
}

// 业务场景：多个来源并发保存同一状态键，不允许竞态或写丢：
// 每次落盘的内容必须与保存时的快照一致（原子可见），最终文件可正常读回。
func TestConcurrentSavesNoRaceNoLoss(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir, DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	const writers = 8
	const rounds = 20

	var wg sync.WaitGroup
	errs := make(chan error, writers*rounds)
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			p := newTestPipeline()
			p.BindStore(store, RealtimeKey)
			p.BindCursor(filepath.Join(dir, "events.jsonl"))
			for i := 0; i < rounds; i++ {
				p.IngestEvent(evt(fmt.Sprintf("w%d-e%d", w, i), i, fmt.Sprintf("host-%d", w)))
				if _, err := p.Checkpoint(); err != nil {
					errs <- err
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent save failed: %v", err)
	}

	// 最终文件必须是完整可解析的某一份快照（原子 rename 保证不会读到混合内容）。
	st, err := store.Load(RealtimeKey)
	if err != nil {
		t.Fatalf("[concurrent-scenario] final state unreadable: %v", err)
	}
	if len(st.Correlator.SeenIDs) == 0 {
		t.Fatal("[concurrent-scenario] final state lost all events")
	}
	t.Logf("[concurrent-scenario] %d writers x %d rounds: final state intact, seen_ids=%d, no race",
		writers, rounds, len(st.Correlator.SeenIDs))
}

// 业务场景：同一键同时有两个进程尝试加锁，第二个必须拿到 ErrLockBusy，
// 不能把对方的状态文件覆盖掉。
func TestLockContentionRejected(t *testing.T) {
	dir := t.TempDir()
	fl, err := acquireLock(dir, "contended")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := acquireLock(dir, "contended"); !errors.Is(err, ErrLockBusy) {
		t.Fatalf("[lock-scenario] want ErrLockBusy, got %v", err)
	}
	t.Logf("[lock-scenario] second locker rejected while first holds the key")
	if err := fl.Unlock(); err != nil {
		t.Fatal(err)
	}
	fl2, err := acquireLock(dir, "contended")
	if err != nil {
		t.Fatalf("[lock-scenario] lock must be reusable after unlock: %v", err)
	}
	_ = fl2.Unlock()
}

// ---- helpers ----

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func writeRaw(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func makeEnvelope(t *testing.T, payload string, savedAt time.Time) envelope {
	t.Helper()
	sum := sha256Hex(payload)
	return envelope{
		Magic:    stateMagic,
		Version:  StoreFormatVersion,
		SavedAt:  savedAt.UnixNano(),
		Checksum: sum,
		Payload:  payload,
	}
}

func buildEnvelope(t *testing.T, st PipelineState, savedAt time.Time) (envelope, string) {
	t.Helper()
	b, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	return makeEnvelope(t, string(b), savedAt), string(b)
}
