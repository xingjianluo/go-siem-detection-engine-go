package state

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func testCheckpoint(processed int64) Checkpoint {
	return Checkpoint{
		RulesFingerprint: "fp",
		LatenessNs:       int64(10 * time.Minute),
		DedupWindowNs:    int64(10 * time.Minute),
		Processed:        processed,
	}
}

// 场景：运维把引擎跑了一半停机，落盘的状态能原样读回来继续用。
func TestSaveLoadRoundtrip(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir, 3, time.Hour)

	want := testCheckpoint(42)
	if err := s.Save(want); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := s.Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.Processed != want.Processed || got.RulesFingerprint != want.RulesFingerprint {
		t.Fatalf("roundtrip mismatch: got %+v want %+v", got, want)
	}
	t.Logf("停机续跑场景：processed=%d 的检查点落盘后可完整读回", got.Processed)
}

// 场景：首次运行，状态目录里什么都没有，必须明确报告“无状态”，
// 而不是误报成损坏。
func TestLoadNoState(t *testing.T) {
	s := NewStore(t.TempDir(), 3, time.Hour)
	_, err := s.Load()
	if !errors.Is(err, ErrNoState) {
		t.Fatalf("want ErrNoState, got %v", err)
	}
	t.Log("首次运行场景：加载返回 ErrNoState，可与损坏/过期明确区分")
}

// 场景：状态文件被写坏（截断/篡改），必须识别为损坏，
// 不能一声不吭当作没有状态从头开始。
func TestLoadCorruptedFile(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir, 3, time.Hour)
	if err := s.Save(testCheckpoint(1)); err != nil {
		t.Fatalf("save: %v", err)
	}
	// 截断文件模拟写坏。
	path := filepath.Join(dir, currentFile)
	if err := os.WriteFile(path, []byte(`{"version":1,"saved_at`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(); !errors.Is(err, ErrCorrupted) {
		t.Fatalf("truncated: want ErrCorrupted, got %v", err)
	}
	t.Log("文件截断场景：识别为 ErrCorrupted")

	// 篡改负载但保留合法信封结构，校验和必须兜住。
	if err := s.Save(testCheckpoint(2)); err != nil {
		t.Fatalf("save: %v", err)
	}
	data, _ := os.ReadFile(path)
	// 翻转负载区一个字节（payload 在文件后部）。
	data[len(data)-10] ^= 0xff
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(); !errors.Is(err, ErrCorrupted) {
		t.Fatalf("tampered: want ErrCorrupted, got %v", err)
	}
	t.Log("内容篡改场景：CRC 校验和不匹配，识别为 ErrCorrupted")
}

// 场景：状态文件来自更新/更旧版本的引擎，版本号对不上，
// 必须识别为版本不兼容而不是损坏。
func TestLoadIncompatibleVersion(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir, 3, time.Hour)
	if err := s.Save(testCheckpoint(7)); err != nil {
		t.Fatalf("save: %v", err)
	}
	// 把版本号改成不支持的值（保持校验和一致，排除损坏干扰）。
	path := filepath.Join(dir, currentFile)
	data, _ := os.ReadFile(path)
	var env map[string]any
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}
	env["version"] = 999
	raw, _ := json.Marshal(env)
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(); !errors.Is(err, ErrIncompatibleVersion) {
		t.Fatalf("want ErrIncompatibleVersion, got %v", err)
	}
	t.Log("版本演进场景：version=999 的状态文件识别为 ErrIncompatibleVersion")
}

// 场景：停机太久，状态已超出保留期，旧进度不再可信，
// 必须与“没有状态”“损坏”区分开。
func TestLoadExpired(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	s := NewStore(dir, 3, time.Hour)
	s.now = func() time.Time { return now }
	if err := s.Save(testCheckpoint(9)); err != nil {
		t.Fatalf("save: %v", err)
	}
	// 时钟拨到保留期之外。
	s.now = func() time.Time { return now.Add(2 * time.Hour) }
	if _, err := s.Load(); !errors.Is(err, ErrExpired) {
		t.Fatalf("want ErrExpired, got %v", err)
	}
	t.Log("长期停机场景：快照年龄 2h > 保留期 1h，识别为 ErrExpired")
}

// 场景：长期运行反复落盘，本地快照文件数必须有硬上限，
// 不能无限膨胀。
func TestRotationCapsSnapshotFiles(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir, 3, time.Hour)
	for i := 0; i < 10; i++ {
		if err := s.Save(testCheckpoint(int64(i))); err != nil {
			t.Fatalf("save %d: %v", i, err)
		}
	}
	files, err := s.SnapshotFiles()
	if err != nil {
		t.Fatal(err)
	}
	if len(files) > 3 {
		t.Fatalf("snapshot files = %d, want <= 3: %v", len(files), files)
	}
	// 最新一份必须是最新写入的内容。
	got, err := s.Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.Processed != 9 {
		t.Fatalf("latest checkpoint processed = %d, want 9", got.Processed)
	}
	t.Logf("容量策略场景：连续落盘 10 次，磁盘上仅保留 %d 份快照：%v", len(files), files)
}

// 场景：多个来源（多 goroutine / 多进程）同时落盘，
// 不能竞态、不能写丢、不能留下撕裂文件。
func TestConcurrentSaveNoRaceNoTornWrite(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir, 2, time.Hour)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				if err := s.Save(testCheckpoint(int64(g*1000 + i))); err != nil {
					t.Errorf("save: %v", err)
					return
				}
			}
		}(g)
	}
	wg.Wait()
	// 并发写结束后，读出来的必须是一份完整合法的检查点。
	if _, err := s.Load(); err != nil {
		t.Fatalf("load after concurrent saves: %v", err)
	}
	files, _ := s.SnapshotFiles()
	if len(files) > 2 {
		t.Fatalf("snapshot files = %d, want <= 2", len(files))
	}
	t.Logf("并发落盘场景：8 来源 x 50 次写入后状态完整可读，保留文件 %v", files)
}

// 场景：写入过程中崩溃（模拟：只留下 tmp 文件），
// 旧检查点必须仍然完好可用。
func TestCrashDuringWriteKeepsOldCheckpoint(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir, 3, time.Hour)
	if err := s.Save(testCheckpoint(5)); err != nil {
		t.Fatalf("save: %v", err)
	}
	// 模拟崩溃现场：留下一个未完成的临时文件。
	tmp := filepath.Join(dir, currentFile+".tmp")
	if err := os.WriteFile(tmp, []byte(`{"version":1,partial`), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := s.Load()
	if err != nil {
		t.Fatalf("load with leftover tmp: %v", err)
	}
	if got.Processed != 5 {
		t.Fatalf("processed = %d, want 5", got.Processed)
	}
	t.Log("写盘崩溃场景：残留 tmp 文件不影响旧检查点，processed=5 完好")
}
