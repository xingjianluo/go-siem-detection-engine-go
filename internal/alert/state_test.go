package alert

import (
	"testing"
	"time"
)

// 业务场景：进程重启后恢复告警表，Hits/Suppressed/状态/抑制原因原样保留，
// 序号不回退，后续合并仍计入同一条告警。
func TestSnapshotRestorePreservesAlerts(t *testing.T) {
	m := NewManager(10 * time.Minute)
	a1, _ := m.Record(match("R1", "web-1", 0), base)
	m.Record(match("R1", "web-1", 3), base.Add(3*time.Minute)) // 合并
	m.Record(match("R2", "web-9", 0), base)                    // 另一条
	t.Logf("[alert-restore-scenario] before restart: %d alerts, first id=%s hits=%d suppressed=%d",
		len(m.Snapshot()), a1.ID, m.Snapshot()[0].Hits, m.Snapshot()[0].Suppressed)

	m2 := NewManager(0)
	if err := m2.RestoreState(m.SnapshotState()); err != nil {
		t.Fatalf("restore: %v", err)
	}
	got := m2.Snapshot()
	if len(got) != 2 {
		t.Fatalf("want 2 restored alerts, got %d", len(got))
	}
	var web1 *Alert
	for i := range got {
		if got[i].GroupKey == "web-1" {
			web1 = &got[i]
		}
	}
	if web1 == nil || web1.Hits != 2 || web1.Suppressed != 1 {
		t.Fatalf("hits/suppressed changed across restart: %+v", web1)
	}
	t.Logf("[alert-restore-scenario] restored alert id=%s hits=%d suppressed=%d status=%s reason=%q",
		web1.ID, web1.Hits, web1.Suppressed, web1.Status, web1.Reason)

	// 再命中仍在去重窗口内：必须并入原告警，Hits=3，不能新开一条。
	merged, isNew := m2.Record(match("R1", "web-1", 5), base.Add(5*time.Minute))
	if isNew || merged.ID != web1.ID || merged.Hits != 3 || merged.Suppressed != 2 {
		t.Fatalf("post-restart hit must merge: %+v", merged)
	}
	t.Logf("[alert-restore-scenario] post-restort merged hit -> hits=%d suppressed=%d id unchanged=%v",
		merged.Hits, merged.Suppressed, merged.ID == web1.ID)
}

// 业务场景：resolved 告警按保留边界清理，firing 告警不动。
func TestPruneResolvedOnly(t *testing.T) {
	m := NewManager(time.Hour)
	m.Record(match("R1", "web-1", 0), base)
	m.Record(match("R2", "web-2", 0), base)
	m.Expire(base.Add(2 * time.Hour))                        // 两条都 resolved
	m.Record(match("R3", "web-3", 0), base.Add(3*time.Hour)) // 新的 firing

	removed := m.PruneResolvedBefore(base.Add(90 * time.Minute))
	if removed != 2 {
		t.Fatalf("want 2 resolved alerts pruned, got %d", removed)
	}
	got := m.Snapshot()
	if len(got) != 1 || got[0].RuleID != "R3" || got[0].Status != StatusFiring {
		t.Fatalf("firing alert must survive pruning: %+v", got)
	}
	t.Logf("[alert-prune-scenario] pruned=%d resolved alerts; firing alert retained: %s",
		removed, got[0].ID)
}

// 业务场景：损坏的告警快照不能恢复成半条状态。
func TestRestoreRejectsBadAlertState(t *testing.T) {
	good := NewManager(time.Minute)
	good.Record(match("R1", "web-1", 0), base)

	dirty := NewManager(time.Minute)
	dirty.Record(match("R9", "x", 0), base)
	if err := dirty.RestoreState(good.SnapshotState()); err == nil {
		t.Fatal("restore into non-empty manager must fail")
	}
	t.Logf("[alert-restore-guard-scenario] restore into dirty manager rejected")

	bad := good.SnapshotState()
	bad.Alerts[0].Status = "bogus"
	if err := NewManager(time.Minute).RestoreState(bad); err == nil {
		t.Fatal("unknown alert status must be rejected")
	}
	t.Logf("[alert-restore-guard-scenario] unknown status rejected")
}
