package alert

import (
	"testing"
	"time"

	"github.com/xingjianluo/go-siem-detection-engine-go/internal/engine"
)

func hit(ruleID, group string, min int) engine.Match {
	return engine.Match{
		RuleID:    ruleID,
		GroupKey:  group,
		Count:     3,
		WindowEnd: time.Date(2026, 10, 1, 10, min, 0, 0, time.UTC),
	}
}

// 场景：进程重启后，已有告警的命中次数与抑制结论必须接着攒，
// 不能因为重启把同一去重键当成全新告警。
func TestRestoreContinuesHitsAndSuppression(t *testing.T) {
	m := NewManager(10 * time.Minute)
	m.Record(hit("R1", "web-1", 0), hit("R1", "web-1", 0).WindowEnd)
	m.Record(hit("R1", "web-1", 1), hit("R1", "web-1", 1).WindowEnd) // 被抑制合并
	st := m.Export()

	m2, err := RestoreState(st, 10*time.Minute)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	// 恢复后窗口内再次命中：继续合并进同一条告警。
	a, isNew := m2.Record(hit("R1", "web-1", 2), hit("R1", "web-1", 2).WindowEnd)
	if isNew {
		t.Fatal("hit after restore created a new alert, want merge into existing")
	}
	if a.Hits != 3 || a.Suppressed != 2 {
		t.Fatalf("hits=%d suppressed=%d, want 3/2", a.Hits, a.Suppressed)
	}
	t.Logf("重启续跑场景：恢复后命中继续合并，hits=%d suppressed=%d，告警未被重置", a.Hits, a.Suppressed)
}

// 场景：重启前去重窗口已经过半，恢复后生命周期判断必须
// 基于原始时间线，而不是从重启时刻重新计窗口。
func TestRestorePreservesLifecycleTiming(t *testing.T) {
	m := NewManager(10 * time.Minute)
	now := time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)
	m.Record(hit("R1", "web-1", 0), now)
	st := m.Export()

	m2, err := RestoreState(st, 10*time.Minute)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	// 距上次命中 11 分钟 > 去重窗口：旧告警应被 Expire 关闭。
	closed := m2.Expire(now.Add(11 * time.Minute))
	if len(closed) != 1 || closed[0].Status != StatusResolved {
		t.Fatalf("closed = %+v, want 1 resolved alert", closed)
	}
	t.Log("生命周期场景：恢复后按原始时间线判定，超时告警正常 resolved")
}

// 场景：去重窗口参数与落盘时不一致，必须显式报错。
func TestRestoreRejectsWindowMismatch(t *testing.T) {
	m := NewManager(10 * time.Minute)
	m.Record(hit("R1", "web-1", 0), time.Now())
	if _, err := RestoreState(m.Export(), 5*time.Minute); err == nil {
		t.Fatal("want error for window mismatch, got nil")
	}
	t.Log("参数变更场景：dedup 10m->5m 恢复告警状态被显式拒绝")
}
