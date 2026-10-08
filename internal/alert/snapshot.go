package alert

import (
	"errors"
	"fmt"
	"time"
)

// ErrWindowMismatch 表示恢复快照时去重窗口与落盘时不一致。
var ErrWindowMismatch = errors.New("dedup window mismatch with snapshot")

// State 是告警管理器状态的可序列化快照。
// 恢复后继续记录命中，Hits/Suppressed 计数与生命周期结论
// 与从未中断的单次运行一致。
type State struct {
	WindowNs int64
	Alerts   []Alert
}

// Export 导出当前告警状态（深拷贝）。
func (m *Manager) Export() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := State{WindowNs: int64(m.window), Alerts: make([]Alert, 0, len(m.alerts))}
	for _, a := range m.alerts {
		st.Alerts = append(st.Alerts, *a)
	}
	return st
}

// RestoreState 从快照恢复告警管理器；去重窗口必须与快照一致，
// 否则返回 ErrWindowMismatch，由调用方区分处理。
func RestoreState(st State, window time.Duration) (*Manager, error) {
	if time.Duration(st.WindowNs) != window {
		return nil, fmt.Errorf("%w: snapshot=%s current=%s",
			ErrWindowMismatch, time.Duration(st.WindowNs), window)
	}
	m := NewManager(window)
	for _, a := range st.Alerts {
		cp := a
		m.alerts[cp.RuleID+"|"+cp.GroupKey] = &cp
	}
	return m, nil
}
