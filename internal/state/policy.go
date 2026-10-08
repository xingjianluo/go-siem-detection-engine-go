package state

import "time"

// 默认保留参数（本地运维排查场景）。
const (
	// DefaultMaxAge：resolved 告警与磁盘上旧 checkpoint 默认保留 3 天。
	DefaultMaxAge = 72 * time.Hour
	// DefaultMaxBytes：单个状态文件默认 16 MiB 软上限。
	DefaultMaxBytes = 16 << 20
)

// Policy 定义落盘状态的容量与保留策略。
//
// 状态不能只涨不消。保存时按以下顺序收缩：
//  1. 关联器状态本身已由水位线语义自然限定在
//     “(lateness + 最大规则窗口) 事件跨度”之内，快照不会超过这个范围；
//  2. LastSeen 早于 now-MaxAge 的 resolved 告警被删除
//     （firing 告警永不因保留策略被静默丢弃）；
//  3. 体积仍超过 MaxBytes 时，先尝试把 resolved 告警全部清掉；
//  4. 若连关联器的最小必要状态都超过 MaxBytes，返回
//     ErrCapacityExceeded —— 不能靠删判定状态来“假装装得下”，
//     因为那会改变乱序/迟到窗口的既有结论。
//
// 磁盘上的 checkpoint 文件由 Store.Sweep 按同一 MaxAge 清理，
// 避免多次历史回放产生的状态键无限堆积。
type Policy struct {
	// MaxAge 是 resolved 告警与旧 checkpoint 的墙钟保留时长；零值表示不限制。
	MaxAge time.Duration
	// MaxBytes 是单个状态文件序列化后的软上限；零值表示不限制。
	MaxBytes int
}

// DefaultPolicy 是本地运维排查场景的默认保留策略：
// resolved 告警与旧 checkpoint 保留 3 天，状态文件软上限 16 MiB。
func DefaultPolicy() Policy {
	return Policy{MaxAge: DefaultMaxAge, MaxBytes: DefaultMaxBytes}
}

// resolvedCutoff 返回 resolved 告警的清理边界：LastSeen 早于该时刻的
// resolved 告警应被删除。MaxAge 为 0 时返回零值时间，表示不清理。
func (p Policy) resolvedCutoff(now time.Time) time.Time {
	if p.MaxAge <= 0 {
		return time.Time{}
	}
	return now.Add(-p.MaxAge)
}

// isExpired 判断保存于 savedAt 的 checkpoint 是否已超出墙钟保留期。
// MaxAge 为 0 时永不过期。
func (p Policy) isExpired(savedAt, now time.Time) bool {
	if p.MaxAge <= 0 || savedAt.IsZero() {
		return false
	}
	return now.Sub(savedAt) > p.MaxAge
}
