// Package state 在既有检测语义之上提供“可暂停续跑、历史回放对账、
// 状态保留与兼容处理”能力：
//
//   - Pipeline 把 Correlator + alert.Manager 组合成一条可落盘/恢复的处理链路；
//   - Store 负责状态文件的原子写、互斥锁、校验与版本/损坏/过期识别；
//   - Cursor 记录日志文件读取进度（路径 + 字节偏移），重启后跳过已处理部分；
//   - Policy 定义状态的容量与保留策略。
package state

import "errors"

// 落盘状态在读取时可能出现的、互相可区分的问题类别。
var (
	// ErrVersionIncompatible 状态文件版本与当前程序不兼容
	//（版本过新无法理解，或格式魔数不认识）。
	ErrVersionIncompatible = errors.New("state version incompatible")
	// ErrCorrupt 状态文件内容损坏（校验和不符、JSON 无法解析、内部数据不一致）。
	ErrCorrupt = errors.New("state file corrupt")
	// ErrExpired 状态整体早于保留策略允许的最早时间，恢复它会违反
	// “超出保留范围不能静默续跑”的约定。
	ErrExpired = errors.New("state beyond retention horizon")
	// ErrCapacityExceeded 即便按策略尽力裁剪后，最小必要状态仍超出容量上限。
	ErrCapacityExceeded = errors.New("state exceeds capacity limit")
	// ErrRulesChanged 恢复时发现落盘规则与当前传入规则不一致。
	ErrRulesChanged = errors.New("rules changed since checkpoint")
	// ErrLockBusy 状态键已被其他进程/实例锁定。
	ErrLockBusy = errors.New("state key locked by another process")
	// ErrProgressTruncated 日志文件比已记录的进度还短（文件被轮转/截断）。
	ErrProgressTruncated = errors.New("log file truncated before saved offset")
)

// LoadError 给可区分的错误类别附上细节，errors.Is 可匹配上面的哨兵。
type LoadError struct {
	Kind   error
	Detail string
}

func (e *LoadError) Error() string { return e.Kind.Error() + ": " + e.Detail }
func (e *LoadError) Unwrap() error { return e.Kind }
