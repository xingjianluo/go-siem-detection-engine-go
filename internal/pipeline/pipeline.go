// Package pipeline 把关联器、告警管理器与状态仓库组装成
// 可暂停续跑的实时链路，并提供与实时链路隔离的历史回放。
//
// 语义约定（沿用 engine/alert 的既有结论，不推翻已产出的判定）：
//   - 每处理完一批事件就把进度与判定状态落盘，进程重启后从
//     落盘位置继续；已处理过的事件再喂进来只会被按 ID 去重，
//     不会重复计数、不会改动已有告警的命中/抑制结论；
//   - 打开链路时状态不可用会返回互相可区分的 ResumeStatus
//     （无状态/版本不兼容/内容损坏/超出保留期/配置变更），
//     绝不静默从头开始；
//   - Replay 使用独立的内存现场，不读写任何落盘状态，
//     结论与同一批事件按时间交给实时链路的结果一致。
package pipeline

import (
	"errors"
	"fmt"
	"time"

	"github.com/xingjianluo/go-siem-detection-engine-go/internal/alert"
	"github.com/xingjianluo/go-siem-detection-engine-go/internal/engine"
	"github.com/xingjianluo/go-siem-detection-engine-go/internal/rules"
	"github.com/xingjianluo/go-siem-detection-engine-go/internal/state"
)

// ResumeStatus 区分打开实时链路时的状态恢复结果。
type ResumeStatus string

const (
	// StatusResumed 从落盘状态恢复，继续往后处理。
	StatusResumed ResumeStatus = "resumed"
	// StatusNoState 状态文件不存在，从头开始。
	StatusNoState ResumeStatus = "no_state"
	// StatusIncompatible 状态版本不兼容。
	StatusIncompatible ResumeStatus = "incompatible_version"
	// StatusCorrupted 状态内容损坏。
	StatusCorrupted ResumeStatus = "corrupted"
	// StatusExpired 状态超出保留期。
	StatusExpired ResumeStatus = "expired"
	// StatusConfigChanged 规则或水位线/去重窗口参数与落盘时不一致。
	StatusConfigChanged ResumeStatus = "config_changed"
)

// Pipeline 是可暂停、可续跑的实时检测链路。
type Pipeline struct {
	corr       *engine.Correlator
	mgr        *alert.Manager
	store      *state.Store
	rules      []rules.Rule
	lateness   time.Duration
	dedup      time.Duration
	processed  int64 // 已从来源消费的事件条数
	checkpoint bool  // 是否在每批后自动落盘（store 为 nil 时关闭）
}

// OpenLive 打开实时链路。状态可用时恢复并返回 StatusResumed；
// 状态不存在时返回全新链路与 StatusNoState；
// 状态不可用（版本不兼容/损坏/过期/配置变更）时返回 nil 链路与
// 对应状态码，由调用方显式决定是报错退出还是放弃旧状态重来，
// 不会静默丢弃已有判定结论。
func OpenLive(store *state.Store, rs []rules.Rule, lateness, dedup time.Duration) (*Pipeline, ResumeStatus, error) {
	p := &Pipeline{
		store:      store,
		rules:      rs,
		lateness:   lateness,
		dedup:      dedup,
		checkpoint: store != nil,
	}
	if store == nil { // 纯内存模式：不落盘，等价于一次性跑完。
		p.corr = engine.NewCorrelator(rs, lateness)
		p.mgr = alert.NewManager(dedup)
		return p, StatusNoState, nil
	}

	cp, err := store.Load()
	switch {
	case errors.Is(err, state.ErrNoState):
		p.corr = engine.NewCorrelator(rs, lateness)
		p.mgr = alert.NewManager(dedup)
		return p, StatusNoState, nil
	case errors.Is(err, state.ErrIncompatibleVersion):
		return nil, StatusIncompatible, nil
	case errors.Is(err, state.ErrCorrupted):
		return nil, StatusCorrupted, nil
	case errors.Is(err, state.ErrExpired):
		return nil, StatusExpired, nil
	case err != nil:
		return nil, "", fmt.Errorf("load state: %w", err)
	}

	// 状态可读，校验配置一致性：规则、水位线、去重窗口任一变化
	// 都可能导致旧状态与新参数下的判定语义对不上，必须显式区分。
	if cp.RulesFingerprint != rules.Fingerprint(rs) ||
		cp.LatenessNs != int64(lateness) || cp.DedupWindowNs != int64(dedup) {
		return nil, StatusConfigChanged, nil
	}

	corr, err := engine.RestoreSnapshot(cp.Engine, rs, lateness)
	if err != nil {
		return nil, StatusConfigChanged, nil
	}
	mgr, err := alert.RestoreState(cp.Alerts, dedup)
	if err != nil {
		return nil, StatusConfigChanged, nil
	}
	p.corr = corr
	p.mgr = mgr
	p.processed = cp.Processed
	return p, StatusResumed, nil
}

// OpenFresh 显式放弃已有落盘状态（如有），从零开始一条实时链路；
// 旧状态会在首次落盘时被覆盖。用于调用方在拿到 StatusIncompatible /
// StatusCorrupted / StatusExpired / StatusConfigChanged 后，
// 明确决定放弃旧现场的场景。
func OpenFresh(store *state.Store, rs []rules.Rule, lateness, dedup time.Duration) *Pipeline {
	return &Pipeline{
		corr:       engine.NewCorrelator(rs, lateness),
		mgr:        alert.NewManager(dedup),
		store:      store,
		rules:      rs,
		lateness:   lateness,
		dedup:      dedup,
		checkpoint: store != nil,
	}
}

// IngestBatch 处理一批事件，把命中记入告警，然后把进度与判定状态
// 落盘（store 非空时）。返回本批新产生的规则命中。
func (p *Pipeline) IngestBatch(events []engine.Event) ([]engine.Match, error) {
	var matches []engine.Match
	for _, e := range events {
		for _, m := range p.corr.Ingest(e) {
			p.mgr.Record(m, m.WindowEnd)
			matches = append(matches, m)
		}
	}
	p.processed += int64(len(events))
	if err := p.save(); err != nil {
		return matches, err
	}
	return matches, nil
}

// Flush 闭合所有未闭合窗口，把命中记入告警并落盘。
// 语义同 engine.Correlator.Flush。
func (p *Pipeline) Flush() ([]engine.Match, error) {
	var matches []engine.Match
	for _, m := range p.corr.Flush() {
		p.mgr.Record(m, m.WindowEnd)
		matches = append(matches, m)
	}
	if err := p.save(); err != nil {
		return matches, err
	}
	return matches, nil
}

// Processed 返回已从来源消费的事件条数（续跑偏移）。
func (p *Pipeline) Processed() int64 { return p.processed }

// Alerts 返回当前告警快照（按 ID 排序）。
func (p *Pipeline) Alerts() []alert.Alert { return p.mgr.Snapshot() }

// Stats 返回关联器运行统计。
func (p *Pipeline) Stats() engine.Stats { return p.corr.Stats() }

// save 把当前进度与判定状态写入状态仓库。
func (p *Pipeline) save() error {
	if !p.checkpoint {
		return nil
	}
	cp := state.Checkpoint{
		RulesFingerprint: rules.Fingerprint(p.rules),
		LatenessNs:       int64(p.lateness),
		DedupWindowNs:    int64(p.dedup),
		Processed:        p.processed,
		Engine:           p.corr.Snapshot(),
		Alerts:           p.mgr.Export(),
	}
	if err := p.store.Save(cp); err != nil {
		return fmt.Errorf("save checkpoint: %w", err)
	}
	return nil
}

// Replay 用当前规则对一批历史事件独立重跑一遍，返回最终告警快照。
// 全程只使用内存现场，不读写任何落盘状态，不会干扰正在运行的
// 实时链路；结论与把这些事件按时间交给实时链路（含 Flush）一致。
func Replay(events []engine.Event, rs []rules.Rule, lateness, dedup time.Duration) []alert.Alert {
	corr := engine.NewCorrelator(rs, lateness)
	mgr := alert.NewManager(dedup)
	for _, e := range events {
		for _, m := range corr.Ingest(e) {
			mgr.Record(m, m.WindowEnd)
		}
	}
	for _, m := range corr.Flush() {
		mgr.Record(m, m.WindowEnd)
	}
	return mgr.Snapshot()
}
