package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/xingjianluo/go-siem-detection-engine-go/internal/alert"
	"github.com/xingjianluo/go-siem-detection-engine-go/internal/engine"
	"github.com/xingjianluo/go-siem-detection-engine-go/internal/rules"
)

// RealtimeKey 是实时链路默认使用的状态键。
const RealtimeKey = "realtime"

// ErrNoStore 表示 Pipeline 未绑定 Store 却调用了 Checkpoint。
var ErrNoStore = errors.New("pipeline has no bound state store")

// AlertOutcome 是一次命中产出的告警结果。
type AlertOutcome struct {
	Match engine.Match
	Alert alert.Alert
	IsNew bool
}

// IngestResult 是摄入事件的结果：本次新产出的命中、告警与累计统计。
type IngestResult struct {
	Matches  []engine.Match
	Outcomes []AlertOutcome
	Stats    engine.Stats
}

// Config 是 Pipeline 的构造参数。
type Config struct {
	Rules       []rules.Rule
	Lateness    time.Duration
	DedupWindow time.Duration
}

// Pipeline 是一条可暂停、可续跑的检测链路：
// 关联器 + 告警管理器 + 进度游标，状态可通过 Store 落盘/恢复。
type Pipeline struct {
	corr *engine.Correlator
	mgr  *alert.Manager
	cur  *Cursor
	cfg  Config

	store *Store
	key   string
}

// NewPipeline 按配置创建一条全新链路。
func NewPipeline(cfg Config) *Pipeline {
	return &Pipeline{
		corr: engine.NewCorrelator(cfg.Rules, cfg.Lateness),
		mgr:  alert.NewManager(cfg.DedupWindow),
		cfg:  cfg,
	}
}

// BindStore 把状态存储与状态键绑定到链路（实时链路用 RealtimeKey，
// 历史回放用各自独立的 ReplayKey，互不干扰）。
func (p *Pipeline) BindStore(s *Store, key string) { p.store, p.key = s, key }

// BindCursor 把链路与某个日志文件的进度游标绑定（从头开始）。
func (p *Pipeline) BindCursor(path string) { p.cur = NewCursor(path) }

// RestorePipeline 从落盘状态恢复一条链路。
// expectRules 为当前规则：与落盘规则不一致时返回 ErrRulesChanged
// （不静默用新规则覆盖既有判定；要换新规则请走历史回放另开现场）。
func RestorePipeline(st PipelineState, expectRules []rules.Rule, store *Store, key string) (*Pipeline, error) {
	if rulesFingerprint(st.Correlator.Rules) != rulesFingerprint(expectRules) {
		return nil, fmt.Errorf("%w: checkpoint rules differ from current rules", ErrRulesChanged)
	}
	corr := engine.NewCorrelator(nil, 0)
	if err := corr.RestoreState(st.Correlator); err != nil {
		return nil, fmt.Errorf("restore correlator: %w", err)
	}
	mgr := alert.NewManager(0)
	if err := mgr.RestoreState(st.Alerts); err != nil {
		return nil, fmt.Errorf("restore alerts: %w", err)
	}
	p := &Pipeline{
		corr:  corr,
		mgr:   mgr,
		cur:   &Cursor{},
		store: store,
		key:   key,
		cfg: Config{
			Rules:       st.Correlator.Rules,
			Lateness:    time.Duration(st.Correlator.LatenessNS),
			DedupWindow: time.Duration(st.Alerts.DedupWindowNS),
		},
	}
	if err := p.cur.Restore(st.Cursor); err != nil {
		return nil, err
	}
	return p, nil
}

// rulesFingerprint 计算归一化规则集的稳定指纹（与切片顺序无关）：
// 落盘规则与当前规则只要语义一致，指纹就一致。
func rulesFingerprint(rs []rules.Rule) string {
	// rules.LoadFile 已保证文件内 id 不重复；按 id 排序消除顺序影响。
	sorted := make([]rules.Rule, len(rs))
	copy(sorted, rs)
	// 简单插入排序，避免为这点逻辑再引 sort 到本文件关注点里。
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && sorted[j-1].ID > sorted[j].ID; j-- {
			sorted[j-1], sorted[j] = sorted[j], sorted[j-1]
		}
	}
	b, _ := json.Marshal(sorted)
	return string(b)
}

// IngestEvent 摄入一条已解析事件，记录命中与告警结果。
// 重复事件、迟到事件沿用关联器既有语义（去重 / 丢弃计数），
// 不会产生新命中，因此也不会改乱已有告警的命中次数与抑制结论。
func (p *Pipeline) IngestEvent(e engine.Event) IngestResult {
	return p.record(p.corr.Ingest(e))
}

// Flush 在输入结束（典型为一次历史回放跑完）时闭合所有未闭合窗口。
func (p *Pipeline) Flush() IngestResult { return p.record(p.corr.Flush()) }

func (p *Pipeline) record(ms []engine.Match) IngestResult {
	res := IngestResult{Matches: ms}
	for _, m := range ms {
		// 与 cmd/siem 既有用法一致：以窗口右端事件时间作为告警时间，
		// 保证回放与实时的去重合并结论只取决于事件本身。
		a, isNew := p.mgr.Record(m, m.WindowEnd)
		res.Outcomes = append(res.Outcomes, AlertOutcome{Match: m, Alert: a, IsNew: isNew})
	}
	res.Stats = p.corr.Stats()
	return res
}

// Expire 按给定当前时间关闭超期 firing 告警。
func (p *Pipeline) Expire(now time.Time) []alert.Alert { return p.mgr.Expire(now) }

// Alerts 返回当前告警快照。
func (p *Pipeline) Alerts() []alert.Alert { return p.mgr.Snapshot() }

// Stats 返回关联器统计快照（本次进程运行期口径）。
func (p *Pipeline) Stats() engine.Stats { return p.corr.Stats() }

// Cursor 返回进度记录器。
func (p *Pipeline) Cursor() *Cursor { return p.cur }

// State 导出当前链路的完整状态（深拷贝）。
func (p *Pipeline) State() PipelineState {
	var cur CursorState
	if p.cur != nil {
		cur = p.cur.State()
	}
	return PipelineState{
		Correlator: p.corr.SnapshotState(),
		Alerts:     p.mgr.SnapshotState(),
		Cursor:     cur,
	}
}

// CheckpointResult 汇报一次落盘顺带做了多少保留清理。
type CheckpointResult struct {
	ResolvedPruned int // 因 MaxAge 被清理的 resolved 告警数
	Bytes          int // 最终序列化字节数
}

// Checkpoint 按保留策略裁剪后把进度与判定状态原子落盘。
func (p *Pipeline) Checkpoint() (CheckpointResult, error) {
	if p.store == nil {
		return CheckpointResult{}, ErrNoStore
	}
	now := p.store.now()
	cutoff := p.store.policy.resolvedCutoff(now)

	pruned := 0
	if !cutoff.IsZero() {
		pruned = p.mgr.PruneResolvedBefore(cutoff)
	}
	st := p.State()
	payload, err := json.Marshal(st)
	if err != nil {
		return CheckpointResult{}, fmt.Errorf("marshal checkpoint: %w", err)
	}

	// 超容量时再退一步：resolved 告警全部可弃（它们是已关闭结论，
	// 不影响后续判定），firing 告警与关联判定状态绝不静默删除。
	if p.store.policy.MaxBytes > 0 && len(payload) > p.store.policy.MaxBytes {
		all := p.mgr.PruneResolvedBefore(time.Unix(1<<62, 0))
		pruned += all
		st = p.State()
		payload, err = json.Marshal(st)
		if err != nil {
			return CheckpointResult{}, fmt.Errorf("marshal checkpoint: %w", err)
		}
	}
	if p.store.policy.MaxBytes > 0 && len(payload) > p.store.policy.MaxBytes {
		return CheckpointResult{}, fmt.Errorf("%w: key=%s need %d bytes limit=%d",
			ErrCapacityExceeded, p.key, len(payload), p.store.policy.MaxBytes)
	}
	if err := p.store.Save(p.key, st); err != nil {
		return CheckpointResult{}, err
	}
	return CheckpointResult{ResolvedPruned: pruned, Bytes: len(payload)}, nil
}

// ReplayKey 为一次历史回放生成独立状态键（带 replay- 前缀与时间戳，
// 与实时链路的 RealtimeKey 物理隔离，回放绝不覆盖实时现场）。
func ReplayKey(name string) string {
	if name == "" {
		name = "run"
	}
	return "replay-" + name + "-" + time.Now().UTC().Format("20060102T150405.000000000")
}
