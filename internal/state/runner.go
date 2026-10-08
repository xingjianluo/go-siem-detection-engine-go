package state

import (
	"encoding/json"
	"time"

	"github.com/xingjianluo/go-siem-detection-engine-go/internal/engine"
)

// RunResult 汇总一次 RunFile 的处理量与落盘清理量。
type RunResult struct {
	LinesRead      int // 本次新读到的行数
	BadLines       int // 无法解析为事件的行数（跳过并计数，不中断整批）
	Ingested       int // 成功摄入（未重复、未迟到）的事件数
	Duplicates     int // 被去重的事件数
	LateDropped    int // 被判迟到丢弃的事件数
	NewAlerts      int // 本次新建的告警数
	MergedHits     int // 本次被合并抑制的命中数
	Matches        []engine.Match
	Checkpoints    int
	ResolvedPruned int
}

// rawEvent 与 cmd/siem 的 JSONL 事件格式保持一致。
type rawEvent struct {
	ID        string            `json:"id"`
	Timestamp time.Time         `json:"timestamp"`
	Source    string            `json:"source"`
	Fields    map[string]string `json:"fields"`
}

// Runner 控制一批日志的处理过程：
// 从游标当前偏移读到文件末尾，期间按 CheckpointEvery 批（事件数）落盘一次。
type Runner struct {
	// CheckpointEvery > 0 时，每处理这么多行就落一次盘（含进度偏移），
	// 进程在批中间被杀也只会重跑最后一小段（重复事件由去重表兜底）。
	CheckpointEvery int
	// OnBadLine 回调解析失败的行（可为 nil）；坏行不中断处理。
	OnBadLine func(lineNo int, line []byte, err error)
	// OnResult 每条事件摄入后回调一次（可为 nil），用于实时观察命中/告警。
	OnResult func(e engine.Event, r IngestResult)
}

// RunFile 通过链路绑定的游标读取日志文件并摄入。
// 实时续跑与历史回放都走这里，区别只在 Pipeline 绑定的状态键不同。
func (rn Runner) RunFile(p *Pipeline) (RunResult, error) {
	var out RunResult

	err := p.Cursor().ReadLines(func(offset int64, line []byte) error {
		out.LinesRead++
		var re rawEvent
		if err := json.Unmarshal(line, &re); err != nil || re.ID == "" {
			out.BadLines++
			if rn.OnBadLine != nil {
				rn.OnBadLine(out.LinesRead, line, err)
			}
		} else {
			e := engine.Event{ID: re.ID, Timestamp: re.Timestamp, Source: re.Source, Fields: re.Fields}
			r := p.IngestEvent(e)
			out.Matches = append(out.Matches, r.Matches...)
			for _, o := range r.Outcomes {
				if o.IsNew {
					out.NewAlerts++
				} else {
					out.MergedHits++
				}
			}
			if rn.OnResult != nil {
				rn.OnResult(e, r)
			}
		}

		// 先推进进度，再落盘：崩溃发生在落盘前 -> 重启后重跑这一小段，
		// 重复事件被去重挡住；崩溃发生在落盘后 -> 偏移已持久，不再重跑。
		if err := p.Cursor().Advance(offset); err != nil {
			return err
		}
		if rn.CheckpointEvery > 0 && out.LinesRead%rn.CheckpointEvery == 0 {
			res, err := p.Checkpoint()
			if err != nil {
				return err
			}
			out.Checkpoints++
			out.ResolvedPruned += res.ResolvedPruned
		}
		return nil
	})
	if err != nil {
		return out, err
	}
	st := p.Stats()
	out.Ingested = st.Ingested
	out.Duplicates = st.Duplicates
	out.LateDropped = st.LateDropped
	return out, nil
}

// FinishAndCheckpoint 闭合剩余窗口并做最后一次落盘（输入结束时调用）。
func (rn Runner) FinishAndCheckpoint(p *Pipeline) (IngestResult, CheckpointResult, error) {
	fr := p.Flush()
	cp, err := p.Checkpoint()
	return fr, cp, err
}
