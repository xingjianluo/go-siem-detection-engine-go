// Package rules 负责从本地文件加载检测规则、校验并归一化为统一模型。
//
// 任何不合法的条目都不会被悄悄跳过：LoadFile 会把每一条被拒绝的规则
// 连同可区分的 RejectReason 一起返回给调用方。
package rules

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"
)

// SupportedRuleVersion 是当前引擎支持的规则格式版本。
const SupportedRuleVersion = 1

// RejectReason 区分规则被拒绝的原因类别。
type RejectReason string

const (
	// ReasonVersionTooNew 规则版本高于引擎支持的版本。
	ReasonVersionTooNew RejectReason = "version_too_new"
	// ReasonInvalidCondition 匹配条件非法（未知操作符、数值条件值不是数字等）。
	ReasonInvalidCondition RejectReason = "invalid_condition"
	// ReasonMissingField 必填字段缺失或为空（id、window、threshold、conditions 等）。
	ReasonMissingField RejectReason = "missing_field"
)

// Rejection 描述一条被拒绝的规则及其原因。
type Rejection struct {
	RuleID string
	Reason RejectReason
	Detail string
}

func (r Rejection) String() string {
	return fmt.Sprintf("rule %q rejected: %s (%s)", r.RuleID, r.Reason, r.Detail)
}

// 合法的条件操作符。
const (
	OpEq       = "eq"
	OpNeq      = "neq"
	OpContains = "contains"
	OpGt       = "gt"
	OpLt       = "lt"
)

// Condition 是归一化后的匹配条件。
type Condition struct {
	Field    string
	Op       string // eq | neq | contains | gt | lt
	Value    string
	Number   float64 // 仅 gt/lt 有效
	IsNumber bool
}

// Rule 是归一化后的统一规则模型。
type Rule struct {
	ID          string
	Version     int
	Description string
	Severity    string
	Window      time.Duration
	Threshold   int
	GroupBy     string // 按哪个事件字段分组计数，空串表示按 source 分组
	Conditions  []Condition
}

// LoadResult 是加载结果：通过的规则与被拒绝的条目。
type LoadResult struct {
	Rules      []Rule
	Rejections []Rejection
}

// fileFormat 是规则文件的顶层结构。
type fileFormat struct {
	Rules []rawRule `json:"rules"`
}

type rawRule struct {
	ID          string         `json:"id"`
	Version     int            `json:"version"`
	Description string         `json:"description"`
	Severity    string         `json:"severity"`
	Window      string         `json:"window"`
	Threshold   int            `json:"threshold"`
	GroupBy     string         `json:"group_by"`
	Conditions  []rawCondition `json:"conditions"`
}

type rawCondition struct {
	Field string `json:"field"`
	Op    string `json:"op"`
	Value string `json:"value"`
}

// LoadFile 从本地 JSON 文件加载规则。文件本身无法解析时返回 error；
// 单条规则不合法时不报错，而是记入 LoadResult.Rejections。
func LoadFile(path string) (LoadResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return LoadResult{}, fmt.Errorf("read rules file: %w", err)
	}
	var ff fileFormat
	if err := json.Unmarshal(data, &ff); err != nil {
		return LoadResult{}, fmt.Errorf("parse rules file %s: %w", path, err)
	}
	res := LoadResult{}
	seen := map[string]bool{}
	for _, raw := range ff.Rules {
		rule, rej, ok := normalize(raw, seen)
		if !ok {
			res.Rejections = append(res.Rejections, rej)
			continue
		}
		seen[rule.ID] = true
		res.Rules = append(res.Rules, rule)
	}
	return res, nil
}

// normalize 校验并归一化一条原始规则。ok=false 时 rej 携带拒绝原因。
func normalize(raw rawRule, seen map[string]bool) (Rule, Rejection, bool) {
	reject := func(reason RejectReason, detail string) (Rule, Rejection, bool) {
		return Rule{}, Rejection{RuleID: raw.ID, Reason: reason, Detail: detail}, false
	}

	// 1. 版本检查：过新的版本直接拒绝，避免语义被误读。
	if raw.Version > SupportedRuleVersion {
		return reject(ReasonVersionTooNew,
			fmt.Sprintf("rule version %d > supported %d", raw.Version, SupportedRuleVersion))
	}

	// 2. 必填字段检查。
	if raw.ID == "" {
		return reject(ReasonMissingField, "id is empty")
	}
	if seen[raw.ID] {
		return reject(ReasonMissingField, "duplicate rule id")
	}
	if raw.Window == "" {
		return reject(ReasonMissingField, "window is empty")
	}
	if raw.Threshold <= 0 {
		return reject(ReasonMissingField, "threshold must be > 0")
	}
	if len(raw.Conditions) == 0 {
		return reject(ReasonMissingField, "conditions is empty")
	}

	// 3. 窗口时长解析失败视为条件非法（格式错误而非缺失）。
	window, err := time.ParseDuration(raw.Window)
	if err != nil || window <= 0 {
		return reject(ReasonInvalidCondition, fmt.Sprintf("bad window %q", raw.Window))
	}

	// 4. 逐条校验匹配条件。
	conds := make([]Condition, 0, len(raw.Conditions))
	for i, rc := range raw.Conditions {
		if rc.Field == "" {
			return reject(ReasonMissingField, fmt.Sprintf("condition %d: field is empty", i))
		}
		c := Condition{Field: rc.Field, Op: rc.Op, Value: rc.Value}
		switch rc.Op {
		case OpEq, OpNeq, OpContains:
			// 字符串比较，value 原样保留。
		case OpGt, OpLt:
			n, err := strconv.ParseFloat(rc.Value, 64)
			if err != nil {
				return reject(ReasonInvalidCondition,
					fmt.Sprintf("condition %d: op %q requires numeric value, got %q", i, rc.Op, rc.Value))
			}
			c.Number, c.IsNumber = n, true
		default:
			return reject(ReasonInvalidCondition,
				fmt.Sprintf("condition %d: unknown op %q", i, rc.Op))
		}
		conds = append(conds, c)
	}

	return Rule{
		ID:          raw.ID,
		Version:     raw.Version,
		Description: raw.Description,
		Severity:    raw.Severity,
		Window:      window,
		Threshold:   raw.Threshold,
		GroupBy:     raw.GroupBy,
		Conditions:  conds,
	}, Rejection{}, true
}
