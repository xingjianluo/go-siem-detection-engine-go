package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

// Fingerprint 计算规则集的确定性指纹：与规则切片顺序无关，
// 任何规则内容变化都会改变指纹。用于检测“落盘时的规则”与
// “当前规则”是否一致，避免规则变更后静默沿用旧判定状态。
func Fingerprint(rs []Rule) string {
	cp := make([]Rule, len(rs))
	copy(cp, rs)
	sort.Slice(cp, func(i, j int) bool { return cp[i].ID < cp[j].ID })
	data, _ := json.Marshal(cp)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
