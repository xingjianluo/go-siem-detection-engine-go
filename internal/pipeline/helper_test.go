package pipeline

import (
	"os"
	"path/filepath"
)

// corruptCheckpoint 截断状态仓库里的当前检查点文件，模拟写坏的状态。
func corruptCheckpoint(dir string) error {
	path := filepath.Join(dir, "checkpoint.json")
	return os.WriteFile(path, []byte(`{"version":1,"saved_at":"2026`), 0o644)
}
