package state

import (
	"regexp"
)

// fileLock 是同键跨进程互斥锁。
//
// Linux/macOS 用 O_EXCL 锁文件（内容记录持有者 pid/主机/时间，
// 便于识别陈旧锁）；Windows 实现见 lock_windows.go。
type fileLock interface {
	Unlock() error
}

var unsafeKeyChars = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// safeKey 把状态键转成可安全用作文件名的形式。
func safeKey(key string) string {
	if key == "" {
		key = "_"
	}
	s := unsafeKeyChars.ReplaceAllString(key, "_")
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}
