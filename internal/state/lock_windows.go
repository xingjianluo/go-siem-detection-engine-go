//go:build windows

package state

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"
)

// windowsLock 用 LockFileEx 对锁文件加排他锁：句柄关闭（进程退出也会）
// 时锁自动释放，因此不会留下 Unix 那种需要判断陈旧性的锁文件。
type windowsLock struct {
	f *os.File
}

var (
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	procLockFileEx   = kernel32.NewProc("LockFileEx")
	procUnlockFileEx = kernel32.NewProc("UnlockFileEx")
)

const (
	lockfileExclusiveLock   = 0x00000002
	lockfileFailImmediately = 0x00000001
)

func lockPath(dir, key string) string {
	return filepath.Join(dir, "."+safeKey(key)+".lock")
}

func acquireLock(dir, key string) (fileLock, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create state dir for lock: %w", err)
	}
	path := lockPath(dir, key)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock %s: %w", path, err)
	}

	var ol syscall.Overlapped
	r1, _, errno := procLockFileEx.Call(
		uintptr(f.Fd()),
		uintptr(lockfileExclusiveLock|lockfileFailImmediately),
		0, 1, 0, uintptr(unsafe.Pointer(&ol)),
	)
	if r1 == 0 {
		f.Close()
		if errors.Is(errno, syscall.Errno(33)) { // ERROR_LOCK_VIOLATION
			return nil, fmt.Errorf("%w: %s", ErrLockBusy, path)
		}
		return nil, fmt.Errorf("lock %s: %w", path, errno)
	}
	// 持有者信息仅作排障用途。
	_, _ = f.Seek(0, 0)
	_ = f.Truncate(0)
	_, _ = fmt.Fprintf(f, "%d %s %d\n", os.Getpid(), hostnameWindows(), time.Now().UnixNano())
	return &windowsLock{f: f}, nil
}

func (l *windowsLock) Unlock() error {
	var ol syscall.Overlapped
	r1, _, errno := procUnlockFileEx.Call(uintptr(l.f.Fd()), 0, 1, 0, uintptr(unsafe.Pointer(&ol)))
	cerr := l.f.Close()
	if r1 == 0 {
		return fmt.Errorf("unlock: %w", errno)
	}
	return cerr
}

var cachedHostname string

func hostnameWindows() string {
	if cachedHostname != "" {
		return cachedHostname
	}
	h, err := os.Hostname()
	if err != nil || h == "" {
		h = "unknown-host"
	}
	cachedHostname = h
	return h
}
