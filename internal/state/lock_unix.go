//go:build !windows

package state

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// unixLock 用 O_CREATE|O_EXCL 的锁文件实现同键跨进程互斥。
// 锁文件内容为 "pid hostname createdAt"，便于识别残留的陈旧锁。
type unixLock struct {
	path string
}

func lockPath(dir, key string) string {
	return filepath.Join(dir, "."+safeKey(key)+".lock")
}

func acquireLock(dir, key string) (fileLock, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create state dir for lock: %w", err)
	}
	path := lockPath(dir, key)
	content := []byte(fmt.Sprintf("%d %s %d\n", os.Getpid(), hostname(), time.Now().UnixNano()))

	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err == nil {
		if _, werr := f.Write(content); werr != nil {
			f.Close()
			os.Remove(path)
			return nil, fmt.Errorf("write lock file: %w", werr)
		}
		if cerr := f.Close(); cerr != nil {
			os.Remove(path)
			return nil, fmt.Errorf("close lock file: %w", cerr)
		}
		return &unixLock{path: path}, nil
	}
	if !errors.Is(err, os.ErrExist) {
		return nil, fmt.Errorf("acquire lock %s: %w", path, err)
	}

	// 锁已存在：若持有者进程已死（陈旧锁），可以接管；否则报忙。
	stale, err := isStaleLock(path)
	if err != nil {
		return nil, fmt.Errorf("inspect lock %s: %w", path, err)
	}
	if !stale {
		return nil, fmt.Errorf("%w: %s", ErrLockBusy, path)
	}
	// 接管陈旧锁：先删再以 O_EXCL 重建，多个接管者之间仍能分出胜负。
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("remove stale lock %s: %w", path, err)
	}
	f, err = os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("%w: %s (stale lock taken over)", ErrLockBusy, path)
		}
		return nil, fmt.Errorf("re-acquire lock %s: %w", path, err)
	}
	if _, werr := f.Write(content); werr != nil {
		f.Close()
		os.Remove(path)
		return nil, fmt.Errorf("write lock file: %w", werr)
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return nil, fmt.Errorf("close lock file: %w", err)
	}
	return &unixLock{path: path}, nil
}

func (l *unixLock) Unlock() error {
	if err := os.Remove(l.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("release lock %s: %w", l.path, err)
	}
	return nil
}

// isStaleLock 判断锁文件是否由已退出的进程持有。
// kill(pid, 0) 在 Unix 上只做存在性探测；EPERM 表示进程仍活着
// （只是不归我们所有），ESRCH 表示进程已死。
func isStaleLock(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return true, nil
		}
		return false, err
	}
	fields := strings.Fields(string(bytes.TrimSpace(data)))
	if len(fields) < 1 {
		// 内容无法解析，视为损坏的陈旧锁，允许接管。
		return true, nil
	}
	pid, err := strconv.Atoi(fields[0])
	if err != nil || pid <= 0 {
		return true, nil
	}
	if pid == os.Getpid() {
		// 同一进程不该二次加锁；按忙处理，暴露调用方错误。
		return false, nil
	}
	if err := syscall.Kill(pid, 0); err == nil {
		return false, nil // 进程仍在
	} else if errors.Is(err, syscall.EPERM) {
		return false, nil // 进程仍在，但无发信号权限
	}
	return true, nil // ESRCH：进程不存在
}

var cachedHostname string

func hostname() string {
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
