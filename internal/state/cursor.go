package state

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
)

// CursorState 是日志读取进度。
type CursorState struct {
	Path   string `json:"path"`
	Offset int64  `json:"offset"` // 已确认处理完的字节偏移
	Size   int64  `json:"size"`   // 上次记录时的文件大小
}

// Cursor 按记录的字节偏移续读本地 JSONL 日志文件。
//
// 两层保证“重启后不会把已处理事件重新算一遍”：
//   - 偏移层：重启后直接从上次确认的字节偏移继续读，已处理区间不再喂入；
//   - 去重层：即使调用方又把旧事件喂进来（比如文件被重放/手工补喂），
//     关联器的 seenIDs 快照也会把它们判为重复，计数、命中与抑制结论不变。
type Cursor struct {
	st CursorState
}

// NewCursor 为指定日志文件创建进度记录器，初始偏移为 0。
func NewCursor(path string) *Cursor {
	return &Cursor{st: CursorState{Path: path}}
}

// State 返回进度快照（落盘用）。
func (c *Cursor) State() CursorState { return c.st }

// Restore 恢复进度。记录的偏移超过当前文件大小说明日志已被轮转/截断，
// 返回 ErrProgressTruncated，不静默从头开始。
func (c *Cursor) Restore(st CursorState) error {
	fi, err := os.Stat(st.Path)
	if err != nil {
		return fmt.Errorf("stat cursor target %s: %w", st.Path, err)
	}
	if st.Offset > fi.Size() {
		return fmt.Errorf("%w: saved offset %d > current size %d of %s",
			ErrProgressTruncated, st.Offset, fi.Size(), st.Path)
	}
	st.Size = fi.Size()
	c.st = st
	return nil
}

// ReadLines 从已记录偏移继续逐行读取。每读到一行（以 '\n' 结尾）
// 回调 fn，参数 offset 为“该行结束之后”的字节偏移（下次续读起点）。
//
// 最后一行若没有换行结尾（正在被追加写入的半行），停在换行之前等待
// 下一批，避免把半条 JSON 解析坏。文件已增长时再次调用即可读到后半行。
func (c *Cursor) ReadLines(fn func(offset int64, line []byte) error) error {
	if c.st.Path == "" {
		return errors.New("cursor has no bound path")
	}
	f, err := os.Open(c.st.Path)
	if err != nil {
		return fmt.Errorf("open %s: %w", c.st.Path, err)
	}
	defer f.Close()

	if _, err := f.Seek(c.st.Offset, io.SeekStart); err != nil {
		return fmt.Errorf("seek %s to %d: %w", c.st.Path, c.st.Offset, err)
	}

	r := bufio.NewReader(f)
	pos := c.st.Offset
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			if errors.Is(err, io.EOF) {
				// 没有换行结尾的尾巴：可能是写了一半的行，先不推进偏移。
				break
			}
			if err != nil {
				return fmt.Errorf("read %s: %w", c.st.Path, err)
			}
			next := pos + int64(len(line))
			trimmed := line[:len(line)-1] // 去掉行尾 '\n'
			if len(trimmed) > 0 && trimmed[len(trimmed)-1] == '\r' {
				trimmed = trimmed[:len(trimmed)-1] // 兼容 CRLF
			}
			if len(trimmed) > 0 {
				if err := fn(next, trimmed); err != nil {
					return err
				}
			}
			pos = next
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read %s: %w", c.st.Path, err)
		}
	}
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", c.st.Path, err)
	}
	c.st.Offset = pos
	c.st.Size = fi.Size()
	return nil
}

// Advance 把进度推进到指定字节偏移（供调用方自行读行时使用）。
// 越过当前文件大小会被拒绝。
func (c *Cursor) Advance(offset int64) error {
	if c.st.Path == "" {
		return errors.New("cursor has no bound path")
	}
	if offset < c.st.Offset {
		return fmt.Errorf("cursor cannot move backwards: %d < %d", offset, c.st.Offset)
	}
	fi, err := os.Stat(c.st.Path)
	if err != nil {
		return fmt.Errorf("stat cursor target %s: %w", c.st.Path, err)
	}
	if offset > fi.Size() {
		return fmt.Errorf("%w: offset %d > size %d of %s",
			ErrProgressTruncated, offset, fi.Size(), c.st.Path)
	}
	c.st.Offset = offset
	c.st.Size = fi.Size()
	return nil
}

// Path 返回当前跟踪的日志文件路径。
func (c *Cursor) Path() string { return c.st.Path }

// Offset 返回当前已确认的字节偏移。
func (c *Cursor) Offset() int64 { return c.st.Offset }
