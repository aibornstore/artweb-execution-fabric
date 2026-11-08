//go:build windows

package cutover

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"syscall"
)

type platformLock interface{ Close() error }
type windowsLock struct{ f *os.File }

func acquirePlatformLock(path string) (platformLock, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := syscall.CreateFile(p, syscall.GENERIC_READ|syscall.GENERIC_WRITE, 0, nil, syscall.OPEN_ALWAYS, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		if errors.Is(err, syscall.Errno(32)) {
			return nil, ErrAlreadyLocked
		}
		return nil, fmt.Errorf("CreateFile lock: %w", err)
	}
	f := os.NewFile(uintptr(h), path)
	if f == nil {
		syscall.CloseHandle(h)
		return nil, fmt.Errorf("lock handle unavailable")
	}
	if err := f.Truncate(0); err == nil {
		_, _ = f.Seek(0, 0)
		_, _ = f.WriteString(strconv.Itoa(os.Getpid()) + "\r\n")
		_ = f.Sync()
	}
	return &windowsLock{f: f}, nil
}
func (l *windowsLock) Close() error {
	if l == nil || l.f == nil {
		return nil
	}
	return l.f.Close()
}
