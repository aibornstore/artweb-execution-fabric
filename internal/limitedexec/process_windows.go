//go:build windows

package limitedexec

import (
	"context"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func nativeProcessList(_ context.Context, hardLimit int) ([]ProcessInfo, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	if err := windows.Process32First(snap, &pe); err != nil {
		return nil, err
	}
	out := make([]ProcessInfo, 0, 64)
	for {
		name := syscall.UTF16ToString(pe.ExeFile[:])
		out = append(out, ProcessInfo{PID: int(pe.ProcessID), Name: name})
		if hardLimit > 0 && len(out) >= hardLimit {
			return out, nil
		}
		if err := windows.Process32Next(snap, &pe); err != nil {
			if err == windows.ERROR_NO_MORE_FILES {
				break
			}
			return nil, err
		}
	}
	return out, nil
}
