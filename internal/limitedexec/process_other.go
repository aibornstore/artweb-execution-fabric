//go:build !windows

package limitedexec

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func nativeProcessList(_ context.Context, hardLimit int) ([]ProcessInfo, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	out := make([]ProcessInfo, 0, 64)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("/proc", e.Name(), "comm"))
		if err != nil {
			continue
		}
		out = append(out, ProcessInfo{PID: pid, Name: strings.TrimSpace(string(raw))})
		if hardLimit > 0 && len(out) >= hardLimit {
			break
		}
	}
	return out, nil
}
