package limitedexec

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aibornstore/artweb-execution-fabric/pkg/bcp"
)

const (
	SystemInfoCapability  = "system.info@1"
	ProcessListCapability = "process.list@1"
	FileStatCapability    = "fs.stat@1"
	FileListCapability    = "fs.list@1"
	NetworkPingCapability = "network.ping@1"
)

type SystemInfoProvider struct{}

type SystemInfoResult struct {
	Schema   string `json:"schema"`
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	CPUs     int    `json:"cpus"`
}

func (p *SystemInfoProvider) Read(_ context.Context, op bcp.Operation) ([]byte, error) {
	if op.Capability != SystemInfoCapability || op.Risk != bcp.RiskRead {
		return nil, ErrUnsupportedCapability
	}
	host, err := os.Hostname()
	if err != nil {
		return nil, err
	}
	return json.Marshal(SystemInfoResult{
		Schema: "system.info/v1", Hostname: host,
		OS: runtime.GOOS, Arch: runtime.GOARCH, CPUs: runtime.NumCPU(),
	})
}

type ProcessListProvider struct{}

type ProcessInfo struct {
	PID  int    `json:"pid"`
	Name string `json:"name"`
}

type ProcessListResult struct {
	Schema    string        `json:"schema"`
	Processes []ProcessInfo `json:"processes"`
	Truncated bool          `json:"truncated"`
}

func (p *ProcessListProvider) Read(ctx context.Context, op bcp.Operation) ([]byte, error) {
	if op.Capability != ProcessListCapability || op.Risk != bcp.RiskRead {
		return nil, ErrUnsupportedCapability
	}
	items, err := nativeProcessList(ctx, 512)
	if err != nil {
		return nil, err
	}
	sort.Slice(items, func(i, j int) bool { return items[i].PID < items[j].PID })
	truncated := len(items) > 256
	if truncated {
		items = items[:256]
	}
	return json.Marshal(ProcessListResult{Schema: "process.list/v1", Processes: items, Truncated: truncated})
}

type FileMetaProvider struct {
	AllowedRoots []string
}

type FileStatRequest struct {
	Path string `json:"path"`
}

type FileStatResult struct {
	Schema  string    `json:"schema"`
	Path    string    `json:"path"`
	Name    string    `json:"name"`
	Size    int64     `json:"size"`
	Mode    string    `json:"mode"`
	ModTime time.Time `json:"mod_time"`
	IsDir   bool      `json:"is_dir"`
}

func (p *FileMetaProvider) ReadStat(_ context.Context, op bcp.Operation) ([]byte, error) {
	if op.Capability != FileStatCapability || op.Risk != bcp.RiskRead {
		return nil, ErrUnsupportedCapability
	}
	var req FileStatRequest
	if err := json.Unmarshal(op.Payload, &req); err != nil || strings.TrimSpace(req.Path) == "" {
		return nil, errors.New("invalid fs.stat payload")
	}
	r := FileReadProvider{AllowedRoots: p.AllowedRoots}
	path, err := r.resolveAllowed(req.Path)
	if err != nil {
		return nil, err
	}
	if sensitivePath(path) {
		return nil, ErrSensitivePath
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	return json.Marshal(FileStatResult{
		Schema: "fs.stat/v1", Path: path, Name: info.Name(), Size: info.Size(),
		Mode: info.Mode().String(), ModTime: info.ModTime().UTC(), IsDir: info.IsDir(),
	})
}

type FileListRequest struct {
	Path       string `json:"path"`
	MaxEntries int    `json:"max_entries,omitempty"`
}

type FileListEntry struct {
	Name  string `json:"name"`
	IsDir bool   `json:"is_dir"`
	Size  int64  `json:"size,omitempty"`
	Mode  string `json:"mode"`
}

type FileListResult struct {
	Schema    string          `json:"schema"`
	Path      string          `json:"path"`
	Entries   []FileListEntry `json:"entries"`
	Truncated bool            `json:"truncated"`
	Hidden    int             `json:"hidden_sensitive"`
}

func (p *FileMetaProvider) ReadList(_ context.Context, op bcp.Operation) ([]byte, error) {
	if op.Capability != FileListCapability || op.Risk != bcp.RiskRead {
		return nil, ErrUnsupportedCapability
	}
	var req FileListRequest
	if err := json.Unmarshal(op.Payload, &req); err != nil || strings.TrimSpace(req.Path) == "" {
		return nil, errors.New("invalid fs.list payload")
	}
	limit := req.MaxEntries
	if limit <= 0 {
		limit = 128
	}
	if limit > 256 {
		return nil, errors.New("max_entries exceeds 256")
	}
	r := FileReadProvider{AllowedRoots: p.AllowedRoots}
	path, err := r.resolveAllowed(req.Path)
	if err != nil {
		return nil, err
	}
	if sensitivePath(path) {
		return nil, ErrSensitivePath
	}
	dir, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	out := make([]FileListEntry, 0, min(limit, len(dir)))
	hidden := 0
	truncated := false
	for _, e := range dir {
		child := filepath.Join(path, e.Name())
		if sensitivePath(child) {
			hidden++
			continue
		}
		if len(out) >= limit {
			truncated = true
			break
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, FileListEntry{Name: e.Name(), IsDir: e.IsDir(), Size: info.Size(), Mode: info.Mode().String()})
	}
	return json.Marshal(FileListResult{Schema: "fs.list/v1", Path: path, Entries: out, Truncated: truncated, Hidden: hidden})
}

type PingProvider struct{}

type PingRequest struct {
	Target        string `json:"target"`
	TimeoutMillis int    `json:"timeout_ms,omitempty"`
}

type PingResult struct {
	Schema     string `json:"schema"`
	Target     string `json:"target"`
	Reachable  bool   `json:"reachable"`
	DurationMS int64  `json:"duration_ms"`
}

func (p *PingProvider) Read(ctx context.Context, op bcp.Operation) ([]byte, error) {
	if op.Capability != NetworkPingCapability || op.Risk != bcp.RiskRead {
		return nil, ErrUnsupportedCapability
	}
	var req PingRequest
	if err := json.Unmarshal(op.Payload, &req); err != nil {
		return nil, errors.New("invalid network.ping payload")
	}
	target := strings.TrimSpace(req.Target)
	if err := validatePingTarget(target); err != nil {
		return nil, err
	}
	ms := req.TimeoutMillis
	if ms <= 0 {
		ms = 1500
	}
	if ms < 200 || ms > 5000 {
		return nil, errors.New("timeout_ms must be between 200 and 5000")
	}
	start := time.Now()
	reachable, err := runPing(ctx, target, time.Duration(ms)*time.Millisecond)
	if err != nil {
		return nil, err
	}
	return json.Marshal(PingResult{Schema: "network.ping/v1", Target: target, Reachable: reachable, DurationMS: time.Since(start).Milliseconds()})
}

func validatePingTarget(s string) error {
	if s == "" || len(s) > 253 || strings.ContainsAny(s, " \t\r\n/\\\\") {
		return errors.New("invalid ping target")
	}
	if ip := net.ParseIP(s); ip != nil {
		return nil
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("invalid ping target")
		}
		for _, r := range label {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-') {
				return errors.New("invalid ping target")
			}
		}
	}
	return nil
}

func runPing(ctx context.Context, target string, timeout time.Duration) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout+time.Second)
	defer cancel()
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "ping.exe", "-n", "1", "-w", fmtInt(int(timeout.Milliseconds())), target)
	} else {
		secs := int(timeout.Seconds())
		if secs < 1 {
			secs = 1
		}
		cmd = exec.CommandContext(ctx, "ping", "-c", "1", "-W", fmtInt(secs), target)
	}
	err := cmd.Run()
	if err == nil {
		return true, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		return false, nil
	}
	return false, err
}

func fmtInt(v int) string {
	return strconv.Itoa(v)
}
