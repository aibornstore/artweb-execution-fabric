package limitedexec

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/aibornstore/artweb-execution-fabric/pkg/bcp"
)

const (
	FileReadCapability = "fs.read@1"
	defaultReadBytes   = 16 << 10
	hardMaxReadBytes   = 64 << 10
)

var (
	ErrPathOutsideRoots = errors.New("path outside allowed read roots")
	ErrSensitivePath    = errors.New("sensitive path is not readable")
	ErrBinaryFile       = errors.New("binary file is not readable through fs.read")
)

type FileReadRequest struct {
	Path     string `json:"path"`
	MaxBytes int    `json:"max_bytes,omitempty"`
}

type FileReadResult struct {
	Schema     string `json:"schema"`
	Path       string `json:"path"`
	Bytes      int    `json:"bytes"`
	Truncated  bool   `json:"truncated"`
	Content    string `json:"content"`
	Redactions int    `json:"redactions"`
}

type FileReadProvider struct {
	AllowedRoots []string
	HardMaxBytes int
}

func (p *FileReadProvider) Read(_ context.Context, op bcp.Operation) ([]byte, error) {
	if op.Capability != FileReadCapability || op.Risk != bcp.RiskRead {
		return nil, ErrUnsupportedCapability
	}
	var req FileReadRequest
	if err := json.Unmarshal(op.Payload, &req); err != nil {
		return nil, errors.New("invalid fs.read payload")
	}
	req.Path = strings.TrimSpace(req.Path)
	if req.Path == "" {
		return nil, errors.New("fs.read path is required")
	}
	path, err := p.resolveAllowed(req.Path)
	if err != nil {
		return nil, err
	}
	if sensitivePath(path) {
		return nil, ErrSensitivePath
	}

	limit := req.MaxBytes
	if limit <= 0 {
		limit = defaultReadBytes
	}
	hard := p.HardMaxBytes
	if hard <= 0 || hard > hardMaxReadBytes {
		hard = hardMaxReadBytes
	}
	if limit > hard {
		limit = hard
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	raw, err := io.ReadAll(io.LimitReader(f, int64(limit+1)))
	if err != nil {
		return nil, err
	}
	truncated := len(raw) > limit
	if truncated {
		raw = raw[:limit]
	}
	if !utf8.Valid(raw) {
		return nil, ErrBinaryFile
	}
	content, redactions := redactSensitiveText(string(raw))
	return json.Marshal(FileReadResult{
		Schema: "fs.read/v1", Path: path, Bytes: len(raw),
		Truncated: truncated, Content: content, Redactions: redactions,
	})
}

func (p *FileReadProvider) resolveAllowed(path string) (string, error) {
	if len(p.AllowedRoots) == 0 {
		return "", ErrPathOutsideRoots
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	for _, root := range p.AllowedRoots {
		root = strings.TrimSpace(root)
		if root == "" {
			continue
		}
		rootAbs, err := filepath.Abs(root)
		if err != nil {
			continue
		}
		rootResolved, err := filepath.EvalSymlinks(rootAbs)
		if err != nil {
			continue
		}
		rel, err := filepath.Rel(rootResolved, resolved)
		if err != nil {
			continue
		}
		if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
			return resolved, nil
		}
	}
	return "", ErrPathOutsideRoots
}

func sensitivePath(path string) bool {
	clean := strings.ToLower(filepath.Clean(path))
	parts := strings.FieldsFunc(clean, func(r rune) bool {
		return r == '/' || r == '\\'
	})
	for _, part := range parts {
		switch part {
		case ".ssh", ".secrets", "secrets", "credentials":
			return true
		}
	}
	base := strings.ToLower(filepath.Base(clean))
	if base == ".env" || strings.HasPrefix(base, ".env.") {
		return true
	}
	ext := strings.ToLower(filepath.Ext(base))
	switch ext {
	case ".key", ".pfx", ".p12":
		return true
	}
	if strings.HasPrefix(base, "id_") && !strings.HasSuffix(base, ".pub") {
		return true
	}
	return false
}

func redactSensitiveText(in string) (string, int) {
	markers := []string{
		"password", "passwd", "secret", "token", "api_key", "apikey",
		"authorization", "cookie", "private_key", "private key",
	}
	lines := strings.Split(in, "\n")
	redactions := 0
	for i, line := range lines {
		lower := strings.ToLower(line)
		sensitive := false
		for _, marker := range markers {
			if strings.Contains(lower, marker) {
				sensitive = true
				break
			}
		}
		if sensitive {
			lines[i] = "[REDACTED]"
			redactions++
		}
	}
	return strings.Join(lines, "\n"), redactions
}

type CompositeProvider struct {
	HostStatus  *HostStatusProvider
	FileRead    *FileReadProvider
	SystemInfo  *SystemInfoProvider
	ProcessList *ProcessListProvider
	FileMeta    *FileMetaProvider
	Ping        *PingProvider
}

func (p *CompositeProvider) Read(ctx context.Context, op bcp.Operation) ([]byte, error) {
	switch op.Capability {
	case HostStatusCapability:
		if p.HostStatus == nil {
			return nil, ErrUnsupportedCapability
		}
		return p.HostStatus.Read(ctx, op)
	case FileReadCapability:
		if p.FileRead == nil {
			return nil, ErrUnsupportedCapability
		}
		return p.FileRead.Read(ctx, op)
	case SystemInfoCapability:
		if p.SystemInfo == nil {
			return nil, ErrUnsupportedCapability
		}
		return p.SystemInfo.Read(ctx, op)
	case ProcessListCapability:
		if p.ProcessList == nil {
			return nil, ErrUnsupportedCapability
		}
		return p.ProcessList.Read(ctx, op)
	case FileStatCapability:
		if p.FileMeta == nil {
			return nil, ErrUnsupportedCapability
		}
		return p.FileMeta.ReadStat(ctx, op)
	case FileListCapability:
		if p.FileMeta == nil {
			return nil, ErrUnsupportedCapability
		}
		return p.FileMeta.ReadList(ctx, op)
	case NetworkPingCapability:
		if p.Ping == nil {
			return nil, ErrUnsupportedCapability
		}
		return p.Ping.Read(ctx, op)
	default:
		return nil, ErrUnsupportedCapability
	}
}
