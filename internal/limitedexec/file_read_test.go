package limitedexec

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aibornstore/artweb-execution-fabric/pkg/bcp"
)

func fsReadOp(t *testing.T, path string, max int) bcp.Operation {
	t.Helper()
	payload, err := json.Marshal(FileReadRequest{Path: path, MaxBytes: max})
	if err != nil {
		t.Fatal(err)
	}
	return bcp.Operation{
		ID: "fs-op", IdempotencyKey: "fs-idem", ActorID: "owner",
		Capability: FileReadCapability, Target: "device://HOME-2/fs/read",
		Action: "read", Risk: bcp.RiskRead, Payload: payload,
	}
}

func TestFileReadAllowlistCapAndRedaction(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "sample.txt")
	content := "public=hello\napi_token=super-secret\nvisible=world\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	p := &FileReadProvider{AllowedRoots: []string{root}}
	raw, err := p.Read(context.Background(), fsReadOp(t, path, 1<<10))
	if err != nil {
		t.Fatal(err)
	}
	var got FileReadResult
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.Schema != "fs.read/v1" || got.Path == "" || got.Truncated {
		t.Fatalf("bad result: %+v", got)
	}
	if got.Redactions != 1 || strings.Contains(got.Content, "super-secret") ||
		!strings.Contains(got.Content, "[REDACTED]") ||
		!strings.Contains(got.Content, "visible=world") {
		t.Fatalf("redaction failed: %+v", got)
	}

	raw, err = p.Read(context.Background(), fsReadOp(t, path, 8))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if !got.Truncated || got.Bytes != 8 {
		t.Fatalf("cap not enforced: %+v", got)
	}
}

func TestFileReadRejectsOutsideRootSensitiveAndBinary(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	p := &FileReadProvider{AllowedRoots: []string{root}}
	if _, err := p.Read(context.Background(), fsReadOp(t, outside, 100)); !errors.Is(err, ErrPathOutsideRoots) {
		t.Fatalf("expected outside-root denial, got %v", err)
	}

	secretDir := filepath.Join(root, ".secrets")
	if err := os.MkdirAll(secretDir, 0700); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(secretDir, "relay.token")
	if err := os.WriteFile(secret, []byte("token"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Read(context.Background(), fsReadOp(t, secret, 100)); !errors.Is(err, ErrSensitivePath) {
		t.Fatalf("expected sensitive-path denial, got %v", err)
	}

	binary := filepath.Join(root, "binary.bin")
	if err := os.WriteFile(binary, []byte{0xff, 0xfe, 0x00, 0x01}, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Read(context.Background(), fsReadOp(t, binary, 100)); !errors.Is(err, ErrBinaryFile) {
		t.Fatalf("expected binary denial, got %v", err)
	}
}

func TestFileReadRejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outsideRoot := t.TempDir()
	outside := filepath.Join(outsideRoot, "outside.txt")
	if err := os.WriteFile(outside, []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "escape.txt")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	p := &FileReadProvider{AllowedRoots: []string{root}}
	if _, err := p.Read(context.Background(), fsReadOp(t, link, 100)); !errors.Is(err, ErrPathOutsideRoots) {
		t.Fatalf("expected symlink escape denial, got %v", err)
	}
}

func TestCompositeProviderRoutesReadCapabilities(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "a.txt")
	if err := os.WriteFile(path, []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}
	p := &CompositeProvider{
		HostStatus: &HostStatusProvider{},
		FileRead:   &FileReadProvider{AllowedRoots: []string{root}},
	}
	if _, err := p.Read(context.Background(), bcp.Operation{
		Capability: HostStatusCapability, Risk: bcp.RiskRead,
	}); err != nil {
		t.Fatalf("host status routing: %v", err)
	}
	if _, err := p.Read(context.Background(), fsReadOp(t, path, 100)); err != nil {
		t.Fatalf("fs.read routing: %v", err)
	}
	if _, err := p.Read(context.Background(), bcp.Operation{
		Capability: "unsupported@1", Risk: bcp.RiskRead,
	}); !errors.Is(err, ErrUnsupportedCapability) {
		t.Fatalf("unsupported routing: %v", err)
	}
}
