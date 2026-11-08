package limitedexec

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/aibornstore/artweb-execution-fabric/pkg/bcp"
)

func readOp(cap string, payload []byte) bcp.Operation {
	return bcp.Operation{Capability: cap, Risk: bcp.RiskRead, Payload: payload}
}

func TestSystemInfoProvider(t *testing.T) {
	raw, err := (&SystemInfoProvider{}).Read(context.Background(), readOp(SystemInfoCapability, nil))
	if err != nil {
		t.Fatal(err)
	}
	var got SystemInfoResult
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.Schema != "system.info/v1" || got.Hostname == "" || got.OS == "" || got.CPUs < 1 {
		t.Fatalf("bad system info: %+v", got)
	}
}

func TestProcessListProviderIsBounded(t *testing.T) {
	raw, err := (&ProcessListProvider{}).Read(context.Background(), readOp(ProcessListCapability, nil))
	if err != nil {
		t.Fatal(err)
	}
	var got ProcessListResult
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.Schema != "process.list/v1" || len(got.Processes) == 0 || len(got.Processes) > 256 {
		t.Fatalf("bad process list: count=%d schema=%q", len(got.Processes), got.Schema)
	}
	for _, item := range got.Processes {
		if item.PID < 0 || item.Name == "" {
			t.Fatalf("invalid process item: %+v", item)
		}
	}
}

func TestFileMetaStatAndListHideSensitive(t *testing.T) {
	root := t.TempDir()
	visible := filepath.Join(root, "visible.txt")
	if err := os.WriteFile(visible, []byte("ok"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("SECRET=x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "private.key"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	provider := &FileMetaProvider{AllowedRoots: []string{root}}
	statPayload, _ := json.Marshal(FileStatRequest{Path: visible})
	raw, err := provider.ReadStat(context.Background(), readOp(FileStatCapability, statPayload))
	if err != nil {
		t.Fatal(err)
	}
	var stat FileStatResult
	if err := json.Unmarshal(raw, &stat); err != nil || stat.Schema != "fs.stat/v1" || stat.Name != "visible.txt" {
		t.Fatalf("bad stat: %+v err=%v", stat, err)
	}
	listPayload, _ := json.Marshal(FileListRequest{Path: root, MaxEntries: 16})
	raw, err = provider.ReadList(context.Background(), readOp(FileListCapability, listPayload))
	if err != nil {
		t.Fatal(err)
	}
	var list FileListResult
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatal(err)
	}
	if list.Hidden != 2 {
		t.Fatalf("expected 2 hidden sensitive entries, got %+v", list)
	}
	for _, entry := range list.Entries {
		if entry.Name == ".env" || entry.Name == "private.key" {
			t.Fatalf("sensitive entry leaked: %+v", entry)
		}
	}
}

func TestValidatePingTargetFailClosed(t *testing.T) {
	for _, good := range []string{"127.0.0.1", "debian.tail131312.ts.net", "example.com"} {
		if err := validatePingTarget(good); err != nil {
			t.Fatalf("valid target rejected %q: %v", good, err)
		}
	}
	for _, bad := range []string{"", "host name", "127.0.0.1/24", "example.com;whoami", "-bad.example", "bad_.example"} {
		if err := validatePingTarget(bad); err == nil {
			t.Fatalf("invalid target accepted: %q", bad)
		}
	}
}

func TestPingProviderRejectsShellishTargetBeforeExecution(t *testing.T) {
	payload, _ := json.Marshal(PingRequest{Target: "127.0.0.1 & whoami", TimeoutMillis: 500})
	_, err := (&PingProvider{}).Read(context.Background(), readOp(NetworkPingCapability, payload))
	if err == nil {
		t.Fatal("shell-like ping target must be rejected")
	}
}
