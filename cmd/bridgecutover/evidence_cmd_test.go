package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aibornstore/artweb-execution-fabric/internal/protocol"
	"github.com/aibornstore/artweb-execution-fabric/pkg/bcp"
)

func signedCompletedJob(t *testing.T) ([]byte, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	cmd := protocol.Command{
		CommandID: "cmd-1", AgentID: "HOME-2",
		Operation: bcp.Operation{
			ID: "cmd-1", Capability: "fs.read@1",
			Target: "device://HOME-2/fs/read", Action: "read", Risk: bcp.RiskRead,
		},
		Grant:    bcp.Grant{ID: "grant-1"},
		IssuedAt: now, ExpiresAt: now.Add(2 * time.Minute), Nonce: "nonce-1",
	}
	cmd, err = protocol.SignCommand(cmd, "controller-main", priv)
	if err != nil {
		t.Fatal(err)
	}
	result := protocol.JobResult{
		CommandID: "cmd-1", OperationID: "cmd-1", AgentID: "HOME-2",
		BootID: "boot-a", AgentVersion: "sha256:" + strings.Repeat("a", 64),
		Status: "ok", Code: "limited_read_ok", CreatedAt: now.Add(time.Second),
	}
	raw, err := json.Marshal(completedJobOutput{
		Status: "PASS", State: "completed", CommandID: "cmd-1",
		Command: cmd, Result: result,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw, pub
}

func TestEvidenceFromCompletedJob(t *testing.T) {
	raw, pub := signedCompletedJob(t)
	ev, err := evidenceFromCompletedJob(raw, pub, "GLOBAL")
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != "PASS" || ev.Capability != "fs.read@1" ||
		ev.Target != "device://HOME-2/fs/read" || ev.BootID != "boot-a" {
		t.Fatalf("unexpected evidence: %+v", ev)
	}
	if len(ev.ResultSHA256) != 64 || ev.EvidenceSource != "relay-authenticated-command" {
		t.Fatalf("bad evidence provenance: %+v", ev)
	}
}

func TestEvidenceRejectsTamperedSignedCommand(t *testing.T) {
	raw, pub := signedCompletedJob(t)
	var in completedJobOutput
	if err := json.Unmarshal(raw, &in); err != nil {
		t.Fatal(err)
	}
	in.Command.Operation.Target = "device://HOME-2/fs/other"
	tampered, _ := json.Marshal(in)
	if _, err := evidenceFromCompletedJob(tampered, pub, "GLOBAL"); err == nil {
		t.Fatal("tampered signed command must be rejected")
	}
}

func TestEvidenceRejectsResultIdentityMismatch(t *testing.T) {
	raw, pub := signedCompletedJob(t)
	var in completedJobOutput
	if err := json.Unmarshal(raw, &in); err != nil {
		t.Fatal(err)
	}
	in.Result.AgentID = "HOME-PC"
	bad, _ := json.Marshal(in)
	if _, err := evidenceFromCompletedJob(bad, pub, "GLOBAL"); err == nil {
		t.Fatal("result identity mismatch must be rejected")
	}
}

func TestEvidenceAcceptsPowerShellUTF16LE(t *testing.T) {
	raw, pub := signedCompletedJob(t)
	encoded := []byte{0xff, 0xfe}
	for _, b := range raw {
		encoded = append(encoded, b, 0)
	}
	ev, err := evidenceFromCompletedJob(encoded, pub, "GLOBAL")
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != "PASS" || ev.CommandID != "cmd-1" {
		t.Fatalf("unexpected UTF-16 evidence: %+v", ev)
	}
}
