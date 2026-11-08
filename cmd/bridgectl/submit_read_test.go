package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/aibornstore/artweb-execution-fabric/internal/auth"
	"github.com/aibornstore/artweb-execution-fabric/internal/limitedexec"
	"github.com/aibornstore/artweb-execution-fabric/internal/protocol"
)

func TestBuildFileReadCommandSignedAndScoped(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cmd, err := buildFileReadCommand("HOME-2", "owner", "controller-main", `D:\safe\sample.txt`, 4096, priv)
	if err != nil {
		t.Fatal(err)
	}
	if cmd.AgentID != "HOME-2" || cmd.Operation.Capability != limitedexec.FileReadCapability ||
		cmd.Operation.Target != "device://HOME-2/fs/read" ||
		cmd.Grant.TargetPrefix != "device://HOME-2/fs/" {
		t.Fatalf("bad fs.read command: %+v", cmd)
	}
	var payload limitedexec.FileReadRequest
	if err := json.Unmarshal(cmd.Operation.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Path != `D:\safe\sample.txt` || payload.MaxBytes != 4096 {
		t.Fatalf("bad payload: %+v", payload)
	}
	now := time.Now().UTC()
	if err := (protocol.CommandVerifier{Keys: map[string]ed25519.PublicKey{"controller-main": pub}}).Verify(cmd, now); err != nil {
		t.Fatalf("command signature: %v", err)
	}
	if err := (auth.Verifier{Keys: map[string]ed25519.PublicKey{"controller-main": pub}}).VerifyAndAuthorize(now, cmd.Operation, cmd.Grant); err != nil {
		t.Fatalf("grant signature: %v", err)
	}
}

func TestParseMaxBytes(t *testing.T) {
	for _, raw := range []string{"", "0", "1", "65536"} {
		if _, err := parseMaxBytes(raw); err != nil {
			t.Fatalf("%q should pass: %v", raw, err)
		}
	}
	for _, raw := range []string{"-1", "65537", "abc"} {
		if _, err := parseMaxBytes(raw); err == nil {
			t.Fatalf("%q should fail", raw)
		}
	}
}
