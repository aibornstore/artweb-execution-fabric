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

func TestBuildTypedReadCommandSignedAndScoped(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := limitedexec.FileStatRequest{Path: "D:\\safe\\sample.txt"}
	cmd, err := buildTypedReadCommand(
		"HOME-2", "owner", "controller-main",
		limitedexec.FileStatCapability, "fs/stat", "fs-stat", payload, priv,
	)
	if err != nil {
		t.Fatal(err)
	}
	if cmd.AgentID != "HOME-2" ||
		cmd.Operation.Capability != limitedexec.FileStatCapability ||
		cmd.Operation.Target != "device://HOME-2/fs/stat" ||
		cmd.Grant.TargetPrefix != "device://HOME-2/" {
		t.Fatalf("bad typed read command: %+v", cmd)
	}
	var got limitedexec.FileStatRequest
	if err := json.Unmarshal(cmd.Operation.Payload, &got); err != nil {
		t.Fatal(err)
	}
	if got.Path != payload.Path {
		t.Fatalf("bad payload: %+v", got)
	}
	now := time.Now().UTC()
	if err := (protocol.CommandVerifier{
		Keys: map[string]ed25519.PublicKey{"controller-main": pub},
	}).Verify(cmd, now); err != nil {
		t.Fatalf("command signature: %v", err)
	}
	if err := (auth.Verifier{
		Keys: map[string]ed25519.PublicKey{"controller-main": pub},
	}).VerifyAndAuthorize(now, cmd.Operation, cmd.Grant); err != nil {
		t.Fatalf("grant signature: %v", err)
	}
}

func TestBuildTypedReadCommandCapabilities(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		capability string
		target     string
	}{
		{limitedexec.SystemInfoCapability, "system/info"},
		{limitedexec.ProcessListCapability, "process/list"},
		{limitedexec.FileListCapability, "fs/list"},
		{limitedexec.NetworkPingCapability, "network/ping"},
	}
	for _, tc := range cases {
		cmd, err := buildTypedReadCommand(
			"HOME-2", "owner", "controller-main",
			tc.capability, tc.target, "test", nil, priv,
		)
		if err != nil {
			t.Fatalf("%s: %v", tc.capability, err)
		}
		if cmd.Operation.Capability != tc.capability ||
			cmd.Operation.Target != "device://HOME-2/"+tc.target {
			t.Fatalf("wrong command for %s: %+v", tc.capability, cmd)
		}
	}
}

func TestParseBoundedInt(t *testing.T) {
	for _, raw := range []string{"", "0", "1", "256"} {
		if _, err := parseBoundedInt(raw, 256, "value"); err != nil {
			t.Fatalf("%q should pass: %v", raw, err)
		}
	}
	for _, raw := range []string{"-1", "257", "abc"} {
		if _, err := parseBoundedInt(raw, 256, "value"); err == nil {
			t.Fatalf("%q should fail", raw)
		}
	}
}
