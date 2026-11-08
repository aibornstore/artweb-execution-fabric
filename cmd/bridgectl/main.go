package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aibornstore/artweb-execution-fabric/internal/auth"
	"github.com/aibornstore/artweb-execution-fabric/internal/identity"
	"github.com/aibornstore/artweb-execution-fabric/internal/limitedexec"
	"github.com/aibornstore/artweb-execution-fabric/internal/protocol"
	"github.com/aibornstore/artweb-execution-fabric/pkg/bcp"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: bridgectl keygen [dir] | sign-status <agent-id> <output.json> | submit-status <agent-id> <https-relay-base> | submit-read <agent-id> <https-relay-base> <path> [max-bytes] | submit-system-info <agent-id> <https-relay-base> | submit-process-list <agent-id> <https-relay-base> | submit-stat <agent-id> <https-relay-base> <path> | submit-list <agent-id> <https-relay-base> <path> [max-entries] | submit-ping <agent-id> <https-relay-base> <target> [timeout-ms]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		dir := envOr("BRIDGE_CONTROLLER_IDENTITY_DIR", ".controller")
		if len(os.Args) > 2 {
			dir = os.Args[2]
		}
		err = keygen(dir)
	case "sign-status":
		if len(os.Args) != 4 {
			err = errors.New("usage: bridgectl sign-status <agent-id> <output.json>")
		} else {
			err = signStatus(os.Args[2], os.Args[3])
		}
	case "submit-status":
		if len(os.Args) != 4 {
			err = errors.New("usage: bridgectl submit-status <agent-id> <https-relay-base>")
		} else {
			err = submitStatus(os.Args[2], os.Args[3])
		}
	case "submit-read":
		if len(os.Args) < 5 || len(os.Args) > 6 {
			err = errors.New("usage: bridgectl submit-read <agent-id> <https-relay-base> <path> [max-bytes]")
		} else {
			maxBytes := 0
			if len(os.Args) == 6 {
				maxBytes, err = parseMaxBytes(os.Args[5])
			}
			if err == nil {
				err = submitFileRead(os.Args[2], os.Args[3], os.Args[4], maxBytes)
			}
		}
	case "submit-system-info":
		if len(os.Args) != 4 {
			err = errors.New("usage: bridgectl submit-system-info <agent-id> <https-relay-base>")
		} else {
			err = submitSystemInfo(os.Args[2], os.Args[3])
		}
	case "submit-process-list":
		if len(os.Args) != 4 {
			err = errors.New("usage: bridgectl submit-process-list <agent-id> <https-relay-base>")
		} else {
			err = submitProcessList(os.Args[2], os.Args[3])
		}
	case "submit-stat":
		if len(os.Args) != 5 {
			err = errors.New("usage: bridgectl submit-stat <agent-id> <https-relay-base> <path>")
		} else {
			err = submitFileStat(os.Args[2], os.Args[3], os.Args[4])
		}
	case "submit-list":
		if len(os.Args) < 5 || len(os.Args) > 6 {
			err = errors.New("usage: bridgectl submit-list <agent-id> <https-relay-base> <path> [max-entries]")
		} else {
			maxEntries := 0
			if len(os.Args) == 6 {
				maxEntries, err = parseBoundedInt(os.Args[5], 256, "max-entries")
			}
			if err == nil {
				err = submitFileList(os.Args[2], os.Args[3], os.Args[4], maxEntries)
			}
		}
	case "submit-ping":
		if len(os.Args) < 5 || len(os.Args) > 6 {
			err = errors.New("usage: bridgectl submit-ping <agent-id> <https-relay-base> <target> [timeout-ms]")
		} else {
			timeoutMS := 0
			if len(os.Args) == 6 {
				timeoutMS, err = parseBoundedInt(os.Args[5], 5000, "timeout-ms")
			}
			if err == nil {
				err = submitPing(os.Args[2], os.Args[3], os.Args[4], timeoutMS)
			}
		}
	default:
		err = errors.New("unknown command")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func keygen(dir string) error {
	keyID := envOr("BRIDGE_CONTROLLER_KEY_ID", "controller-main")
	_, created, err := identity.Ensure(dir, keyID)
	if err != nil {
		return err
	}
	_, pub := identity.Paths(dir)
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"status": "PASS", "created": created,
		"key_id": keyID, "public_key_file": pub,
	})
}

func signStatus(agentID, outputPath string) error {
	agentID = strings.TrimSpace(agentID)
	if agentID == "" {
		return errors.New("agent id is required")
	}
	keyID := envOr("BRIDGE_CONTROLLER_KEY_ID", "controller-main")
	dir := envOr("BRIDGE_CONTROLLER_IDENTITY_DIR", ".controller")
	actorID := envOr("BRIDGE_ACTOR_ID", "owner")
	pair, err := identity.Load(dir, keyID)
	if err != nil {
		return err
	}
	id, err := randomID(16)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	expires := now.Add(2 * time.Minute)
	grant := bcp.Grant{
		ID: "grant-" + id, Subject: actorID, Capability: limitedexec.HostStatusCapability,
		TargetPrefix: "device://" + agentID + "/", Risks: []bcp.Risk{bcp.RiskRead},
		NotBefore: now.Add(-15 * time.Second), ExpiresAt: expires,
	}
	grant, err = auth.SignGrant(grant, keyID, pair.Private)
	if err != nil {
		return err
	}
	nonce, err := protocol.NewCommandNonce()
	if err != nil {
		return err
	}
	cmd := protocol.Command{
		CommandID: id, AgentID: agentID,
		Operation: bcp.Operation{
			ID: id, IdempotencyKey: "host-status-" + id, ActorID: actorID,
			Capability: limitedexec.HostStatusCapability,
			Target:     "device://" + agentID + "/status",
			Action:     "read", Risk: bcp.RiskRead,
		},
		Grant: grant, IssuedAt: now, ExpiresAt: expires, Nonce: nonce,
	}
	cmd, err = protocol.SignCommand(cmd, keyID, pair.Private)
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(cmd, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0700); err != nil && filepath.Dir(outputPath) != "." {
		return err
	}
	f, err := os.OpenFile(outputPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(append(raw, '\n')); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"status": "PASS", "command_id": id, "agent_id": agentID,
		"output": outputPath, "expires_at": expires,
	})
}

func randomID(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func envOr(name, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return fallback
}
