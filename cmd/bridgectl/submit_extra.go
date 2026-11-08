package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/aibornstore/artweb-execution-fabric/internal/auth"
	"github.com/aibornstore/artweb-execution-fabric/internal/identity"
	"github.com/aibornstore/artweb-execution-fabric/internal/limitedexec"
	"github.com/aibornstore/artweb-execution-fabric/internal/protocol"
	"github.com/aibornstore/artweb-execution-fabric/pkg/bcp"
)

func submitSystemInfo(agentID, relayBase string) error {
	return submitTypedRead(agentID, relayBase, limitedexec.SystemInfoCapability, "system/info", "system-info", nil)
}

func submitProcessList(agentID, relayBase string) error {
	return submitTypedRead(agentID, relayBase, limitedexec.ProcessListCapability, "process/list", "process-list", nil)
}

func submitFileStat(agentID, relayBase, path string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("path is required")
	}
	return submitTypedRead(agentID, relayBase, limitedexec.FileStatCapability, "fs/stat", "fs-stat",
		limitedexec.FileStatRequest{Path: path})
}
func submitFileList(agentID, relayBase, path string, maxEntries int) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("path is required")
	}
	if maxEntries < 0 || maxEntries > 256 {
		return errors.New("max-entries must be between 0 and 256")
	}
	return submitTypedRead(agentID, relayBase, limitedexec.FileListCapability, "fs/list", "fs-list",
		limitedexec.FileListRequest{Path: path, MaxEntries: maxEntries})
}

func submitPing(agentID, relayBase, target string, timeoutMS int) error {
	if timeoutMS < 0 || timeoutMS > 5000 {
		return errors.New("timeout-ms must be between 0 and 5000")
	}
	return submitTypedRead(agentID, relayBase, limitedexec.NetworkPingCapability, "network/ping", "network-ping",
		limitedexec.PingRequest{Target: target, TimeoutMillis: timeoutMS})
}

func submitTypedRead(agentID, relayBase, capability, targetSuffix, idemPrefix string, payload any) error {
	agentID = strings.TrimSpace(agentID)
	relayBase = strings.TrimSpace(relayBase)
	if agentID == "" || relayBase == "" {
		return errors.New("agent id and relay base URL are required")
	}
	keyID := envOr("BRIDGE_CONTROLLER_KEY_ID", "controller-main")
	dir := envOr("BRIDGE_CONTROLLER_IDENTITY_DIR", ".controller")
	actorID := envOr("BRIDGE_ACTOR_ID", "owner")
	pair, err := identity.Load(dir, keyID)
	if err != nil {
		return err
	}
	cmd, err := buildTypedReadCommand(agentID, actorID, keyID, capability, targetSuffix, idemPrefix, payload, pair.Private)
	if err != nil {
		return err
	}
	return submitSignedCommand(agentID, relayBase, keyID, pair.Private, cmd)
}
func buildTypedReadCommand(agentID, actorID, keyID, capability, targetSuffix, idemPrefix string, payload any, privateKey ed25519.PrivateKey) (protocol.Command, error) {
	id, err := randomID(16)
	if err != nil {
		return protocol.Command{}, err
	}
	var raw []byte
	if payload != nil {
		raw, err = json.Marshal(payload)
		if err != nil {
			return protocol.Command{}, err
		}
	}
	now := time.Now().UTC()
	expires := now.Add(2 * time.Minute)
	grant := bcp.Grant{
		ID: "grant-" + id, Subject: actorID, Capability: capability,
		TargetPrefix: "device://" + agentID + "/", Risks: []bcp.Risk{bcp.RiskRead},
		NotBefore: now.Add(-15 * time.Second), ExpiresAt: expires,
	}
	grant, err = auth.SignGrant(grant, keyID, privateKey)
	if err != nil {
		return protocol.Command{}, err
	}
	nonce, err := protocol.NewCommandNonce()
	if err != nil {
		return protocol.Command{}, err
	}
	cmd := protocol.Command{
		CommandID: id, AgentID: agentID,
		Operation: bcp.Operation{
			ID: id, IdempotencyKey: idemPrefix + "-" + id, ActorID: actorID,
			Capability: capability, Target: "device://" + agentID + "/" + targetSuffix,
			Action: "read", Risk: bcp.RiskRead, Payload: raw,
		},
		Grant: grant, IssuedAt: now, ExpiresAt: expires, Nonce: nonce,
	}
	return protocol.SignCommand(cmd, keyID, privateKey)
}

func parseBoundedInt(raw string, max int, name string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 || n > max {
		return 0, errors.New(name + " must be an integer between 0 and " + strconv.Itoa(max))
	}
	return n, nil
}
