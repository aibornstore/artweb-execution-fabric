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

func submitFileRead(agentID, relayBase, path string, maxBytes int) error {
	agentID = strings.TrimSpace(agentID)
	relayBase = strings.TrimSpace(relayBase)
	path = strings.TrimSpace(path)
	if agentID == "" || relayBase == "" || path == "" {
		return errors.New("agent id, relay base URL and path are required")
	}
	if maxBytes < 0 || maxBytes > 64<<10 {
		return errors.New("max-bytes must be between 0 and 65536")
	}
	keyID := envOr("BRIDGE_CONTROLLER_KEY_ID", "controller-main")
	dir := envOr("BRIDGE_CONTROLLER_IDENTITY_DIR", ".controller")
	actorID := envOr("BRIDGE_ACTOR_ID", "owner")
	pair, err := identity.Load(dir, keyID)
	if err != nil {
		return err
	}
	cmd, err := buildFileReadCommand(agentID, actorID, keyID, path, maxBytes, pair.Private)
	if err != nil {
		return err
	}
	return submitSignedCommand(agentID, relayBase, keyID, pair.Private, cmd)
}

func buildFileReadCommand(agentID, actorID, keyID, path string, maxBytes int, privateKey ed25519.PrivateKey) (protocol.Command, error) {
	id, err := randomID(16)
	if err != nil {
		return protocol.Command{}, err
	}
	payload, err := json.Marshal(limitedexec.FileReadRequest{Path: path, MaxBytes: maxBytes})
	if err != nil {
		return protocol.Command{}, err
	}
	now := time.Now().UTC()
	expires := now.Add(2 * time.Minute)
	grant := bcp.Grant{
		ID: "grant-" + id, Subject: actorID, Capability: limitedexec.FileReadCapability,
		TargetPrefix: "device://" + agentID + "/fs/", Risks: []bcp.Risk{bcp.RiskRead},
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
			ID: id, IdempotencyKey: "fs-read-" + id, ActorID: actorID,
			Capability: limitedexec.FileReadCapability,
			Target:     "device://" + agentID + "/fs/read",
			Action:     "read", Risk: bcp.RiskRead, Payload: payload,
		},
		Grant: grant, IssuedAt: now, ExpiresAt: expires, Nonce: nonce,
	}
	return protocol.SignCommand(cmd, keyID, privateKey)
}

func parseMaxBytes(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 || n > 64<<10 {
		return 0, errors.New("max-bytes must be an integer between 0 and 65536")
	}
	return n, nil
}
