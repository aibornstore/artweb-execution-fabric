package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/aibornstore/artweb-execution-fabric/internal/auth"
	"github.com/aibornstore/artweb-execution-fabric/internal/identity"
	"github.com/aibornstore/artweb-execution-fabric/internal/limitedexec"
	"github.com/aibornstore/artweb-execution-fabric/internal/protocol"
	"github.com/aibornstore/artweb-execution-fabric/internal/shadow"
	"github.com/aibornstore/artweb-execution-fabric/internal/store"
	"github.com/aibornstore/artweb-execution-fabric/internal/transport"
	"github.com/aibornstore/artweb-execution-fabric/internal/worker"
	"github.com/aibornstore/artweb-execution-fabric/pkg/bcp"
	"github.com/coder/websocket"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: bridge-agent selfcheck|keygen [dir]|canary|worker")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "selfcheck":
		err = selfcheck()
	case "keygen":
		dir := ".secrets"
		if len(os.Args) > 2 {
			dir = os.Args[2]
		}
		err = keygen(dir)
	case "canary":
		err = canary()
	case "worker":
		err = runWorker()
	default:
		err = errors.New("unknown command")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func selfcheck() error {
	root, err := os.MkdirTemp("", "bridge-selfcheck-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(root)
	db, err := store.Open("file:selfcheck?mode=memory&cache=shared")
	if err != nil {
		return err
	}
	defer db.Close()
	if _, err = transport.ValidateEndpoint("wss://relay.invalid/bridge"); err != nil {
		return err
	}
	if err := shadow.SelfCheck(root); err != nil {
		return err
	}
	if err := limitedexec.SelfCheck(root); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"status": "PASS", "journal": "WAL_SCHEMA_OK",
		"transport": "WSS_TLS13_POLICY_OK", "shadow": "AUTH_EVIDENCE_NO_EXECUTION_OK",
		"limited_exec": "HOST_STATUS_READ_ONLY_OK",
	})
}

func keygen(dir string) error {
	keyID := envOr("BRIDGE_KEY_ID", "home2-main")
	_, created, err := identity.Ensure(dir, keyID)
	if err != nil {
		return err
	}
	privPath, pubPath := identity.Paths(dir)
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"status": "PASS", "created": created,
		"private_key_file": privPath, "public_key_file": pubPath, "key_id": keyID,
	})
}

func writeExclusive(path, value string, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err = f.WriteString(value + "\n"); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func canary() error {
	endpoint := strings.TrimSpace(os.Getenv("BRIDGE_ENDPOINT"))
	if endpoint == "" {
		return errors.New("BRIDGE_ENDPOINT is required")
	}
	agentID := envOr("BRIDGE_AGENT_ID", "HOME-2")
	keyID := envOr("BRIDGE_KEY_ID", "home2-main")
	identityDir := envOr("BRIDGE_IDENTITY_DIR", ".secrets")
	dataDir := envOr("BRIDGE_DATA_DIR", "data")
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return err
	}
	pair, err := identity.Load(identityDir, keyID)
	if err != nil {
		return err
	}
	privateKey := pair.Private
	sessionID, err := loadOrCreateSessionID(dataDir)
	if err != nil {
		return err
	}
	db, err := store.Open(filepath.Join(dataDir, "bridge.db"))
	if err != nil {
		return err
	}
	defer db.Close()
	messageID, err := randomID(16)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]any{
		"kind": "shadow_canary", "agent_id": agentID, "session_id": sessionID,
		"created_at": time.Now().UTC(), "provider_execution": false,
	})
	seq, err := db.EnqueueOutbox(context.Background(), bcp.OutboxItem{
		MessageID: messageID, Kind: "shadow_canary", Body: body,
	})
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pin := strings.TrimSpace(os.Getenv("BRIDGE_TLS_SPKI_SHA256"))
	conn, _, err := transport.Dial(ctx, transport.Config{
		Endpoint: endpoint, ConnectTimeout: 10 * time.Second, ServerSPKISHA256: pin,
	})
	if err != nil {
		return err
	}
	defer conn.Close(websocket.StatusNormalClosure, "canary complete")
	if err := transport.AuthenticateAgent(ctx, conn, agentID, sessionID, keyID, privateKey); err != nil {
		return err
	}
	if err := transport.ReplayPending(ctx, db, conn, agentID, sessionID, 100); err != nil {
		return err
	}
	for {
		pending, err := db.PendingOutbox(ctx, 100)
		if err != nil {
			return err
		}
		if len(pending) == 0 {
			break
		}
		_, data, err := conn.Read(ctx)
		if err != nil {
			return err
		}
		if err := transport.HandleAck(ctx, db, data, agentID, sessionID); err != nil {
			return err
		}
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"status": "PASS", "mode": "shadow_canary", "seq": seq, "acked": true,
		"provider_execution": false,
	})
}

func runWorker() error {
	endpoint := strings.TrimSpace(os.Getenv("BRIDGE_ENDPOINT"))
	if endpoint == "" {
		return errors.New("BRIDGE_ENDPOINT is required")
	}
	agentID := envOr("BRIDGE_AGENT_ID", "HOME-2")
	keyID := envOr("BRIDGE_KEY_ID", "home2-main")
	identityDir := envOr("BRIDGE_IDENTITY_DIR", ".secrets")
	dataDir := envOr("BRIDGE_DATA_DIR", filepath.Join("data", "worker"))
	controllerKeyID := strings.TrimSpace(os.Getenv("BRIDGE_CONTROLLER_KEY_ID"))
	controllerPubPath := strings.TrimSpace(os.Getenv("BRIDGE_CONTROLLER_PUBLIC_KEY_FILE"))
	controllerKeyringPath := strings.TrimSpace(os.Getenv("BRIDGE_CONTROLLER_KEYRING_FILE"))
	grantKeyID := envOr("BRIDGE_GRANT_KEY_ID", controllerKeyID)
	grantPubPath := envOr("BRIDGE_GRANT_PUBLIC_KEY_FILE", controllerPubPath)
	grantKeyringPath := envOr("BRIDGE_GRANT_KEYRING_FILE", controllerKeyringPath)
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return err
	}

	pair, err := identity.Load(identityDir, keyID)
	if err != nil {
		return err
	}
	controllerKeys, err := identity.LoadPublicKeySet(controllerKeyID, controllerPubPath, controllerKeyringPath)
	if err != nil {
		return fmt.Errorf("load controller public keys: %w", err)
	}
	grantKeys, err := identity.LoadPublicKeySet(grantKeyID, grantPubPath, grantKeyringPath)
	if err != nil {
		return fmt.Errorf("load grant public keys: %w", err)
	}
	sessionID, err := loadOrCreateSessionID(dataDir)
	if err != nil {
		return err
	}
	db, err := store.Open(filepath.Join(dataDir, "bridge.db"))
	if err != nil {
		return err
	}
	defer db.Close()

	grantVerifier := auth.Verifier{Keys: grantKeys}
	readRoots := filepath.SplitList(strings.TrimSpace(os.Getenv("BRIDGE_READ_ROOTS")))
	executor := limitedexec.Executor{
		Store:    db,
		Verifier: grantVerifier,
		Provider: &limitedexec.CompositeProvider{
			HostStatus:  &limitedexec.HostStatusProvider{},
			FileRead:    &limitedexec.FileReadProvider{AllowedRoots: readRoots},
			SystemInfo:  &limitedexec.SystemInfoProvider{},
			ProcessList: &limitedexec.ProcessListProvider{},
			FileMeta:    &limitedexec.FileMetaProvider{AllowedRoots: readRoots},
			Ping:        &limitedexec.PingProvider{},
		},
	}
	bootID, err := randomID(16)
	if err != nil {
		return err
	}
	agentVersion, err := selfAgentVersion()
	if err != nil {
		return err
	}
	handler := worker.Handler{
		AgentID: agentID, BootID: bootID, AgentVersion: agentVersion,
		Store:           db,
		CommandVerifier: protocol.CommandVerifier{Keys: controllerKeys},
		GrantVerifier:   grantVerifier,
		Executor:        executor,
	}
	runtime := worker.Runtime{
		Endpoint:       endpoint,
		ServerSPKIPin:  strings.TrimSpace(os.Getenv("BRIDGE_TLS_SPKI_SHA256")),
		AgentID:        agentID,
		SessionID:      sessionID,
		KeyID:          keyID,
		PrivateKey:     pair.Private,
		Store:          db,
		Handler:        handler,
		BaseBackoff:    time.Second,
		MaxBackoff:     30 * time.Second,
		JitterFraction: 0.20,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return runtime.Run(ctx)
}

func loadOrCreateSessionID(dir string) (string, error) {
	path := filepath.Join(dir, "session.id")
	if b, err := os.ReadFile(path); err == nil {
		v := strings.TrimSpace(string(b))
		if v != "" {
			return v, nil
		}
	}
	id, err := randomID(16)
	if err != nil {
		return "", err
	}
	if err := writeExclusive(path, id, 0600); err != nil {
		if b, e := os.ReadFile(path); e == nil && strings.TrimSpace(string(b)) != "" {
			return strings.TrimSpace(string(b)), nil
		}
		return "", err
	}
	return id, nil
}

func selfAgentVersion() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	raw, err := os.ReadFile(exe)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
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
