package worker

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/aibornstore/artweb-execution-fabric/internal/auth"
	"github.com/aibornstore/artweb-execution-fabric/internal/limitedexec"
	"github.com/aibornstore/artweb-execution-fabric/internal/protocol"
	"github.com/aibornstore/artweb-execution-fabric/internal/store"
	"github.com/aibornstore/artweb-execution-fabric/pkg/bcp"
)

type workerFixture struct {
	store    *store.Store
	handler  Handler
	provider *limitedexec.HostStatusProvider
	priv     ed25519.PrivateKey
	now      time.Time
}

func newWorkerFixture(t *testing.T) workerFixture {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "worker.db"))
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0).UTC()
	provider := &limitedexec.HostStatusProvider{Now: func() time.Time { return now }}
	grantVerifier := auth.Verifier{Keys: map[string]ed25519.PublicKey{"controller-main": pub}}
	ex := limitedexec.Executor{
		Store: s, Verifier: grantVerifier, Provider: provider,
		Now: func() time.Time { return now },
	}
	return workerFixture{
		store: s, provider: provider, priv: priv, now: now,
		handler: Handler{
			AgentID: "HOME-2", BootID: "boot-test-a", AgentVersion: "sha256:test-agent",
			Store:           s,
			CommandVerifier: protocol.CommandVerifier{Keys: map[string]ed25519.PublicKey{"controller-main": pub}},
			GrantVerifier:   grantVerifier, Executor: ex,
			Now: func() time.Time { return now },
		},
	}
}

func (f workerFixture) command(t *testing.T, id string) protocol.Command {
	t.Helper()
	g := bcp.Grant{
		ID: "grant-" + id, Subject: "owner", Capability: limitedexec.HostStatusCapability,
		TargetPrefix: "device://HOME-2/", Risks: []bcp.Risk{bcp.RiskRead},
		NotBefore: f.now.Add(-time.Minute), ExpiresAt: f.now.Add(time.Minute),
	}
	var err error
	g, err = auth.SignGrant(g, "controller-main", f.priv)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := protocol.NewCommandNonce()
	if err != nil {
		t.Fatal(err)
	}
	cmd := protocol.Command{
		CommandID: id, AgentID: "HOME-2",
		Operation: bcp.Operation{
			ID: id, IdempotencyKey: "idem-" + id, ActorID: "owner",
			Capability: limitedexec.HostStatusCapability, Target: "device://HOME-2/status",
			Action: "read", Risk: bcp.RiskRead,
		},
		Grant: g, IssuedAt: f.now, ExpiresAt: f.now.Add(time.Minute), Nonce: nonce,
	}
	cmd, err = protocol.SignCommand(cmd, "controller-main", f.priv)
	if err != nil {
		t.Fatal(err)
	}
	return cmd
}

func TestWorkerExecutesReadOnlyAndQueuesResult(t *testing.T) {
	f := newWorkerFixture(t)
	defer f.store.Close()
	cmd := f.command(t, "op1")
	res := f.handler.Handle(context.Background(), protocol.Job{Command: cmd})
	if res.Status != "ok" || res.Code != "limited_read_ok" || res.Error != "" {
		t.Fatalf("bad result: %+v", res)
	}
	if res.BootID != "boot-test-a" || res.AgentVersion != "sha256:test-agent" {
		t.Fatalf("missing authenticated runtime provenance: %+v", res)
	}
	if f.provider.Calls() != 1 {
		t.Fatalf("provider calls=%d", f.provider.Calls())
	}
	var status limitedexec.HostStatus
	if err := json.Unmarshal(res.Output, &status); err != nil {
		t.Fatal(err)
	}
	if status.Schema != "host.status/v1" {
		t.Fatalf("bad output: %+v", status)
	}
	if _, err := f.handler.EnqueueResult(context.Background(), res); err != nil {
		t.Fatal(err)
	}
	pending, err := f.store.PendingOutbox(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 2 {
		t.Fatalf("expected limited receipt + job result, got %+v", pending)
	}
}

func TestWorkerDuplicateUsesCachedProviderResult(t *testing.T) {
	f := newWorkerFixture(t)
	defer f.store.Close()
	cmd := f.command(t, "op1")
	first := f.handler.Handle(context.Background(), protocol.Job{Command: cmd})
	second := f.handler.Handle(context.Background(), protocol.Job{Command: cmd})
	if first.Status != "ok" || second.Status != "ok" {
		t.Fatalf("bad duplicate results: first=%+v second=%+v", first, second)
	}
	if f.provider.Calls() != 1 {
		t.Fatalf("duplicate reexecuted provider: %d", f.provider.Calls())
	}
	if string(first.Output) != string(second.Output) {
		t.Fatal("cached output mismatch")
	}
}

func TestWorkerRejectsTamperedCommandBeforeProvider(t *testing.T) {
	f := newWorkerFixture(t)
	defer f.store.Close()
	cmd := f.command(t, "op1")
	cmd.Operation.Target = "device://HOME-PC/status"
	res := f.handler.Handle(context.Background(), protocol.Job{Command: cmd})
	if res.Code != "command_verify_failed" {
		t.Fatalf("expected command verify failure, got %+v", res)
	}
	if f.provider.Calls() != 0 {
		t.Fatal("provider ran after command tamper")
	}
}

func TestWorkerRejectsWrongAgentBeforeProvider(t *testing.T) {
	f := newWorkerFixture(t)
	defer f.store.Close()
	cmd := f.command(t, "op1")
	cmd.AgentID = "HOME-PC"
	res := f.handler.Handle(context.Background(), protocol.Job{Command: cmd})
	if res.Code != "agent_mismatch" {
		t.Fatalf("expected agent mismatch, got %+v", res)
	}
	if f.provider.Calls() != 0 {
		t.Fatal("provider ran for wrong agent")
	}
}

func TestWorkerRejectsMutateBeforeProvider(t *testing.T) {
	f := newWorkerFixture(t)
	defer f.store.Close()
	cmd := f.command(t, "op1")
	cmd.Operation.Risk = bcp.RiskMutate
	cmd, err := protocol.SignCommand(cmd, "controller-main", f.priv)
	if err != nil {
		t.Fatal(err)
	}
	res := f.handler.Handle(context.Background(), protocol.Job{Command: cmd})
	if res.Status == "ok" || res.Error == "" {
		t.Fatalf("mutate must fail: %+v", res)
	}
	if f.provider.Calls() != 0 {
		t.Fatal("provider ran for mutate risk")
	}
}

func TestWorkerIncompleteOperationKeepsIdentityAndDoesNotReexecute(t *testing.T) {
	f := newWorkerFixture(t)
	defer f.store.Close()
	ctx := context.Background()
	cmd := f.command(t, "op-incomplete")
	if _, err := f.store.BeginOperation(ctx, cmd.Operation); err != nil {
		t.Fatal(err)
	}

	res := f.handler.Handle(ctx, protocol.Job{Command: cmd})
	if res.CommandID != cmd.CommandID || res.OperationID != cmd.Operation.ID {
		t.Fatalf("lost result identity: %+v", res)
	}
	if res.Status != "error" || res.Code != "limited_exec_error" || res.Error == "" {
		t.Fatalf("expected terminal fail-closed result: %+v", res)
	}
	if f.provider.Calls() != 0 {
		t.Fatal("incomplete durable operation must not reexecute provider")
	}
	if _, err := f.handler.EnqueueResult(ctx, res); err != nil {
		t.Fatal(err)
	}
	pending, err := f.store.PendingOutbox(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].OperationID != cmd.Operation.ID {
		t.Fatalf("identified job result not queued: %+v", pending)
	}
}
