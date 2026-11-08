package limitedexec

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/aibornstore/artweb-execution-fabric/internal/auth"
	"github.com/aibornstore/artweb-execution-fabric/internal/store"
	"github.com/aibornstore/artweb-execution-fabric/pkg/bcp"
)

func fixture(t *testing.T) (*store.Store, Executor, *HostStatusProvider, time.Time) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "limited.db"))
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0).UTC()
	g := bcp.Grant{
		ID: "g1", Subject: "owner", Capability: HostStatusCapability,
		TargetPrefix: "device://HOME-2/", Risks: []bcp.Risk{bcp.RiskRead},
		NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute),
	}
	g, err = auth.SignGrant(g, "owner-main", priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutGrant(context.Background(), g); err != nil {
		t.Fatal(err)
	}
	provider := &HostStatusProvider{Now: func() time.Time { return now }}
	ex := Executor{
		Store:    s,
		Verifier: auth.Verifier{Keys: map[string]ed25519.PublicKey{"owner-main": pub}},
		Provider: provider,
		Now:      func() time.Time { return now },
	}
	return s, ex, provider, now
}

func validOperation() bcp.Operation {
	return bcp.Operation{
		ID: "op1", IdempotencyKey: "idem1", ActorID: "owner",
		Capability: HostStatusCapability, Target: "device://HOME-2/status",
		Action: "read", Risk: bcp.RiskRead,
	}
}

func TestLimitedExecHostStatusAndDurableEvidence(t *testing.T) {
	s, ex, provider, _ := fixture(t)
	defer s.Close()

	r, err := ex.Execute(context.Background(), validOperation(), "g1")
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "ok" || r.Code != "limited_read_ok" {
		t.Fatalf("bad result: %+v", r)
	}
	if provider.Calls() != 1 {
		t.Fatalf("provider calls=%d", provider.Calls())
	}
	var status HostStatus
	if err := json.Unmarshal(r.Output, &status); err != nil {
		t.Fatal(err)
	}
	if status.Schema != "host.status/v1" || status.Hostname == "" || status.OS == "" || status.Arch == "" {
		t.Fatalf("bad host status: %+v", status)
	}
	pending, err := s.PendingOutbox(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].Kind != "limited_exec_receipt" {
		t.Fatalf("missing limited evidence: %+v", pending)
	}
}

func TestLimitedExecDuplicateReturnsCachedWithoutSecondProviderCall(t *testing.T) {
	s, ex, provider, _ := fixture(t)
	defer s.Close()
	op := validOperation()

	first, err := ex.Execute(context.Background(), op, "g1")
	if err != nil {
		t.Fatal(err)
	}
	second, err := ex.Execute(context.Background(), op, "g1")
	if err != nil {
		t.Fatal(err)
	}
	if provider.Calls() != 1 {
		t.Fatalf("duplicate reexecuted provider: calls=%d", provider.Calls())
	}
	if string(first.Output) != string(second.Output) || first.Code != second.Code {
		t.Fatalf("cached result mismatch first=%+v second=%+v", first, second)
	}
}

func TestLimitedExecRejectsMutationBeforeProvider(t *testing.T) {
	s, ex, provider, _ := fixture(t)
	defer s.Close()
	op := validOperation()
	op.Risk = bcp.RiskMutate
	if _, err := ex.Execute(context.Background(), op, "g1"); !errors.Is(err, ErrReadOnlyExecutor) {
		t.Fatalf("expected read-only denial, got %v", err)
	}
	if provider.Calls() != 0 {
		t.Fatal("provider must not run for mutate risk")
	}
}

func TestLimitedExecRejectsUnsupportedCapabilityBeforeProvider(t *testing.T) {
	s, ex, provider, _ := fixture(t)
	defer s.Close()
	op := validOperation()
	op.Capability = "unsupported.read@1"
	if _, err := ex.Execute(context.Background(), op, "g1"); !errors.Is(err, ErrUnsupportedCapability) {
		t.Fatalf("expected unsupported capability, got %v", err)
	}
	if provider.Calls() != 0 {
		t.Fatal("provider must not run for unsupported capability")
	}
}

func TestLimitedExecAuthorityDenialDoesNotCallProvider(t *testing.T) {
	s, ex, provider, _ := fixture(t)
	defer s.Close()
	op := validOperation()
	op.ActorID = "other"
	if _, err := ex.Execute(context.Background(), op, "g1"); err == nil {
		t.Fatal("expected authority denial")
	}
	if provider.Calls() != 0 {
		t.Fatal("provider must not run after authority denial")
	}
}

func TestLimitedExecRetryRepairsMissingEvidenceWithoutReexecution(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "repair.db")
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0).UTC()
	g := bcp.Grant{
		ID: "repair-grant", Subject: "owner", Capability: HostStatusCapability,
		TargetPrefix: "device://HOME-2/", Risks: []bcp.Risk{bcp.RiskRead},
		NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute),
	}
	g, err = auth.SignGrant(g, "repair-key", priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutGrant(context.Background(), g); err != nil {
		t.Fatal(err)
	}
	provider := &HostStatusProvider{Now: func() time.Time { return now }}
	ex := Executor{
		Store:    s,
		Verifier: auth.Verifier{Keys: map[string]ed25519.PublicKey{"repair-key": pub}},
		Provider: provider,
		Now:      func() time.Time { return now },
	}
	op := validOperation()
	op.ID = "repair-op"
	op.IdempotencyKey = "repair-idem"

	if _, err := ex.Execute(context.Background(), op, "repair-grant"); err != nil {
		t.Fatal(err)
	}
	if provider.Calls() != 1 {
		t.Fatalf("initial provider calls=%d", provider.Calls())
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("DELETE FROM outbox WHERE message_id=?", "limited:"+op.ID); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	pending, err := s.PendingOutbox(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("expected simulated missing evidence, got %+v", pending)
	}

	if _, err := ex.Execute(context.Background(), op, "repair-grant"); err != nil {
		t.Fatal(err)
	}
	if provider.Calls() != 1 {
		t.Fatalf("retry reexecuted provider: calls=%d", provider.Calls())
	}
	pending, err = s.PendingOutbox(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].MessageID != "limited:"+op.ID {
		t.Fatalf("evidence was not repaired: %+v", pending)
	}
}
