package shadow

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/aibornstore/artweb-execution-fabric/internal/auth"
	"github.com/aibornstore/artweb-execution-fabric/internal/store"
	"github.com/aibornstore/artweb-execution-fabric/pkg/bcp"
)

func TestShadowAuthorizesButNeverExecutesOrConsumesGrant(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "shadow.db"))
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
		ID: "g1", Subject: "owner", Capability: "agent.close",
		TargetPrefix: "device://HOME-2/agent/", Risks: []bcp.Risk{bcp.RiskDestructive},
		NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute),
		OneTime: true, HighRiskApproved: true, BoundOperationID: "op1",
	}
	g, err = auth.SignGrant(g, "owner-main", priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutGrant(context.Background(), g); err != nil {
		t.Fatal(err)
	}

	c := Canary{Store: s, Verifier: VerifierFromKey("owner-main", pub), Now: func() time.Time { return now }}
	op := bcp.Operation{ID: "op1", ActorID: "owner", Capability: "agent.close", Target: "device://HOME-2/agent/r1", Action: "close", Risk: bcp.RiskDestructive}
	r, err := c.Observe(context.Background(), op, "g1")
	if err != nil {
		t.Fatal(err)
	}
	if r.Decision != "would_proceed" || r.Executed {
		t.Fatalf("bad shadow receipt: %+v", r)
	}

	// Observation must not consume the one-time grant.
	if err := s.ReserveGrant(context.Background(), "g1", "op1"); err != nil {
		t.Fatalf("shadow consumed grant: %v", err)
	}

	pending, err := s.PendingOutbox(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].Kind != "shadow_receipt" {
		t.Fatalf("unexpected outbox: %+v", pending)
	}
	var decoded bcp.ShadowReceipt
	if err := json.Unmarshal(pending[0].Body, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Executed || decoded.Code != "shadow_authorized_not_executed" {
		t.Fatalf("bad persisted receipt: %+v", decoded)
	}
}

func TestShadowDeniedStillEmitsEvidenceAndDoesNotExecute(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "shadow-deny.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Unix(1000, 0).UTC()
	g := bcp.Grant{
		ID: "g1", Subject: "owner", Capability: "agent.read",
		TargetPrefix: "device://HOME-2/", Risks: []bcp.Risk{bcp.RiskRead},
		NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute),
	}
	g, _ = auth.SignGrant(g, "k", priv)
	if err := s.PutGrant(context.Background(), g); err != nil {
		t.Fatal(err)
	}

	c := Canary{Store: s, Verifier: VerifierFromKey("k", pub), Now: func() time.Time { return now }}
	op := bcp.Operation{ID: "op2", ActorID: "owner", Capability: "agent.close", Target: "device://HOME-2/agent/r1", Risk: bcp.RiskDestructive}
	r, err := c.Observe(context.Background(), op, "g1")
	if err == nil {
		t.Fatal("expected authority denial")
	}
	if r.Executed || r.Code != "authority_denied" {
		t.Fatalf("bad denial receipt: %+v", r)
	}
	pending, err := s.PendingOutbox(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].OperationID != "op2" {
		t.Fatalf("denial evidence missing: %+v", pending)
	}
}
