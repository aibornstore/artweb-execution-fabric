package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/aibornstore/artweb-execution-fabric/pkg/bcp"
)

func TestSignedGrantAuthorizeAndTamperFail(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	g := bcp.Grant{
		ID: "g1", Subject: "owner", Capability: "agent.close",
		TargetPrefix: "device://HOME-2/agent/", Risks: []bcp.Risk{bcp.RiskDestructive},
		NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute),
		OneTime: true, HighRiskApproved: true, BoundOperationID: "op1",
	}
	g, err = SignGrant(g, "owner-main", priv)
	if err != nil {
		t.Fatal(err)
	}
	v := Verifier{Keys: map[string]ed25519.PublicKey{"owner-main": pub}}
	op := bcp.Operation{ID: "op1", ActorID: "owner", Capability: "agent.close", Target: "device://HOME-2/agent/r1", Action: "close", Risk: bcp.RiskDestructive}
	if err := v.VerifyAndAuthorize(now, op, g); err != nil {
		t.Fatal(err)
	}

	tampered := g
	tampered.TargetPrefix = "device://HOME-PC/agent/"
	if err := v.Verify(tampered); err == nil {
		t.Fatal("tampered grant must fail signature verification")
	}
}

func TestHighRiskGrantFailsClosed(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	g := bcp.Grant{
		ID: "g1", Subject: "owner", Capability: "agent.close", TargetPrefix: "device://HOME-2/agent/",
		Risks: []bcp.Risk{bcp.RiskDestructive}, NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute),
		OneTime: false, HighRiskApproved: true, BoundOperationID: "op1",
	}
	g, _ = SignGrant(g, "k", priv)
	v := Verifier{Keys: map[string]ed25519.PublicKey{"k": pub}}
	op := bcp.Operation{ID: "op1", ActorID: "owner", Capability: "agent.close", Target: "device://HOME-2/agent/r1", Risk: bcp.RiskDestructive}
	if err := v.VerifyAndAuthorize(now, op, g); err == nil {
		t.Fatal("non-one-time destructive grant must fail")
	}
}
