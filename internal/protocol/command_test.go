package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/aibornstore/artweb-execution-fabric/pkg/bcp"
)

func TestSignedCommandRoundTripAndTamperFailClosed(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0).UTC()
	nonce, err := NewCommandNonce()
	if err != nil {
		t.Fatal(err)
	}
	c := Command{
		CommandID: "op1", AgentID: "HOME-2",
		Operation: bcp.Operation{ID: "op1", IdempotencyKey: "idem1", ActorID: "owner", Capability: "host.status@1", Target: "device://HOME-2/status", Action: "read", Risk: bcp.RiskRead},
		Grant:     bcp.Grant{ID: "g1", Subject: "owner", Capability: "host.status@1", TargetPrefix: "device://HOME-2/", Risks: []bcp.Risk{bcp.RiskRead}, NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute), KeyID: "grant-key", Signature: "signed-grant"},
		IssuedAt:  now, ExpiresAt: now.Add(time.Minute), Nonce: nonce,
	}
	c, err = SignCommand(c, "controller-main", priv)
	if err != nil {
		t.Fatal(err)
	}
	v := CommandVerifier{Keys: map[string]ed25519.PublicKey{"controller-main": pub}}
	if err := v.Verify(c, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}

	tampered := c
	tampered.Operation.Target = "device://HOME-PC/status"
	if err := v.Verify(tampered, now.Add(time.Second)); err == nil {
		t.Fatal("tampered command must fail")
	}

	expired := c
	if err := v.Verify(expired, now.Add(2*time.Minute)); err == nil {
		t.Fatal("expired command must fail")
	}
}

func TestCommandIdentityBinding(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Unix(1000, 0).UTC()
	nonce, _ := NewCommandNonce()
	c := Command{
		CommandID: "cmd1", AgentID: "HOME-2",
		Operation: bcp.Operation{ID: "op-different"},
		Grant:     bcp.Grant{ID: "g1"},
		IssuedAt:  now, ExpiresAt: now.Add(time.Minute), Nonce: nonce,
	}
	if _, err := SignCommand(c, "k", priv); err == nil {
		t.Fatal("command id mismatch must fail")
	}
}
