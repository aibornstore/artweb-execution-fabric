package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestJobQuerySignVerifyAndTamper(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0).UTC()
	q, err := SignJobQuery(JobQuery{
		CommandID: "op1", AgentID: "HOME-2",
		IssuedAt: now, ExpiresAt: now.Add(time.Minute),
	}, "controller-main", priv)
	if err != nil {
		t.Fatal(err)
	}
	v := JobQueryVerifier{Keys: map[string]ed25519.PublicKey{"controller-main": pub}}
	if err := v.Verify(q, now.Add(10*time.Second)); err != nil {
		t.Fatal(err)
	}
	tampered := q
	tampered.CommandID = "op2"
	if err := v.Verify(tampered, now.Add(10*time.Second)); err == nil {
		t.Fatal("tampered job query must fail")
	}
}

func TestJobQueryExpiryAndLifetimeFailClosed(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Unix(1000, 0).UTC()
	v := JobQueryVerifier{Keys: map[string]ed25519.PublicKey{"controller-main": pub}, MaxLifetime: time.Minute}

	expired, err := SignJobQuery(JobQuery{
		CommandID: "op1", AgentID: "HOME-2",
		IssuedAt: now.Add(-2 * time.Minute), ExpiresAt: now.Add(-time.Minute),
	}, "controller-main", priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(expired, now); err == nil {
		t.Fatal("expired query must fail")
	}

	tooLong, err := SignJobQuery(JobQuery{
		CommandID: "op1", AgentID: "HOME-2",
		IssuedAt: now, ExpiresAt: now.Add(2 * time.Minute),
	}, "controller-main", priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(tooLong, now); err == nil {
		t.Fatal("overlong query must fail")
	}
}
