package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestChallengeHelloRoundTripAndReplayFence(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0).UTC()
	c, err := NewChallenge(now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	p, err := SignHello("HOME-2", "session-1", "home2-main", c, priv)
	if err != nil {
		t.Fatal(err)
	}

	v := HelloVerifier{
		Keys: map[string]ed25519.PublicKey{"home2-main": pub},
		Now:  func() time.Time { return now.Add(10 * time.Second) },
	}
	if err := v.Verify(c, p); err != nil {
		t.Fatal(err)
	}

	other, err := NewChallenge(now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(other, p); err == nil {
		t.Fatal("proof replayed against another challenge must fail")
	}
}

func TestHelloTamperAndExpiryFailClosed(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Unix(1000, 0).UTC()
	c, _ := NewChallenge(now, time.Minute)
	p, _ := SignHello("HOME-2", "session-1", "home2-main", c, priv)

	tampered := p
	tampered.AgentID = "HOME-PC"
	v := HelloVerifier{Keys: map[string]ed25519.PublicKey{"home2-main": pub}, Now: func() time.Time { return now }}
	if err := v.Verify(c, tampered); err == nil {
		t.Fatal("tampered identity must fail")
	}

	expired := HelloVerifier{Keys: map[string]ed25519.PublicKey{"home2-main": pub}, Now: func() time.Time { return now.Add(2 * time.Minute) }}
	if err := expired.Verify(c, p); err == nil {
		t.Fatal("expired challenge must fail")
	}
}
