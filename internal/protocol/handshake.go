package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"
)

type Challenge struct {
	Nonce     string    `json:"nonce"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type HelloProof struct {
	AgentID   string `json:"agent_id"`
	SessionID string `json:"session_id"`
	KeyID     string `json:"key_id"`
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"`
}

func NewChallenge(now time.Time, ttl time.Duration) (Challenge, error) {
	if ttl <= 0 || ttl > 5*time.Minute {
		return Challenge{}, errors.New("invalid challenge ttl")
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return Challenge{}, err
	}
	return Challenge{
		Nonce:     base64.RawURLEncoding.EncodeToString(buf),
		IssuedAt:  now.UTC(),
		ExpiresAt: now.UTC().Add(ttl),
	}, nil
}

func proofBytes(agentID, sessionID, keyID, nonce string) []byte {
	return []byte("bridge-handshake-v1\n" + agentID + "\n" + sessionID + "\n" + keyID + "\n" + nonce)
}

func SignHello(agentID, sessionID, keyID string, c Challenge, privateKey ed25519.PrivateKey) (HelloProof, error) {
	if agentID == "" || sessionID == "" || keyID == "" || c.Nonce == "" {
		return HelloProof{}, errors.New("hello identity fields are required")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return HelloProof{}, errors.New("invalid private key")
	}
	sig := ed25519.Sign(privateKey, proofBytes(agentID, sessionID, keyID, c.Nonce))
	return HelloProof{
		AgentID: agentID, SessionID: sessionID, KeyID: keyID, Nonce: c.Nonce,
		Signature: base64.RawURLEncoding.EncodeToString(sig),
	}, nil
}

type HelloVerifier struct {
	Keys map[string]ed25519.PublicKey
	Now  func() time.Time
}

func (v HelloVerifier) Verify(c Challenge, proof HelloProof) error {
	now := time.Now().UTC()
	if v.Now != nil {
		now = v.Now().UTC()
	}
	if c.Nonce == "" || proof.Nonce != c.Nonce {
		return errors.New("challenge nonce mismatch")
	}
	if now.Before(c.IssuedAt) || !now.Before(c.ExpiresAt) {
		return errors.New("challenge outside validity window")
	}
	key, ok := v.Keys[proof.KeyID]
	if !ok || len(key) != ed25519.PublicKeySize {
		return errors.New("unknown hello signing key")
	}
	sig, err := base64.RawURLEncoding.DecodeString(proof.Signature)
	if err != nil {
		return errors.New("invalid hello signature encoding")
	}
	if !ed25519.Verify(key, proofBytes(proof.AgentID, proof.SessionID, proof.KeyID, proof.Nonce), sig) {
		return errors.New("hello signature verification failed")
	}
	return nil
}
