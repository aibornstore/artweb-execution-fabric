package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const JobQueryVersion = "bridge-job-query/v1"

type JobQuery struct {
	Version         string    `json:"version"`
	CommandID       string    `json:"command_id"`
	AgentID         string    `json:"agent_id"`
	ControllerKeyID string    `json:"controller_key_id"`
	IssuedAt        time.Time `json:"issued_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	Nonce           string    `json:"nonce"`
	Signature       string    `json:"signature,omitempty"`
}

type jobQueryPayload struct {
	Version         string `json:"version"`
	CommandID       string `json:"command_id"`
	AgentID         string `json:"agent_id"`
	ControllerKeyID string `json:"controller_key_id"`
	IssuedAt        string `json:"issued_at"`
	ExpiresAt       string `json:"expires_at"`
	Nonce           string `json:"nonce"`
}

func jobQuerySigningBytes(q JobQuery) ([]byte, error) {
	if q.Version != JobQueryVersion || q.CommandID == "" || q.AgentID == "" ||
		q.ControllerKeyID == "" || q.Nonce == "" {
		return nil, errors.New("job query identity fields are incomplete")
	}
	if q.IssuedAt.IsZero() || q.ExpiresAt.IsZero() || !q.ExpiresAt.After(q.IssuedAt) {
		return nil, errors.New("job query validity window is invalid")
	}
	return json.Marshal(jobQueryPayload{
		Version: q.Version, CommandID: q.CommandID, AgentID: q.AgentID,
		ControllerKeyID: q.ControllerKeyID,
		IssuedAt:        q.IssuedAt.UTC().Format(time.RFC3339Nano),
		ExpiresAt:       q.ExpiresAt.UTC().Format(time.RFC3339Nano),
		Nonce:           q.Nonce,
	})
}

func SignJobQuery(q JobQuery, keyID string, privateKey ed25519.PrivateKey) (JobQuery, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return JobQuery{}, errors.New("invalid controller private key")
	}
	q.Version = JobQueryVersion
	q.ControllerKeyID = keyID
	if q.Nonce == "" {
		var b [18]byte
		if _, err := rand.Read(b[:]); err != nil {
			return JobQuery{}, err
		}
		q.Nonce = base64.RawURLEncoding.EncodeToString(b[:])
	}
	q.Signature = ""
	body, err := jobQuerySigningBytes(q)
	if err != nil {
		return JobQuery{}, err
	}
	q.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, body))
	return q, nil
}

type JobQueryVerifier struct {
	Keys        map[string]ed25519.PublicKey
	MaxLifetime time.Duration
	ClockSkew   time.Duration
}

func (v JobQueryVerifier) Verify(q JobQuery, now time.Time) error {
	body, err := jobQuerySigningBytes(q)
	if err != nil {
		return err
	}
	max := v.MaxLifetime
	if max <= 0 {
		max = 2 * time.Minute
	}
	if q.ExpiresAt.Sub(q.IssuedAt) > max {
		return fmt.Errorf("job query lifetime exceeds %s", max)
	}
	skew := v.ClockSkew
	if skew <= 0 {
		skew = 30 * time.Second
	}
	now = now.UTC()
	if now.Before(q.IssuedAt.Add(-skew)) {
		return errors.New("job query issued in the future")
	}
	if !now.Before(q.ExpiresAt) {
		return errors.New("job query expired")
	}
	key, ok := v.Keys[q.ControllerKeyID]
	if !ok || len(key) != ed25519.PublicKeySize {
		return errors.New("unknown controller signing key")
	}
	sig, err := base64.RawURLEncoding.DecodeString(q.Signature)
	if err != nil {
		return errors.New("invalid job query signature encoding")
	}
	if !ed25519.Verify(key, body, sig) {
		return errors.New("job query signature verification failed")
	}
	return nil
}
