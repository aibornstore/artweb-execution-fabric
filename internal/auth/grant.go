package auth

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/aibornstore/artweb-execution-fabric/pkg/bcp"
)

type grantPayload struct {
	ID               string     `json:"id"`
	Subject          string     `json:"subject"`
	Capability       string     `json:"capability"`
	TargetPrefix     string     `json:"target_prefix"`
	Risks            []bcp.Risk `json:"risks"`
	NotBefore        string     `json:"not_before"`
	ExpiresAt        string     `json:"expires_at"`
	OneTime          bool       `json:"one_time"`
	HighRiskApproved bool       `json:"high_risk_approved"`
	BoundOperationID string     `json:"bound_operation_id,omitempty"`
	KeyID            string     `json:"key_id"`
}

func signingBytes(g bcp.Grant) ([]byte, error) {
	if g.ID == "" || g.Subject == "" || g.Capability == "" || g.TargetPrefix == "" || g.KeyID == "" {
		return nil, errors.New("grant identity fields are required")
	}
	if g.NotBefore.IsZero() || g.ExpiresAt.IsZero() || !g.ExpiresAt.After(g.NotBefore) {
		return nil, errors.New("grant validity window is invalid")
	}
	p := grantPayload{
		ID: g.ID, Subject: g.Subject, Capability: g.Capability, TargetPrefix: g.TargetPrefix,
		Risks:     append([]bcp.Risk(nil), g.Risks...),
		NotBefore: g.NotBefore.UTC().Format(time.RFC3339Nano),
		ExpiresAt: g.ExpiresAt.UTC().Format(time.RFC3339Nano),
		OneTime:   g.OneTime, HighRiskApproved: g.HighRiskApproved,
		BoundOperationID: g.BoundOperationID, KeyID: g.KeyID,
	}
	return json.Marshal(p)
}

func SignGrant(g bcp.Grant, keyID string, privateKey ed25519.PrivateKey) (bcp.Grant, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return bcp.Grant{}, errors.New("invalid ed25519 private key")
	}
	g.KeyID = keyID
	g.Signature = ""
	body, err := signingBytes(g)
	if err != nil {
		return bcp.Grant{}, err
	}
	g.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, body))
	return g, nil
}

type Verifier struct {
	Keys map[string]ed25519.PublicKey
}

func (v Verifier) Verify(g bcp.Grant) error {
	key, ok := v.Keys[g.KeyID]
	if !ok || len(key) != ed25519.PublicKeySize {
		return errors.New("unknown grant signing key")
	}
	sig, err := base64.RawURLEncoding.DecodeString(g.Signature)
	if err != nil {
		return errors.New("invalid grant signature encoding")
	}
	body, err := signingBytes(g)
	if err != nil {
		return err
	}
	if !ed25519.Verify(key, body, sig) {
		return errors.New("grant signature verification failed")
	}
	return nil
}

func (v Verifier) VerifyAndAuthorize(now time.Time, op bcp.Operation, g bcp.Grant) error {
	if err := v.Verify(g); err != nil {
		return err
	}
	if now.Before(g.NotBefore) || !now.Before(g.ExpiresAt) {
		return errors.New("grant outside validity window")
	}
	if g.Subject != op.ActorID {
		return errors.New("grant subject mismatch")
	}
	if g.Capability != "*" && g.Capability != op.Capability {
		return errors.New("grant capability mismatch")
	}
	if !scopeMatches(g.TargetPrefix, op.Target) {
		return errors.New("target outside grant scope")
	}
	if !riskAllowed(g.Risks, op.Risk) {
		return errors.New("risk class not granted")
	}
	if op.Risk == bcp.RiskHigh || op.Risk == bcp.RiskDestructive {
		if !g.HighRiskApproved || !g.OneTime || g.BoundOperationID != op.ID {
			return errors.New("high-risk operation requires approved one-time operation-bound grant")
		}
	}
	return nil
}

func scopeMatches(prefix, target string) bool {
	if prefix == "*" || prefix == target {
		return true
	}
	return strings.HasSuffix(prefix, "/") && strings.HasPrefix(target, prefix)
}

func riskAllowed(risks []bcp.Risk, want bcp.Risk) bool {
	for _, r := range risks {
		if r == want {
			return true
		}
	}
	return false
}
