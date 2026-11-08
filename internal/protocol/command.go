package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/aibornstore/artweb-execution-fabric/pkg/bcp"
)

const CommandVersion = "bridge-command/v1"

type Command struct {
	Version         string        `json:"version"`
	CommandID       string        `json:"command_id"`
	AgentID         string        `json:"agent_id"`
	Operation       bcp.Operation `json:"operation"`
	Grant           bcp.Grant     `json:"grant"`
	ControllerKeyID string        `json:"controller_key_id"`
	IssuedAt        time.Time     `json:"issued_at"`
	ExpiresAt       time.Time     `json:"expires_at"`
	Nonce           string        `json:"nonce"`
	Signature       string        `json:"signature,omitempty"`
}

type commandPayload struct {
	Version         string        `json:"version"`
	CommandID       string        `json:"command_id"`
	AgentID         string        `json:"agent_id"`
	Operation       bcp.Operation `json:"operation"`
	Grant           bcp.Grant     `json:"grant"`
	ControllerKeyID string        `json:"controller_key_id"`
	IssuedAt        string        `json:"issued_at"`
	ExpiresAt       string        `json:"expires_at"`
	Nonce           string        `json:"nonce"`
}

func commandSigningBytes(c Command) ([]byte, error) {
	if c.Version != CommandVersion || c.CommandID == "" || c.AgentID == "" ||
		c.ControllerKeyID == "" || c.Nonce == "" || c.Operation.ID == "" ||
		c.Grant.ID == "" {
		return nil, errors.New("command identity fields are incomplete")
	}
	if c.CommandID != c.Operation.ID {
		return nil, errors.New("command id must equal operation id")
	}
	if c.IssuedAt.IsZero() || c.ExpiresAt.IsZero() || !c.ExpiresAt.After(c.IssuedAt) {
		return nil, errors.New("command validity window is invalid")
	}
	p := commandPayload{
		Version: c.Version, CommandID: c.CommandID, AgentID: c.AgentID,
		Operation: c.Operation, Grant: c.Grant, ControllerKeyID: c.ControllerKeyID,
		IssuedAt:  c.IssuedAt.UTC().Format(time.RFC3339Nano),
		ExpiresAt: c.ExpiresAt.UTC().Format(time.RFC3339Nano),
		Nonce:     c.Nonce,
	}
	return json.Marshal(p)
}

func NewCommandNonce() (string, error) {
	var b [18]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func SignCommand(c Command, keyID string, privateKey ed25519.PrivateKey) (Command, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return Command{}, errors.New("invalid command private key")
	}
	c.Version = CommandVersion
	c.ControllerKeyID = keyID
	c.Signature = ""
	body, err := commandSigningBytes(c)
	if err != nil {
		return Command{}, err
	}
	c.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, body))
	return c, nil
}

func CommandDigest(c Command) (string, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

type CommandVerifier struct {
	Keys        map[string]ed25519.PublicKey
	MaxLifetime time.Duration
	ClockSkew   time.Duration
}

func (v CommandVerifier) Verify(c Command, now time.Time) error {
	body, err := commandSigningBytes(c)
	if err != nil {
		return err
	}
	max := v.MaxLifetime
	if max <= 0 {
		max = 10 * time.Minute
	}
	if c.ExpiresAt.Sub(c.IssuedAt) > max {
		return fmt.Errorf("command lifetime exceeds %s", max)
	}
	skew := v.ClockSkew
	if skew <= 0 {
		skew = 30 * time.Second
	}
	now = now.UTC()
	if now.Before(c.IssuedAt.Add(-skew)) {
		return errors.New("command issued in the future")
	}
	if !now.Before(c.ExpiresAt) {
		return errors.New("command expired")
	}
	key, ok := v.Keys[c.ControllerKeyID]
	if !ok || len(key) != ed25519.PublicKeySize {
		return errors.New("unknown controller signing key")
	}
	sig, err := base64.RawURLEncoding.DecodeString(c.Signature)
	if err != nil {
		return errors.New("invalid command signature encoding")
	}
	if !ed25519.Verify(key, body, sig) {
		return errors.New("command signature verification failed")
	}
	return nil
}

type Job struct {
	Command    Command    `json:"command"`
	State      string     `json:"state"`
	LeaseUntil *time.Time `json:"lease_until,omitempty"`
	Result     *JobResult `json:"result,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

type JobMessage struct {
	Type string `json:"type"`
	Job  Job    `json:"job"`
}

type JobResult struct {
	CommandID    string    `json:"command_id"`
	OperationID  string    `json:"operation_id"`
	AgentID      string    `json:"agent_id"`
	BootID       string    `json:"boot_id,omitempty"`
	AgentVersion string    `json:"agent_version,omitempty"`
	Status       string    `json:"status"`
	Code         string    `json:"code"`
	Output       []byte    `json:"output,omitempty"`
	Error        string    `json:"error,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

func (r JobResult) Digest() (string, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
