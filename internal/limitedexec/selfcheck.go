package limitedexec

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"path/filepath"
	"time"

	"github.com/aibornstore/artweb-execution-fabric/internal/auth"
	"github.com/aibornstore/artweb-execution-fabric/internal/store"
	"github.com/aibornstore/artweb-execution-fabric/pkg/bcp"
)

func SelfCheck(root string) error {
	s, err := store.Open(filepath.Join(root, "limited-selfcheck.db"))
	if err != nil {
		return err
	}
	defer s.Close()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	g := bcp.Grant{
		ID: "limited-selfcheck-grant", Subject: "selfcheck",
		Capability: HostStatusCapability, TargetPrefix: "device://HOME-2/",
		Risks:     []bcp.Risk{bcp.RiskRead},
		NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute),
	}
	g, err = auth.SignGrant(g, "limited-selfcheck-key", priv)
	if err != nil {
		return err
	}
	if err := s.PutGrant(context.Background(), g); err != nil {
		return err
	}

	provider := &HostStatusProvider{Now: func() time.Time { return now }}
	ex := Executor{
		Store: s,
		Verifier: auth.Verifier{Keys: map[string]ed25519.PublicKey{
			"limited-selfcheck-key": pub,
		}},
		Provider: provider,
		Now:      func() time.Time { return now },
	}
	op := bcp.Operation{
		ID: "limited-selfcheck-op", IdempotencyKey: "limited-selfcheck-idem",
		ActorID: "selfcheck", Capability: HostStatusCapability,
		Target: "device://HOME-2/status", Action: "read", Risk: bcp.RiskRead,
	}
	first, err := ex.Execute(context.Background(), op, "limited-selfcheck-grant")
	if err != nil {
		return err
	}
	second, err := ex.Execute(context.Background(), op, "limited-selfcheck-grant")
	if err != nil {
		return err
	}
	if provider.Calls() != 1 {
		return errors.New("limited selfcheck duplicate reexecuted provider")
	}
	if first.Status != "ok" || first.Code != "limited_read_ok" ||
		string(first.Output) != string(second.Output) {
		return errors.New("limited selfcheck durable cached result mismatch")
	}
	var status HostStatus
	if err := json.Unmarshal(first.Output, &status); err != nil {
		return err
	}
	if status.Schema != "host.status/v1" || status.Hostname == "" ||
		status.OS == "" || status.Arch == "" {
		return errors.New("limited selfcheck host status incomplete")
	}
	return nil
}
