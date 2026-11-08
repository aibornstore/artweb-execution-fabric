package shadow

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"time"

	"github.com/aibornstore/artweb-execution-fabric/internal/auth"
	"github.com/aibornstore/artweb-execution-fabric/internal/store"
	"github.com/aibornstore/artweb-execution-fabric/pkg/bcp"
)

func SelfCheck(root string) error {
	s, err := store.Open(filepath.Join(root, "shadow-selfcheck.db"))
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
		ID: "selfcheck-grant", Subject: "selfcheck", Capability: "agent.read",
		TargetPrefix: "device://HOME-2/", Risks: []bcp.Risk{bcp.RiskRead},
		NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute),
	}
	g, err = auth.SignGrant(g, "selfcheck-key", priv)
	if err != nil {
		return err
	}
	if err := s.PutGrant(context.Background(), g); err != nil {
		return err
	}
	c := Canary{
		Store:    s,
		Verifier: VerifierFromKey("selfcheck-key", pub),
		Now:      func() time.Time { return now },
	}
	op := bcp.Operation{
		ID: "selfcheck-op", ActorID: "selfcheck", Capability: "agent.read",
		Target: "device://HOME-2/status", Action: "read", Risk: bcp.RiskRead,
	}
	r, err := c.Observe(context.Background(), op, "selfcheck-grant")
	if err != nil {
		return err
	}
	if r.Decision != "would_proceed" || r.Executed {
		return errShadowSelfCheck
	}
	return nil
}

var errShadowSelfCheck = &shadowError{}

type shadowError struct{}

func (*shadowError) Error() string { return "shadow selfcheck invariant failed" }
