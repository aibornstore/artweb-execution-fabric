package relay

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/aibornstore/artweb-execution-fabric/internal/auth"
	"github.com/aibornstore/artweb-execution-fabric/internal/protocol"
	"github.com/aibornstore/artweb-execution-fabric/pkg/bcp"
)

func signedIngressCommand(t *testing.T, now time.Time, id string, priv ed25519.PrivateKey) protocol.Command {
	t.Helper()
	grant := bcp.Grant{
		ID: "grant-" + id, Subject: "owner", Capability: "host.status@1",
		TargetPrefix: "device://HOME-2/", Risks: []bcp.Risk{bcp.RiskRead},
		NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute),
	}
	var err error
	grant, err = auth.SignGrant(grant, "controller-main", priv)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := protocol.NewCommandNonce()
	if err != nil {
		t.Fatal(err)
	}
	cmd := protocol.Command{
		CommandID: id, AgentID: "HOME-2",
		Operation: bcp.Operation{
			ID: id, IdempotencyKey: "idem-" + id, ActorID: "owner",
			Capability: "host.status@1", Target: "device://HOME-2/status",
			Action: "read", Risk: bcp.RiskRead,
		},
		Grant: grant, IssuedAt: now, ExpiresAt: now.Add(time.Minute), Nonce: nonce,
	}
	cmd, err = protocol.SignCommand(cmd, "controller-main", priv)
	if err != nil {
		t.Fatal(err)
	}
	return cmd
}

func TestIngressVerifiesBeforeDurableQueue(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0).UTC()
	jobs, err := OpenJobStore(filepath.Join(t.TempDir(), "jobs.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer jobs.Close()
	verifier := protocol.CommandVerifier{Keys: map[string]ed25519.PublicKey{"controller-main": pub}}
	grantVerifier := auth.Verifier{Keys: map[string]ed25519.PublicKey{"controller-main": pub}}
	ingress := Ingress{
		Jobs: jobs, CommandVerifier: verifier, GrantVerifier: grantVerifier,
		ExpectedAgentID: "HOME-2", Now: func() time.Time { return now },
	}
	cmd := signedIngressCommand(t, now, "op1", priv)
	job, duplicate, err := ingress.Enqueue(context.Background(), cmd)
	if err != nil || duplicate || job.State != "queued" {
		t.Fatalf("enqueue failed job=%+v duplicate=%v err=%v", job, duplicate, err)
	}
	_, duplicate, err = ingress.Enqueue(context.Background(), cmd)
	if err != nil || !duplicate {
		t.Fatalf("idempotent duplicate failed duplicate=%v err=%v", duplicate, err)
	}

	tampered := cmd
	tampered.Operation.Target = "device://HOME-PC/status"
	if _, _, err := ingress.Enqueue(context.Background(), tampered); err == nil {
		t.Fatal("tampered command must fail before queue")
	}
	if _, err := jobs.Get(context.Background(), "op1"); err != nil {
		t.Fatalf("original durable job lost: %v", err)
	}
}

func TestIngressRejectsWrongAgentAndBadGrant(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Unix(1000, 0).UTC()
	jobs, err := OpenJobStore(filepath.Join(t.TempDir(), "jobs.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer jobs.Close()
	ingress := Ingress{
		Jobs:            jobs,
		CommandVerifier: protocol.CommandVerifier{Keys: map[string]ed25519.PublicKey{"controller-main": pub}},
		GrantVerifier:   auth.Verifier{Keys: map[string]ed25519.PublicKey{"controller-main": pub}},
		ExpectedAgentID: "HOME-2", Now: func() time.Time { return now },
	}
	wrongAgent := signedIngressCommand(t, now, "op2", priv)
	wrongAgent.AgentID = "HOME-PC"
	wrongAgent, err = protocol.SignCommand(wrongAgent, "controller-main", priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ingress.Enqueue(context.Background(), wrongAgent); err == nil {
		t.Fatal("wrong agent must fail")
	}

	badGrant := signedIngressCommand(t, now, "op3", priv)
	badGrant.Grant.Capability = "service.restart@1"
	badGrant, err = protocol.SignCommand(badGrant, "controller-main", priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ingress.Enqueue(context.Background(), badGrant); err == nil {
		t.Fatal("tampered grant must fail")
	}
	if _, err := jobs.Get(context.Background(), "op3"); !errors.Is(err, ErrJobNotFound) {
		t.Fatalf("rejected command reached queue: %v", err)
	}
}
