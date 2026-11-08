package relay

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/aibornstore/artweb-execution-fabric/internal/protocol"
	"github.com/aibornstore/artweb-execution-fabric/pkg/bcp"
)

func signedTestCommand(t *testing.T, now time.Time, id string) protocol.Command {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := protocol.NewCommandNonce()
	if err != nil {
		t.Fatal(err)
	}
	cmd := protocol.Command{
		CommandID: id,
		AgentID:   "HOME-2",
		Operation: bcp.Operation{
			ID: id, IdempotencyKey: "idem-" + id, ActorID: "owner",
			Capability: "host.status@1", Target: "device://HOME-2/status",
			Action: "read", Risk: bcp.RiskRead,
		},
		Grant: bcp.Grant{
			ID: "grant-" + id, Subject: "owner", Capability: "host.status@1",
			TargetPrefix: "device://HOME-2/", Risks: []bcp.Risk{bcp.RiskRead},
			NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute),
			KeyID: "grant-key", Signature: "signed-grant",
		},
		IssuedAt: now, ExpiresAt: now.Add(time.Minute), Nonce: nonce,
	}
	cmd, err = protocol.SignCommand(cmd, "controller-main", priv)
	if err != nil {
		t.Fatal(err)
	}
	return cmd
}

func TestJobStoreSemanticDuplicateAndConflict(t *testing.T) {
	s, err := OpenJobStore(filepath.Join(t.TempDir(), "jobs.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	now := time.Unix(1000, 0).UTC()
	cmd := signedTestCommand(t, now, "op1")

	first, duplicate, err := s.Create(ctx, cmd, now)
	if err != nil || duplicate || first.State != "queued" {
		t.Fatalf("first create: job=%+v duplicate=%v err=%v", first, duplicate, err)
	}
	second, duplicate, err := s.Create(ctx, cmd, now)
	if err != nil || !duplicate || second.Command.CommandID != "op1" {
		t.Fatalf("duplicate create: job=%+v duplicate=%v err=%v", second, duplicate, err)
	}

	tampered := cmd
	tampered.Operation.Target = "device://HOME-PC/status"
	if _, _, err := s.Create(ctx, tampered, now); !errors.Is(err, ErrJobConflict) {
		t.Fatalf("expected ErrJobConflict, got %v", err)
	}
}

func TestJobStoreLeaseExpiryRequeues(t *testing.T) {
	s, err := OpenJobStore(filepath.Join(t.TempDir(), "lease.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	now := time.Unix(1000, 0).UTC()
	cmd := signedTestCommand(t, now, "op1")
	if _, _, err := s.Create(ctx, cmd, now); err != nil {
		t.Fatal(err)
	}

	j1, err := s.LeaseNext(ctx, "HOME-2", now, 10*time.Second)
	if err != nil || j1 == nil || j1.State != "leased" {
		t.Fatalf("first lease: %+v err=%v", j1, err)
	}
	j2, err := s.LeaseNext(ctx, "HOME-2", now.Add(5*time.Second), 10*time.Second)
	if err != nil || j2 != nil {
		t.Fatalf("lease should still be held: %+v err=%v", j2, err)
	}
	j3, err := s.LeaseNext(ctx, "HOME-2", now.Add(11*time.Second), 10*time.Second)
	if err != nil || j3 == nil || j3.Command.CommandID != "op1" {
		t.Fatalf("expired lease did not requeue: %+v err=%v", j3, err)
	}
}

func TestJobStoreCompletionIdempotentAndConflict(t *testing.T) {
	s, err := OpenJobStore(filepath.Join(t.TempDir(), "complete.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	now := time.Unix(1000, 0).UTC()
	cmd := signedTestCommand(t, now, "op1")
	if _, _, err := s.Create(ctx, cmd, now); err != nil {
		t.Fatal(err)
	}
	result := protocol.JobResult{
		CommandID: "op1", OperationID: "op1", AgentID: "HOME-2",
		Status: "ok", Code: "limited_read_ok", Output: []byte("ok"), CreatedAt: now,
	}
	if err := s.Complete(ctx, "HOME-2", result, now); err != nil {
		t.Fatal(err)
	}
	if err := s.Complete(ctx, "HOME-2", result, now); err != nil {
		t.Fatalf("same result must be idempotent: %v", err)
	}
	conflict := result
	conflict.Output = []byte("different")
	if err := s.Complete(ctx, "HOME-2", conflict, now); !errors.Is(err, ErrJobResultConflict) {
		t.Fatalf("expected result conflict, got %v", err)
	}
	got, err := s.Get(ctx, "op1")
	if err != nil {
		t.Fatal(err)
	}
	if got.State != "completed" || got.Result == nil || string(got.Result.Output) != "ok" {
		t.Fatalf("bad completed job: %+v", got)
	}
}

func TestJobStorePersistsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "restart.db")
	ctx := context.Background()
	now := time.Unix(1000, 0).UTC()
	s, err := OpenJobStore(path)
	if err != nil {
		t.Fatal(err)
	}
	cmd := signedTestCommand(t, now, "op1")
	if _, _, err := s.Create(ctx, cmd, now); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s, err = OpenJobStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, err := s.Get(ctx, "op1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Command.CommandID != "op1" || got.State != "queued" {
		t.Fatalf("reopen lost job: %+v", got)
	}
}

func TestJobStoreAllowsOnlyOneActiveLeasePerAgent(t *testing.T) {
	s, err := OpenJobStore(filepath.Join(t.TempDir(), "single-active.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	now := time.Unix(1000, 0).UTC()
	cmd1 := signedTestCommand(t, now, "op1")
	cmd2 := signedTestCommand(t, now, "op2")
	if _, _, err := s.Create(ctx, cmd1, now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Create(ctx, cmd2, now.Add(time.Millisecond)); err != nil {
		t.Fatal(err)
	}

	first, err := s.LeaseNext(ctx, "HOME-2", now, 10*time.Second)
	if err != nil || first == nil || first.Command.CommandID != "op1" {
		t.Fatalf("first lease: %+v err=%v", first, err)
	}
	blocked, err := s.LeaseNext(ctx, "HOME-2", now.Add(time.Second), 10*time.Second)
	if err != nil || blocked != nil {
		t.Fatalf("second job leased while first active: %+v err=%v", blocked, err)
	}

	result := protocol.JobResult{
		CommandID: "op1", OperationID: "op1", AgentID: "HOME-2",
		Status: "ok", Code: "limited_read_ok", Output: []byte("ok"),
		CreatedAt: now.Add(2 * time.Second),
	}
	if err := s.Complete(ctx, "HOME-2", result, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	second, err := s.LeaseNext(ctx, "HOME-2", now.Add(3*time.Second), 10*time.Second)
	if err != nil || second == nil || second.Command.CommandID != "op2" {
		t.Fatalf("next lease after completion: %+v err=%v", second, err)
	}
}
