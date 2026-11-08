package store

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/aibornstore/artweb-execution-fabric/pkg/bcp"
)

func TestDurableIdempotencyAndRecovery(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	op := bcp.Operation{ID: "op1", IdempotencyKey: "idem1", ActorID: "owner", Capability: "agent.exec", Target: "device://HOME-2", Action: "exec", Risk: bcp.RiskMutate}
	created, err := s.BeginOperation(ctx, op)
	if err != nil || !created {
		t.Fatalf("first insert: %v %v", created, err)
	}
	created, err = s.BeginOperation(ctx, op)
	if err != nil || created {
		t.Fatalf("idempotent retry should reuse existing operation: created=%v err=%v", created, err)
	}
	p, err := s.RecoverPending(ctx)
	if err != nil || len(p) != 1 {
		t.Fatalf("pending=%v err=%v", p, err)
	}
	if err := s.MarkUncertain(ctx, "op1"); err != nil {
		t.Fatal(err)
	}
	if err := s.Complete(ctx, bcp.Result{OperationID: "op1", Status: "ok", Code: "done", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	p, err = s.RecoverPending(ctx)
	if err != nil || len(p) != 0 {
		t.Fatalf("pending after complete=%v err=%v", p, err)
	}
}

func TestOneTimeGrantReservationIsAtomic(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "grant.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	g := bcp.Grant{
		ID: "g1", Subject: "owner", Capability: "agent.exec", TargetPrefix: "device://HOME-2/",
		Risks: []bcp.Risk{bcp.RiskMutate}, NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute),
		OneTime: true, KeyID: "k", Signature: "test",
	}
	if err := s.PutGrant(ctx, g); err != nil {
		t.Fatal(err)
	}

	type result struct {
		op  string
		err error
	}
	ch := make(chan result, 32)
	for i := 0; i < 32; i++ {
		go func(i int) {
			op := fmt.Sprintf("op-%d", i)
			ch <- result{op: op, err: s.ReserveGrant(ctx, "g1", op)}
		}(i)
	}
	wins := []string{}
	for i := 0; i < 32; i++ {
		r := <-ch
		if r.err == nil {
			wins = append(wins, r.op)
		} else if !errors.Is(r.err, ErrGrantConsumed) {
			t.Fatalf("unexpected error: %v", r.err)
		}
	}
	if len(wins) != 1 {
		t.Fatalf("expected one winner, got %v", wins)
	}
	if err := s.ReserveGrant(ctx, "g1", wins[0]); err != nil {
		t.Fatalf("same operation retry must be idempotent: %v", err)
	}
}

func TestOutboxRejectsUnsentAckAndReplaysAfterReopen(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "outbox.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	seq1, err := s.EnqueueOutbox(ctx, bcp.OutboxItem{MessageID: "m1", OperationID: "op1", Kind: "operation", Body: []byte("one")})
	if err != nil {
		t.Fatal(err)
	}
	seq2, err := s.EnqueueOutbox(ctx, bcp.OutboxItem{MessageID: "m2", OperationID: "op2", Kind: "operation", Body: []byte("two")})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AckThrough(ctx, seq1); !errors.Is(err, ErrAckUnsent) {
		t.Fatalf("expected ErrAckUnsent, got %v", err)
	}
	if err := s.MarkSent(ctx, seq1); err != nil {
		t.Fatal(err)
	}
	if err := s.AckThrough(ctx, seq1); err != nil {
		t.Fatal(err)
	}
	pending, err := s.PendingOutbox(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].Seq != seq2 {
		t.Fatalf("unexpected pending: %+v", pending)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s, err = Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	pending, err = s.PendingOutbox(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].MessageID != "m2" {
		t.Fatalf("reopen replay mismatch: %+v", pending)
	}
	if err := s.MarkSent(ctx, seq2); err != nil {
		t.Fatal(err)
	}
	if err := s.AckThrough(ctx, seq2); err != nil {
		t.Fatal(err)
	}
	pending, err = s.PendingOutbox(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("expected empty outbox, got %+v", pending)
	}
}

func TestIdempotencyConflictFailsClosed(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "idem-conflict.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	op := bcp.Operation{ID: "op1", IdempotencyKey: "idem1", ActorID: "owner", Capability: "agent.read", Target: "device://HOME-2/status", Action: "read", Risk: bcp.RiskRead, Payload: []byte("a")}
	if created, err := s.BeginOperation(ctx, op); err != nil || !created {
		t.Fatalf("first: created=%v err=%v", created, err)
	}
	tampered := op
	tampered.Target = "device://HOME-PC/status"
	tampered.Payload = []byte("b")
	if created, err := s.BeginOperation(ctx, tampered); !errors.Is(err, ErrIdempotencyConflict) || created {
		t.Fatalf("expected conflict, created=%v err=%v", created, err)
	}
}

func TestDeviceTableCRUD(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "device.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()

	dev := bcp.DeviceEntry{
		ID:              "HOME-2",
		Generation:      "v2",
		Fingerprint:     "fp-abc123",
		RoutingEligible: true,
		PublisherDeny:   false,
	}
	if err := s.PutDevice(ctx, dev); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetDevice(ctx, "HOME-2")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "HOME-2" || got.Generation != "v2" || got.Fingerprint != "fp-abc123" || !got.RoutingEligible || got.PublisherDeny {
		t.Fatalf("device mismatch: %+v", got)
	}

	list, err := s.ListDevices(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v %v", list, err)
	}

	_, err = s.GetDevice(ctx, "UNKNOWN")
	if !errors.Is(err, ErrDeviceNotFound) {
		t.Fatalf("expected ErrDeviceNotFound, got %v", err)
	}
}

func TestDeviceTableUpdate(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "device-update.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()

	dev := bcp.DeviceEntry{
		ID:              "HOME-2",
		Generation:      "v2",
		Fingerprint:     "fp-abc123",
		RoutingEligible: true,
		PublisherDeny:   false,
	}
	if err := s.PutDevice(ctx, dev); err != nil {
		t.Fatal(err)
	}

	dev.RoutingEligible = false
	dev.PublisherDeny = true
	dev.Fingerprint = "fp-new456"
	if err := s.PutDevice(ctx, dev); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetDevice(ctx, "HOME-2")
	if err != nil {
		t.Fatal(err)
	}
	if got.RoutingEligible || !got.PublisherDeny || got.Fingerprint != "fp-new456" {
		t.Fatalf("update not applied: %+v", got)
	}
}
