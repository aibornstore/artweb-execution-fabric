package relay

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/aibornstore/artweb-execution-fabric/pkg/bcp"
)

func env(seq int64, id string) bcp.Envelope {
	return bcp.Envelope{
		Version: bcp.ContractVersion, MessageID: id, AgentID: "HOME-2", SessionID: "s1",
		Seq: seq, Type: "shadow_receipt", Body: []byte(id), SentAt: time.Unix(seq, 0).UTC(),
	}
}

func TestLedgerDurableExactlyOnceAndGapFence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay.jsonl")
	l, err := OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	if ack, err := l.Record(env(1, "m1")); err != nil || ack != 1 {
		t.Fatalf("ack=%d err=%v", ack, err)
	}
	if ack, err := l.Record(env(1, "m1")); err != nil || ack != 1 {
		t.Fatalf("duplicate ack=%d err=%v", ack, err)
	}
	if _, err := l.Record(env(3, "m3")); !errors.Is(err, ErrSequenceGap) {
		t.Fatalf("expected gap, got %v", err)
	}
	conflict := env(1, "other")
	if _, err := l.Record(conflict); !errors.Is(err, ErrSequenceConflict) {
		t.Fatalf("expected conflict, got %v", err)
	}

	l2, err := OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	if ack, err := l2.Record(env(1, "m1")); err != nil || ack != 1 {
		t.Fatalf("restart duplicate ack=%d err=%v", ack, err)
	}
	if ack, err := l2.Record(env(2, "m2")); err != nil || ack != 2 {
		t.Fatalf("seq2 ack=%d err=%v", ack, err)
	}
}
