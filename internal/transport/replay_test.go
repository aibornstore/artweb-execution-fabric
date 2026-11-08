package transport

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/aibornstore/artweb-execution-fabric/pkg/bcp"
	"github.com/coder/websocket"
)

type fakeOutbox struct {
	mu     sync.Mutex
	items  []bcp.OutboxItem
	marked []int64
	acked  []int64
}

func (f *fakeOutbox) PendingOutbox(context.Context, int) ([]bcp.OutboxItem, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]bcp.OutboxItem, len(f.items))
	copy(out, f.items)
	return out, nil
}
func (f *fakeOutbox) MarkSent(_ context.Context, seq int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.marked = append(f.marked, seq)
	return nil
}
func (f *fakeOutbox) AckThrough(_ context.Context, seq int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.acked = append(f.acked, seq)
	return nil
}

type fakeWire struct {
	writes [][]byte
	failAt int
}

func (w *fakeWire) Write(_ context.Context, _ websocket.MessageType, b []byte) error {
	if w.failAt > 0 && len(w.writes)+1 == w.failAt {
		return errors.New("write failed")
	}
	w.writes = append(w.writes, append([]byte(nil), b...))
	return nil
}
func (w *fakeWire) Read(context.Context) (websocket.MessageType, []byte, error) {
	return 0, nil, errors.New("closed")
}
func (w *fakeWire) Close(websocket.StatusCode, string) error { return nil }

func TestReplayMarksOnlySuccessfulWrites(t *testing.T) {
	ob := &fakeOutbox{items: []bcp.OutboxItem{
		{Seq: 1, MessageID: "m1", Kind: "operation", Body: []byte("a")},
		{Seq: 2, MessageID: "m2", Kind: "operation", Body: []byte("b")},
	}}
	w := &fakeWire{failAt: 2}
	err := ReplayPending(context.Background(), ob, w, "HOME-2", "s1", 100)
	if err == nil {
		t.Fatal("expected write failure")
	}
	if len(ob.marked) != 1 || ob.marked[0] != 1 {
		t.Fatalf("marked=%v", ob.marked)
	}
	var env bcp.Envelope
	if err := json.Unmarshal(w.writes[0], &env); err != nil {
		t.Fatal(err)
	}
	if env.Seq != 1 || env.AgentID != "HOME-2" || env.Version != bcp.ContractVersion {
		t.Fatalf("bad envelope: %+v", env)
	}
}

func TestHandleAckIdentityAndSequence(t *testing.T) {
	ob := &fakeOutbox{}
	env := bcp.Envelope{Version: bcp.ContractVersion, Type: "ack", Ack: 7, AgentID: "HOME-2", SessionID: "s1", SentAt: time.Now()}
	data, _ := json.Marshal(env)
	if err := HandleAck(context.Background(), ob, data, "HOME-2", "s1"); err != nil {
		t.Fatal(err)
	}
	if len(ob.acked) != 1 || ob.acked[0] != 7 {
		t.Fatalf("acked=%v", ob.acked)
	}
	env.AgentID = "other"
	data, _ = json.Marshal(env)
	if err := HandleAck(context.Background(), ob, data, "HOME-2", "s1"); err == nil {
		t.Fatal("identity mismatch must fail")
	}
}

func TestRetryDelayIsBounded(t *testing.T) {
	base := time.Second
	max := 8 * time.Second
	if got := RetryDelay(0, base, max, 0, 0.5); got != time.Second {
		t.Fatalf("got %v", got)
	}
	if got := RetryDelay(99, base, max, 0, 0.5); got != max {
		t.Fatalf("expected cap, got %v", got)
	}
	if got := RetryDelay(2, base, max, 0.25, 0); got < 3*time.Second || got > 4*time.Second {
		t.Fatalf("unexpected jitter low %v", got)
	}
	if got := RetryDelay(2, base, max, 0.25, 1); got != 5*time.Second {
		t.Fatalf("unexpected jitter high %v", got)
	}
}
