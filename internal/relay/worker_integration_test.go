package relay

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aibornstore/artweb-execution-fabric/internal/protocol"
	"github.com/aibornstore/artweb-execution-fabric/internal/transport"
	"github.com/aibornstore/artweb-execution-fabric/pkg/bcp"
	"github.com/coder/websocket"
)

func TestWorkerWSSDeliversQueuedJobAndPersistsResult(t *testing.T) {
	agentPub, agentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()

	ledger, err := OpenLedger(filepath.Join(t.TempDir(), "relay.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	jobs, err := OpenJobStore(filepath.Join(t.TempDir(), "jobs.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer jobs.Close()

	cmd := signedTestCommand(t, now, "worker-op1")
	if _, _, err := jobs.Create(context.Background(), cmd, now); err != nil {
		t.Fatal(err)
	}

	s := &Server{
		Verifier: protocol.HelloVerifier{Keys: map[string]ed25519.PublicKey{"home2": agentPub}},
		Ledger:   ledger, Jobs: jobs,
		ChallengeTTL: time.Minute, JobLease: time.Second, JobPollInterval: 10 * time.Millisecond,
		ExpectedKeyByAgent: map[string]string{"HOME-2": "home2"},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/worker", s.ServeWorkerHTTP)
	server, pin := startPinnedTLS13Server(t, mux)
	defer server.Close()

	endpoint := "wss" + strings.TrimPrefix(server.URL, "https") + "/worker"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := transport.Dial(ctx, transport.Config{
		Endpoint: endpoint, ConnectTimeout: time.Second, ServerSPKISHA256: pin,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(websocket.StatusNormalClosure, "done")
	if err := transport.AuthenticateAgent(ctx, c, "HOME-2", "s1", "home2", agentPriv); err != nil {
		t.Fatal(err)
	}

	typ, data, err := c.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if typ != websocket.MessageText {
		t.Fatal("job must be text")
	}
	var msg protocol.JobMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		t.Fatal(err)
	}
	if msg.Type != "job" || msg.Job.Command.CommandID != "worker-op1" {
		t.Fatalf("unexpected job: %+v", msg)
	}

	result := protocol.JobResult{
		CommandID: "worker-op1", OperationID: "worker-op1", AgentID: "HOME-2",
		Status: "ok", Code: "limited_read_ok", Output: []byte("status-ok"), CreatedAt: now,
	}
	body, _ := json.Marshal(result)
	env := bcp.Envelope{
		Version: bcp.ContractVersion, MessageID: "job-result:worker-op1",
		AgentID: "HOME-2", SessionID: "s1", Seq: 1,
		Type: "job_result", OperationID: "worker-op1", Body: body, SentAt: now,
	}
	wire, _ := json.Marshal(env)
	if err := c.Write(ctx, websocket.MessageText, wire); err != nil {
		t.Fatal(err)
	}
	_, ackData, err := c.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var ack bcp.Envelope
	if err := json.Unmarshal(ackData, &ack); err != nil {
		t.Fatal(err)
	}
	if ack.Type != "ack" || ack.Ack != 1 {
		t.Fatalf("bad ack: %+v", ack)
	}

	stored, err := jobs.Get(context.Background(), "worker-op1")
	if err != nil {
		t.Fatal(err)
	}
	if stored.State != "completed" || stored.Result == nil ||
		stored.Result.Code != "limited_read_ok" || string(stored.Result.Output) != "status-ok" {
		t.Fatalf("job not durably completed: %+v", stored)
	}
}

func TestWorkerWSSRejectsUnexpectedEnvelopeType(t *testing.T) {
	agentPub, agentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	ledger, err := OpenLedger(filepath.Join(t.TempDir(), "relay.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	jobs, err := OpenJobStore(filepath.Join(t.TempDir(), "jobs.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer jobs.Close()
	cmd := signedTestCommand(t, now, "worker-op-bad-type")
	if _, _, err := jobs.Create(context.Background(), cmd, now); err != nil {
		t.Fatal(err)
	}
	s := &Server{
		Verifier: protocol.HelloVerifier{Keys: map[string]ed25519.PublicKey{"home2": agentPub}},
		Ledger:   ledger, Jobs: jobs, ChallengeTTL: time.Minute,
		JobLease: time.Second, JobPollInterval: 10 * time.Millisecond,
		ExpectedKeyByAgent: map[string]string{"HOME-2": "home2"},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/worker", s.ServeWorkerHTTP)
	server, pin := startPinnedTLS13Server(t, mux)
	defer server.Close()

	endpoint := "wss" + strings.TrimPrefix(server.URL, "https") + "/worker"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := transport.Dial(ctx, transport.Config{
		Endpoint: endpoint, ConnectTimeout: time.Second, ServerSPKISHA256: pin,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(websocket.StatusNormalClosure, "done")
	if err := transport.AuthenticateAgent(ctx, c, "HOME-2", "s1", "home2", agentPriv); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Read(ctx); err != nil {
		t.Fatal(err)
	}
	bad := bcp.Envelope{
		Version: bcp.ContractVersion, MessageID: "bad:1",
		AgentID: "HOME-2", SessionID: "s1", Seq: 1,
		Type: "unexpected_control", OperationID: "worker-op-bad-type", SentAt: now,
	}
	wire, _ := json.Marshal(bad)
	if err := c.Write(ctx, websocket.MessageText, wire); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Read(ctx); err == nil {
		t.Fatal("unexpected worker envelope type must close without ACK")
	}
	stored, err := jobs.Get(context.Background(), "worker-op-bad-type")
	if err != nil {
		t.Fatal(err)
	}
	if stored.State == "completed" {
		t.Fatalf("invalid envelope completed job: %+v", stored)
	}
}
