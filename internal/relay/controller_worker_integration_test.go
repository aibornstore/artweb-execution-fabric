package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aibornstore/artweb-execution-fabric/internal/auth"
	"github.com/aibornstore/artweb-execution-fabric/internal/protocol"
	"github.com/aibornstore/artweb-execution-fabric/internal/transport"
	"github.com/aibornstore/artweb-execution-fabric/pkg/bcp"
	"github.com/coder/websocket"
)

func controllerPost(t *testing.T, client *http.Client, endpoint string, in, out any) {
	t.Helper()
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Post(endpoint, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s: %s", resp.Status, body)
	}
	if err := json.Unmarshal(body, out); err != nil {
		t.Fatal(err)
	}
}

func TestControllerHTTPSSubmitWorkerWSSAndSignedQueryE2E(t *testing.T) {
	controllerPub, controllerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
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

	ingress := Ingress{
		Jobs: jobs,
		CommandVerifier: protocol.CommandVerifier{
			Keys: map[string]ed25519.PublicKey{"controller-main": controllerPub},
		},
		GrantVerifier: auth.Verifier{
			Keys: map[string]ed25519.PublicKey{"controller-main": controllerPub},
		},
		ExpectedAgentID: "HOME-2",
	}
	controllerHTTP := ControllerHTTP{
		Ingress: ingress,
		Jobs:    jobs,
		QueryVerifier: protocol.JobQueryVerifier{
			Keys: map[string]ed25519.PublicKey{"controller-main": controllerPub},
		},
		ExpectedAgentID: "HOME-2",
	}
	workerServer := &Server{
		Verifier: protocol.HelloVerifier{Keys: map[string]ed25519.PublicKey{"home2": agentPub}},
		Ledger:   ledger, Jobs: jobs,
		ChallengeTTL: time.Minute, JobLease: time.Second, JobPollInterval: 10 * time.Millisecond,
		ExpectedKeyByAgent: map[string]string{"HOME-2": "home2"},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/controller/submit", controllerHTTP.Submit)
	mux.HandleFunc("/controller/query", controllerHTTP.Query)
	mux.HandleFunc("/worker", workerServer.ServeWorkerHTTP)
	server, pin := startPinnedTLS13Server(t, mux)
	defer server.Close()

	httpClient, base, err := transport.NewPinnedHTTPClient(server.URL, pin, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	cmd := signedIngressCommand(t, now, "controller-e2e-1", controllerPriv)
	var submitted submitResponse
	controllerPost(t, httpClient, base.String()+"/controller/submit", cmd, &submitted)
	if submitted.Duplicate || submitted.Job.State != "queued" {
		t.Fatalf("unexpected submit: %+v", submitted)
	}

	workerURL := "wss" + strings.TrimPrefix(server.URL, "https") + "/worker"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := transport.Dial(ctx, transport.Config{
		Endpoint: workerURL, ConnectTimeout: time.Second, ServerSPKISHA256: pin,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "done")
	if err := transport.AuthenticateAgent(ctx, conn, "HOME-2", "session-e2e", "home2", agentPriv); err != nil {
		t.Fatal(err)
	}
	typ, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if typ != websocket.MessageText {
		t.Fatal("worker job must be text")
	}
	var msg protocol.JobMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		t.Fatal(err)
	}
	if msg.Job.Command.CommandID != cmd.CommandID {
		t.Fatalf("wrong worker command: %+v", msg)
	}

	result := protocol.JobResult{
		CommandID: cmd.CommandID, OperationID: cmd.Operation.ID, AgentID: "HOME-2",
		Status: "ok", Code: "limited_read_ok", Output: []byte("controller-e2e-status"),
		CreatedAt: time.Now().UTC(),
	}
	resultBody, _ := json.Marshal(result)
	wire, _ := json.Marshal(bcp.Envelope{
		Version: bcp.ContractVersion, MessageID: "job-result:" + cmd.CommandID,
		AgentID: "HOME-2", SessionID: "session-e2e", Seq: 1,
		Type: "job_result", OperationID: cmd.Operation.ID, Body: resultBody, SentAt: time.Now().UTC(),
	})
	if err := conn.Write(ctx, websocket.MessageText, wire); err != nil {
		t.Fatal(err)
	}
	if _, _, err := conn.Read(ctx); err != nil {
		t.Fatal(err)
	}

	queryNow := time.Now().UTC()
	query, err := protocol.SignJobQuery(protocol.JobQuery{
		CommandID: cmd.CommandID, AgentID: "HOME-2",
		IssuedAt: queryNow, ExpiresAt: queryNow.Add(time.Minute),
	}, "controller-main", controllerPriv)
	if err != nil {
		t.Fatal(err)
	}
	var completed protocol.Job
	controllerPost(t, httpClient, base.String()+"/controller/query", query, &completed)
	if completed.State != "completed" || completed.Result == nil ||
		completed.Result.Code != "limited_read_ok" ||
		string(completed.Result.Output) != "controller-e2e-status" {
		t.Fatalf("controller did not receive completed result: %+v", completed)
	}
}
