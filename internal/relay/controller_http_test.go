package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/aibornstore/artweb-execution-fabric/internal/auth"
	"github.com/aibornstore/artweb-execution-fabric/internal/protocol"
)

func controllerHTTPFixture(t *testing.T, now time.Time) (ControllerHTTP, ed25519.PrivateKey, *JobStore) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jobs, err := OpenJobStore(filepath.Join(t.TempDir(), "jobs.db"))
	if err != nil {
		t.Fatal(err)
	}
	ingress := Ingress{
		Jobs: jobs,
		CommandVerifier: protocol.CommandVerifier{
			Keys: map[string]ed25519.PublicKey{"controller-main": pub},
		},
		GrantVerifier: auth.Verifier{
			Keys: map[string]ed25519.PublicKey{"controller-main": pub},
		},
		ExpectedAgentID: "HOME-2",
		Now:             func() time.Time { return now },
	}
	h := ControllerHTTP{
		Ingress: ingress,
		Jobs:    jobs,
		QueryVerifier: protocol.JobQueryVerifier{
			Keys: map[string]ed25519.PublicKey{"controller-main": pub},
		},
		ExpectedAgentID: "HOME-2",
		Now:             func() time.Time { return now },
	}
	return h, priv, jobs
}

func postJSON(t *testing.T, handler http.HandlerFunc, v any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "https://relay.test/", bytes.NewReader(raw))
	rr := httptest.NewRecorder()
	handler(rr, req)
	return rr
}

func TestControllerHTTPSubmitAndSignedQuery(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	h, priv, jobs := controllerHTTPFixture(t, now)
	defer jobs.Close()

	cmd := signedIngressCommand(t, now, "op-http-1", priv)
	first := postJSON(t, h.Submit, cmd)
	if first.Code != http.StatusOK {
		t.Fatalf("submit status=%d body=%s", first.Code, first.Body.String())
	}
	var firstResp submitResponse
	if err := json.Unmarshal(first.Body.Bytes(), &firstResp); err != nil {
		t.Fatal(err)
	}
	if firstResp.Duplicate || firstResp.Job.State != "queued" {
		t.Fatalf("unexpected submit response: %+v", firstResp)
	}

	dup := postJSON(t, h.Submit, cmd)
	if dup.Code != http.StatusOK {
		t.Fatalf("duplicate status=%d body=%s", dup.Code, dup.Body.String())
	}
	var dupResp submitResponse
	if err := json.Unmarshal(dup.Body.Bytes(), &dupResp); err != nil {
		t.Fatal(err)
	}
	if !dupResp.Duplicate || dupResp.Job.Command.CommandID != cmd.CommandID {
		t.Fatalf("duplicate polling mismatch: %+v", dupResp)
	}

	q, err := protocol.SignJobQuery(protocol.JobQuery{
		CommandID: cmd.CommandID, AgentID: "HOME-2",
		IssuedAt: now, ExpiresAt: now.Add(time.Minute),
	}, "controller-main", priv)
	if err != nil {
		t.Fatal(err)
	}
	got := postJSON(t, h.Query, q)
	if got.Code != http.StatusOK {
		t.Fatalf("query status=%d body=%s", got.Code, got.Body.String())
	}
	var job protocol.Job
	if err := json.Unmarshal(got.Body.Bytes(), &job); err != nil {
		t.Fatal(err)
	}
	if job.Command.CommandID != cmd.CommandID || job.State != "queued" {
		t.Fatalf("bad queried job: %+v", job)
	}

	result := protocol.JobResult{
		CommandID: cmd.CommandID, OperationID: cmd.Operation.ID, AgentID: "HOME-2",
		Status: "ok", Code: "limited_read_ok", Output: []byte("status"),
		CreatedAt: now.Add(time.Second),
	}
	if err := jobs.Complete(context.Background(), "HOME-2", result, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	q2, err := protocol.SignJobQuery(protocol.JobQuery{
		CommandID: cmd.CommandID, AgentID: "HOME-2",
		IssuedAt: now.Add(time.Second), ExpiresAt: now.Add(time.Minute),
	}, "controller-main", priv)
	if err != nil {
		t.Fatal(err)
	}
	completed := postJSON(t, h.Query, q2)
	if completed.Code != http.StatusOK {
		t.Fatalf("completed query status=%d body=%s", completed.Code, completed.Body.String())
	}
	var completedJob protocol.Job
	if err := json.Unmarshal(completed.Body.Bytes(), &completedJob); err != nil {
		t.Fatal(err)
	}
	if completedJob.State != "completed" || completedJob.Result == nil ||
		completedJob.Result.Code != "limited_read_ok" {
		t.Fatalf("bad completed job: %+v", completedJob)
	}
}

func TestControllerHTTPRejectsTamperedAndExpiredQueries(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	h, priv, jobs := controllerHTTPFixture(t, now)
	defer jobs.Close()

	cmd := signedIngressCommand(t, now, "op-http-2", priv)
	tampered := cmd
	tampered.Operation.Target = "device://HOME-PC/status"
	if rr := postJSON(t, h.Submit, tampered); rr.Code != http.StatusForbidden {
		t.Fatalf("tampered command status=%d body=%s", rr.Code, rr.Body.String())
	}

	q, err := protocol.SignJobQuery(protocol.JobQuery{
		CommandID: "op-http-2", AgentID: "HOME-2",
		IssuedAt: now.Add(-2 * time.Minute), ExpiresAt: now.Add(-time.Minute),
	}, "controller-main", priv)
	if err != nil {
		t.Fatal(err)
	}
	if rr := postJSON(t, h.Query, q); rr.Code != http.StatusForbidden {
		t.Fatalf("expired query status=%d body=%s", rr.Code, rr.Body.String())
	}

	fresh, err := protocol.SignJobQuery(protocol.JobQuery{
		CommandID: "op-http-2", AgentID: "HOME-2",
		IssuedAt: now, ExpiresAt: now.Add(time.Minute),
	}, "controller-main", priv)
	if err != nil {
		t.Fatal(err)
	}
	fresh.AgentID = "HOME-PC"
	if rr := postJSON(t, h.Query, fresh); rr.Code != http.StatusForbidden {
		t.Fatalf("tampered query status=%d body=%s", rr.Code, rr.Body.String())
	}
}
