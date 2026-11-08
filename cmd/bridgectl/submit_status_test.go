package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/aibornstore/artweb-execution-fabric/internal/protocol"
)

type controllerTestState struct {
	mu             sync.Mutex
	job            protocol.Job
	accepted       bool
	submitCount    int
	executionCount int
	commandIDs     []string
}

func completedControllerJob(cmd protocol.Command) protocol.Job {
	now := time.Now().UTC()
	result := protocol.JobResult{
		CommandID: cmd.CommandID, OperationID: cmd.Operation.ID,
		AgentID: cmd.AgentID, Status: "ok", Code: "limited_read_ok",
		Output:    []byte(`{"schema":"host.status/v1","hostname":"HOME-2"}`),
		CreatedAt: now,
	}
	return protocol.Job{
		Command: cmd, State: "completed", Result: &result,
		CreatedAt: now, UpdatedAt: now,
	}
}

func decodeCommand(t *testing.T, r *http.Request) protocol.Command {
	t.Helper()
	var cmd protocol.Command
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		t.Fatalf("decode command: %v", err)
	}
	return cmd
}

func writeSubmitResponse(w http.ResponseWriter, job protocol.Job, duplicate bool) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": "PASS", "duplicate": duplicate, "job": job,
	})
}

func writeQueryResponse(w http.ResponseWriter, st *controllerTestState) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if !st.accepted {
		http.Error(w, "job not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(st.job)
}

func newSignedStatus(t *testing.T) (ed25519.PrivateKey, protocol.Command) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cmd, err := buildStatusCommand("HOME-2", "owner", "controller-main", priv)
	if err != nil {
		t.Fatal(err)
	}
	return priv, cmd
}

func TestSubmitRecoversAcceptedCommandAfterHTTPTimeout(t *testing.T) {
	priv, cmd := newSignedStatus(t)
	st := &controllerTestState{}
	mux := http.NewServeMux()
	mux.HandleFunc("/controller/submit", func(w http.ResponseWriter, r *http.Request) {
		got := decodeCommand(t, r)
		st.mu.Lock()
		st.submitCount++
		st.commandIDs = append(st.commandIDs, got.CommandID)
		if !st.accepted {
			st.accepted = true
			st.executionCount++
			st.job = completedControllerJob(got)
		}
		job := st.job
		st.mu.Unlock()
		time.Sleep(150 * time.Millisecond)
		writeSubmitResponse(w, job, false)
	})
	mux.HandleFunc("/controller/query", func(w http.ResponseWriter, _ *http.Request) {
		writeQueryResponse(w, st)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	base, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := server.Client()
	client.Timeout = 40 * time.Millisecond
	if err := submitSignedCommandWithClient(
		"HOME-2", "controller-main", priv, cmd, client, base, time.Second,
	); err != nil {
		t.Fatal(err)
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.executionCount != 1 || st.submitCount != 1 {
		t.Fatalf("execution=%d submits=%d", st.executionCount, st.submitCount)
	}
}

func TestSubmitRetriesSameCommandAfterTransientFailure(t *testing.T) {
	priv, cmd := newSignedStatus(t)
	st := &controllerTestState{}
	mux := http.NewServeMux()
	mux.HandleFunc("/controller/submit", func(w http.ResponseWriter, r *http.Request) {
		got := decodeCommand(t, r)
		st.mu.Lock()
		st.submitCount++
		call := st.submitCount
		st.commandIDs = append(st.commandIDs, got.CommandID)
		if call > 1 && !st.accepted {
			st.accepted = true
			st.executionCount++
			st.job = completedControllerJob(got)
		}
		job := st.job
		st.mu.Unlock()
		if call == 1 {
			http.Error(w, "temporary", http.StatusServiceUnavailable)
			return
		}
		writeSubmitResponse(w, job, call > 2)
	})
	mux.HandleFunc("/controller/query", func(w http.ResponseWriter, _ *http.Request) {
		writeQueryResponse(w, st)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	base, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := server.Client()
	client.Timeout = 100 * time.Millisecond
	if err := submitSignedCommandWithClient(
		"HOME-2", "controller-main", priv, cmd, client, base, time.Second,
	); err != nil {
		t.Fatal(err)
	}

	st.mu.Lock()
	defer st.mu.Unlock()
	if st.executionCount != 1 || st.submitCount < 2 {
		t.Fatalf("execution=%d submits=%d", st.executionCount, st.submitCount)
	}
	for _, id := range st.commandIDs {
		if id != cmd.CommandID {
			t.Fatalf("retry changed command id: got=%s want=%s", id, cmd.CommandID)
		}
	}
}
