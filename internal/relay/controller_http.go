package relay

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/aibornstore/artweb-execution-fabric/internal/protocol"
)

const maxControllerBody = 1 << 20

type ControllerHTTP struct {
	Ingress         Ingress
	Jobs            *JobStore
	QueryVerifier   protocol.JobQueryVerifier
	ExpectedAgentID string
	Now             func() time.Time
}

type submitResponse struct {
	Status    string       `json:"status"`
	Duplicate bool         `json:"duplicate"`
	Job       protocol.Job `json:"job"`
}

func (h ControllerHTTP) Submit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var cmd protocol.Command
	if err := decodeControllerJSON(w, r, &cmd); err != nil {
		return
	}
	job, duplicate, err := h.Ingress.Enqueue(r.Context(), cmd)
	if err != nil {
		http.Error(w, "command rejected", http.StatusForbidden)
		return
	}
	writeControllerJSON(w, http.StatusOK, submitResponse{
		Status: "PASS", Duplicate: duplicate, Job: job,
	})
}

func (h ControllerHTTP) Query(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.Jobs == nil || h.ExpectedAgentID == "" {
		http.Error(w, "controller query unavailable", http.StatusServiceUnavailable)
		return
	}
	var q protocol.JobQuery
	if err := decodeControllerJSON(w, r, &q); err != nil {
		return
	}
	now := time.Now().UTC()
	if h.Now != nil {
		now = h.Now().UTC()
	}
	if err := h.QueryVerifier.Verify(q, now); err != nil {
		http.Error(w, "query rejected", http.StatusForbidden)
		return
	}
	if q.AgentID != h.ExpectedAgentID {
		http.Error(w, "query agent mismatch", http.StatusForbidden)
		return
	}
	job, err := h.Jobs.Get(r.Context(), q.CommandID)
	if errors.Is(err, ErrJobNotFound) {
		http.Error(w, "job not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "job query failed", http.StatusInternalServerError)
		return
	}
	if job.Command.AgentID != q.AgentID {
		http.Error(w, "job agent mismatch", http.StatusForbidden)
		return
	}
	writeControllerJSON(w, http.StatusOK, job)
}

func decodeControllerJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxControllerBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("multiple json values")
		}
		http.Error(w, "invalid json", http.StatusBadRequest)
		return err
	}
	return nil
}

func writeControllerJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
