package worker

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/aibornstore/artweb-execution-fabric/internal/auth"
	"github.com/aibornstore/artweb-execution-fabric/internal/limitedexec"
	"github.com/aibornstore/artweb-execution-fabric/internal/protocol"
	"github.com/aibornstore/artweb-execution-fabric/internal/store"
	"github.com/aibornstore/artweb-execution-fabric/pkg/bcp"
)

type Handler struct {
	AgentID         string
	BootID          string
	AgentVersion    string
	Store           *store.Store
	CommandVerifier protocol.CommandVerifier
	GrantVerifier   auth.Verifier
	Executor        limitedexec.Executor
	Now             func() time.Time
}

func (h Handler) Handle(ctx context.Context, job protocol.Job) protocol.JobResult {
	now := time.Now().UTC()
	if h.Now != nil {
		now = h.Now().UTC()
	}
	cmd := job.Command
	out := protocol.JobResult{
		CommandID: cmd.CommandID, OperationID: cmd.Operation.ID,
		AgentID: h.AgentID, BootID: h.BootID, AgentVersion: h.AgentVersion,
		Status: "rejected", Code: "invalid_command", CreatedAt: now,
	}
	if h.Store == nil || h.AgentID == "" {
		out.Code = "worker_not_configured"
		out.Error = "worker store and agent id are required"
		return out
	}
	if cmd.AgentID != h.AgentID {
		out.Code = "agent_mismatch"
		out.Error = "command targets another agent"
		return out
	}
	if err := h.CommandVerifier.Verify(cmd, now); err != nil {
		out.Code = "command_verify_failed"
		out.Error = err.Error()
		return out
	}
	if err := h.GrantVerifier.VerifyAndAuthorize(now, cmd.Operation, cmd.Grant); err != nil {
		out.Code = "grant_authority_denied"
		out.Error = err.Error()
		return out
	}
	if err := h.ensureGrant(ctx, cmd.Grant); err != nil {
		out.Code = "grant_persist_failed"
		out.Error = err.Error()
		return out
	}

	res, execErr := h.Executor.Execute(ctx, cmd.Operation, cmd.Grant.ID)
	if res.OperationID != "" {
		out.OperationID = res.OperationID
	}
	out.Status = res.Status
	out.Code = res.Code
	out.Output = res.Output
	out.CreatedAt = res.CreatedAt
	if out.CreatedAt.IsZero() {
		out.CreatedAt = now
	}
	if execErr != nil {
		if out.Status == "" {
			out.Status = "error"
		}
		if out.Code == "" {
			out.Code = "limited_exec_error"
		}
		out.Error = execErr.Error()
	}
	return out
}

func (h Handler) ensureGrant(ctx context.Context, want bcp.Grant) error {
	got, err := h.Store.GetGrant(ctx, want.ID)
	if errors.Is(err, store.ErrGrantNotFound) {
		return h.Store.PutGrant(ctx, want)
	}
	if err != nil {
		return err
	}
	if !sameGrant(got, want) {
		return errors.New("grant id conflicts with different signed grant")
	}
	return nil
}

func sameGrant(a, b bcp.Grant) bool {
	if a.ID != b.ID || a.Subject != b.Subject || a.Capability != b.Capability ||
		a.TargetPrefix != b.TargetPrefix || !a.NotBefore.Equal(b.NotBefore) ||
		!a.ExpiresAt.Equal(b.ExpiresAt) || a.OneTime != b.OneTime ||
		a.HighRiskApproved != b.HighRiskApproved ||
		a.BoundOperationID != b.BoundOperationID || a.KeyID != b.KeyID ||
		a.Signature != b.Signature || len(a.Risks) != len(b.Risks) {
		return false
	}
	for i := range a.Risks {
		if a.Risks[i] != b.Risks[i] {
			return false
		}
	}
	return true
}

func (h Handler) EnqueueResult(ctx context.Context, result protocol.JobResult) (int64, error) {
	if h.Store == nil {
		return 0, errors.New("worker store is required")
	}
	body, err := json.Marshal(result)
	if err != nil {
		return 0, err
	}
	return h.Store.EnqueueOutbox(ctx, bcp.OutboxItem{
		MessageID:   "job-result:" + result.CommandID,
		OperationID: result.OperationID,
		Kind:        "job_result",
		Body:        body,
	})
}
