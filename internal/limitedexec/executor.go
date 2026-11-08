package limitedexec

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/aibornstore/artweb-execution-fabric/internal/auth"
	"github.com/aibornstore/artweb-execution-fabric/internal/store"
	"github.com/aibornstore/artweb-execution-fabric/pkg/bcp"
)

const HostStatusCapability = "host.status@1"

var (
	ErrReadOnlyExecutor      = errors.New("limited executor accepts read risk only")
	ErrUnsupportedCapability = errors.New("unsupported limited-exec capability")
	ErrOperationIncomplete   = errors.New("existing operation has no durable result")
)

type Provider interface {
	Read(context.Context, bcp.Operation) ([]byte, error)
}

type Executor struct {
	Store    *store.Store
	Verifier auth.Verifier
	Provider Provider
	Now      func() time.Time
}

func (e Executor) Execute(ctx context.Context, op bcp.Operation, grantID string) (bcp.Result, error) {
	if e.Store == nil || e.Provider == nil {
		return bcp.Result{}, errors.New("limited executor is not configured")
	}
	if op.Risk != bcp.RiskRead {
		return bcp.Result{}, ErrReadOnlyExecutor
	}
	switch op.Capability {
	case HostStatusCapability, FileReadCapability, SystemInfoCapability, ProcessListCapability, FileStatCapability, FileListCapability, NetworkPingCapability:
	default:
		return bcp.Result{}, ErrUnsupportedCapability
	}
	now := time.Now().UTC()
	if e.Now != nil {
		now = e.Now().UTC()
	}

	grant, err := e.Store.GetGrant(ctx, grantID)
	if err != nil {
		return bcp.Result{}, err
	}
	if err := e.Verifier.VerifyAndAuthorize(now, op, grant); err != nil {
		return bcp.Result{}, err
	}

	created, err := e.Store.BeginOperation(ctx, op)
	if err != nil {
		return bcp.Result{}, err
	}
	if !created {
		r, err := e.Store.GetResult(ctx, op.ID)
		if errors.Is(err, store.ErrResultNotFound) {
			return bcp.Result{}, ErrOperationIncomplete
		}
		if err != nil {
			return bcp.Result{}, err
		}
		// Repair the crash window where the durable result committed but the
		// outbox receipt did not. EnqueueOutbox is semantically idempotent.
		if err := e.persistEvidence(ctx, r); err != nil {
			return bcp.Result{}, err
		}
		return r, nil
	}

	output, providerErr := e.Provider.Read(ctx, op)
	result := bcp.Result{
		OperationID: op.ID,
		Status:      "ok",
		Code:        "limited_read_ok",
		Output:      output,
		CreatedAt:   now,
	}
	if providerErr != nil {
		result.Status = "error"
		result.Code = "limited_read_provider_error"
		result.Output = []byte(providerErr.Error())
	}
	if err := e.Store.Complete(ctx, result); err != nil {
		return bcp.Result{}, err
	}
	if err := e.persistEvidence(ctx, result); err != nil {
		return bcp.Result{}, err
	}
	if providerErr != nil {
		return result, providerErr
	}
	return result, nil
}

func (e Executor) persistEvidence(ctx context.Context, result bcp.Result) error {
	body, err := json.Marshal(result)
	if err != nil {
		return err
	}
	_, err = e.Store.EnqueueOutbox(ctx, bcp.OutboxItem{
		MessageID:   "limited:" + result.OperationID,
		OperationID: result.OperationID,
		Kind:        "limited_exec_receipt",
		Body:        body,
	})
	return err
}

type HostStatusProvider struct {
	calls atomic.Uint32
	Now   func() time.Time
}

type HostStatus struct {
	Schema   string    `json:"schema"`
	Hostname string    `json:"hostname"`
	OS       string    `json:"os"`
	Arch     string    `json:"arch"`
	Observed time.Time `json:"observed_at"`
}

func (p *HostStatusProvider) Read(_ context.Context, op bcp.Operation) ([]byte, error) {
	if op.Capability != HostStatusCapability || op.Risk != bcp.RiskRead {
		return nil, ErrUnsupportedCapability
	}
	p.calls.Add(1)
	hostname, err := os.Hostname()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	if p.Now != nil {
		now = p.Now().UTC()
	}
	return json.Marshal(HostStatus{
		Schema: "host.status/v1", Hostname: hostname,
		OS: runtime.GOOS, Arch: runtime.GOARCH, Observed: now,
	})
}

func (p *HostStatusProvider) Calls() uint32 { return p.calls.Load() }
