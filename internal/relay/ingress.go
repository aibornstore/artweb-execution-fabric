package relay

import (
	"context"
	"errors"
	"time"

	"github.com/aibornstore/artweb-execution-fabric/internal/auth"
	"github.com/aibornstore/artweb-execution-fabric/internal/protocol"
)

type Ingress struct {
	Jobs            *JobStore
	CommandVerifier protocol.CommandVerifier
	GrantVerifier   auth.Verifier
	ExpectedAgentID string
	Now             func() time.Time
}

func (i Ingress) Enqueue(ctx context.Context, cmd protocol.Command) (protocol.Job, bool, error) {
	now := time.Now().UTC()
	if i.Now != nil {
		now = i.Now().UTC()
	}
	if i.Jobs == nil {
		return protocol.Job{}, false, errors.New("job store is required")
	}
	if i.ExpectedAgentID == "" {
		return protocol.Job{}, false, errors.New("expected agent id is required")
	}
	if cmd.AgentID != i.ExpectedAgentID {
		return protocol.Job{}, false, errors.New("command targets unexpected agent")
	}
	if err := i.CommandVerifier.Verify(cmd, now); err != nil {
		return protocol.Job{}, false, err
	}
	if err := i.GrantVerifier.VerifyAndAuthorize(now, cmd.Operation, cmd.Grant); err != nil {
		return protocol.Job{}, false, err
	}
	return i.Jobs.Create(ctx, cmd, now)
}
