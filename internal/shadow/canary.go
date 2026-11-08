package shadow

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"time"

	"github.com/aibornstore/artweb-execution-fabric/internal/auth"
	"github.com/aibornstore/artweb-execution-fabric/internal/store"
	"github.com/aibornstore/artweb-execution-fabric/pkg/bcp"
)

type Canary struct {
	Store    *store.Store
	Verifier auth.Verifier
	Now      func() time.Time
}

func (c Canary) Observe(ctx context.Context, op bcp.Operation, grantID string) (bcp.ShadowReceipt, error) {
	now := time.Now().UTC()
	if c.Now != nil {
		now = c.Now().UTC()
	}
	r := bcp.ShadowReceipt{
		OperationID: op.ID,
		Decision:    "deny",
		Code:        "shadow_invalid",
		Executed:    false,
		ObservedAt:  now,
	}
	if c.Store == nil {
		return r, errors.New("shadow store is required")
	}
	g, err := c.Store.GetGrant(ctx, grantID)
	if err != nil {
		r.Code = "grant_unavailable"
		_ = c.persist(ctx, r)
		return r, err
	}
	if err := c.Verifier.VerifyAndAuthorize(now, op, g); err != nil {
		r.Code = "authority_denied"
		_ = c.persist(ctx, r)
		return r, err
	}
	// Shadow invariant: authorization can be evaluated, but no provider is called
	// and one-time grants are not consumed by observation.
	r.Decision = "would_proceed"
	r.Code = "shadow_authorized_not_executed"
	if err := c.persist(ctx, r); err != nil {
		return r, err
	}
	return r, nil
}

func (c Canary) persist(ctx context.Context, r bcp.ShadowReceipt) error {
	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
	messageID := "shadow:" + r.OperationID
	_, err = c.Store.EnqueueOutbox(ctx, bcp.OutboxItem{
		MessageID:   messageID,
		OperationID: r.OperationID,
		Kind:        "shadow_receipt",
		Body:        body,
	})
	return err
}

func VerifierFromKey(keyID string, pub ed25519.PublicKey) auth.Verifier {
	return auth.Verifier{Keys: map[string]ed25519.PublicKey{keyID: pub}}
}
