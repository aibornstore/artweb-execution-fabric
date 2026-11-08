package worker

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"time"

	"github.com/aibornstore/artweb-execution-fabric/internal/protocol"
	"github.com/aibornstore/artweb-execution-fabric/internal/store"
	"github.com/aibornstore/artweb-execution-fabric/internal/transport"
	"github.com/coder/websocket"
)

type Runtime struct {
	Endpoint       string
	ServerSPKIPin  string
	AgentID        string
	SessionID      string
	KeyID          string
	PrivateKey     ed25519.PrivateKey
	Store          *store.Store
	Handler        Handler
	BaseBackoff    time.Duration
	MaxBackoff     time.Duration
	JitterFraction float64
	Random         func() float64
}

func (r Runtime) Run(ctx context.Context) error {
	if r.Endpoint == "" || r.AgentID == "" || r.SessionID == "" || r.KeyID == "" ||
		len(r.PrivateKey) != ed25519.PrivateKeySize || r.Store == nil {
		return errors.New("worker runtime configuration incomplete")
	}
	attempt := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		sessionErr := r.runOnce(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if sessionErr == nil {
			attempt = 0
		}
		unit := 0.5
		if r.Random != nil {
			unit = r.Random()
		}
		delay := transport.RetryDelay(attempt, r.BaseBackoff, r.MaxBackoff, r.JitterFraction, unit)
		if err := sleepContext(ctx, delay); err != nil {
			return err
		}
		attempt++
	}
}

func (r Runtime) runOnce(ctx context.Context) error {
	conn, _, err := transport.Dial(ctx, transport.Config{
		Endpoint: r.Endpoint, ConnectTimeout: 10 * time.Second,
		ServerSPKISHA256: r.ServerSPKIPin,
	})
	if err != nil {
		return err
	}
	defer conn.Close(websocket.StatusNormalClosure, "worker reconnect")

	if err := transport.AuthenticateAgent(ctx, conn, r.AgentID, r.SessionID, r.KeyID, r.PrivateKey); err != nil {
		return err
	}
	if err := transport.ReplayPending(ctx, r.Store, conn, r.AgentID, r.SessionID, 100); err != nil {
		return err
	}

	for {
		typ, data, err := conn.Read(ctx)
		if err != nil {
			return err
		}
		if typ != websocket.MessageText {
			return errors.New("worker message must be text")
		}
		var header struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(data, &header); err != nil {
			return err
		}
		switch header.Type {
		case "ack":
			if err := transport.HandleAck(ctx, r.Store, data, r.AgentID, r.SessionID); err != nil {
				return err
			}
		case "job":
			var msg protocol.JobMessage
			if err := json.Unmarshal(data, &msg); err != nil {
				return err
			}
			result := r.Handler.Handle(ctx, msg.Job)
			if _, err := r.Handler.EnqueueResult(ctx, result); err != nil {
				return err
			}
			if err := transport.ReplayPending(ctx, r.Store, conn, r.AgentID, r.SessionID, 100); err != nil {
				return err
			}
		default:
			return errors.New("unexpected worker message type")
		}
	}
}

func sleepContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		d = time.Second
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
