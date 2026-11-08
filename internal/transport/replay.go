package transport

import (
	"context"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"time"

	"github.com/aibornstore/artweb-execution-fabric/pkg/bcp"
	"github.com/coder/websocket"
)

type Outbox interface {
	PendingOutbox(context.Context, int) ([]bcp.OutboxItem, error)
	MarkSent(context.Context, int64) error
	AckThrough(context.Context, int64) error
}

type Wire interface {
	Write(context.Context, websocket.MessageType, []byte) error
	Read(context.Context) (websocket.MessageType, []byte, error)
	Close(websocket.StatusCode, string) error
}

func ReplayPending(ctx context.Context, outbox Outbox, wire Wire, agentID, sessionID string, limit int) error {
	items, err := outbox.PendingOutbox(ctx, limit)
	if err != nil {
		return err
	}
	for _, item := range items {
		env := bcp.Envelope{
			Version: bcp.ContractVersion, MessageID: item.MessageID, AgentID: agentID, SessionID: sessionID,
			Seq: item.Seq, Type: item.Kind, OperationID: item.OperationID, Body: item.Body, SentAt: time.Now().UTC(),
		}
		data, err := json.Marshal(env)
		if err != nil {
			return err
		}
		if err := wire.Write(ctx, websocket.MessageText, data); err != nil {
			return err
		}
		if err := outbox.MarkSent(ctx, item.Seq); err != nil {
			return err
		}
	}
	return nil
}

func HandleAck(ctx context.Context, outbox Outbox, data []byte, agentID, sessionID string) error {
	var env bcp.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return err
	}
	if env.Version != bcp.ContractVersion || env.Type != "ack" || env.Ack <= 0 {
		return errors.New("invalid ack envelope")
	}
	if env.AgentID != agentID || env.SessionID != sessionID {
		return errors.New("ack identity mismatch")
	}
	return outbox.AckThrough(ctx, env.Ack)
}

func RetryDelay(attempt int, base, max time.Duration, jitterFraction, unit float64) time.Duration {
	if base <= 0 {
		base = time.Second
	}
	if max < base {
		max = 30 * time.Second
	}
	if attempt < 0 {
		attempt = 0
	}
	d := base
	for i := 0; i < attempt && d < max; i++ {
		if d > max/2 {
			d = max
			break
		}
		d *= 2
	}
	if d > max {
		d = max
	}
	if jitterFraction < 0 {
		jitterFraction = 0
	}
	if jitterFraction > 1 {
		jitterFraction = 1
	}
	if unit < 0 {
		unit = 0
	}
	if unit > 1 {
		unit = 1
	}
	factor := 1 + jitterFraction*(unit*2-1)
	out := time.Duration(float64(d) * factor)
	if out < 0 {
		out = 0
	}
	if out > max {
		out = max
	}
	return out
}

type DialFunc func(context.Context) (Wire, error)

type Session struct {
	Dial           DialFunc
	Outbox         Outbox
	AgentID        string
	SessionID      string
	BaseBackoff    time.Duration
	MaxBackoff     time.Duration
	JitterFraction float64
	FlushInterval  time.Duration
	Random         func() float64
}

type readResult struct {
	data []byte
	err  error
}

func (s Session) Run(ctx context.Context) error {
	if s.Dial == nil || s.Outbox == nil || s.AgentID == "" || s.SessionID == "" {
		return errors.New("session configuration incomplete")
	}
	if s.FlushInterval <= 0 {
		s.FlushInterval = time.Second
	}
	if s.Random == nil {
		s.Random = rand.Float64
	}
	attempt := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		wire, err := s.Dial(ctx)
		if err != nil {
			if err := sleepContext(ctx, RetryDelay(attempt, s.BaseBackoff, s.MaxBackoff, s.JitterFraction, s.Random())); err != nil {
				return err
			}
			attempt++
			continue
		}
		err = s.serve(ctx, wire)
		_ = wire.Close(websocket.StatusNormalClosure, "reconnect")
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil && !errors.Is(err, context.Canceled) {
			if err := sleepContext(ctx, RetryDelay(attempt, s.BaseBackoff, s.MaxBackoff, s.JitterFraction, s.Random())); err != nil {
				return err
			}
			attempt++
			continue
		}
		attempt = 0
	}
}

func (s Session) serve(ctx context.Context, wire Wire) error {
	if err := ReplayPending(ctx, s.Outbox, wire, s.AgentID, s.SessionID, 100); err != nil {
		return err
	}
	readCh := make(chan readResult, 1)
	go func() {
		for {
			_, data, err := wire.Read(ctx)
			readCh <- readResult{data: data, err: err}
			if err != nil {
				return
			}
		}
	}()
	ticker := time.NewTicker(s.FlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case rr := <-readCh:
			if rr.err != nil {
				return rr.err
			}
			if err := HandleAck(ctx, s.Outbox, rr.data, s.AgentID, s.SessionID); err != nil {
				return err
			}
		case <-ticker.C:
			if err := ReplayPending(ctx, s.Outbox, wire, s.AgentID, s.SessionID, 100); err != nil {
				return err
			}
		}
	}
}

func sleepContext(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
