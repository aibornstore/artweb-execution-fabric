package relay

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/aibornstore/artweb-execution-fabric/internal/protocol"
	"github.com/aibornstore/artweb-execution-fabric/pkg/bcp"
	"github.com/coder/websocket"
)

type Server struct {
	Verifier           protocol.HelloVerifier
	Ledger             *Ledger
	Jobs               *JobStore
	ChallengeTTL       time.Duration
	JobLease           time.Duration
	JobPollInterval    time.Duration
	ExpectedKeyByAgent map[string]string
}

type authenticatedPeer struct {
	AgentID   string
	SessionID string
	KeyID     string
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/bridge" {
		http.NotFound(w, r)
		return
	}
	if s.Ledger == nil {
		http.Error(w, "relay unavailable", http.StatusServiceUnavailable)
		return
	}
	c, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer c.Close(websocket.StatusInternalError, "relay closed")

	handshakeCtx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	peer, err := s.handshake(handshakeCtx, c)
	cancel()
	if err != nil {
		_ = c.Close(websocket.StatusPolicyViolation, "handshake failed")
		return
	}
	if err := s.loop(r.Context(), c, peer); err != nil {
		_ = c.Close(websocket.StatusPolicyViolation, "protocol error")
		return
	}
	_ = c.Close(websocket.StatusNormalClosure, "done")
}

func (s *Server) handshake(ctx context.Context, c *websocket.Conn) (authenticatedPeer, error) {
	ttl := s.ChallengeTTL
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	challenge, err := protocol.NewChallenge(time.Now().UTC(), ttl)
	if err != nil {
		return authenticatedPeer{}, err
	}
	msg := protocol.ChallengeMessage{Type: "challenge", Challenge: challenge}
	data, _ := json.Marshal(msg)
	if err := c.Write(ctx, websocket.MessageText, data); err != nil {
		return authenticatedPeer{}, err
	}
	typ, data, err := c.Read(ctx)
	if err != nil {
		return authenticatedPeer{}, err
	}
	if typ != websocket.MessageText {
		return authenticatedPeer{}, errors.New("hello must be text")
	}
	var hello protocol.HelloMessage
	if err := json.Unmarshal(data, &hello); err != nil {
		return authenticatedPeer{}, err
	}
	if hello.Type != "hello" {
		return authenticatedPeer{}, errors.New("expected hello")
	}
	if err := s.Verifier.Verify(challenge, hello.Proof); err != nil {
		return authenticatedPeer{}, err
	}
	if len(s.ExpectedKeyByAgent) != 0 {
		expectedKey, ok := s.ExpectedKeyByAgent[hello.Proof.AgentID]
		if !ok || expectedKey != hello.Proof.KeyID {
			return authenticatedPeer{}, errors.New("agent identity is not bound to signing key")
		}
	}
	peer := authenticatedPeer{
		AgentID:   hello.Proof.AgentID,
		SessionID: hello.Proof.SessionID,
		KeyID:     hello.Proof.KeyID,
	}
	ok := protocol.HelloOKMessage{Type: "hello_ok", AgentID: peer.AgentID, SessionID: peer.SessionID}
	data, _ = json.Marshal(ok)
	if err := c.Write(ctx, websocket.MessageText, data); err != nil {
		return authenticatedPeer{}, err
	}
	return peer, nil
}

func (s *Server) loop(ctx context.Context, c *websocket.Conn, peer authenticatedPeer) error {
	for {
		typ, data, err := c.Read(ctx)
		if err != nil {
			return err
		}
		if typ != websocket.MessageText {
			return errors.New("envelope must be text")
		}
		var env bcp.Envelope
		if err := json.Unmarshal(data, &env); err != nil {
			return err
		}
		if env.Version != bcp.ContractVersion {
			return errors.New("contract version mismatch")
		}
		if env.AgentID != peer.AgentID || env.SessionID != peer.SessionID {
			return errors.New("envelope identity does not match authenticated peer")
		}
		ack, err := s.Ledger.Record(env)
		if err != nil {
			return err
		}
		ackEnv := bcp.Envelope{
			Version: bcp.ContractVersion, MessageID: "ack:" + env.MessageID,
			AgentID: peer.AgentID, SessionID: peer.SessionID, Ack: ack, Type: "ack", SentAt: time.Now().UTC(),
		}
		out, _ := json.Marshal(ackEnv)
		if err := c.Write(ctx, websocket.MessageText, out); err != nil {
			return err
		}
	}
}

type workerReadResult struct {
	typ  websocket.MessageType
	data []byte
	err  error
}

func (s *Server) ServeWorkerHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/worker" {
		http.NotFound(w, r)
		return
	}
	if s.Ledger == nil || s.Jobs == nil {
		http.Error(w, "worker relay unavailable", http.StatusServiceUnavailable)
		return
	}
	c, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer c.Close(websocket.StatusInternalError, "worker relay closed")

	handshakeCtx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	peer, err := s.handshake(handshakeCtx, c)
	cancel()
	if err != nil {
		_ = c.Close(websocket.StatusPolicyViolation, "handshake failed")
		return
	}
	if err := s.workerLoop(r.Context(), c, peer); err != nil {
		_ = c.Close(websocket.StatusPolicyViolation, "worker protocol error")
		return
	}
	_ = c.Close(websocket.StatusNormalClosure, "done")
}

func (s *Server) workerLoop(ctx context.Context, c *websocket.Conn, peer authenticatedPeer) error {
	lease := s.JobLease
	if lease <= 0 {
		lease = 30 * time.Second
	}
	interval := s.JobPollInterval
	if interval <= 0 {
		interval = time.Second
	}

	readCh := make(chan workerReadResult, 1)
	go func() {
		for {
			typ, data, err := c.Read(ctx)
			select {
			case readCh <- workerReadResult{typ: typ, data: data, err: err}:
			case <-ctx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()

	sendNext := func() error {
		job, err := s.Jobs.LeaseNext(ctx, peer.AgentID, time.Now().UTC(), lease)
		if err != nil {
			return err
		}
		if job == nil {
			return nil
		}
		msg := protocol.JobMessage{Type: "job", Job: *job}
		data, err := json.Marshal(msg)
		if err != nil {
			return err
		}
		return c.Write(ctx, websocket.MessageText, data)
	}

	if err := sendNext(); err != nil {
		return err
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case rr := <-readCh:
			if rr.err != nil {
				return rr.err
			}
			if rr.typ != websocket.MessageText {
				return errors.New("worker envelope must be text")
			}
			var env bcp.Envelope
			if err := json.Unmarshal(rr.data, &env); err != nil {
				return err
			}
			if env.Version != bcp.ContractVersion {
				return errors.New("worker contract version mismatch")
			}
			if env.AgentID != peer.AgentID || env.SessionID != peer.SessionID {
				return errors.New("worker envelope identity mismatch")
			}
			switch env.Type {
			case "job_result", "limited_exec_receipt", "shadow_receipt", "shadow_canary":
			default:
				return errors.New("unexpected worker envelope type")
			}
			var jobResult *protocol.JobResult
			if env.Type == "job_result" {
				var result protocol.JobResult
				if err := json.Unmarshal(env.Body, &result); err != nil {
					return err
				}
				if result.AgentID != peer.AgentID {
					return errors.New("job result identity mismatch")
				}
				if env.OperationID == "" || env.OperationID != result.OperationID {
					return errors.New("job result envelope operation mismatch")
				}
				jobResult = &result
			}
			ack, err := s.Ledger.Record(env)
			if err != nil {
				return err
			}
			if jobResult != nil {
				if err := s.Jobs.Complete(ctx, peer.AgentID, *jobResult, time.Now().UTC()); err != nil {
					return err
				}
			}
			ackEnv := bcp.Envelope{
				Version: bcp.ContractVersion, MessageID: "ack:" + env.MessageID,
				AgentID: peer.AgentID, SessionID: peer.SessionID,
				Ack: ack, Type: "ack", SentAt: time.Now().UTC(),
			}
			out, _ := json.Marshal(ackEnv)
			if err := c.Write(ctx, websocket.MessageText, out); err != nil {
				return err
			}
		case <-ticker.C:
			if err := sendNext(); err != nil {
				return err
			}
		}
	}
}
