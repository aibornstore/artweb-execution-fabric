package transport

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"

	"github.com/aibornstore/artweb-execution-fabric/internal/protocol"
	"github.com/coder/websocket"
)

func AuthenticateAgent(ctx context.Context, c *websocket.Conn, agentID, sessionID, keyID string, privateKey ed25519.PrivateKey) error {
	typ, data, err := c.Read(ctx)
	if err != nil {
		return err
	}
	if typ != websocket.MessageText {
		return errors.New("challenge must be text")
	}
	var ch protocol.ChallengeMessage
	if err := json.Unmarshal(data, &ch); err != nil {
		return err
	}
	if ch.Type != "challenge" {
		return errors.New("expected challenge")
	}
	proof, err := protocol.SignHello(agentID, sessionID, keyID, ch.Challenge, privateKey)
	if err != nil {
		return err
	}
	hello := protocol.HelloMessage{Type: "hello", Proof: proof}
	data, err = json.Marshal(hello)
	if err != nil {
		return err
	}
	if err := c.Write(ctx, websocket.MessageText, data); err != nil {
		return err
	}
	typ, data, err = c.Read(ctx)
	if err != nil {
		return err
	}
	if typ != websocket.MessageText {
		return errors.New("hello_ok must be text")
	}
	var ok protocol.HelloOKMessage
	if err := json.Unmarshal(data, &ok); err != nil {
		return err
	}
	if ok.Type != "hello_ok" || ok.AgentID != agentID || ok.SessionID != sessionID {
		return errors.New("relay hello identity mismatch")
	}
	return nil
}
