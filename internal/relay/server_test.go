package relay

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aibornstore/artweb-execution-fabric/internal/protocol"
	"github.com/aibornstore/artweb-execution-fabric/internal/transport"
	"github.com/aibornstore/artweb-execution-fabric/pkg/bcp"
	"github.com/coder/websocket"
)

func TestRelayHandshakeAndDurableAck(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := OpenLedger(filepath.Join(t.TempDir(), "relay.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		Verifier: protocol.HelloVerifier{Keys: map[string]ed25519.PublicKey{"home2": pub}},
		Ledger:   ledger, ChallengeTTL: time.Minute,
		ExpectedKeyByAgent: map[string]string{"HOME-2": "home2"},
	}
	ts := httptest.NewServer(s)
	defer ts.Close()
	url := "ws" + strings.TrimPrefix(ts.URL, "http") + "/bridge"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(websocket.StatusNormalClosure, "done")
	if err := transport.AuthenticateAgent(ctx, c, "HOME-2", "s1", "home2", priv); err != nil {
		t.Fatal(err)
	}
	env := bcp.Envelope{Version: bcp.ContractVersion, MessageID: "m1", AgentID: "HOME-2", SessionID: "s1", Seq: 1, Type: "shadow_receipt", Body: []byte("ok"), SentAt: time.Now().UTC()}
	data, _ := json.Marshal(env)
	if err := c.Write(ctx, websocket.MessageText, data); err != nil {
		t.Fatal(err)
	}
	_, ackData, err := c.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var ack bcp.Envelope
	if err := json.Unmarshal(ackData, &ack); err != nil {
		t.Fatal(err)
	}
	if ack.Type != "ack" || ack.Ack != 1 {
		t.Fatalf("bad ack %+v", ack)
	}
}

func TestRelayRejectsEnvelopeIdentitySpoofAfterHandshake(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := OpenLedger(filepath.Join(t.TempDir(), "relay.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		Verifier: protocol.HelloVerifier{Keys: map[string]ed25519.PublicKey{"home2": pub}},
		Ledger:   ledger, ChallengeTTL: time.Minute,
		ExpectedKeyByAgent: map[string]string{"HOME-2": "home2"},
	}
	ts := httptest.NewServer(s)
	defer ts.Close()
	url := "ws" + strings.TrimPrefix(ts.URL, "http") + "/bridge"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(websocket.StatusNormalClosure, "done")
	if err := transport.AuthenticateAgent(ctx, c, "HOME-2", "s1", "home2", priv); err != nil {
		t.Fatal(err)
	}
	spoof := bcp.Envelope{
		Version: bcp.ContractVersion, MessageID: "m-spoof",
		AgentID: "HOME-PC", SessionID: "s1", Seq: 1,
		Type: "shadow_receipt", Body: []byte("spoof"), SentAt: time.Now().UTC(),
	}
	data, _ := json.Marshal(spoof)
	if err := c.Write(ctx, websocket.MessageText, data); err != nil {
		t.Fatal(err)
	}
	_, _, err = c.Read(ctx)
	if err == nil {
		t.Fatal("spoofed envelope identity must close the connection")
	}
}
