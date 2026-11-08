package relay

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aibornstore/artweb-execution-fabric/internal/protocol"
	"github.com/aibornstore/artweb-execution-fabric/internal/transport"
	"github.com/aibornstore/artweb-execution-fabric/pkg/bcp"
	"github.com/coder/websocket"
)

func TestRawTCPPassthroughPreservesPinnedRelayTLS(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := OpenLedger(filepath.Join(t.TempDir(), "relay.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		Verifier: protocol.HelloVerifier{
			Keys: map[string]ed25519.PublicKey{"home2": pub},
		},
		Ledger:             ledger,
		ChallengeTTL:       time.Minute,
		ExpectedKeyByAgent: map[string]string{"HOME-2": "home2"},
	}

	target, pin := startPinnedTLS13Server(t, s)
	defer target.Close()

	u, err := url.Parse(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxyAddr, stopProxy := startRawTCPProxy(t, u.Host)
	defer stopProxy()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c, _, err := transport.Dial(ctx, transport.Config{
		Endpoint:         "wss://" + proxyAddr + "/bridge",
		ConnectTimeout:   2 * time.Second,
		ServerSPKISHA256: pin,
	})
	if err != nil {
		t.Fatalf("pinned relay TLS must survive raw TCP passthrough: %v", err)
	}
	defer c.Close(websocket.StatusNormalClosure, "done")

	if err := transport.AuthenticateAgent(ctx, c, "HOME-2", "s1", "home2", priv); err != nil {
		t.Fatal(err)
	}

	env := bcp.Envelope{
		Version:   bcp.ContractVersion,
		MessageID: "raw-tcp-m1",
		AgentID:   "HOME-2",
		SessionID: "s1",
		Seq:       1,
		Type:      "shadow_receipt",
		Body:      []byte("through-raw-tcp"),
		SentAt:    time.Now().UTC(),
	}
	data, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
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
	if ack.Type != "ack" || ack.Ack != 1 || ack.AgentID != "HOME-2" || ack.SessionID != "s1" {
		t.Fatalf("bad proxied ack: %+v", ack)
	}
}

func TestRawTCPPassthroughCannotBypassWrongSPKIPin(t *testing.T) {
	ledger, err := OpenLedger(filepath.Join(t.TempDir(), "relay.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	target, _ := startPinnedTLS13Server(t, &Server{Ledger: ledger})
	defer target.Close()

	u, err := url.Parse(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxyAddr, stopProxy := startRawTCPProxy(t, u.Host)
	defer stopProxy()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, _, err := transport.Dial(ctx, transport.Config{
		Endpoint:         "wss://" + proxyAddr + "/bridge",
		ConnectTimeout:   time.Second,
		ServerSPKISHA256: strings.Repeat("00", 32),
	})
	if err == nil {
		_ = c.Close(websocket.StatusNormalClosure, "unexpected")
		t.Fatal("raw TCP passthrough must not bypass relay SPKI pin")
	}
}

func startRawTCPProxy(t *testing.T, targetAddr string) (string, func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	done := make(chan struct{})

	go func() {
		defer close(done)
		for {
			src, err := ln.Accept()
			if err != nil {
				return
			}
			dst, err := net.DialTimeout("tcp", targetAddr, time.Second)
			if err != nil {
				_ = src.Close()
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer src.Close()
				defer dst.Close()

				copied := make(chan struct{}, 2)
				go func() {
					_, _ = io.Copy(dst, src)
					copied <- struct{}{}
				}()
				go func() {
					_, _ = io.Copy(src, dst)
					copied <- struct{}{}
				}()
				<-copied
			}()
		}
	}()

	return ln.Addr().String(), func() {
		_ = ln.Close()
		<-done
		wg.Wait()
	}
}
