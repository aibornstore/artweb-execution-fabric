package relay

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
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

func TestWSS13PinnedHandshakeAndDurableAck(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	ledger, err := OpenLedger(filepath.Join(t.TempDir(), "relay.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		Verifier:           protocol.HelloVerifier{Keys: map[string]ed25519.PublicKey{"home2": pub}},
		Ledger:             ledger,
		ChallengeTTL:       time.Minute,
		ExpectedKeyByAgent: map[string]string{"HOME-2": "home2"},
	}

	server, pin := startPinnedTLS13Server(t, s)
	defer server.Close()
	endpoint := "wss" + strings.TrimPrefix(server.URL, "https") + "/bridge"

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := transport.Dial(ctx, transport.Config{
		Endpoint:         endpoint,
		ConnectTimeout:   2 * time.Second,
		ServerSPKISHA256: pin,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(websocket.StatusNormalClosure, "done")

	if err := transport.AuthenticateAgent(ctx, c, "HOME-2", "s1", "home2", priv); err != nil {
		t.Fatal(err)
	}
	env := bcp.Envelope{
		Version: bcp.ContractVersion, MessageID: "m1", AgentID: "HOME-2", SessionID: "s1",
		Seq: 1, Type: "shadow_receipt", Body: []byte("ok"), SentAt: time.Now().UTC(),
	}
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
	if ack.Type != "ack" || ack.Ack != 1 || ack.AgentID != "HOME-2" || ack.SessionID != "s1" {
		t.Fatalf("bad ack: %+v", ack)
	}
}

func TestPinnedWSSRejectsWrongPin(t *testing.T) {
	ledger, err := OpenLedger(filepath.Join(t.TempDir(), "relay.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	server, _ := startPinnedTLS13Server(t, &Server{Ledger: ledger})
	defer server.Close()
	endpoint := "wss" + strings.TrimPrefix(server.URL, "https") + "/bridge"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, _, err = transport.Dial(ctx, transport.Config{
		Endpoint: endpoint, ConnectTimeout: time.Second, ServerSPKISHA256: strings.Repeat("00", 32),
	})
	if err == nil {
		t.Fatal("wrong SPKI pin must fail")
	}
}

func startPinnedTLS13Server(t *testing.T, handler http.Handler) (*httptest.Server, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)

	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	}
	server.StartTLS()
	return server, hex.EncodeToString(sum[:])
}
