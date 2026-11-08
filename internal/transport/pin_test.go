package transport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestDialWithSPKIPin(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		_ = c.Close(websocket.StatusNormalClosure, "ok")
	})
	ts := httptest.NewTLSServer(mux)
	defer ts.Close()
	sum := sha256.Sum256(ts.Certificate().RawSubjectPublicKeyInfo)
	endpoint := "wss" + strings.TrimPrefix(ts.URL, "https") + "/ws"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, _, err := Dial(ctx, Config{Endpoint: endpoint, ServerSPKISHA256: hex.EncodeToString(sum[:])})
	if err != nil {
		t.Fatalf("valid pin: %v", err)
	}
	_ = c.Close(websocket.StatusNormalClosure, "done")
	wrong := sum
	wrong[0] ^= 0xff
	if c, _, err = Dial(ctx, Config{Endpoint: endpoint, ServerSPKISHA256: hex.EncodeToString(wrong[:])}); err == nil {
		_ = c.Close(websocket.StatusNormalClosure, "done")
		t.Fatal("wrong pin must fail")
	}
}
