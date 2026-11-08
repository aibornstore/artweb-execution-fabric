package transport

import (
	"testing"
	"time"
)

func TestNewPinnedHTTPClientPolicy(t *testing.T) {
	if _, _, err := NewPinnedHTTPClient("http://relay.example.com:8443", "", time.Second); err == nil {
		t.Fatal("external http controller endpoint must fail")
	}
	if _, _, err := NewPinnedHTTPClient("http://127.0.0.1:8443", "", time.Second); err != nil {
		t.Fatalf("loopback http controller endpoint should be allowed: %v", err)
	}
	if _, _, err := NewPinnedHTTPClient("http://localhost:8443", "", time.Second); err != nil {
		t.Fatalf("localhost http controller endpoint should be allowed: %v", err)
	}
	if _, _, err := NewPinnedHTTPClient("http://127.0.0.1:8443", "abcd", time.Second); err == nil {
		t.Fatal("plaintext loopback controller endpoint must reject SPKI pin")
	}
	if _, _, err := NewPinnedHTTPClient("https://relay.example.com:8443", "", time.Second); err == nil {
		t.Fatal("external controller endpoint without pin must fail")
	}
	if _, _, err := NewPinnedHTTPClient("https://relay.example.com:8443?x=1", "abcd", time.Second); err == nil {
		t.Fatal("query-bearing controller endpoint must fail")
	}
	if _, _, err := NewPinnedHTTPClient("https://localhost:8443", "", time.Second); err != nil {
		t.Fatalf("loopback controller endpoint should allow no pin: %v", err)
	}
	if _, _, err := NewPinnedHTTPClient("https://relay.example.com:8443", "abcd", time.Second); err == nil {
		t.Fatal("malformed SPKI pin must fail")
	}
}
