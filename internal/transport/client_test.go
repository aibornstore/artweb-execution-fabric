package transport

import "testing"

func TestValidateEndpoint(t *testing.T) {
	ok := []string{"wss://relay.example.com/ws", "wss://relay.example.com:443/ws"}
	for _, s := range ok {
		if _, err := ValidateEndpoint(s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
	bad := []string{"ws://relay.example.com/ws", "https://relay.example.com/ws", "wss://u:p@relay.example.com/ws", "wss://relay.example.com/ws?token=x", "wss://relay.example.com/ws#x", "wss:///ws"}
	for _, s := range bad {
		if _, err := ValidateEndpoint(s); err == nil {
			t.Fatalf("expected reject: %s", s)
		}
	}
}

func TestValidateExternalPinPolicy(t *testing.T) {
	if err := ValidateExternalPinPolicy("wss://127.0.0.1:8443/bridge", ""); err != nil {
		t.Fatalf("loopback should allow CA-only/no pin test path: %v", err)
	}
	if err := ValidateExternalPinPolicy("wss://localhost:8443/bridge", ""); err != nil {
		t.Fatalf("localhost should allow no pin: %v", err)
	}
	if err := ValidateExternalPinPolicy("wss://relay.example.com/bridge", ""); err == nil {
		t.Fatal("external endpoint without pin must fail closed")
	}
	if err := ValidateExternalPinPolicy("wss://relay.example.com/bridge", "deadbeef"); err != nil {
		t.Fatalf("policy only requires a non-empty pin; Dial validates format: %v", err)
	}
}
