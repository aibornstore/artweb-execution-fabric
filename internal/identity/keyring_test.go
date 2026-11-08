package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func writeTestPublicKey(t *testing.T, path string, pub ed25519.PublicKey) {
	t.Helper()
	if err := os.WriteFile(path, []byte(base64.RawURLEncoding.EncodeToString(pub)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadPublicKeySetLegacyOnly(t *testing.T) {
	dir := t.TempDir()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "legacy.pub")
	writeTestPublicKey(t, p, pub)

	keys, err := LoadPublicKeySet("controller-main", p, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || !keys["controller-main"].Equal(pub) {
		t.Fatalf("unexpected legacy key set: %#v", keys)
	}
}

func TestLoadPublicKeySetMergesAdditionalKeyring(t *testing.T) {
	dir := t.TempDir()
	oldPub, _, _ := ed25519.GenerateKey(rand.Reader)
	newPub, _, _ := ed25519.GenerateKey(rand.Reader)
	oldPath := filepath.Join(dir, "old.pub")
	newPath := filepath.Join(dir, "new.pub")
	writeTestPublicKey(t, oldPath, oldPub)
	writeTestPublicKey(t, newPath, newPub)

	ringPath := filepath.Join(dir, "ring.json")
	ring := PublicKeyring{
		Schema: PublicKeyringSchema,
		Keys: []PublicKeyringEntry{{
			KeyID: "controller-homepc-main", PublicKeyFile: "new.pub",
		}},
	}
	raw, _ := json.Marshal(ring)
	if err := os.WriteFile(ringPath, raw, 0600); err != nil {
		t.Fatal(err)
	}

	keys, err := LoadPublicKeySet("controller-main", oldPath, ringPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("want 2 keys, got %d", len(keys))
	}
	if !keys["controller-main"].Equal(oldPub) || !keys["controller-homepc-main"].Equal(newPub) {
		t.Fatal("merged keyring did not preserve both controller keys")
	}
}

func TestLoadPublicKeySetRejectsConflictingDuplicate(t *testing.T) {
	dir := t.TempDir()
	oldPub, _, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	oldPath := filepath.Join(dir, "old.pub")
	otherPath := filepath.Join(dir, "other.pub")
	writeTestPublicKey(t, oldPath, oldPub)
	writeTestPublicKey(t, otherPath, otherPub)

	ringPath := filepath.Join(dir, "ring.json")
	ring := PublicKeyring{
		Schema: PublicKeyringSchema,
		Keys: []PublicKeyringEntry{{
			KeyID: "controller-main", PublicKeyFile: "other.pub",
		}},
	}
	raw, _ := json.Marshal(ring)
	if err := os.WriteFile(ringPath, raw, 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadPublicKeySet("controller-main", oldPath, ringPath); err == nil {
		t.Fatal("expected conflicting duplicate key id to fail closed")
	}
}

func TestLoadPublicKeySetRejectsEmptyConfiguration(t *testing.T) {
	if _, err := LoadPublicKeySet("", "", ""); err == nil {
		t.Fatal("expected empty trusted-key configuration to fail")
	}
}
