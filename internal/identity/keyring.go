package identity

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const PublicKeyringSchema = "artweb-public-keyring/v1"

type PublicKeyringEntry struct {
	KeyID         string `json:"key_id"`
	PublicKeyFile string `json:"public_key_file"`
}

type PublicKeyring struct {
	Schema string               `json:"schema"`
	Keys   []PublicKeyringEntry `json:"keys"`
}

// LoadPublicKeySet preserves the legacy single-key configuration and
// optionally merges an additive public-only keyring for controller rotation.
// Duplicate key IDs are allowed only when they resolve to the same public key.
func LoadPublicKeySet(primaryKeyID, primaryPublicKeyFile, keyringFile string) (map[string]ed25519.PublicKey, error) {
	keys := make(map[string]ed25519.PublicKey)

	primaryKeyID = strings.TrimSpace(primaryKeyID)
	primaryPublicKeyFile = strings.TrimSpace(primaryPublicKeyFile)
	keyringFile = strings.TrimSpace(keyringFile)

	if (primaryKeyID == "") != (primaryPublicKeyFile == "") {
		return nil, errors.New("primary key id and public key file must be configured together")
	}
	if primaryKeyID != "" {
		pub, err := ReadPublicFile(primaryPublicKeyFile)
		if err != nil {
			return nil, fmt.Errorf("read primary public key: %w", err)
		}
		keys[primaryKeyID] = pub
	}

	if keyringFile != "" {
		raw, err := os.ReadFile(keyringFile)
		if err != nil {
			return nil, fmt.Errorf("read public keyring: %w", err)
		}
		var ring PublicKeyring
		if err := json.Unmarshal(raw, &ring); err != nil {
			return nil, fmt.Errorf("parse public keyring: %w", err)
		}
		if ring.Schema != PublicKeyringSchema {
			return nil, fmt.Errorf("unsupported public keyring schema %q", ring.Schema)
		}
		if len(ring.Keys) == 0 {
			return nil, errors.New("public keyring contains no keys")
		}
		base := filepath.Dir(keyringFile)
		for i, entry := range ring.Keys {
			id := strings.TrimSpace(entry.KeyID)
			p := strings.TrimSpace(entry.PublicKeyFile)
			if id == "" || p == "" {
				return nil, fmt.Errorf("public keyring entry %d is incomplete", i)
			}
			if !filepath.IsAbs(p) {
				p = filepath.Join(base, p)
			}
			pub, err := ReadPublicFile(p)
			if err != nil {
				return nil, fmt.Errorf("read public key %q: %w", id, err)
			}
			if existing, ok := keys[id]; ok {
				if !existing.Equal(pub) {
					return nil, fmt.Errorf("conflicting public key for key id %q", id)
				}
				continue
			}
			keys[id] = pub
		}
	}

	if len(keys) == 0 {
		return nil, errors.New("no trusted public keys configured")
	}
	return keys, nil
}
