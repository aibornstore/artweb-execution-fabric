package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

const (
	privateName = "agent.ed25519"
	publicName  = "agent.ed25519.pub"
)

type Pair struct {
	KeyID   string
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

func Paths(dir string) (privatePath, publicPath string) {
	return filepath.Join(dir, privateName), filepath.Join(dir, publicName)
}

func Ensure(dir, keyID string) (Pair, bool, error) {
	if dir == "" || keyID == "" {
		return Pair{}, false, errors.New("identity dir and key id are required")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return Pair{}, false, err
	}
	privPath, pubPath := Paths(dir)
	_, privErr := os.Stat(privPath)
	_, pubErr := os.Stat(pubPath)
	if privErr == nil || pubErr == nil {
		if privErr != nil || pubErr != nil {
			return Pair{}, false, errors.New("partial identity key pair")
		}
		pair, err := Load(dir, keyID)
		return pair, false, err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Pair{}, false, err
	}
	if err := writeExclusive(privPath, encode(priv), 0600); err != nil {
		return Pair{}, false, err
	}
	if err := writeExclusive(pubPath, encode(pub), 0644); err != nil {
		_ = os.Remove(privPath)
		return Pair{}, false, err
	}
	return Pair{KeyID: keyID, Public: pub, Private: priv}, true, nil
}

func Load(dir, keyID string) (Pair, error) {
	privPath, pubPath := Paths(dir)
	privRaw, err := os.ReadFile(privPath)
	if err != nil {
		return Pair{}, err
	}
	priv, err := decodePrivate(privRaw)
	if err != nil {
		return Pair{}, err
	}
	pub, err := ReadPublicFile(pubPath)
	if err != nil {
		return Pair{}, err
	}
	derived := priv.Public().(ed25519.PublicKey)
	if !derived.Equal(pub) {
		return Pair{}, errors.New("identity key pair mismatch")
	}
	return Pair{KeyID: keyID, Public: pub, Private: priv}, nil
}

func ReadPublicFile(path string) (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("invalid public identity key")
	}
	return ed25519.PublicKey(b), nil
}

func decodePrivate(raw []byte) (ed25519.PrivateKey, error) {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(b) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid private identity key")
	}
	return ed25519.PrivateKey(b), nil
}

func encode(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func writeExclusive(path, value string, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err = f.WriteString(value + "\n"); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
