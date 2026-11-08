package identity

import (
	"os"
	"testing"
)

func TestEnsureLoadAndPartialFailClosed(t *testing.T) {
	dir := t.TempDir()
	first, created, err := Ensure(dir, "k1")
	if err != nil || !created {
		t.Fatalf("first created=%v err=%v", created, err)
	}
	second, created, err := Ensure(dir, "k1")
	if err != nil || created {
		t.Fatalf("second created=%v err=%v", created, err)
	}
	if !first.Public.Equal(second.Public) || !first.Private.Equal(second.Private) {
		t.Fatal("identity changed across Ensure")
	}
	priv, pub := Paths(dir)
	if _, err := os.Stat(priv); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPublicFile(pub); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(pub); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Ensure(dir, "k1"); err == nil {
		t.Fatal("partial key pair must fail closed")
	}
}
