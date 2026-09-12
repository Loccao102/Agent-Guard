package signing

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSignVerify(t *testing.T) {
	d := t.TempDir()
	priv, pub := filepath.Join(d, "priv.pem"), filepath.Join(d, "pub.pem")
	file, sig := filepath.Join(d, "pack.yaml"), filepath.Join(d, "pack.sig")
	if err := Generate(priv, pub); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("name: test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := SignFile(file, priv, sig); err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyFile(file, pub, sig)
	if err != nil || !ok {
		t.Fatalf("verify failed: %v %v", ok, err)
	}
}
