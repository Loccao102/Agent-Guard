package audit

import (
	"path/filepath"
	"testing"
	"time"
)

func TestHashChain(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for _, v := range []string{"git status", "git push"} {
		if err := store.Record(Event{Timestamp: time.Now().UTC(), Agent: "test", Kind: "shell", Value: v, Decision: "allow", Risk: "low", Reason: "test"}); err != nil {
			t.Fatal(err)
		}
	}
	verify, err := store.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if !verify.Valid || verify.Checked != 2 {
		t.Fatalf("unexpected verification: %+v", verify)
	}
}
