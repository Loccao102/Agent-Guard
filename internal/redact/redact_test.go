package redact

import (
	"strings"
	"testing"
)

func TestRedactsSecrets(t *testing.T) {
	got := New().String("Authorization: Bearer abc.def.ghi api_key=supersecret")
	if strings.Contains(got, "supersecret") || strings.Contains(got, "abc.def.ghi") {
		t.Fatalf("secret leaked: %s", got)
	}
}
