package risk

import "testing"

func TestCriticalSecret(t *testing.T) {
	got := NewAnalyzer().Analyze("file", ".env.production")
	if got.Level != "critical" {
		t.Fatalf("expected critical, got %+v", got)
	}
}

func TestGitPushHigh(t *testing.T) {
	got := NewAnalyzer().Analyze("shell", "git push origin main")
	if got.Level != "high" {
		t.Fatalf("expected high, got %+v", got)
	}
}
