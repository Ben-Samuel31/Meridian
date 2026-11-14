package main

import (
	"net"
	"strings"
	"testing"
	"time"
)

func TestOriginAllowed(t *testing.T) {
	cases := []struct {
		origin string
		want   bool
	}{
		{"http://meridian.localhost:5173", true},
		{"http://localhost:5173", true},
		{"http://localhost:5174", false},
		{"http://evil.example", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := originAllowed(tc.origin, defaultCORSOrigins); got != tc.want {
			t.Errorf("originAllowed(%q) = %v, want %v", tc.origin, got, tc.want)
		}
	}
	if !originAllowed("https://meridian.example.com", " https://meridian.example.com/ , http://localhost:5173") {
		t.Error("expected whitespace and trailing slash in allowlist entries to be ignored")
	}
}

func TestSLOState(t *testing.T) {
	cases := []struct {
		name          string
		total, passed int
		target        float64
		want          string
	}{
		{"no runs", 0, 0, 99, "no_data"},
		{"all passing", 100, 100, 99, "on_track"},
		{"budget mostly left", 100, 99, 95, "on_track"},
		{"exactly 20% budget left", 100, 96, 95, "on_track"},
		{"under 20% budget left", 100, 91, 90, "at_risk"},
		{"budget exactly spent", 100, 95, 95, "at_risk"},
		{"budget exceeded", 100, 94, 95, "breached"},
	}
	for _, tc := range cases {
		if _, _, got := sloState(tc.total, tc.passed, tc.target); got != tc.want {
			t.Errorf("%s: sloState(%d,%d,%v) = %q, want %q", tc.name, tc.total, tc.passed, tc.target, got, tc.want)
		}
	}
}

func TestFillBuckets(t *testing.T) {
	now := time.Date(2026, 11, 14, 12, 30, 0, 0, time.UTC)
	got := fillBuckets(map[int][2]int{0: {3, 1}, 23: {0, 2}}, now)
	if len(got) != overviewBucketCount {
		t.Fatalf("got %d buckets, want %d", len(got), overviewBucketCount)
	}
	if last := got[len(got)-1]; last.Passed != 3 || last.Failed != 1 || !last.At.Equal(now.Add(-time.Hour)) {
		t.Errorf("most recent bucket = %+v", last)
	}
	if first := got[0]; first.Failed != 2 || !first.At.Equal(now.Add(-24*time.Hour)) {
		t.Errorf("oldest bucket = %+v", first)
	}
	if mid := got[10]; mid.Passed != 0 || mid.Failed != 0 {
		t.Errorf("empty hour should be zero, got %+v", mid)
	}
	if empty := fillBuckets(nil, now); len(empty) != overviewBucketCount {
		t.Errorf("nil counts should still yield %d buckets", overviewBucketCount)
	}
}

func TestMatchesShape(t *testing.T) {
	data := map[string]any{"user": map[string]any{"id":"u_1","active":true}, "count": float64(3)}
	if !matchesShape(data, map[string]any{"user":map[string]any{"id":"string","active":"boolean"},"count":"number"}) { t.Fatal("expected matching shape") }
	if matchesShape(data, map[string]any{"missing":"string"}) { t.Fatal("missing field must fail") }
}

func TestAssertions(t *testing.T) {
	data := map[string]any{"user":map[string]any{"id":"u_1","score":float64(9)}}
	for _, tc := range []struct{ a Assertion; want bool }{
		{Assertion{"user.id","non_empty",nil},true}, {Assertion{"user.none","exists",nil},false},
		{Assertion{"user.id","equals","u_1"},true}, {Assertion{"user.score","greater_than",5},true},
	} { v,ok:=jsonPath(data,tc.a.Field); if got:=assertionOK(v,ok,tc.a); got!=tc.want { t.Fatalf("%+v: got %v",tc.a,got) } }
}

func TestBlockedOutboundAddresses(t *testing.T) {
	for _, value := range []string{"127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.169.254", "::1", "fe80::1", "224.0.0.1"} {
		if !isBlockedIP(net.ParseIP(value)) { t.Fatalf("expected %s to be blocked", value) }
	}
	for _, value := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"} {
		if isBlockedIP(net.ParseIP(value)) { t.Fatalf("expected %s to be allowed", value) }
	}
}

func TestAlertWebhookEncryptionAndMasking(t *testing.T) {
	app := &App{cfg: Config{AlertWebhookEncryptionKey: "test-only-key"}}
	plain := "https://hooks.example.test/services/very-sensitive-token"
	ciphertext, err := app.encryptAlertWebhook(plain)
	if err != nil { t.Fatal(err) }
	if ciphertext == plain || !strings.HasPrefix(ciphertext, "enc:v1:") { t.Fatal("webhook was not encrypted") }
	decoded, err := app.decryptAlertWebhook(ciphertext)
	if err != nil || decoded != plain { t.Fatalf("decrypt failed: %v, %q", err, decoded) }
	if hint := alertWebhookHint(plain); hint != "hooks.example.test" { t.Fatalf("unsafe hint: %q", hint) }
}

func TestMFASecretEncryptionAndTOTP(t *testing.T) {
	app := &App{cfg: Config{MFAEncryptionKey: "test-mfa-key"}}
	secret := "JBSWY3DPEHPK3PXP"
	ciphertext, err := app.encryptMFASecret(secret)
	if err != nil || ciphertext == secret { t.Fatalf("MFA secret was not encrypted: %v", err) }
	decoded, err := app.decryptMFASecret(ciphertext)
	if err != nil || decoded != secret { t.Fatalf("MFA secret decrypt failed: %v", err) }
	code, ok := totpCode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", time.Unix(59, 0))
	if !ok || code != "287082" { t.Fatalf("unexpected TOTP code: %q", code) }
}

func TestOIDCConfigurationRequiresCompleteProvider(t *testing.T) {
	app := &App{cfg: Config{OIDCAuthURL:"https://id.example/authorize", OIDCTokenURL:"https://id.example/token", OIDCUserInfoURL:"https://id.example/userinfo", OIDCClientID:"client", OIDCClientSecret:"secret", OIDCRedirectURL:"https://meridian.example/auth/oidc/callback"}}
	if !app.oidcEnabled() { t.Fatal("complete OIDC config should be enabled") }
	app.cfg.OIDCClientSecret = ""
	if app.oidcEnabled() { t.Fatal("incomplete OIDC config must be disabled") }
}
