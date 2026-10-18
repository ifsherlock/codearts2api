package auth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func permanentFixture() map[string]string {
	return map[string]string{
		"auth_type": "aksk", "user_id": "synthetic-user", "user_name": "synthetic-name",
		"domain_id": "synthetic-domain", "access_key_id": "synthetic-access-key",
		"secret_access_key": "synthetic-secret-key", "cloud_dragon_token": "",
		"refresh_token": "", "expiration": "",
	}
}

func writeFixture(t *testing.T, dir string, fields map[string]string) {
	t.Helper()
	raw, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "codearts-synthetic-user.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadDirCredentialTypes(t *testing.T) {
	for _, tt := range []struct {
		name   string
		change func(map[string]string)
		want   int
	}{
		{name: "permanent without token", want: 1},
		{name: "permanent omitted token", change: func(v map[string]string) { delete(v, "cloud_dragon_token") }, want: 1},
		{name: "permanent ignores obsolete expiry", change: func(v map[string]string) { v["expiration"] = "2000-01-01T00:00:00Z" }, want: 1},
		{name: "undeclared empty token skipped", change: func(v map[string]string) { delete(v, "auth_type") }},
		{name: "unknown type empty token skipped", change: func(v map[string]string) { v["auth_type"] = "unknown" }},
		{name: "old token format accepted", change: func(v map[string]string) {
			delete(v, "auth_type")
			delete(v, "domain_id")
			delete(v, "access_key_id")
			delete(v, "secret_access_key")
			v["cloud_dragon_token"] = "synthetic-token"
		}, want: 1},
		{name: "explicit oauth token accepted", change: func(v map[string]string) {
			v["auth_type"] = "oauth"
			v["cloud_dragon_token"] = "synthetic-token"
		}, want: 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			fields := permanentFixture()
			if tt.change != nil {
				tt.change(fields)
			}
			writeFixture(t, dir, fields)
			loaded, err := LoadDir(dir)
			if err != nil || len(loaded) != tt.want {
				t.Fatalf("LoadDir count=%d err=%v, want count=%d", len(loaded), err, tt.want)
			}
			if len(loaded) == 0 {
				return
			}
			token, ak, sk := loaded[0].Credentials()
			if token != fields["cloud_dragon_token"] || ak != fields["access_key_id"] || sk != fields["secret_access_key"] {
				t.Fatal("loading changed credential values")
			}
		})
	}
}

func TestLoadDirRejectsIncompletePermanentCredentials(t *testing.T) {
	for _, field := range []string{"user_id", "user_name", "domain_id", "access_key_id", "secret_access_key"} {
		for _, blank := range []struct {
			name, value string
			missing     bool
		}{
			{name: "missing", missing: true},
			{name: "empty"},
			{name: "whitespace", value: " \t"},
		} {
			t.Run(field+"/"+blank.name, func(t *testing.T) {
				dir := t.TempDir()
				fields := permanentFixture()
				if blank.missing {
					delete(fields, field)
				} else {
					fields[field] = blank.value
				}
				writeFixture(t, dir, fields)
				_, err := LoadDir(dir)
				if err == nil || !strings.Contains(err.Error(), field) || !strings.Contains(err.Error(), "auth_type aksk") {
					t.Fatalf("expected field-specific permanent credential error, got %v", err)
				}
				for _, secret := range []string{"synthetic-access-key", "synthetic-secret-key"} {
					if strings.Contains(err.Error(), secret) {
						t.Fatal("configuration error leaked a credential value")
					}
				}
			})
		}
	}
}

func TestCredentialLifetimeAndRefresh(t *testing.T) {
	past := time.Now().Add(-time.Hour).Format(time.RFC3339)
	soon := time.Now().Add(10 * time.Minute).Format(time.RFC3339)
	for _, tt := range []struct {
		name, kind, expiration string
		expired, soon          bool
	}{
		{name: "permanent empty", kind: "aksk"},
		{name: "permanent expired field", kind: "aksk", expiration: past},
		{name: "permanent soon field", kind: "aksk", expiration: soon},
		{name: "permanent invalid field", kind: "aksk", expiration: "invalid"},
		{name: "legacy expired", expiration: past, expired: true},
		{name: "legacy soon", expiration: soon, soon: true},
		{name: "legacy empty"},
		{name: "legacy invalid", expiration: "invalid"},
		{name: "legacy zero", expiration: time.Time{}.Format(time.RFC3339)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a := &Auth{AuthType: tt.kind, Expiration: tt.expiration, RefreshToken: "synthetic-refresh"}
			if a.Expired() != tt.expired || a.ExpiringSoon(time.Hour) != tt.soon {
				t.Fatal("unexpected expiry classification")
			}
			if tt.kind == "aksk" {
				if !a.ExpiresAt().IsZero() || a.Refresh() != "" || a.ExpiringSoon(time.Duration(1<<63-1)) {
					t.Fatal("permanent credentials entered token expiry or refresh handling")
				}
				if a.Expiration != tt.expiration || a.RefreshToken != "synthetic-refresh" {
					t.Fatal("reading lifetime mutated stored fields")
				}
			} else if a.Refresh() != "synthetic-refresh" {
				t.Fatal("legacy refresh token changed")
			}
		})
	}
}

func TestCredentialPersistence(t *testing.T) {
	for _, kind := range []string{"", "aksk"} {
		t.Run("type="+kind, func(t *testing.T) {
			dir := t.TempDir()
			a := &Auth{
				AuthType: kind, UserID: "synthetic-user", UserName: "synthetic-name", DomainID: "synthetic-domain",
				AccessKeyID: "synthetic-access-key", SecretAccessKey: "synthetic-secret-key",
			}
			if kind == "" {
				a.CloudDragonTok = "synthetic-token"
			}
			if err := SaveNew(dir, a); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(filepath.Join(dir, a.FileName()))
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]any
			if err := json.Unmarshal(raw, &fields); err != nil {
				t.Fatal(err)
			}
			_, hasType := fields["auth_type"]
			if hasType != (kind != "") {
				t.Fatal("auth_type omission compatibility changed")
			}
			if fields["cloud_dragon_token"] != a.CloudDragonTok || fields["expiration"] != "" {
				t.Fatal("persistence fabricated a token or expiration")
			}
			loaded, err := LoadDir(dir)
			if err != nil || len(loaded) != 1 || loaded[0].AuthType != kind {
				t.Fatalf("round trip failed: count=%d err=%v", len(loaded), err)
			}
			if kind == "aksk" {
				if err := loaded[0].UpdateCredentials("replacement", "replacement", "replacement", "2099-01-01T00:00:00Z", "replacement"); err == nil {
					t.Fatal("permanent credentials accepted an OAuth refresh")
				}
				unchanged, err := os.ReadFile(filepath.Join(dir, a.FileName()))
				if err != nil || string(unchanged) != string(raw) {
					t.Fatal("rejected refresh modified the credential file")
				}
			}
		})
	}
}

func TestSaveRejectsIncompletePermanentCredentials(t *testing.T) {
	a := &Auth{AuthType: "aksk", UserID: "synthetic-user"}
	if err := SaveNew(t.TempDir(), a); err == nil || !strings.Contains(err.Error(), "user_name") {
		t.Fatalf("expected missing identity field error, got %v", err)
	}
}
