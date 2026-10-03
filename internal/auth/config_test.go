package auth

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	jwtpkg "github.com/portswigger/nats-aws-auth/internal/jwt"
)

func TestLoadConfig(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		valid      bool
	}{
		{"valid", "[[permission]]\nsubject='orders'\nallowed-pub-subjects=['orders.>']\nallowed-sub-subjects=[]", true},
		{"empty", "permission=[]", true},
		{"syntax", "[[permission", false},
		{"unknown", "permissions=[]", false},
		{"missing subject", "[[permission]]", false},
		{"duplicate", "[[permission]]\nsubject='a'\n[[permission]]\nsubject='a'", false},
		{"invalid subject", "[[permission]]\nsubject='a'\nallowed-sub-subjects=['a.>.b']", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			if err := os.WriteFile(path, []byte(tc.text), 0600); err != nil {
				t.Fatal(err)
			}
			_, err := LoadConfig(path)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, error=%v", tc.valid, err)
			}
		})
	}
	if _, err := LoadConfig(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("expected missing file error")
	}
}

func TestDefaultAndAdditionalPermissions(t *testing.T) {
	subject := "system:serviceaccount:orders:app"
	defaults := Permissions{Pub: []string{"orders.>"}, Sub: []string{"_INBOX.>", "_INBOX_orders_app.>", "orders.>"}}
	for _, tc := range []struct {
		name   string
		config *Config
		legacy PermissionsProvider
		want   Permissions
	}{
		{"no blocks", &Config{}, NoServiceAccountPermissions{}, defaults},
		{"unmatched block", &Config{Permissions: []Permission{{Subject: "system:serviceaccount:other:app", Pub: []string{"other.>"}}}}, NoServiceAccountPermissions{}, defaults},
		{"empty matching block", &Config{Permissions: []Permission{{Subject: subject}}}, NoServiceAccountPermissions{}, defaults},
		{"config additions", &Config{Permissions: []Permission{{Subject: subject, Pub: []string{"orders.>", "shared.>"}, Sub: []string{"commands.>"}}}}, NoServiceAccountPermissions{}, Permissions{Pub: []string{"orders.>", "shared.>"}, Sub: []string{"_INBOX.>", "_INBOX_orders_app.>", "orders.>", "commands.>"}}},
		{"legacy additions", &Config{}, &mockPermissionsProvider{pub: []string{"orders.>", "legacy.>"}, sub: []string{"_INBOX.>"}, found: true}, Permissions{Pub: []string{"orders.>", "legacy.>"}, Sub: defaults.Sub}},
		{"both additions", &Config{Permissions: []Permission{{Subject: subject, Pub: []string{"shared.>"}}}}, &mockPermissionsProvider{pub: []string{"shared.>", "legacy.>"}, found: true}, Permissions{Pub: []string{"orders.>", "shared.>", "legacy.>"}, Sub: defaults.Sub}},
		{"missing serviceaccount", &Config{}, &mockPermissionsProvider{found: false}, defaults},
	} {
		t.Run(tc.name, func(t *testing.T) {
			validator := &mockJWTValidator{claims: &jwtpkg.Claims{Subject: subject, Namespace: "untrusted", ServiceAccount: "untrusted", Audience: []string{"nats"}}}
			authorizer := NewConfigAuthorizer(validator, tc.config, tc.legacy, "nats")
			ok, name, perms, err := authorizer.Authorize("token")
			if err != nil || !ok || name != "orders:app" || !reflect.DeepEqual(perms, tc.want) {
				t.Fatalf("ok=%v name=%s permissions=%+v error=%v", ok, name, perms, err)
			}
		})
	}
}

func TestConfigAuthorizerRejectsInvalidIdentity(t *testing.T) {
	validator := &mockJWTValidator{claims: &jwtpkg.Claims{Subject: "invalid"}}
	authorizer := NewConfigAuthorizer(validator, &Config{}, NoServiceAccountPermissions{}, "nats")
	if ok, _, _, err := authorizer.Authorize("token"); ok || err == nil {
		t.Fatal("invalid subject accepted")
	}
	if ok, _, _, err := authorizer.Authorize(""); ok || err == nil {
		t.Fatal("empty token accepted")
	}
	validator.err = jwtpkg.ErrInvalidSignature
	if ok, _, _, err := authorizer.Authorize("token"); ok || err == nil {
		t.Fatal("invalid signature accepted")
	}
}

func TestLoadLegacyPermissionsOption(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte("legacy-serviceaccount-permissions = true\n[[permission]]\nsubject='orders'"), 0600); err != nil {
		t.Fatal(err)
	}
	config, err := LoadConfig(path)
	if err != nil || !config.LegacyServiceAccountPermissions || len(config.Permissions) != 1 {
		t.Fatalf("config: %+v, error: %v", config, err)
	}
}
