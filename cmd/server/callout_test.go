package main

import (
	"errors"
	"testing"

	"github.com/nats-io/jwt/v2"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestLogAuthorizationDeniedIncludesReasonAndClientContext(t *testing.T) {
	core, logs := observer.New(zap.WarnLevel)
	handler := &AuthCalloutHandler{logger: zap.New(core)}
	claims := &jwt.AuthorizationRequestClaims{
		AuthorizationRequest: jwt.AuthorizationRequest{
			Server:   jwt.ServerID{ID: "server-id", Name: "nats-1"},
			UserNkey: "user-nkey",
			ClientInformation: jwt.ClientInformation{
				ID:   42,
				Name: "new-client",
				Host: "10.0.0.8",
				Kind: "Client",
				Type: "nats",
			},
			ConnectOptions: jwt.ConnectOptions{
				Token:   "redacted-token-value",
				Lang:    "go",
				Version: "1.2.3",
			},
		},
	}

	handler.logAuthorizationDenied(claims, errors.New("token validation failed: audience mismatch"))

	entries := logs.All()
	if len(entries) != 1 {
		t.Fatalf("expected one denial log, got %d", len(entries))
	}
	entry := entries[0]
	if entry.Message != "Authorization denied" {
		t.Fatalf("unexpected log message: %q", entry.Message)
	}
	context := entry.ContextMap()
	want := map[string]interface{}{
		"error":             "token validation failed: audience mismatch",
		"server_id":         "server-id",
		"client_id":         uint64(42),
		"client_name":       "new-client",
		"client_language":   "go",
		"client_version":    "1.2.3",
		"auth_method":       "bearer_token",
		"credential_length": int64(len(claims.ConnectOptions.Token)),
	}
	for key, wantValue := range want {
		if got := context[key]; got != wantValue {
			t.Errorf("%s = %#v, want %#v", key, got, wantValue)
		}
	}
	if _, found := context["token"]; found {
		t.Error("denial log must not include the token")
	}
}
