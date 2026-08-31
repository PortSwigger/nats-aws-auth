// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 nats-aws-auth contributors

package main

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	jwtvalidator "github.com/portswigger/nats-aws-auth/internal/jwt"
	"k8s.io/client-go/rest"
)

func TestNewJWKSHTTPClient_AuthenticatesToKubernetesAPI(t *testing.T) {
	jwksData, err := os.ReadFile(filepath.Join("..", "..", "testdata", "jwks.json"))
	if err != nil {
		t.Fatalf("failed to read test JWKS: %v", err)
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-service-account-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksData)
	}))
	defer server.Close()

	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("test-service-account-token"), 0o600); err != nil {
		t.Fatalf("failed to write test service account token: %v", err)
	}
	caData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	k8sConfig := &rest.Config{
		Host:            server.URL,
		BearerTokenFile: tokenPath,
		TLSClientConfig: rest.TLSClientConfig{CAData: caData},
	}

	client, err := newJWKSHTTPClient(k8sConfig, server.URL+"/openid/v1/jwks")
	if err != nil {
		t.Fatalf("failed to create authenticated JWKS client: %v", err)
	}
	validator, err := jwtvalidator.NewValidatorFromURL(
		client,
		server.URL+"/openid/v1/jwks",
		"https://test-issuer.com",
		"test-audience",
	)
	if err != nil {
		t.Fatalf("expected authenticated JWKS fetch to succeed, got %v", err)
	}
	if validator == nil {
		t.Fatal("expected a JWT validator")
	}
}

func TestIsKubernetesAPIURL(t *testing.T) {
	tests := []struct {
		name     string
		jwksURL  string
		apiURL   string
		expected bool
	}{
		{name: "service DNS", jwksURL: "https://kubernetes.default.svc/openid/v1/jwks", apiURL: "https://10.0.0.1:443", expected: true},
		{name: "service IP", jwksURL: "https://10.0.0.1:443/openid/v1/jwks", apiURL: "https://10.0.0.1:443", expected: true},
		{name: "public issuer", jwksURL: "https://oidc.eks.example.com/keys", apiURL: "https://10.0.0.1:443", expected: false},
		{name: "lookalike DNS", jwksURL: "https://kubernetes.default.svc.example.com/keys", apiURL: "https://10.0.0.1:443", expected: false},
		{name: "insecure service URL", jwksURL: "http://kubernetes.default.svc/openid/v1/jwks", apiURL: "https://10.0.0.1:443", expected: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isKubernetesAPIURL(test.jwksURL, test.apiURL); got != test.expected {
				t.Fatalf("isKubernetesAPIURL() = %t, expected %t", got, test.expected)
			}
		})
	}
}
