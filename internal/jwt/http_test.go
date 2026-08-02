package jwt

import (
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestNewValidatorFromURL_UsesCAFile(t *testing.T) {
	jwksData, err := os.ReadFile(filepath.Join("..", "..", "testdata", "jwks.json"))
	if err != nil {
		t.Fatalf("failed to read test JWKS: %v", err)
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksData)
	}))
	defer server.Close()

	caPath := filepath.Join(t.TempDir(), "ca.crt")
	caData := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: server.Certificate().Raw,
	})
	if err := os.WriteFile(caPath, caData, 0o600); err != nil {
		t.Fatalf("failed to write test CA: %v", err)
	}

	client, err := NewHTTPClientWithCAFile(caPath)
	if err != nil {
		t.Fatalf("failed to create HTTP client: %v", err)
	}

	validator, err := NewValidatorFromURL(client, server.URL, "https://test-issuer.com", "test-audience")
	if err != nil {
		t.Fatalf("expected JWKS fetch to trust the provided CA, got %v", err)
	}
	defer validator.jwks.EndBackground()
}

func TestNewHTTPClientWithCAFile_PreservesSystemRoots(t *testing.T) {
	systemRoots, err := x509.SystemCertPool()
	if err != nil {
		t.Fatalf("failed to load system roots: %v", err)
	}
	server := httptest.NewTLSServer(nil)
	defer server.Close()

	caPath := filepath.Join(t.TempDir(), "ca.crt")
	caData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(caPath, caData, 0o600); err != nil {
		t.Fatalf("failed to write test CA: %v", err)
	}

	client, err := NewHTTPClientWithCAFile(caPath)
	if err != nil {
		t.Fatalf("failed to create HTTP client: %v", err)
	}

	transport := client.Transport.(*http.Transport)
	if transport.TLSClientConfig.RootCAs == nil {
		t.Fatal("expected HTTP client to have a root CA pool")
	}
	if len(transport.TLSClientConfig.RootCAs.Subjects()) <= len(systemRoots.Subjects()) {
		t.Fatal("expected HTTP client to preserve system roots when appending the CA")
	}
}

func TestNewHTTPClientWithCAFile_RejectsInvalidPEM(t *testing.T) {
	caPath := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(caPath, []byte("not a certificate"), 0o600); err != nil {
		t.Fatalf("failed to write invalid CA: %v", err)
	}

	client, err := NewHTTPClientWithCAFile(caPath)
	if err == nil {
		t.Fatal("expected invalid CA data to return an error")
	}
	if client != nil {
		t.Fatal("expected no HTTP client when CA data is invalid")
	}
}
