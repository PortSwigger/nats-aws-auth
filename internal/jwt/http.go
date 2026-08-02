package jwt

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
)

// NewHTTPClientWithCAFile creates an HTTP client that trusts the system roots
// and the certificates in caPath.
func NewHTTPClientWithCAFile(caPath string) (*http.Client, error) {
	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("failed to load system certificate pool: %w", err)
	}

	caData, err := os.ReadFile(caPath) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("failed to read CA file %q: %w", caPath, err)
	}
	if ok := rootCAs.AppendCertsFromPEM(caData); !ok {
		return nil, fmt.Errorf("failed to parse certificates from CA file %q", caPath)
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	} else {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	}
	transport.TLSClientConfig.RootCAs = rootCAs

	return &http.Client{Transport: transport}, nil
}
