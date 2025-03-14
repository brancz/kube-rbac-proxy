/*
Copyright 2025 the kube-rbac-proxy maintainers All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package authn

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// newTestOIDCIssuer creates an HTTPS test server serving minimal OIDC discovery and JWKS endpoints.
func newTestOIDCIssuer() *httptest.Server {
	var ts *httptest.Server
	ts = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			// Use the test server's URL as issuer and JWKS URI.
			fmt.Fprintf(w, `{"issuer": "%s", "jwks_uri": "%s/jwks"}`, ts.URL, ts.URL)
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"keys": []}`)
		default:
			http.NotFound(w, r)
		}
	}))
	return ts
}

func TestNewOIDCAuthenticator(t *testing.T) {
	// Create a dummy OIDC issuer (HTTPS).
	ts := newTestOIDCIssuer()
	defer ts.Close()

	// Override the default transport to skip TLS verification.
	// This is needed because ts uses a self-signed certificate.
	// This should be legit for testing purpose, even with parallel test cases run at the same time.
	origTransport := http.DefaultTransport
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	defer func() {
		http.DefaultTransport = origTransport
	}()

	// common dummy configuration values.
	baseConfig := OIDCConfig{
		IssuerURL:            ts.URL,
		ClientID:             "test-client",
		UsernameClaim:        "email",
		UsernamePrefix:       "",
		GroupsClaim:          "groups",
		GroupsPrefix:         "",
		SupportedSigningAlgs: []string{"RS256"},
	}

	t.Run("EmptyCAFile", func(t *testing.T) {
		// CAFile is empty; the authenticator should default to using the host's trust store.
		config := baseConfig
		config.CAFile = ""

		auth, err := NewOIDCAuthenticator(context.Background(), &config)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if auth.dynamicClientCA != nil {
			t.Errorf("expected dynamicClientCA to be nil when CAFile is empty, got non-nil")
		}
	})

	t.Run("ValidCAFile", func(t *testing.T) {
		// Extract the test server's certificate and write it to a temporary file.
		if ts.TLS == nil || len(ts.TLS.Certificates) == 0 {
			t.Fatal("test server does not have a TLS certificate")
		}
		certBytes := ts.TLS.Certificates[0].Certificate[0]
		validCAPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})

		tmpFile, err := os.CreateTemp("", "test-ca-*.pem")
		if err != nil {
			t.Fatalf("failed to create temporary file: %v", err)
		}
		defer os.Remove(tmpFile.Name())

		if _, err = tmpFile.Write(validCAPEM); err != nil {
			t.Fatalf("failed to write certificate to temporary file: %v", err)
		}
		tmpFile.Close()

		config := baseConfig
		config.CAFile = tmpFile.Name()

		auth, err := NewOIDCAuthenticator(context.Background(), &config)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if auth.dynamicClientCA == nil {
			t.Errorf("expected dynamicClientCA to be non-nil when a valid CAFile is provided")
		}
	})

	t.Run("InvalidCAFile", func(t *testing.T) {
		config := baseConfig
		config.CAFile = "non-existent-file.pem"

		_, err := NewOIDCAuthenticator(context.Background(), &config)
		if err == nil {
			t.Errorf("expected error when using an invalid CAFile, got nil")
		}
	})
}
