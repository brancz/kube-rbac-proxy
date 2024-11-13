/*
Copyright 2024 the kube-rbac-proxy maintainers. All rights reserved.

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
package kubetest

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/wiremock/go-wiremock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"net/http"
	"time"
)

// Test paths on the mock server
const (
	testWebKeySetURL = "/jwks"
	testDiscoveryURL = "/.well-known/openid-configuration"
)

// Test stubs on the mock server
const (
	WebKeySetStub = "jwks-stub"
	DiscoveryStub = "discovery-stub"
)

// CustomClaims defines additional claims that need to be added to the JWT to test the functionality supported by the
// proxy.
type CustomClaims struct {
	*jwt.Claims
	Username string   `json:"preferred_username,omitempty"`
	Roles    []string `json:"roles,omitempty"`
}

// OIDCTokenConfig contains the data required to create a new token and the associated materials.
type OIDCTokenConfig struct {
	Algorithm      string
	Audience       []string
	ExpiresAt      time.Time
	IssuedAt       time.Time
	Issuer         string
	KeyID          string
	Name           string
	PublishedKeyID *string
	Roles          []string
	Subject        string
	Use            string
	Username       string
}

// NewTokenConfig creates a token
func NewTokenConfig(name string) *OIDCTokenConfig {
	return &OIDCTokenConfig{
		Algorithm: "RS256",
		Audience:  []string{"test-client-id"},
		ExpiresAt: time.Now().Add(30 * time.Minute),
		IssuedAt:  time.Now(),
		Issuer:    "https://mock-issuer.default.svc.cluster.local:8443",
		KeyID:     "01234567890",
		Name:      name,
		Roles:     []string{"metrics"},
		Subject:   "test-client-id",
		Use:       "sign",
		Username:  "test-client",
	}
}

// CreateOIDCIssuer inserts expectations into a mock-server to act as a basic OIDC issuer
func CreateOIDCIssuer(issuerURL, mockServerURL string) Action {
	return func(ctx *ScenarioContext) error {
		mockClient := wiremock.NewClient(mockServerURL)
		stub := wiremock.Get(wiremock.URLPathEqualTo(testDiscoveryURL)).
			WillReturnResponse(wiremock.NewResponse().
				WithJSONBody(map[string]interface{}{
					"issuer":                                issuerURL,
					"authorization_endpoint":                fmt.Sprintf("%s/authorize", issuerURL),
					"token_endpoint":                        fmt.Sprintf("%s/token", issuerURL),
					"jwks_uri":                              fmt.Sprintf("%s%s", issuerURL, testWebKeySetURL),
					"userinfo_endpoint":                     fmt.Sprintf("%s/userinfo", issuerURL),
					"id_token_signing_alg_values_supported": []string{"RS256"},
				}).
				WithStatus(http.StatusOK).
				WithHeader("Content-Type", "application/json")).
			AtPriority(1)
		err := mockClient.StubFor(stub)

		if err != nil {
			return fmt.Errorf("failed to register expections with server: %w", err)
		}

		ctx.AddStub(DiscoveryStub, stub)

		return err
	}
}

// CreateOIDCToken creates the token and associated materials required to execute a test
func CreateOIDCToken(client kubernetes.Interface, token *OIDCTokenConfig, mockServerURL string) Action {
	return func(ctx *ScenarioContext) error {
		// Set up the token materials
		jsonWebKey, idToken, err := createOIDCToken(token.Name, token)
		if err != nil {
			return fmt.Errorf("failed to create OIDC token: %w", err)
		}

		// Store the token in a secret
		secretName := fmt.Sprintf("%s-token", token.Name)
		_, err = client.CoreV1().Secrets(ctx.Namespace).Create(context.TODO(), &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: secretName,
			},
			Data: map[string][]byte{
				"token.jwt": idToken,
			},
		}, metav1.CreateOptions{})
		ctx.AddCleanUp(func() error {
			return client.CoreV1().Secrets(ctx.Namespace).Delete(context.TODO(), secretName, metav1.DeleteOptions{})
		})

		var keysEntry interface{}
		err = json.Unmarshal(jsonWebKey, &keysEntry)
		if err != nil {
			return fmt.Errorf("failed to unmarshal JWK into object: %w", err)
		}

		// Register an expectation with the mock-server for the /jwks endpoint to return the JWK entry
		mockClient := wiremock.NewClient(mockServerURL)
		stub := wiremock.Get(wiremock.URLPathEqualTo(testWebKeySetURL)).
			WillReturnResponse(wiremock.NewResponse().
				WithJSONBody(map[string]interface{}{
					"keys": []interface{}{keysEntry},
				}).
				WithStatus(http.StatusOK).
				WithHeader("Content-Type", "application/json")).
			AtPriority(1)
		err = mockClient.StubFor(stub)
		if err != nil {
			return fmt.Errorf("failed to register /jwks expectations with mock-issuer: %w", err)
		}

		ctx.AddStub(WebKeySetStub, stub)
		return err
	}
}

// createOIDCToken is a private utility that is capable of create a JWT and its associated JWK entry
func createOIDCToken(name string, token *OIDCTokenConfig) ([]byte, []byte, error) {
	// Set up the correct token type
	signerOptions := jose.SignerOptions{}
	signerOptions.WithType("JWT")

	// Create a self-signed CA cert that can sign the token
	cert, key, err := createSelfSignedCA(fmt.Sprintf("%s-token-signer", name))
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.SignatureAlgorithm(token.Algorithm),
		Key:       jose.JSONWebKey{Key: key, KeyID: token.KeyID},
	}, &signerOptions)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create jwt signer: %s", err)
	}

	builder := jwt.Signed(signer)

	claims := jwt.Claims{
		Issuer:   token.Issuer,
		Subject:  token.Subject,
		IssuedAt: jwt.NewNumericDate(token.IssuedAt),
		Expiry:   jwt.NewNumericDate(token.ExpiresAt),
		Audience: token.Audience,
	}

	customClaims := CustomClaims{
		Claims:   &claims,
		Username: token.Username,
		Roles:    token.Roles,
	}

	// Build the signed token
	serializedToken, err := builder.Claims(customClaims).Serialize()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to serialize token: %s", err)
	}

	// Build the corresponding JWK object for the signer
	x5tSHA1 := sha1.Sum(cert.Raw)
	x5tSHA256 := sha256.Sum256(cert.Raw)

	keyID := token.KeyID
	if token.PublishedKeyID != nil {
		keyID = *token.PublishedKeyID
	}

	jwk := jose.JSONWebKey{
		Key:                         cert.PublicKey,
		KeyID:                       keyID,
		Algorithm:                   token.Algorithm,
		Use:                         token.Use,
		Certificates:                []*x509.Certificate{cert},
		CertificateThumbprintSHA1:   x5tSHA1[:],
		CertificateThumbprintSHA256: x5tSHA256[:],
	}

	marshaledJWK, err := jwk.MarshalJSON()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal JWK: %s", err)
	}

	return marshaledJWK, []byte(serializedToken), nil
}
