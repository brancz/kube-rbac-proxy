/*
Copyright 2017 Frederic Branczyk All rights reserved.

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

package e2e

import (
	"fmt"
	"k8s.io/client-go/rest"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes"

	"github.com/brancz/kube-rbac-proxy/test/kubetest"
)

const (
	defaultLocalPort  = 18080
	defaultIssuerPort = 8080
	defaultIssuerName = "mock-issuer"
)

func testOIDC(client kubernetes.Interface, config *rest.Config) kubetest.TestSuite {
	return func(t *testing.T) {
		command := `curl --connect-timeout 5 -v -s -k --fail -H "Authorization: Bearer $(cat /tokens/token.jwt)" https://kube-rbac-proxy.default.svc.cluster.local:8443/metrics`

		expiredToken := kubetest.NewTokenConfig("expired")
		expiredToken.IssuedAt = time.Now().Add(-1 * time.Hour)
		expiredToken.ExpiresAt = time.Now().Add(-10 * time.Minute)

		// Set up the mock-server URL to be a local port forwarded to the internal cluster Pod.
		mockServerURL := fmt.Sprintf("http://localhost:%d", defaultLocalPort)
		defaultIssuer := expiredToken.Issuer

		kubetest.Scenario{
			Name:        "Expired Token",
			Description: "As a client with an expired token my request fails.",
			Given: kubetest.Actions(
				kubetest.CreateClientCerts(client, "client"),
				kubetest.CreateServerCerts(client, "kube-rbac-proxy-server"),
				kubetest.CreateServerCerts(client, "mock-issuer"),
				kubetest.WrapCertsInPKSC12(client, "mock-issuer"),
				kubetest.CreatedManifests(
					client,
					"oidc/mock-issuer.yaml",
					"oidc/mock-issuer-service.yaml",
				),
				kubetest.PodsAreReady(client, 1, "app=mock-issuer"),
				kubetest.CreatePortForwarder(client, config, defaultIssuerName, defaultLocalPort, defaultIssuerPort),
				kubetest.CreateOIDCIssuer(defaultIssuer, mockServerURL),
				kubetest.CreateOIDCToken(client, expiredToken, mockServerURL),
				kubetest.CreatedManifests(
					client,
					"oidc/clusterRole.yaml",
					"oidc/clusterRoleBinding.yaml",
					"oidc/clusterRole-client.yaml",
					"oidc/clusterRoleBinding-client.yaml",
					"oidc/service.yaml",
					"oidc/serviceAccount.yaml",
					"oidc/deployment.yaml",
				),
			),
			When: kubetest.Actions(
				kubetest.PodsAreReady(
					client,
					1,
					"app=kube-rbac-proxy",
				),
				kubetest.ServiceIsReady(
					client,
					"kube-rbac-proxy",
				),
			),
			Then: kubetest.Actions(
				kubetest.ClientFails(
					client,
					command,
					&kubetest.RunOptions{OIDCToken: expiredToken.Name},
				),
				kubetest.VerifyExactly(mockServerURL, kubetest.DiscoveryStub, 1),
				kubetest.VerifyExactly(mockServerURL, kubetest.WebKeySetStub, 0),
			),
		}.Run(t)

		unknownKeyToken := kubetest.NewTokenConfig("unknown-key-id")
		publishedKeyID := unknownKeyToken.KeyID
		unknownKeyToken.PublishedKeyID = &publishedKeyID
		unknownKeyToken.KeyID = "unknown-key-id"

		kubetest.Scenario{
			Name:        "Unknown Key ID Token",
			Description: "As a client with a token signed with an unknown key id my request fails",
			Given: kubetest.Actions(
				kubetest.CreateClientCerts(client, "client"),
				kubetest.CreateServerCerts(client, "kube-rbac-proxy-server"),
				kubetest.CreateServerCerts(client, "mock-issuer"),
				kubetest.WrapCertsInPKSC12(client, "mock-issuer"),
				kubetest.CreatedManifests(
					client,
					"oidc/mock-issuer.yaml",
					"oidc/mock-issuer-service.yaml",
				),
				kubetest.PodsAreReady(client, 1, "app=mock-issuer"),
				kubetest.CreatePortForwarder(client, config, defaultIssuerName, defaultLocalPort, defaultIssuerPort),
				kubetest.CreateOIDCIssuer(defaultIssuer, mockServerURL),
				kubetest.CreateOIDCToken(client, unknownKeyToken, mockServerURL),
				kubetest.CreatedManifests(
					client,
					"oidc/clusterRole.yaml",
					"oidc/clusterRoleBinding.yaml",
					"oidc/clusterRole-client.yaml",
					"oidc/clusterRoleBinding-client.yaml",
					"oidc/service.yaml",
					"oidc/serviceAccount.yaml",
					"oidc/deployment.yaml",
				),
			),
			When: kubetest.Actions(
				kubetest.PodsAreReady(
					client,
					1,
					"app=kube-rbac-proxy",
				),
				kubetest.ServiceIsReady(
					client,
					"kube-rbac-proxy",
				),
			),
			Then: kubetest.Actions(
				kubetest.ClientFails(
					client,
					command,
					&kubetest.RunOptions{OIDCToken: unknownKeyToken.Name},
				),
				kubetest.VerifyExactly(mockServerURL, kubetest.DiscoveryStub, 1),
				kubetest.VerifyExactly(mockServerURL, kubetest.WebKeySetStub, 3),
			),
		}.Run(t)

		unknownUsernameToken := kubetest.NewTokenConfig("unknown-user")
		unknownUsernameToken.Username = "unknown-username"

		kubetest.Scenario{
			Name:        "Unknown Username",
			Description: "As a client with a token for an unknown user my request fails",
			Given: kubetest.Actions(
				kubetest.CreateClientCerts(client, "client"),
				kubetest.CreateServerCerts(client, "kube-rbac-proxy-server"),
				kubetest.CreateServerCerts(client, "mock-issuer"),
				kubetest.WrapCertsInPKSC12(client, "mock-issuer"),
				kubetest.CreatedManifests(
					client,
					"oidc/mock-issuer.yaml",
					"oidc/mock-issuer-service.yaml",
				),
				kubetest.PodsAreReady(client, 1, "app=mock-issuer"),
				kubetest.CreatePortForwarder(client, config, defaultIssuerName, defaultLocalPort, defaultIssuerPort),
				kubetest.CreateOIDCIssuer(defaultIssuer, mockServerURL),
				kubetest.CreateOIDCToken(client, unknownUsernameToken, mockServerURL),
				kubetest.CreatedManifests(
					client,
					"oidc/clusterRole.yaml",
					"oidc/clusterRoleBinding.yaml",
					"oidc/clusterRole-client.yaml",
					"oidc/clusterRoleBinding-client.yaml",
					"oidc/service.yaml",
					"oidc/serviceAccount.yaml",
					"oidc/deployment.yaml",
				),
			),
			When: kubetest.Actions(
				kubetest.PodsAreReady(
					client,
					1,
					"app=kube-rbac-proxy",
				),
				kubetest.ServiceIsReady(
					client,
					"kube-rbac-proxy",
				),
			),
			Then: kubetest.Actions(
				kubetest.ClientFails(
					client,
					command,
					&kubetest.RunOptions{OIDCToken: unknownUsernameToken.Name},
				),
				kubetest.VerifyExactly(mockServerURL, kubetest.DiscoveryStub, 1),
				kubetest.VerifyExactly(mockServerURL, kubetest.WebKeySetStub, 1),
			),
		}.Run(t)

		unknownAudienceToken := kubetest.NewTokenConfig("unknown-audience")
		unknownAudienceToken.Audience = []string{"unknown-audience"}

		kubetest.Scenario{
			Name:        "Unknown Audience",
			Description: "As a client with a token for an unknown audience my request fails",
			Given: kubetest.Actions(
				kubetest.CreateClientCerts(client, "client"),
				kubetest.CreateServerCerts(client, "kube-rbac-proxy-server"),
				kubetest.CreateServerCerts(client, "mock-issuer"),
				kubetest.WrapCertsInPKSC12(client, "mock-issuer"),
				kubetest.CreatedManifests(
					client,
					"oidc/mock-issuer.yaml",
					"oidc/mock-issuer-service.yaml",
				),
				kubetest.PodsAreReady(client, 1, "app=mock-issuer"),
				kubetest.CreatePortForwarder(client, config, defaultIssuerName, defaultLocalPort, defaultIssuerPort),
				kubetest.CreateOIDCIssuer(defaultIssuer, mockServerURL),
				kubetest.CreateOIDCToken(client, unknownAudienceToken, mockServerURL),
				kubetest.CreatedManifests(
					client,
					"oidc/clusterRole.yaml",
					"oidc/clusterRoleBinding.yaml",
					"oidc/clusterRole-client.yaml",
					"oidc/clusterRoleBinding-client.yaml",
					"oidc/service.yaml",
					"oidc/serviceAccount.yaml",
					"oidc/deployment.yaml",
				),
			),
			When: kubetest.Actions(
				kubetest.PodsAreReady(
					client,
					1,
					"app=kube-rbac-proxy",
				),
				kubetest.ServiceIsReady(
					client,
					"kube-rbac-proxy",
				),
			),
			Then: kubetest.Actions(
				kubetest.ClientFails(
					client,
					command,
					&kubetest.RunOptions{OIDCToken: unknownAudienceToken.Name},
				),
				kubetest.VerifyExactly(mockServerURL, kubetest.DiscoveryStub, 1),
				kubetest.VerifyExactly(mockServerURL, kubetest.WebKeySetStub, 0),
			),
		}.Run(t)

		validToken := kubetest.NewTokenConfig("valid")

		kubetest.Scenario{
			Name:        "Valid Token",
			Description: "As a client with a valid token for a known username my request succeeds",
			Given: kubetest.Actions(
				kubetest.CreateClientCerts(client, "client"),
				kubetest.CreateServerCerts(client, "kube-rbac-proxy-server"),
				kubetest.CreateServerCerts(client, "mock-issuer"),
				kubetest.WrapCertsInPKSC12(client, "mock-issuer"),
				kubetest.CreatedManifests(
					client,
					"oidc/mock-issuer.yaml",
					"oidc/mock-issuer-service.yaml",
				),
				kubetest.PodsAreReady(client, 1, "app=mock-issuer"),
				kubetest.CreatePortForwarder(client, config, defaultIssuerName, defaultLocalPort, defaultIssuerPort),
				kubetest.CreateOIDCIssuer(defaultIssuer, mockServerURL),
				kubetest.CreateOIDCToken(client, validToken, mockServerURL),
				kubetest.CreatedManifests(
					client,
					"oidc/clusterRole.yaml",
					"oidc/clusterRoleBinding.yaml",
					"oidc/clusterRole-client.yaml",
					"oidc/clusterRoleBinding-client.yaml",
					"oidc/service.yaml",
					"oidc/serviceAccount.yaml",
					"oidc/deployment.yaml",
				),
			),
			When: kubetest.Actions(
				kubetest.PodsAreReady(
					client,
					1,
					"app=kube-rbac-proxy",
				),
				kubetest.ServiceIsReady(
					client,
					"kube-rbac-proxy",
				),
			),
			Then: kubetest.Actions(
				kubetest.ClientSucceeds(
					client,
					command,
					&kubetest.RunOptions{OIDCToken: validToken.Name},
				),
				kubetest.VerifyExactly(mockServerURL, kubetest.DiscoveryStub, 1),
				kubetest.VerifyExactly(mockServerURL, kubetest.WebKeySetStub, 1),
			),
		}.Run(t)

		groupToken := kubetest.NewTokenConfig("group")

		kubetest.Scenario{
			Name:        "Valid Token Matching A Group Binding",
			Description: "As a client with a valid token with a role matching a group binding my request succeeds",
			Given: kubetest.Actions(
				kubetest.CreateClientCerts(client, "client"),
				kubetest.CreateServerCerts(client, "kube-rbac-proxy-server"),
				kubetest.CreateServerCerts(client, "mock-issuer"),
				kubetest.WrapCertsInPKSC12(client, "mock-issuer"),
				kubetest.CreatedManifests(
					client,
					"oidc/mock-issuer.yaml",
					"oidc/mock-issuer-service.yaml",
				),
				kubetest.PodsAreReady(client, 1, "app=mock-issuer"),
				kubetest.CreatePortForwarder(client, config, defaultIssuerName, defaultLocalPort, defaultIssuerPort),
				kubetest.CreateOIDCIssuer(defaultIssuer, mockServerURL),
				kubetest.CreateOIDCToken(client, groupToken, mockServerURL),
				kubetest.CreatedManifests(
					client,
					"oidc/clusterRole.yaml",
					"oidc/clusterRoleBinding.yaml",
					"oidc/clusterRole-client.yaml",
					"oidc/clusterRoleBinding-group.yaml",
					"oidc/service.yaml",
					"oidc/serviceAccount.yaml",
					"oidc/deployment.yaml",
				),
			),
			When: kubetest.Actions(
				kubetest.PodsAreReady(
					client,
					1,
					"app=kube-rbac-proxy",
				),
				kubetest.ServiceIsReady(
					client,
					"kube-rbac-proxy",
				),
			),
			Then: kubetest.Actions(
				kubetest.ClientSucceeds(
					client,
					command,
					&kubetest.RunOptions{OIDCToken: groupToken.Name},
				),
				kubetest.VerifyExactly(mockServerURL, kubetest.DiscoveryStub, 1),
				kubetest.VerifyExactly(mockServerURL, kubetest.WebKeySetStub, 1),
			),
		}.Run(t)
	}
}
