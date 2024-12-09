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
package e2e

import (
	"testing"

	"github.com/brancz/kube-rbac-proxy/test/kubetest"
	"k8s.io/client-go/kubernetes"
)

func testIdentityHeaders(client kubernetes.Interface) kubetest.TestSuite {
	return func(t *testing.T) {
		command := `curl --connect-timeout 5 -v -s -k --fail -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" https://kube-rbac-proxy.default.svc.cluster.local:8443/metrics`

		kubetest.Scenario{
			Name: "With x-remote-user",
			Description: `
				Verifies that remote user is set to the service account, when
				upstreama is listening on loopback through a HTTP connection.
			`,

			Given: kubetest.Actions(
				kubetest.CreatedManifests(
					client,
					"identityheaders/default/clusterRole-client.yaml",
					"identityheaders/default/clusterRole.yaml",
					"identityheaders/default/clusterRoleBinding-client.yaml",
					"identityheaders/default/clusterRoleBinding.yaml",
					"identityheaders/default/configmap-nginx.yaml",
					"identityheaders/default/deployment.yaml",
					"identityheaders/default/service.yaml",
					"identityheaders/default/serviceAccount.yaml",
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
				kubetest.ClientLogsContain(
					client,
					command,
					[]string{`< x-remote-user: system:serviceaccount:default:default`},
					nil,
				),
			),
		}.Run(t)

		kubetest.Scenario{
			Name: "With http on no loopback",
			Description: `
					Verifies that the proxy is not able to connect to the remote upstream service,
					if upstream isn't offering TLS, when identity headers are being used.
				`,

			Given: kubetest.Actions(
				kubetest.CreatedManifests(
					client,
					"identityheaders/insecure/clusterRole-client.yaml",
					"identityheaders/insecure/clusterRole.yaml",
					"identityheaders/insecure/clusterRoleBinding-client.yaml",
					"identityheaders/insecure/clusterRoleBinding.yaml",
					"identityheaders/insecure/deployment-upstream.yaml",
					"identityheaders/insecure/service-upstream.yaml",
					"identityheaders/insecure/deployment-proxy.yaml",
					"identityheaders/insecure/service-proxy.yaml",
					"identityheaders/insecure/serviceAccount.yaml",
				),
			),
			When: kubetest.Actions(
				kubetest.PodsAreReady(
					client,
					1,
					"app=nginx",
				),
				kubetest.ServiceIsReady(
					client,
					"nginx",
				),
			),
			Then: kubetest.Actions(
				kubetest.PodIsCrashLoopBackOff(
					client,
					"kube-rbac-proxy",
				),
			),
		}.Run(t)

		kubetest.Scenario{
			Name: "With https on no loopback",
			Description: `
					Verifies that the proxy is able to connect to the remote upstream service,
					through a mTLS connection, when providing identity headers.
				`,
			Given: kubetest.Actions(
				kubetest.CreateServerCerts(client, "nginx"),
				kubetest.CreateClientCerts(client, "kube-rbac-proxy-client"),
				kubetest.CreateServerCerts(client, "kube-rbac-proxy"),
				kubetest.CreatedManifests(
					client,
					"identityheaders/secure/clusterRole-client.yaml",
					"identityheaders/secure/clusterRole.yaml",
					"identityheaders/secure/clusterRoleBinding-client.yaml",
					"identityheaders/secure/clusterRoleBinding.yaml",
					"identityheaders/secure/configmap-nginx.yaml",
					"identityheaders/secure/deployment-upstream.yaml",
					"identityheaders/secure/service-upstream.yaml",
					"identityheaders/secure/deployment-proxy.yaml",
					"identityheaders/secure/service-proxy.yaml",
					"identityheaders/secure/serviceAccount.yaml",
				),
			),
			When: kubetest.Actions(
				kubetest.PodsAreReady(
					client,
					1,
					"app=nginx",
				),
				kubetest.ServiceIsReady(
					client,
					"nginx",
				),
				kubetest.PodsAreReady(
					client,
					1,
					"app=kube-rbac-proxy",
				),
			),
			Then: kubetest.Actions(
				kubetest.ClientSucceeds(
					client,
					command,
					nil,
				),
			),
		}.Run(t)
	}
}
