/*
Copyright 2023 the kube-rbac-proxy maintainers. All rights reserved.

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

func testHTTP2(client kubernetes.Interface) kubetest.TestSuite {
	return func(t *testing.T) {
		command := `HTTP_VERSION=$(curl -sI --http2 --connect-timeout 5 -k --fail -w "%{http_version}\n" -o /dev/null https://kube-rbac-proxy.default.svc.cluster.local:8443/metrics); if [[ "$HTTP_VERSION" != "2" ]]; then echo "Did expect HTTP/2. Actual protocol: $HTTP_VERSION" > /proc/self/fd/2; exit 1; fi`

		kubetest.Scenario{
			Name: "With succeeding HTTP2-client",
			Description: `
				Expecting http/2 capable client to succeed to connect with http/2.
			`,

			Given: kubetest.Actions(
				kubetest.CreatedManifests(
					client,
					"http2/clusterRole.yaml",
					"http2/clusterRoleBinding.yaml",
					"http2/deployment.yaml",
					"http2/service.yaml",
					"http2/serviceAccount.yaml",
					"http2/clusterRole-client.yaml",
					"http2/clusterRoleBinding-client.yaml",
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
					nil,
				),
			),
		}.Run(t)

		kubetest.Scenario{
			Name: "With failing HTTP2-client",
			Description: `
				Expecting http/2 capable client to fail to connect with http/2.
			`,

			Given: kubetest.Actions(
				kubetest.CreatedManifests(
					client,
					"http2/clusterRole.yaml",
					"http2/clusterRoleBinding.yaml",
					"http2/deployment-no-http2.yaml",
					"http2/service.yaml",
					"http2/serviceAccount.yaml",
					"http2/clusterRole-client.yaml",
					"http2/clusterRoleBinding-client.yaml",
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
					nil,
				),
			),
		}.Run(t)
	}
}
