/*
Copyright 2025 The kube-rbac-proxy maintainers

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
	"testing"

	"k8s.io/client-go/kubernetes"

	"github.com/brancz/kube-rbac-proxy/test/kubetest"
)

func testHeaderRewriteStatic(client kubernetes.Interface) kubetest.TestSuite {
	return func(t *testing.T) {
		commandWithHeader := `curl --connect-timeout 5 -v -s -k --fail -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" -H "x-namespace: %s" https://kube-rbac-proxy.default.svc.cluster.local:8443/metrics`
		commandWithoutHeader := `curl --connect-timeout 5 -v -s -k --fail -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" https://kube-rbac-proxy.default.svc.cluster.local:8443%s`

		for _, tc := range []struct {
			name  string
			given kubetest.Action
			check kubetest.Action
		}{
			{
				name: "allow-header-rewrite-static/granted-by-static",
				given: kubetest.Actions(
					kubetest.CreatedManifests(
						client,
						"authz-allow-header-rewrite-static/configmap.yaml",
						"authz-allow-header-rewrite-static/clusterRole.yaml",
						"authz-allow-header-rewrite-static/clusterRoleBinding.yaml",
						"authz-allow-header-rewrite-static/deployment.yaml",
						"authz-allow-header-rewrite-static/service.yaml",
						"authz-allow-header-rewrite-static/serviceAccount.yaml",
						"authz-allow-header-rewrite-static/serviceAccount-static.yaml",
					),
				),
				check: kubetest.Actions(
					kubetest.ClientSucceeds(
						client,
						fmt.Sprintf(commandWithHeader, "kube-system"),
						&kubetest.RunOptions{
							ServiceAccount: "client-with-static",
						},
					),
				),
			},
			{
				name: "allow-header-rewrite-static/granted-by-rbac",
				given: kubetest.Actions(
					kubetest.CreatedManifests(
						client,
						"authz-allow-header-rewrite-static/configmap.yaml",
						"authz-allow-header-rewrite-static/clusterRole.yaml",
						"authz-allow-header-rewrite-static/clusterRole-client-rbac.yaml",
						"authz-allow-header-rewrite-static/clusterRoleBinding.yaml",
						"authz-allow-header-rewrite-static/clusterRoleBinding-client-rbac.yaml",
						"authz-allow-header-rewrite-static/deployment.yaml",
						"authz-allow-header-rewrite-static/service.yaml",
						"authz-allow-header-rewrite-static/serviceAccount.yaml",
						"authz-allow-header-rewrite-static/serviceAccount-rbac.yaml",
					),
				),
				check: kubetest.Actions(
					kubetest.ClientSucceeds(
						client,
						fmt.Sprintf(commandWithHeader, "default"),
						&kubetest.RunOptions{
							ServiceAccount: "client-with-rbac",
						},
					),
				),
			},
			{
				name: "allow-header-rewrite-static/forbidden-path",
				given: kubetest.Actions(
					kubetest.CreatedManifests(
						client,
						"authz-allow-header-rewrite-static/configmap.yaml",
						"authz-allow-header-rewrite-static/clusterRole.yaml",
						"authz-allow-header-rewrite-static/clusterRoleBinding.yaml",
						"authz-allow-header-rewrite-static/deployment.yaml",
						"authz-allow-header-rewrite-static/service.yaml",
						"authz-allow-header-rewrite-static/serviceAccount.yaml",
					),
				),
				check: kubetest.Actions(
					kubetest.ClientFails(
						client,
						fmt.Sprintf(commandWithoutHeader, "/forbidden"),
						nil,
					),
				),
			},
			{
				name: "allow-header-rewrite-static/forbidden-by-rewrite",
				given: kubetest.Actions(
					kubetest.CreatedManifests(
						client,
						"authz-allow-header-rewrite-static/configmap.yaml",
						"authz-allow-header-rewrite-static/clusterRole.yaml",
						"authz-allow-header-rewrite-static/clusterRoleBinding.yaml",
						"authz-allow-header-rewrite-static/deployment.yaml",
						"authz-allow-header-rewrite-static/service.yaml",
						"authz-allow-header-rewrite-static/serviceAccount.yaml",
					),
				),
				check: kubetest.Actions(
					kubetest.ClientFails(
						client,
						fmt.Sprintf(commandWithHeader, "forbidden"),
						nil,
					),
				),
			},
			{
				name: "allow-header-rewrite-static/forbidden-by-rewrite-for-sa",
				given: kubetest.Actions(
					kubetest.CreatedManifests(
						client,
						"authz-allow-header-rewrite-static/configmap.yaml",
						"authz-allow-header-rewrite-static/clusterRole.yaml",
						"authz-allow-header-rewrite-static/clusterRoleBinding.yaml",
						"authz-allow-header-rewrite-static/deployment.yaml",
						"authz-allow-header-rewrite-static/service.yaml",
						"authz-allow-header-rewrite-static/serviceAccount.yaml",
					),
				),
				check: kubetest.Actions(
					kubetest.ClientFails(
						client,
						fmt.Sprintf(commandWithHeader, "kube-system"),
						nil,
					),
				),
			},
		} {
			kubetest.Scenario{
				Name:  tc.name,
				Given: kubetest.Actions(tc.given),
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
				Then: kubetest.Actions(tc.check),
			}.Run(t)
		}
	}
}
