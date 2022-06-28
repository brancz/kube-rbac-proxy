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
	"testing"

	"k8s.io/client-go/kubernetes"

	"github.com/brancz/kube-rbac-proxy/test/kubetest"
)

func testStaticAuthorizer(client kubernetes.Interface) kubetest.TestSuite {
	return func(t *testing.T) {
		command := `curl --connect-timeout 5 -v -s -k --fail -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" https://kube-rbac-proxy.default.svc.cluster.local:8443%v`

		for _, tc := range []struct {
			name  string
			given kubetest.Action
			check kubetest.Action
		}{
			{
				name: "resource/namespace/metrics/query rewrite/granted",
				given: kubetest.Actions(
					kubetest.CreatedManifests(
						client,
						"static-auth/configmap-resource.yaml",
						"static-auth/clusterRole.yaml",
						"static-auth/clusterRoleBinding.yaml",
						"static-auth/deployment.yaml",
						"static-auth/service.yaml",
						"static-auth/serviceAccount.yaml",
					),
				),
				check: kubetest.Actions(
					kubetest.ClientSucceeds(
						client,
						fmt.Sprintf(command, "/metrics?namespace=default"),
						nil,
					),
				),
			},
			{
				name: "resource/namespace/metrics/query rewrite/forbidden",
				given: kubetest.Actions(
					kubetest.CreatedManifests(
						client,
						"static-auth/configmap-resource.yaml",
						"static-auth/clusterRole.yaml",
						"static-auth/clusterRoleBinding.yaml",
						"static-auth/deployment.yaml",
						"static-auth/service.yaml",
						"static-auth/serviceAccount.yaml",
					),
				),
				check: kubetest.Actions(
					kubetest.ClientFails(
						client,
						fmt.Sprintf(command, "/metrics?namespace=forbidden"),
						nil,
					),
				),
			},
			{
				name: "non-resource/get/metrics/granted",
				given: kubetest.Actions(
					kubetest.CreatedManifests(
						client,
						"static-auth/configmap-non-resource.yaml",
						"static-auth/clusterRole.yaml",
						"static-auth/clusterRoleBinding.yaml",
						"static-auth/deployment.yaml",
						"static-auth/service.yaml",
						"static-auth/serviceAccount.yaml",
					),
				),
				check: kubetest.Actions(
					kubetest.ClientSucceeds(
						client,
						fmt.Sprintf(command, "/metrics"),
						nil,
					),
				),
			},
			{
				name: "non-resource/get/metrics/forbidden",
				given: kubetest.Actions(
					kubetest.CreatedManifests(
						client,
						"static-auth/configmap-non-resource.yaml",
						"static-auth/clusterRole.yaml",
						"static-auth/clusterRoleBinding.yaml",
						"static-auth/deployment.yaml",
						"static-auth/service.yaml",
						"static-auth/serviceAccount.yaml",
					),
				),
				check: kubetest.Actions(
					kubetest.ClientFails(
						client,
						fmt.Sprintf(command, "/forbidden"),
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
