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

	"github.com/brancz/kube-rbac-proxy/test/kubetest"
)

func testMultipleConfigs(s *kubetest.Suite) kubetest.TestSuite {
	return func(t *testing.T) {
		command := `curl --connect-timeout 5 -v -s -k --fail -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" https://kube-rbac-proxy.default.svc.cluster.local:8443%v`

		for _, tc := range []struct {
			name  string
			given []kubetest.Setup
			check []kubetest.Check
		}{
			{
				name: "RBAC + correct namespace",
				given: []kubetest.Setup{
					kubetest.CreatedManifests(
						s.KubeClient,
						"multiple-configs/configmap-resource.yaml",
						"multiple-configs/clusterRole.yaml",
						"multiple-configs/clusterRoleBinding.yaml",
						"multiple-configs/clusterRole-client.yaml",
						"multiple-configs/clusterRoleBinding-client.yaml",
						"multiple-configs/deployment.yaml",
						"multiple-configs/service.yaml",
						"multiple-configs/serviceAccount.yaml",
					),
				},
				check: []kubetest.Check{
					ClientSucceeds(
						s.KubeClient,
						fmt.Sprintf(command, "/metrics?namespace=default"),
						nil,
					),
				},
			},
			{
				name: "no RBAC + correct namespace",
				given: []kubetest.Setup{
					kubetest.CreatedManifests(
						s.KubeClient,
						"multiple-configs/configmap-resource.yaml",
						"multiple-configs/clusterRole.yaml",
						"multiple-configs/clusterRoleBinding.yaml",
						"multiple-configs/deployment.yaml",
						"multiple-configs/service.yaml",
						"multiple-configs/serviceAccount.yaml",
					),
				},
				check: []kubetest.Check{
					ClientFails(
						s.KubeClient,
						fmt.Sprintf(command, "/metrics?namespace=default"),
						nil,
					),
				},
			},
			{
				name: "RBAC + wrong namespace",
				given: []kubetest.Setup{
					kubetest.CreatedManifests(
						s.KubeClient,
						"multiple-configs/configmap-resource.yaml",
						"multiple-configs/clusterRole.yaml",
						"multiple-configs/clusterRoleBinding.yaml",
						"multiple-configs/clusterRole-client.yaml",
						"multiple-configs/clusterRoleBinding-client.yaml",
						"multiple-configs/deployment.yaml",
						"multiple-configs/service.yaml",
						"multiple-configs/serviceAccount.yaml",
					),
				},
				check: []kubetest.Check{
					ClientFails(
						s.KubeClient,
						fmt.Sprintf(command, "/metrics?namespace=forbidden"),
						nil,
					),
				},
			},
			{
				name: "no RBAC + wrong namespace",
				given: []kubetest.Setup{
					kubetest.CreatedManifests(
						s.KubeClient,
						"multiple-configs/configmap-resource.yaml",
						"multiple-configs/clusterRole.yaml",
						"multiple-configs/clusterRoleBinding.yaml",
						"multiple-configs/deployment.yaml",
						"multiple-configs/service.yaml",
						"multiple-configs/serviceAccount.yaml",
					),
				},
				check: []kubetest.Check{
					ClientFails(
						s.KubeClient,
						fmt.Sprintf(command, "/metrics?namespace=forbidden"),
						nil,
					),
				},
			},
		} {
			kubetest.Scenario{
				Name:  tc.name,
				Given: kubetest.Setups(tc.given...),
				When: kubetest.Conditions(
					kubetest.PodsAreReady(
						s.KubeClient,
						1,
						"app=kube-rbac-proxy",
					),
					kubetest.ServiceIsReady(
						s.KubeClient,
						"kube-rbac-proxy",
					),
				),
				Then: kubetest.Checks(tc.check...),
			}.Run(t)
		}
	}
}
