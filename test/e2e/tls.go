/*
Copyright 2021 Frederic Branczyk All rights reserved.

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

func testTLS(client kubernetes.Interface) kubetest.TestSuite {
	return func(t *testing.T) {
		command := `curl %v --connect-timeout 5 -v -s -k --fail -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" https://kube-rbac-proxy.default.svc.cluster.local:8443/metrics`

		for _, tc := range []struct {
			name    string
			tlsFlag string
		}{
			{
				name:    "1.0",
				tlsFlag: "--tlsv1.0",
			},
			{
				name:    "1.1",
				tlsFlag: "--tlsv1.1",
			},
			{
				name:    "1.2",
				tlsFlag: "--tlsv1.2",
			},
			{
				name:    "1.3",
				tlsFlag: "--tlsv1.3",
			},
		} {
			kubetest.Scenario{
				Name: tc.name,

				Given: kubetest.Actions(
					kubetest.CreatedManifests(
						client,
						"basics/clusterRole.yaml",
						"basics/clusterRoleBinding.yaml",
						"basics/deployment.yaml",
						"basics/service.yaml",
						"basics/serviceAccount.yaml",
						// This adds the clients cluster role to succeed
						"basics/clusterRole-client.yaml",
						"basics/clusterRoleBinding-client.yaml",
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
						fmt.Sprintf(command, tc.tlsFlag),
						nil,
					),
				),
			}.Run(t)
		}
	}
}
