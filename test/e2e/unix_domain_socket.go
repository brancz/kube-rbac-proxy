/*
Copyright 2026 the kube-rbac-proxy maintainers. All rights reserved.

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

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/brancz/kube-rbac-proxy/test/kubetest"
)

func testUnixDomainSocket(client kubernetes.Interface) kubetest.TestSuite {
	return func(t *testing.T) {
		command := `curl --connect-timeout 5 -v -s -k --fail -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" https://kube-rbac-proxy.default.svc.cluster.local:8443/metrics`

		unixUpstreamContainer := &corev1.Container{
			Name:  "unix-upstream",
			Image: "quay.io/brancz/unix-upstream:local",
		}

		unixSocketConfig := func() *kubetest.KRPTestConfig {
			return kubetest.NewBasicKubeRBACProxyTestConfig().
				UpdateFlags(map[string]string{
					"upstream": "unix:///sockets/app.sock",
				}).
				ReplaceUpstream(unixUpstreamContainer).
				WithEmptyDirVolume("sockets", "/sockets", 0, 1)
		}

		kubetest.Scenario{
			Name: "WithRBAC",
			Description: `
				As a client with the correct RBAC rules proxying through
				a unix domain socket upstream, I succeed with my request
			`,

			Given: kubetest.Actions(
				unixSocketConfig().Launch(client),
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
			Name: "NoRBAC",
			Description: `
				As a client without RBAC rules proxying through
				a unix domain socket upstream, I fail with my request
			`,

			Given: kubetest.Actions(
				unixSocketConfig().
					WithoutMetricsEndpointAllowClusterRole().
					Launch(client),
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

		kubetest.Scenario{
			Name: "WithHTTPPath",
			Description: `
				As a client with the correct RBAC rules proxying through
				a unix domain socket upstream with an explicit http path,
				I succeed with my request
			`,

			Given: kubetest.Actions(
				kubetest.NewBasicKubeRBACProxyTestConfig().
					UpdateFlags(map[string]string{
						"upstream": "unix:///sockets/app.sock:/metrics",
					}).
					ReplaceUpstream(unixUpstreamContainer).
					WithEmptyDirVolume("sockets", "/sockets", 0, 1).
					Launch(client),
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
	}
}
