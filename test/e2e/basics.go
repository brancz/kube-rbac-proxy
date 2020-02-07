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
	"testing"

	"github.com/brancz/kube-rbac-proxy/test/kubetest"
	"k8s.io/client-go/kubernetes"
)

func testBasics(s *kubetest.Suite) kubetest.TestSuite {
	return func(t *testing.T) {
		command := `curl --connect-timeout 5 -v -s -k --fail -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" https://kube-rbac-proxy.default.svc.cluster.local:8443/metrics`

		kubetest.Scenario{
			Name: "NoRBAC",
			Description: `
				As a client without any RBAC rule access,
				I fail with my request
			`,

			Given: kubetest.Setups(
				kubetest.CreatedManifests(
					s.KubeClient,
					"basics/clusterRole.yaml",
					"basics/clusterRoleBinding.yaml",
					"basics/deployment.yaml",
					"basics/service.yaml",
					"basics/serviceAccount.yaml",
				),
			),
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
			Then: kubetest.Checks(
				ClientFails(
					s.KubeClient,
					command,
					nil,
				),
			),
		}.Run(t)

		kubetest.Scenario{
			Name: "WithRBAC",
			Description: `
				As a client with the correct RBAC rules,
				I succeed with my request
			`,

			Given: kubetest.Setups(
				kubetest.CreatedManifests(
					s.KubeClient,
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
			Then: kubetest.Checks(
				ClientSucceeds(
					s.KubeClient,
					command,
					nil,
				),
			),
		}.Run(t)
	}
}

func testTokenAudience(s *kubetest.Suite) kubetest.TestSuite {
	return func(t *testing.T) {
		command := `curl --connect-timeout 5 -v -s -k --fail -H "Authorization: Bearer $(cat /var/run/secrets/tokens/requestedtoken)" https://kube-rbac-proxy.default.svc.cluster.local:8443/metrics`

		kubetest.Scenario{
			Name: "IncorrectAudience",
			Description: `
				As a client with the wrong token audience,
				I fail with my request
			`,

			Given: kubetest.Setups(
				kubetest.CreatedManifests(
					s.KubeClient,
					"tokenrequest/clusterRole.yaml",
					"tokenrequest/clusterRoleBinding.yaml",
					"tokenrequest/deployment.yaml",
					"tokenrequest/service.yaml",
					"tokenrequest/serviceAccount.yaml",
					"tokenrequest/clusterRole-client.yaml",
					"tokenrequest/clusterRoleBinding-client.yaml",
				),
			),
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
			Then: kubetest.Checks(
				ClientFails(
					s.KubeClient,
					command,
					&kubetest.RunOptions{TokenAudience: "wrong-audience"},
				),
			),
		}.Run(t)

		kubetest.Scenario{
			Name: "CorrectAudience",
			Description: `
				As a client with the correct token audience,
				I succeed with my request
			`,

			Given: kubetest.Setups(
				kubetest.CreatedManifests(
					s.KubeClient,
					"tokenrequest/clusterRole.yaml",
					"tokenrequest/clusterRoleBinding.yaml",
					"tokenrequest/deployment.yaml",
					"tokenrequest/service.yaml",
					"tokenrequest/serviceAccount.yaml",
					"tokenrequest/clusterRole-client.yaml",
					"tokenrequest/clusterRoleBinding-client.yaml",
				),
			),
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
			Then: kubetest.Checks(
				ClientSucceeds(
					s.KubeClient,
					command,
					&kubetest.RunOptions{TokenAudience: "kube-rbac-proxy"},
				),
			),
		}.Run(t)
	}
}

func ClientSucceeds(client kubernetes.Interface, command string, opts *kubetest.RunOptions) kubetest.Check {
	return func(ctx *kubetest.ScenarioContext) error {
		return kubetest.RunSucceeds(
			client,
			"quay.io/brancz/krp-curl:v0.0.1",
			"kube-rbac-proxy-client",
			[]string{"/bin/sh", "-c", command},
			opts,
		)(ctx)
	}
}

func ClientFails(client kubernetes.Interface, command string, opts *kubetest.RunOptions) kubetest.Check {
	return func(ctx *kubetest.ScenarioContext) error {
		return kubetest.RunFails(
			client,
			"quay.io/brancz/krp-curl:v0.0.1",
			"kube-rbac-proxy-client",
			[]string{"/bin/sh", "-c", command},
			opts,
		)(ctx)
	}
}
