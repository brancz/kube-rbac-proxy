package e2e

import (
	"testing"

	"github.com/brancz/kube-rbac-proxy/test/kubetest"
	"k8s.io/client-go/kubernetes"
)

func testBasics(s *kubetest.Suite) kubetest.TestSuite {
	return func(t *testing.T) {
		command := `curl -v -s -k --fail -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" https://kube-rbac-proxy.default.svc.cluster.local:8443/metrics`

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
			),
			Then: kubetest.Checks(
				ClientFails(
					s.KubeClient,
					command,
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
			),
			Then: kubetest.Checks(
				ClientSucceeds(
					s.KubeClient,
					command,
				),
			),
		}.Run(t)
	}
}

func ClientSucceeds(client kubernetes.Interface, command string) kubetest.Check {
	return func(ctx *kubetest.ScenarioContext) error {
		return kubetest.RunSucceeds(
			client,
			"alpine",
			"kube-rbac-proxy-client",
			[]string{"/bin/sh", "-c", "apk add -U curl && " + command},
			&kubetest.RunOptions{ServiceAccount: "default"},
		)(ctx)
	}
}

func ClientFails(client kubernetes.Interface, command string) kubetest.Check {
	return func(ctx *kubetest.ScenarioContext) error {
		return kubetest.RunFails(
			client,
			"alpine",
			"kube-rbac-proxy-client",
			[]string{"/bin/sh", "-c", "apk add -U curl && " + command},
			&kubetest.RunOptions{ServiceAccount: "default"},
		)(ctx)
	}
}
