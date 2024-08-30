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

func testBasics(client kubernetes.Interface) kubetest.TestSuite {
	return func(t *testing.T) {
		command := `curl --connect-timeout 5 -v -s -k --fail -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" https://kube-rbac-proxy.default.svc.cluster.local:8443/metrics`

		kubetest.Scenario{
			Name: "NoRBAC",
			Description: `
				As a client without any RBAC rule access,
				I fail with my request
			`,

			Given: kubetest.Actions(
				kubetest.CreatedManifests(
					client,
					"basics/clusterRole.yaml",
					"basics/clusterRoleBinding.yaml",
					"basics/deployment.yaml",
					"basics/service.yaml",
					"basics/serviceAccount.yaml",
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

		kubetest.Scenario{
			Name: "WithRBAC",
			Description: `
				As a client with the correct RBAC rules,
				I succeed with my request
			`,

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
					command,
					nil,
				),
			),
		}.Run(t)
	}
}

func testFlags(client kubernetes.Interface) kubetest.TestSuite {
	return func(t *testing.T) {
		command := `curl --connect-timeout 5 -v -s -k --fail -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" https://kube-rbac-proxy.default.svc.cluster.local:8443/metrics`

		kubetest.Scenario{
			Name: "WithAllOtherDisabledFlags",
			Description: `
				This should succeed. Even though all flags are set for kube-rbac-proxy.
				This implies deprecated flags that got disabled.
			`,

			Given: kubetest.Actions(
				kubetest.CreatedManifests(
					client,
					"flags/clusterRole.yaml",
					"flags/clusterRoleBinding.yaml",
					"flags/deployment-other-flags.yaml",
					"flags/service.yaml",
					"flags/serviceAccount.yaml",
					"flags/clusterRole-client.yaml",
					"flags/clusterRoleBinding-client.yaml",
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
			Name: "WithDisabledLogToStdErr",
			Description: `
				This should succeed. Even though logtostderr flag is set for
				kube-rbac-proxy.
				It is complementary to the other flags above.
			`,

			Given: kubetest.Actions(
				kubetest.CreatedManifests(
					client,
					"flags/clusterRole.yaml",
					"flags/clusterRoleBinding.yaml",
					"flags/deployment-logtostderr.yaml",
					"flags/service.yaml",
					"flags/serviceAccount.yaml",
					// This adds the clients cluster role to succeed
					"flags/clusterRole-client.yaml",
					"flags/clusterRoleBinding-client.yaml",
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
	}
}

func testTokenAudience(client kubernetes.Interface) kubetest.TestSuite {
	return func(t *testing.T) {
		command := `curl --connect-timeout 5 -v -s -k --fail -H "Authorization: Bearer $(cat /var/run/secrets/tokens/requestedtoken)" https://kube-rbac-proxy.default.svc.cluster.local:8443/metrics`

		kubetest.Scenario{
			Name: "IncorrectAudience",
			Description: `
				As a client with the wrong token audience,
				I fail with my request
			`,

			Given: kubetest.Actions(
				kubetest.CreatedManifests(
					client,
					"tokenrequest/clusterRole.yaml",
					"tokenrequest/clusterRoleBinding.yaml",
					"tokenrequest/deployment.yaml",
					"tokenrequest/service.yaml",
					"tokenrequest/serviceAccount.yaml",
					"tokenrequest/clusterRole-client.yaml",
					"tokenrequest/clusterRoleBinding-client.yaml",
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

			Given: kubetest.Actions(
				kubetest.CreatedManifests(
					client,
					"tokenrequest/clusterRole.yaml",
					"tokenrequest/clusterRoleBinding.yaml",
					"tokenrequest/deployment.yaml",
					"tokenrequest/service.yaml",
					"tokenrequest/serviceAccount.yaml",
					"tokenrequest/clusterRole-client.yaml",
					"tokenrequest/clusterRoleBinding-client.yaml",
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
					&kubetest.RunOptions{TokenAudience: "kube-rbac-proxy"},
				),
			),
		}.Run(t)
	}
}

func testClientCertificates(client kubernetes.Interface) kubetest.TestSuite {
	return func(t *testing.T) {
		command := `curl --connect-timeout 5 -v -s -k --fail --cert /certs/tls.crt --key /certs/tls.key https://kube-rbac-proxy.default.svc.cluster.local:8443/metrics`

		kubetest.Scenario{
			Name: "NoRBAC",
			Description: `
				As a client with client certificates authorization without RBAC,
				I fail with my request
			`,

			Given: kubetest.Actions(
				kubetest.CreatedManifests(
					client,
					"clientcertificates/certificate.yaml",
					"clientcertificates/clusterRole.yaml",
					"clientcertificates/clusterRoleBinding.yaml",
					"clientcertificates/deployment.yaml",
					"clientcertificates/service.yaml",
					"clientcertificates/serviceAccount.yaml",
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
					&kubetest.RunOptions{ClientCertificates: true},
				),
			),
		}.Run(t)

		kubetest.Scenario{
			Name: "WithRBAC",
			Description: `
				As a client with client certificates authorization with RBAC,
				I succeed with my request
			`,

			Given: kubetest.Actions(
				kubetest.CreatedManifests(
					client,
					"clientcertificates/certificate.yaml",
					"clientcertificates/clusterRole.yaml",
					"clientcertificates/clusterRoleBinding.yaml",
					"clientcertificates/deployment.yaml",
					"clientcertificates/service.yaml",
					"clientcertificates/serviceAccount.yaml",
					"clientcertificates/clusterRole-client.yaml",
					"clientcertificates/clusterRoleBinding-client.yaml",
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
					&kubetest.RunOptions{ClientCertificates: true},
				),
			),
		}.Run(t)

		kubetest.Scenario{
			Name: "WrongCA",
			Description: `
				As a client with client certificates authorization with RBAC and with unmatched CA,
				I fail with my request
			`,

			Given: kubetest.Actions(
				kubetest.CreatedManifests(
					client,
					"clientcertificates/certificate.yaml",
					"clientcertificates/clusterRole.yaml",
					"clientcertificates/clusterRoleBinding.yaml",
					"clientcertificates/deployment-wrongca.yaml",
					"clientcertificates/service.yaml",
					"clientcertificates/serviceAccount.yaml",
					"clientcertificates/clusterRole-client.yaml",
					"clientcertificates/clusterRoleBinding-client.yaml",
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
					&kubetest.RunOptions{ClientCertificates: true},
				),
			),
		}.Run(t)
	}
}

func testAllowPathsRegexp(client kubernetes.Interface) kubetest.TestSuite {
	return func(t *testing.T) {
		command := `STATUS_CODE=$(curl --connect-timeout 5 -o /dev/null -v -s -k --write-out "%%{http_code}" -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" https://kube-rbac-proxy.default.svc.cluster.local:8443%s); if [[ "$STATUS_CODE" != %d ]]; then echo "expecting %d status code, got $STATUS_CODE instead" > /proc/self/fd/2; exit 1; fi`

		kubetest.Scenario{
			Name: "WithPathhNotAllowed",
			Description: `
				As a client with the correct RBAC rules,
				I get a 404 response when requesting a path which isn't allowed by kube-rbac-proxy
			`,

			Given: kubetest.Actions(
				kubetest.CreatedManifests(
					client,
					"allowpaths/clusterRole.yaml",
					"allowpaths/clusterRoleBinding.yaml",
					"allowpaths/deployment.yaml",
					"allowpaths/service.yaml",
					"allowpaths/serviceAccount.yaml",
					"allowpaths/clusterRole-client.yaml",
					"allowpaths/clusterRoleBinding-client.yaml",
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
					fmt.Sprintf(command, "/", 404, 404),
					nil,
				),
				kubetest.ClientSucceeds(
					client,
					fmt.Sprintf(command, "/api/v1/label/name", 404, 404),
					nil,
				),
			),
		}.Run(t)

		kubetest.Scenario{
			Name: "WithPathAllowed",
			Description: `
				As a client with the correct RBAC rules,
				I succeed with my request for a path that is allowed
			`,

			Given: kubetest.Actions(
				kubetest.CreatedManifests(
					client,
					"allowpaths/clusterRole.yaml",
					"allowpaths/clusterRoleBinding.yaml",
					"allowpaths/deployment.yaml",
					"allowpaths/service.yaml",
					"allowpaths/serviceAccount.yaml",
					"allowpaths/clusterRole-client.yaml",
					"allowpaths/clusterRoleBinding-client.yaml",
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
					fmt.Sprintf(command, "/metrics", 200, 200),
					nil,
				),
				kubetest.ClientSucceeds(
					client,
					fmt.Sprintf(command, "/api/v1/label/job/values", 200, 200),
					nil,
				),
			),
		}.Run(t)
	}
}

func testIgnorePaths(client kubernetes.Interface) kubetest.TestSuite {
	return func(t *testing.T) {
		commandWithoutAuth := `STATUS_CODE=$(curl --connect-timeout 5 -o /dev/null -v -s -k --write-out "%%{http_code}" https://kube-rbac-proxy.default.svc.cluster.local:8443%s); if [[ "$STATUS_CODE" != %d ]]; then echo "expecting %d status code, got $STATUS_CODE instead" > /proc/self/fd/2; exit 1; fi`

		kubetest.Scenario{
			Name: "WithIgnorePathMatch",
			Description: `
				As a client without an auth token,
				I get a 200 response when requesting a path included in ignorePaths
			`,

			Given: kubetest.Actions(
				kubetest.CreatedManifests(
					client,
					"ignorepaths/clusterRole.yaml",
					"ignorepaths/clusterRoleBinding.yaml",
					"ignorepaths/deployment.yaml",
					"ignorepaths/service.yaml",
					"ignorepaths/serviceAccount.yaml",
					"ignorepaths/clusterRole-client.yaml",
					"ignorepaths/clusterRoleBinding-client.yaml",
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
					fmt.Sprintf(commandWithoutAuth, "/metrics", 200, 200),
					nil,
				),
				kubetest.ClientSucceeds(
					client,
					fmt.Sprintf(commandWithoutAuth, "/api/v1/labels", 200, 200),
					nil,
				),
			),
		}.Run(t)

		kubetest.Scenario{
			Name: "WithIgnorePathNoMatch",
			Description: `
				As a client without an auth token,
				I get a 401 response when requesting a path not included in ignorePaths
			`,

			Given: kubetest.Actions(
				kubetest.CreatedManifests(
					client,
					"ignorepaths/clusterRole.yaml",
					"ignorepaths/clusterRoleBinding.yaml",
					"ignorepaths/deployment.yaml",
					"ignorepaths/service.yaml",
					"ignorepaths/serviceAccount.yaml",
					"ignorepaths/clusterRole-client.yaml",
					"ignorepaths/clusterRoleBinding-client.yaml",
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
					fmt.Sprintf(commandWithoutAuth, "/", 401, 401),
					nil,
				),
				kubetest.ClientSucceeds(
					client,
					fmt.Sprintf(commandWithoutAuth, "/api/v1/label/job/values", 401, 401),
					nil,
				),
			),
		}.Run(t)
	}
}
