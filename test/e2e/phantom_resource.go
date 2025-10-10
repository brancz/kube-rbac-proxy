/*
Copyright 2025 the kube-rbac-proxy maintainers All rights reserved.

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
	"net/http"
	"testing"

	"k8s.io/client-go/kubernetes"

	"github.com/brancz/kube-rbac-proxy/test/kubetest"
)

type curlRequest struct {
	method string
	url    string
}

func newDefaultRequest() curlRequest {
	return curlRequest{
		method: "GET",
		url:    "https://kube-rbac-proxy.default.svc.cluster.local:8443/",
	}
}

func (c curlRequest) WithMethod(method string) curlRequest {
	c.method = method
	return c
}

func (c curlRequest) Build() string {
	authHeader := `-H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)"`
	methodFlag := ""
	if c.method != "" && c.method != "GET" {
		methodFlag = "-X " + c.method + " "
	}
	return `curl --connect-timeout 5 -v -s -k --fail ` + methodFlag + authHeader + ` ` + c.url
}

func testPhantomResource(client kubernetes.Interface) kubetest.TestSuite {
	return func(t *testing.T) {
		baseManifests := []string{
			"phantom-resource/clusterRole.yaml",
			"phantom-resource/clusterRoleBinding.yaml",
			"phantom-resource/configmap.yaml",
			"phantom-resource/deployment.yaml",
			"phantom-resource/service.yaml",
			"phantom-resource/serviceAccount.yaml",
		}

		rbacManifests := append(baseManifests,
			"phantom-resource/clusterRole-client.yaml",
			"phantom-resource/clusterRoleBinding-client.yaml",
		)

		testCases := []string{
			http.MethodGet, http.MethodPost,
		}

		kubetest.Scenario{
			Name: "PhantomResourceNoRBAC",
			Description: `
				As a client without RBAC rules for a phantom resource,
				I fail with my request even though the resource doesn't exist
			`,
			Given: kubetest.Actions(
				kubetest.CreatedManifests(client, baseManifests...),
			),
			When: kubetest.Actions(
				kubetest.PodsAreReady(client, 1, "app=kube-rbac-proxy"),
				kubetest.ServiceIsReady(client, "kube-rbac-proxy"),
			),
			Then: kubetest.Actions(
				kubetest.ClientFails(
					client,
					newDefaultRequest().Build(),
					nil,
				),
			),
		}.Run(t)

		for _, method := range testCases {
			kubetest.Scenario{
				Name: "PhantomResourceCRUD/" + method,
				Given: kubetest.Actions(
					kubetest.CreatedManifests(client, rbacManifests...),
				),
				When: kubetest.Actions(
					kubetest.PodsAreReady(client, 1, "app=kube-rbac-proxy"),
					kubetest.ServiceIsReady(client, "kube-rbac-proxy"),
				),
				Then: kubetest.Actions(
					kubetest.ClientSucceeds(
						client,
						newDefaultRequest().WithMethod(method).Build(),
						nil,
					),
				),
			}.Run(t)
		}
	}
}
