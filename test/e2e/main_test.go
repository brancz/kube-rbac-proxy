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
	"flag"
	"log"
	"os"
	"testing"

	"k8s.io/client-go/kubernetes"

	"github.com/brancz/kube-rbac-proxy/test/kubetest"
)

// Sadly there's no way to pass the k8s client from TestMain to Test,
// so we need this global instance
var client kubernetes.Interface

// TestMain adds the kubeconfig flag to our tests
func TestMain(m *testing.M) {
	kubeconfig := flag.String(
		"kubeconfig",
		"",
		"path to kubeconfig",
	)
	flag.Parse()

	var err error
	client, err = kubetest.NewClientFromKubeconfig(*kubeconfig)
	if err != nil {
		log.Fatal(err)
	}

	os.Exit(m.Run())
}

func Test(t *testing.T) {
	tests := map[string]kubetest.TestSuite{
		"Basics":             testBasics(client),
		"Healthz":            testHealthz(client),
		"H2CUpstream":        testH2CUpstream(client),
		"IdentityHeaders":    testIdentityHeaders(client),
		"ClientCertificates": testClientCertificates(client),
		"TokenAudience":      testTokenAudience(client),
		"AllowPath":          testAllowPathsRegexp(client),
		"IgnorePath":         testIgnorePaths(client),
		"TLS":                testTLS(client),
		"StaticAuthorizer":   testStaticAuthorizer(client),
		"HTTP2":              testHTTP2(client),
	}

	for name, tc := range tests {
		t.Run(name, tc)
	}
}
