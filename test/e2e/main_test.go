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

	"github.com/brancz/kube-rbac-proxy/test/kubetest"
)

// Sadly there's no way to pass Suite from TestMain to Test,
// so we need this global instance
var suite *kubetest.Suite

// TestMain adds the kubeconfig flag to our tests
func TestMain(m *testing.M) {
	kubeconfig := flag.String(
		"kubeconfig",
		"",
		"path to kubeconfig",
	)
	flag.Parse()

	var err error
	suite, err = kubetest.NewSuiteFromKubeconfig(*kubeconfig)
	if err != nil {
		log.Fatal(err)
	}

	os.Exit(m.Run())
}

func Test(t *testing.T) {
	tests := map[string]kubetest.TestSuite{
		"Basics":        testBasics(suite),
		"TokenAudience": testTokenAudience(suite),
		"AllowPath":     testAllowPathsRegexp(suite),
	}

	for name, tc := range tests {
		t.Run(name, tc)
	}
}
