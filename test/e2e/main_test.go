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
		"Basics": testBasics(suite),
	}

	for name, tc := range tests {
		t.Run(name, tc)
	}
}
