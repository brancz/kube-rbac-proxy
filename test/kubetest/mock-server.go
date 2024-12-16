/*
Copyright 2024 the kube-rbac-proxy maintainers. All rights reserved.

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
package kubetest

import (
	"fmt"
	"github.com/wiremock/go-wiremock"
)

// VerifyExactly verifies that the stub has been accessed exactly `times` times.
func VerifyExactly(mockServerURL, stubName string, times int64) Action {
	return func(ctx *ScenarioContext) error {
		mockClient := wiremock.NewClient(mockServerURL)
		stub, found := ctx.GetStub(stubName)
		if !found {
			return fmt.Errorf("stub '%s' not found", stubName)
		}

		result, err := mockClient.Verify(stub.Request(), times)
		if err != nil {
			return fmt.Errorf("error when verifying stub '%s': %v", stubName, err)
		}

		if result != true {
			return fmt.Errorf("stub '%s' not called %d time(s)", stubName, times)
		}

		return nil
	}
}
