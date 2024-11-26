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
	mockserver "github.com/BraspagDevelopers/mock-server-client"
	"net/http"
)

// VerifyGetExactly verifies that the URL has been access exactly `times` times by a GET request.
// Note that the underlying library doesn't properly handle times=0 therefore it cannot be used until they remove the
// "omitempty" from the Times struct since the server defaults to times=1 when the fields are not present.
func VerifyGetExactly(mockServerURL, url string, times int) Action {
	return func(ctx *ScenarioContext) error {
		mockClient := mockserver.NewClientURL(mockServerURL)
		err := mockClient.Verify(mockserver.RequestMatcher{
			Method: http.MethodGet,
			Path:   url,
			Body: mockserver.BodyMatcher{
				Type:      mockserver.MatchBodyJSON,
				JSON:      nil,
				MatchType: mockserver.TolerantMatch,
			},
		}, mockserver.Exactly(times))
		if err != nil {
			return fmt.Errorf("failed to register expections with server: %w", err)
		}
		return err
	}
}
