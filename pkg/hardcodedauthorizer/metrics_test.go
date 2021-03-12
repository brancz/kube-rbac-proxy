/*
Copyright 2021 Frederic Branczyk All rights reserved.

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

package hardcodedauthorizer

import (
	"context"
	"testing"

	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

func TestAuthorizer(t *testing.T) {
	tests := []struct {
		name       string
		authorizer authorizer.Authorizer

		shouldPass      []authorizer.Attributes
		shouldNoOpinion []authorizer.Attributes
	}{
		{
			name:       "metrics",
			authorizer: NewHardCodedMetricsAuthorizer(),
			shouldPass: []authorizer.Attributes{
				authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "system:serviceaccount:openshift-monitoring:prometheus-k8s"}, Verb: "get", Path: "/metrics"},
			},
			shouldNoOpinion: []authorizer.Attributes{
				// wrong user
				authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "other"}, Verb: "get", Path: "/metrics"},
				// wrong verb
				authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "system:serviceaccount:openshift-monitoring:prometheus-k8s"}, Verb: "update", Path: "/metrics"},

				// wrong path
				authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "system:serviceaccount:openshift-monitoring:prometheus-k8s"}, Verb: "get", Path: "/api"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, attr := range tt.shouldPass {
				if decision, _, _ := tt.authorizer.Authorize(context.Background(), attr); decision != authorizer.DecisionAllow {
					t.Errorf("incorrectly restricted %v", attr)
				}
			}

			for _, attr := range tt.shouldNoOpinion {
				if decision, _, _ := tt.authorizer.Authorize(context.Background(), attr); decision != authorizer.DecisionNoOpinion {
					t.Errorf("incorrectly opinionated %v", attr)
				}
			}
		})
	}
}
