/*
￼Copyright 2021 Kube RBAC Proxy Authors rights reserved.
￼
￼Licensed under the Apache License, Version 2.0 (the "License");
￼you may not use this file except in compliance with the License.
￼You may obtain a copy of the License at
￼
￼    http://www.apache.org/licenses/LICENSE-2.0
￼
￼Unless required by applicable law or agreed to in writing, software
￼distributed under the License is distributed on an "AS IS" BASIS,
￼WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
￼See the License for the specific language governing permissions and
￼limitations under the License.
￼*/

package authz

import (
	"context"
	"testing"

	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

func TestStaticAuthorizer(t *testing.T) {
	tests := []struct {
		name       string
		authorizer authorizer.Authorizer

		shouldPass      []authorizer.Attributes
		shouldNoOpinion []authorizer.Attributes
	}{
		{
			name: "pathOnly",
			authorizer: NewStaticAuthorizer([]StaticAuthorizationConfig{
				StaticAuthorizationConfig{Path: "/metrics"},
			}),
			shouldPass: []authorizer.Attributes{
				authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "system:foo"}, Verb: "get", Path: "/metrics"},
				authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "system:foo"}, Verb: "update", Path: "/metrics"},
			},
			shouldNoOpinion: []authorizer.Attributes{
				// wrong path
				authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "system:foo"}, Verb: "get", Path: "/api"},
			},
		},
		{
			name: "pathAndVerb",
			authorizer: NewStaticAuthorizer([]StaticAuthorizationConfig{
				StaticAuthorizationConfig{Path: "/metrics", Verb: "get"},
			}),
			shouldPass: []authorizer.Attributes{
				authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "system:foo"}, Verb: "get", Path: "/metrics"},
			},
			shouldNoOpinion: []authorizer.Attributes{
				// wrong path
				authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "system:foo"}, Verb: "get", Path: "/api"},
				// wrong path
				authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "system:foo"}, Verb: "update", Path: "/metrics"},
			},
		},
		{
			name: "resourceRequestSpecifiedTrue",
			authorizer: NewStaticAuthorizer([]StaticAuthorizationConfig{
				StaticAuthorizationConfig{Path: "/metrics", Verb: "get", ResourceRequest: true},
			}),
			shouldPass: []authorizer.Attributes{
				authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "system:foo"}, Verb: "get", Path: "/metrics", ResourceRequest: true},
			},
			shouldNoOpinion: []authorizer.Attributes{
				// wrong resourceRequest
				authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "system:foo"}, Verb: "get", Path: "/metrics", ResourceRequest: false},
			},
		},
		{
			name: "resourceRequestSpecifiedFalse",
			authorizer: NewStaticAuthorizer([]StaticAuthorizationConfig{
				StaticAuthorizationConfig{Path: "/metrics", Verb: "get", ResourceRequest: false},
			}),
			shouldPass: []authorizer.Attributes{
				authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "system:foo"}, Verb: "get", Path: "/metrics", ResourceRequest: false},
			},
			shouldNoOpinion: []authorizer.Attributes{
				// wrong resourceRequest
				authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "system:foo"}, Verb: "get", Path: "/metrics", ResourceRequest: true},
			},
		},
		{
			name: "resourceRequestUnspecified",
			authorizer: NewStaticAuthorizer([]StaticAuthorizationConfig{
				StaticAuthorizationConfig{Path: "/metrics", Verb: "get"},
			}),
			shouldPass: []authorizer.Attributes{
				authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "system:foo"}, Verb: "get", Path: "/metrics", ResourceRequest: false},
			},
			shouldNoOpinion: []authorizer.Attributes{
				// Verb: get and ResourceRequest: true should be
				// mutually exclusive
				authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "system:foo"}, Verb: "get", Path: "/metrics", ResourceRequest: true},
				// wrong path
				authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "system:foo"}, Verb: "get", Path: "/api", ResourceRequest: true},
				// wrong path
				authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "system:foo"}, Verb: "update", Path: "/metrics", ResourceRequest: false},
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
