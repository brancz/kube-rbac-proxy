/*
Copyright 2025 the kube-rbac-proxy maintainers. All rights reserved.

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

package app

import (
	"context"
	"net/http"
	"testing"

	"github.com/brancz/kube-rbac-proxy/pkg/authorization"
	"github.com/brancz/kube-rbac-proxy/pkg/authorization/rewrite"
	"github.com/brancz/kube-rbac-proxy/pkg/authorization/static"
	"github.com/brancz/kube-rbac-proxy/pkg/server"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	serverconfig "k8s.io/apiserver/pkg/server"
)

type mockAuthorizer struct {
	authorize func(ctx context.Context, a authorizer.Attributes) (authorizer.Decision, string, error)
}

func (m *mockAuthorizer) Authorize(ctx context.Context, a authorizer.Attributes) (authorizer.Decision, string, error) {
	if m.authorize != nil {
		return m.authorize(ctx, a)
	}
	return authorizer.DecisionDeny, "unset mock authorizer", nil
}

func TestSetupAuthorizer_AllowPathsWithRewriteAndStaticAuth(t *testing.T) {
	mockDelegated := &mockAuthorizer{
		authorize: func(ctx context.Context, a authorizer.Attributes) (authorizer.Decision, string, error) {
			if a.GetUser().GetName() == "system:serviceaccount:default:client-with-rbac" {
				return authorizer.DecisionAllow, "delegated allow", nil
			}
			return authorizer.DecisionDeny, "delegated deny", nil
		},
	}

	krbInfo := &server.KubeRBACProxyInfo{
		AllowPaths: []string{"/metrics"},
		Authorization: &authorization.AuthzConfig{
			RewriteAttributesConfig: &rewrite.RewriteAttributesConfig{
				Rewrites: &rewrite.SubjectAccessReviewRewrites{
					ByHTTPHeader: &rewrite.HTTPHeaderRewriteConfig{
						Name: "x-namespace",
					},
				},
				ResourceAttributes: &rewrite.ResourceAttributes{
					Resource:  "namespaces",
					Namespace: "{{ .Value }}",
				},
			},
			Static: []static.StaticAuthorizationConfig{
				{
					User: static.UserConfig{
						Name: "system:serviceaccount:default:client-with-static",
					},
					ResourceRequest: true,
					Resource:        "namespaces",
					Namespace:       "kube-system",
					Verb:            "get",
				},
			},
		},
	}

	delegatedAuthz := &serverconfig.AuthorizationInfo{
		Authorizer: mockDelegated,
	}

	authz, err := setupAuthorizer(krbInfo, delegatedAuthz)
	if err != nil {
		t.Fatalf("setupAuthorizer failed: %v", err)
	}

	for _, tt := range []struct {
		name           string
		user           user.Info
		verb           string
		path           string
		headerValue    string
		expectDecision authorizer.Decision
	}{
		{
			name:           "non-allow-path should be denied",
			user:           &user.DefaultInfo{Name: "system:serviceaccount:default:client-with-static"},
			verb:           "get",
			path:           "/forbidden",
			expectDecision: authorizer.DecisionDeny,
		},
		{
			name:           "allow-path with static auth match should be allowed",
			user:           &user.DefaultInfo{Name: "system:serviceaccount:default:client-with-static"},
			verb:           "get",
			path:           "/metrics",
			headerValue:    "kube-system",
			expectDecision: authorizer.DecisionAllow,
		},
		{
			name:           "allow-path with no static match but delegated match should be allowed",
			user:           &user.DefaultInfo{Name: "system:serviceaccount:default:client-with-rbac"},
			verb:           "get",
			path:           "/metrics",
			headerValue:    "default",
			expectDecision: authorizer.DecisionAllow,
		},
		{
			name:           "allow-path with no static match and no delegated match should be denied",
			user:           &user.DefaultInfo{Name: "other-user"},
			verb:           "get",
			path:           "/metrics",
			headerValue:    "other-namespace",
			expectDecision: authorizer.DecisionDeny,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "http://example.com"+tt.path, nil)
			if tt.headerValue != "" {
				req.Header.Set("x-namespace", tt.headerValue)
			}

			params := []string{}
			if tt.headerValue != "" {
				params = append(params, tt.headerValue)
			}
			ctx := rewrite.WithKubeRBACProxyParams(context.Background(), params)

			attr := authorizer.AttributesRecord{
				User:            tt.user,
				Verb:            tt.verb,
				Path:            tt.path,
				ResourceRequest: false,
			}

			decision, reason, err := authz.Authorize(ctx, &attr)
			if err != nil {
				t.Fatalf("Authorization failed: %v", err)
			}

			if decision != tt.expectDecision {
				t.Errorf("Expected decision %v, got %v (reason: %s)", tt.expectDecision, decision, reason)
			}
		})
	}
}

func TestSetupAuthorizer_IgnorePathsWithResourceAttributes(t *testing.T) {
	mockDelegated := &mockAuthorizer{
		authorize: func(ctx context.Context, a authorizer.Attributes) (authorizer.Decision, string, error) {
			if a.GetUser().GetName() == "system:serviceaccount:default:client-with-rbac" {
				return authorizer.DecisionAllow, "delegated allow", nil
			}
			return authorizer.DecisionDeny, "delegated deny", nil
		},
	}

	krbInfo := &server.KubeRBACProxyInfo{
		IgnorePaths: []string{"/healthz"},
		Authorization: &authorization.AuthzConfig{
			RewriteAttributesConfig: &rewrite.RewriteAttributesConfig{
				ResourceAttributes: &rewrite.ResourceAttributes{
					Resource:  "namespaces",
					Namespace: "kube-system",
				},
			},
			Static: []static.StaticAuthorizationConfig{
				{
					User: static.UserConfig{
						Name: "system:serviceaccount:default:client-with-static",
					},
					ResourceRequest: true,
					Resource:        "namespaces",
					Namespace:       "kube-system",
					Verb:            "get",
				},
			},
		},
	}

	delegatedAuthz := &serverconfig.AuthorizationInfo{
		Authorizer: mockDelegated,
	}

	authz, err := setupAuthorizer(krbInfo, delegatedAuthz)
	if err != nil {
		t.Fatalf("setupAuthorizer failed: %v", err)
	}

	for _, tt := range []struct {
		name           string
		user           user.Info
		verb           string
		path           string
		expectDecision authorizer.Decision
	}{
		{
			name:           "ignore-path should be allowed",
			user:           &user.DefaultInfo{Name: "any-user"},
			verb:           "get",
			path:           "/healthz",
			expectDecision: authorizer.DecisionAllow,
		},
		{
			name:           "non-ignore-path with static auth match should be allowed",
			user:           &user.DefaultInfo{Name: "system:serviceaccount:default:client-with-static"},
			verb:           "get",
			path:           "/metrics",
			expectDecision: authorizer.DecisionAllow,
		},
		{
			name:           "non-ignore-path with no static match but delegated match should be allowed",
			user:           &user.DefaultInfo{Name: "system:serviceaccount:default:client-with-rbac"},
			verb:           "get",
			path:           "/metrics",
			expectDecision: authorizer.DecisionAllow,
		},
		{
			name:           "non-ignore-path with no static and no delegated match should be denied",
			user:           &user.DefaultInfo{Name: "unknown-user"},
			verb:           "get",
			path:           "/metrics",
			expectDecision: authorizer.DecisionDeny,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			attr := authorizer.AttributesRecord{
				User:            tt.user,
				Verb:            tt.verb,
				Path:            tt.path,
				ResourceRequest: false,
			}

			decision, reason, err := authz.Authorize(ctx, &attr)
			if err != nil {
				t.Fatalf("Authorization failed: %v", err)
			}

			if decision != tt.expectDecision {
				t.Errorf("Expected decision %v, got %v (reason: %s)", tt.expectDecision, decision, reason)
			}
		})
	}
}
