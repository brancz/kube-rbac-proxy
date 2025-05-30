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
	"fmt"
	"net/http"
	"testing"

	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	serverconfig "k8s.io/apiserver/pkg/server"

	"github.com/brancz/kube-rbac-proxy/pkg/authorization"
	"github.com/brancz/kube-rbac-proxy/pkg/authorization/rewrite"
	"github.com/brancz/kube-rbac-proxy/pkg/authorization/static"
	"github.com/brancz/kube-rbac-proxy/pkg/server"
)

type mockAuthorizer func(ctx context.Context, a authorizer.Attributes) (authorizer.Decision, string, error)

func (m mockAuthorizer) Authorize(ctx context.Context, a authorizer.Attributes) (authorizer.Decision, string, error) {
	return m(ctx, a)
}

func newMockDelegatedAuthorizer() authorizer.Authorizer {
	return mockAuthorizer(
		func(ctx context.Context, a authorizer.Attributes) (authorizer.Decision, string, error) {
			if a.GetUser().GetName() == "system:serviceaccount:default:client-with-rbac" {
				return authorizer.DecisionAllow, "delegated allow", nil
			}
			if a.GetUser().GetName() == "system:serviceaccount:default:client-with-errbac" {
				return authorizer.DecisionDeny, "delegated deny", fmt.Errorf("delegated error")
			}
			return authorizer.DecisionNoOpinion, "i don't care", nil
		},
	)
}

func TestSetupAuthorizer_AllowPathsWithRewriteAndStaticAuth(t *testing.T) {
	defaultKubeRBACProxyInfo := func() *server.KubeRBACProxyInfo {
		return &server.KubeRBACProxyInfo{
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
	}
	mockDelegated := newMockDelegatedAuthorizer()

	krbInfo := defaultKubeRBACProxyInfo()

	errStatic := defaultKubeRBACProxyInfo()
	errStatic.Authorization.Static[0].ResourceRequest = false

	errPath := defaultKubeRBACProxyInfo()
	errPath.AllowPaths = []string{"/foo/*/metrics"}
	errPath.Authorization.Static[0].ResourceRequest = false

	for _, tt := range []struct {
		name             string
		user             string
		verb             string
		path             string
		headerValue      string
		krbInfo          *server.KubeRBACProxyInfo
		expectDecision   authorizer.Decision
		expectAuthzError bool
		expectSetupError bool
	}{
		{
			name:           "non-allow-path should be denied",
			user:           "system:serviceaccount:default:client-with-static",
			verb:           "get",
			path:           "/forbidden",
			expectDecision: authorizer.DecisionDeny,
		},
		{
			name:           "allow-path with static auth match should be allowed",
			user:           "system:serviceaccount:default:client-with-static",
			verb:           "get",
			path:           "/metrics",
			headerValue:    "kube-system",
			expectDecision: authorizer.DecisionAllow,
		},
		{
			name:           "allow-path with no static match but delegated match should be allowed",
			user:           "system:serviceaccount:default:client-with-rbac",
			verb:           "get",
			path:           "/metrics",
			headerValue:    "default",
			expectDecision: authorizer.DecisionAllow,
		},
		{
			name:           "allow-path with no static match and no delegated match should be denied",
			user:           "other-user",
			verb:           "get",
			path:           "/metrics",
			headerValue:    "other-namespace",
			expectDecision: authorizer.DecisionDeny, // The krp logic is to deny on no-opinion
		},
		{
			name:             "everything looks fine, except that we receive an error from the delegated authz",
			user:             "system:serviceaccount:default:client-with-errbac",
			verb:             "get",
			path:             "/metrics",
			headerValue:      "default",
			expectDecision:   authorizer.DecisionDeny,
			expectAuthzError: true,
		},
		{
			name:             "everything looks fine, except that we screwed up the static auth config",
			user:             "system:serviceaccount:default:client-with-rbac",
			verb:             "get",
			path:             "/metrics",
			headerValue:      "default",
			krbInfo:          errStatic,
			expectAuthzError: false,
			expectSetupError: true,
		},
		{
			name:             "everything looks fine, except that we screwed up the allow path config",
			user:             "system:serviceaccount:default:client-with-rbac",
			verb:             "get",
			path:             "/foo/bar/metrics",
			krbInfo:          errPath,
			expectAuthzError: false,
			expectSetupError: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if tt.krbInfo == nil {
				tt.krbInfo = krbInfo
			}

			authz, err := setupAuthorizer(tt.krbInfo, &serverconfig.AuthorizationInfo{
				Authorizer: mockDelegated,
			})
			if err != nil && !tt.expectSetupError {
				t.Fatalf("setupAuthorizer failed: %v", err)
			}
			if err == nil && tt.expectSetupError {
				t.Fatalf("setupAuthorizer should have failed, but didn't")
			}
			if tt.expectSetupError {
				return
			}

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
				User:            &user.DefaultInfo{Name: tt.user},
				Verb:            tt.verb,
				Path:            tt.path,
				ResourceRequest: false,
			}

			decision, reason, err := authz.Authorize(ctx, &attr)
			if err != nil && !tt.expectAuthzError {
				t.Fatalf("Authorization failed: %v", err)
			}
			if err == nil && tt.expectAuthzError {
				t.Fatalf("Authorization should have failed, but didn't")
			}
			if decision != tt.expectDecision {
				t.Errorf("Expected decision %v, got %v (reason: %s)", tt.expectDecision, decision, reason)
			}
		})
	}
}

func TestSetupAuthorizer_IgnorePathsWithResourceAttributes(t *testing.T) {
	defaultKubeRBACProxyInfo := func() *server.KubeRBACProxyInfo {
		return &server.KubeRBACProxyInfo{
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
	}

	mockDelegated := newMockDelegatedAuthorizer()

	krbInfo := defaultKubeRBACProxyInfo()

	errPath := defaultKubeRBACProxyInfo()
	errPath.AllowPaths = []string{"/foo/*/metrics"}
	errPath.IgnorePaths = nil
	errPath.Authorization.RewriteAttributesConfig.Rewrites = &rewrite.SubjectAccessReviewRewrites{
		ByHTTPHeader: &rewrite.HTTPHeaderRewriteConfig{
			Name: "x-namespace",
		},
	}
	errPath.Authorization.RewriteAttributesConfig.ResourceAttributes.Namespace = "{{ .Value }}"
	errPath.Authorization.Static[0].ResourceRequest = false

	for _, tt := range []struct {
		name             string
		user             string
		verb             string
		path             string
		krbInfo          *server.KubeRBACProxyInfo
		expectDecision   authorizer.Decision
		expectAuthzError bool
		expectSetupError bool
	}{
		{
			name:           "ignore-path should be allowed",
			user:           "any-user",
			verb:           "get",
			path:           "/healthz",
			expectDecision: authorizer.DecisionAllow,
		},
		{
			name:           "non-ignore-path with static auth match should be allowed",
			user:           "system:serviceaccount:default:client-with-static",
			verb:           "get",
			path:           "/metrics",
			expectDecision: authorizer.DecisionAllow,
		},
		{
			name:           "non-ignore-path with no static match but delegated match should be allowed",
			user:           "system:serviceaccount:default:client-with-rbac",
			verb:           "get",
			path:           "/metrics",
			expectDecision: authorizer.DecisionAllow,
		},
		{
			name:           "non-ignore-path with no static and no delegated match should be denied",
			user:           "unknown-user",
			verb:           "get",
			path:           "/metrics",
			expectDecision: authorizer.DecisionDeny,
		},
		{
			name:             "everything looks fine, except that we receive an error from the delegated authz",
			user:             "system:serviceaccount:default:client-with-errbac",
			verb:             "get",
			path:             "/metrics",
			expectDecision:   authorizer.DecisionDeny,
			expectAuthzError: true,
		},
		{
			name:             "everything looks fine, except that we screwed up the ignore path config",
			user:             "system:serviceaccount:default:client-with-rbac",
			verb:             "get",
			path:             "/foo/bar/metrics",
			krbInfo:          errPath,
			expectAuthzError: false,
			expectSetupError: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			if tt.krbInfo == nil {
				tt.krbInfo = krbInfo
			}
			authz, err := setupAuthorizer(tt.krbInfo, &serverconfig.AuthorizationInfo{
				Authorizer: mockDelegated,
			})
			if err != nil && !tt.expectSetupError {
				t.Fatalf("setupAuthorizer failed: %v", err)
			}
			if err == nil && tt.expectSetupError {
				t.Fatalf("setupAuthorizer should have failed, but didn't")
			}
			if tt.expectSetupError {
				return
			}

			attr := authorizer.AttributesRecord{
				User:            &user.DefaultInfo{Name: tt.user},
				Verb:            tt.verb,
				Path:            tt.path,
				ResourceRequest: false,
			}

			decision, reason, err := authz.Authorize(ctx, &attr)
			if err != nil && !tt.expectAuthzError {
				t.Fatalf("Authorization failed: %v", err)
			}
			if err == nil && tt.expectAuthzError {
				t.Fatalf("Authorization should have failed, but didn't")
			}
			if decision != tt.expectDecision {
				t.Errorf("Expected decision %v, got %v (reason: %s)", tt.expectDecision, decision, reason)
			}
		})
	}
}
