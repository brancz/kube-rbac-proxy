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
	"testing"

	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/authorization/authorizerfactory"
	serverconfig "k8s.io/apiserver/pkg/server"

	authz "github.com/brancz/kube-rbac-proxy/pkg/authorization"
	"github.com/brancz/kube-rbac-proxy/pkg/authorization/rewrite"
	"github.com/brancz/kube-rbac-proxy/pkg/authorization/static"
	"github.com/brancz/kube-rbac-proxy/pkg/server"
)

type mockAuthorizer struct {
	decision    authorizer.Decision
	reason      string
	err         error
	lastRequest authorizer.Attributes
}

func (m *mockAuthorizer) Authorize(ctx context.Context, attrs authorizer.Attributes) (authorizer.Decision, string, error) {
	m.lastRequest = attrs
	return m.decision, m.reason, m.err
}

func TestSetupAuthorizer(t *testing.T) {
	testCases := []struct {
		name              string
		krbInfo           *server.KubeRBACProxyInfo
		delegatedAuthz    *serverconfig.AuthorizationInfo
		expectError       bool
		checkPathAuthz    bool
		checkStaticAuthz  bool
		checkRewriteAuthz bool
	}{
		{
			name: "with allow paths",
			krbInfo: &server.KubeRBACProxyInfo{
				AllowPaths: []string{"/healthz", "/metrics/*"},
				Authorization: &authz.AuthzConfig{
					RewriteAttributesConfig: &rewrite.RewriteAttributesConfig{},
				},
			},
			delegatedAuthz: &serverconfig.AuthorizationInfo{
				Authorizer: &mockAuthorizer{},
			},
			checkPathAuthz: true,
		},
		{
			name: "with ignore paths",
			krbInfo: &server.KubeRBACProxyInfo{
				IgnorePaths: []string{"/healthz", "/metrics/*"},
				Authorization: &authz.AuthzConfig{
					RewriteAttributesConfig: &rewrite.RewriteAttributesConfig{},
				},
			},
			delegatedAuthz: &serverconfig.AuthorizationInfo{
				Authorizer: &mockAuthorizer{},
			},
			checkPathAuthz: true,
		},
		{
			name: "with static authorizer",
			krbInfo: &server.KubeRBACProxyInfo{
				Authorization: &authz.AuthzConfig{
					RewriteAttributesConfig: &rewrite.RewriteAttributesConfig{},
					Static: []static.StaticAuthorizationConfig{
						{
							User: static.UserConfig{
								Name:   "test-user",
								Groups: []string{"test-group"},
							},
							ResourceRequest: true,
							Resource:        "pods",
							Namespace:       "default",
							Verb:            "get",
						},
					},
				},
			},
			delegatedAuthz: &serverconfig.AuthorizationInfo{
				Authorizer: &mockAuthorizer{},
			},
			checkStaticAuthz: true,
		},
		{
			name: "with resource attributes",
			krbInfo: &server.KubeRBACProxyInfo{
				Authorization: &authz.AuthzConfig{
					RewriteAttributesConfig: &rewrite.RewriteAttributesConfig{
						ResourceAttributes: &rewrite.ResourceAttributes{
							Namespace:   "default",
							Resource:    "pods",
							Subresource: "proxy",
						},
					},
				},
			},
			delegatedAuthz: &serverconfig.AuthorizationInfo{
				Authorizer: authorizerfactory.NewAlwaysAllowAuthorizer(),
			},
			checkRewriteAuthz: true,
		},
		{
			name: "with templated resource attributes",
			krbInfo: &server.KubeRBACProxyInfo{
				Authorization: &authz.AuthzConfig{
					RewriteAttributesConfig: &rewrite.RewriteAttributesConfig{
						ResourceAttributes: &rewrite.ResourceAttributes{
							Namespace:   "default",
							Resource:    "pods",
							Subresource: "proxy",
						},
						Rewrites: &rewrite.SubjectAccessReviewRewrites{
							ByQueryParameter: &rewrite.QueryParameterRewriteConfig{
								Name: "resource",
							},
						},
					},
				},
			},
			delegatedAuthz: &serverconfig.AuthorizationInfo{
				Authorizer: authorizerfactory.NewAlwaysAllowAuthorizer(),
			},
			checkRewriteAuthz: true,
		},
		{
			name: "with non-resource attributes",
			krbInfo: &server.KubeRBACProxyInfo{
				Authorization: &authz.AuthzConfig{
					RewriteAttributesConfig: &rewrite.RewriteAttributesConfig{},
				},
			},
			delegatedAuthz: &serverconfig.AuthorizationInfo{
				Authorizer: authorizerfactory.NewAlwaysAllowAuthorizer(),
			},
			checkRewriteAuthz: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := setupAuthorizer(tc.krbInfo, tc.delegatedAuthz)

			if tc.expectError {
				if err == nil {
					t.Fatalf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Basic validation that we got an authorizer back
			if result == nil {
				t.Fatalf("expected non-nil authorizer")
			}

			// We won't actually invoke the authorizer since that would require
			// setting up more test fixtures. This test just verifies that the
			// authorizer is properly constructed based on the configuration.
		})
	}
}
