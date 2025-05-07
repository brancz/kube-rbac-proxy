package app

import (
	"context"
	"testing"

	"k8s.io/apiserver/pkg/authorization/authorizer"
	serverconfig "k8s.io/apiserver/pkg/server"

	authz "github.com/brancz/kube-rbac-proxy/pkg/authorization"
	"github.com/brancz/kube-rbac-proxy/pkg/authorization/rewrite"
	"github.com/brancz/kube-rbac-proxy/pkg/authorization/static"
	"github.com/brancz/kube-rbac-proxy/pkg/server"
)

type ConfigBuilder struct {
	config *server.KubeRBACProxyInfo
}

func NewConfigBuilder() *ConfigBuilder {
	return &ConfigBuilder{
		config: &server.KubeRBACProxyInfo{
			Authorization: &authz.AuthzConfig{
				RewriteAttributesConfig: &rewrite.RewriteAttributesConfig{},
			},
		},
	}
}

func (b *ConfigBuilder) WithPaths(paths []string) *ConfigBuilder {
	b.config.IgnorePaths = paths
	return b
}

func (b *ConfigBuilder) WithResourceAttributesRewrite(resourceAttrs *rewrite.ResourceAttributes) *ConfigBuilder {
	if b.config.Authorization == nil {
		b.config.Authorization = &authz.AuthzConfig{}
	}

	// Initialize the embedded RewriteAttributesConfig pointer if it's nil
	if b.config.Authorization.RewriteAttributesConfig == nil {
		b.config.Authorization.RewriteAttributesConfig = &rewrite.RewriteAttributesConfig{}
	}

	b.config.Authorization.ResourceAttributes = resourceAttrs
	b.config.Authorization.Rewrites = nil

	return b
}

func (b *ConfigBuilder) WithStatic(staticConfigs []static.StaticAuthorizationConfig) *ConfigBuilder {
	if b.config.Authorization == nil {
		b.config.Authorization = &authz.AuthzConfig{}
	}
	b.config.Authorization.Static = staticConfigs
	return b
}

func (b *ConfigBuilder) Build() *server.KubeRBACProxyInfo {
	return b.config
}

type authorizerFunc func(ctx context.Context, a authorizer.Attributes) (authorizer.Decision, string, error)

func getAuthorizerFunc(t *testing.T, config *server.KubeRBACProxyInfo, authz authorizer.Authorizer) authorizerFunc {
	t.Helper()

	mustAuthorizer := func(authorizer authorizer.Authorizer, err error) authorizer.Authorizer {
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		return authorizer
	}

	return func(ctx context.Context, a authorizer.Attributes) (authorizer.Decision, string, error) {
		delegatedAuthz := &serverconfig.AuthorizationInfo{
			Authorizer: authz,
		}

		authorizer, err := setupAuthorizer(config, delegatedAuthz)
		return mustAuthorizer(authorizer, err).Authorize(ctx, a)
	}
}

type mockAuthorizer func(context.Context, authorizer.Attributes) (authorizer.Decision, string, error)

func makeAuthorizer(m func(context.Context, authorizer.Attributes) (authorizer.Decision, string, error)) authorizer.Authorizer {
	return mockAuthorizer(m)
}

func (m mockAuthorizer) Authorize(ctx context.Context, a authorizer.Attributes) (authorizer.Decision, string, error) {
	return m(ctx, a)
}

func decisionToString(d authorizer.Decision) string {
	switch d {
	case authorizer.DecisionDeny:
		return "deny"
	case authorizer.DecisionAllow:
		return "allow"
	case authorizer.DecisionNoOpinion:
		return "no opinion"
	}
	return "unknown"
}
