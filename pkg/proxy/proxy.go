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

package proxy

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/textproto"
	"text/template"

	"github.com/brancz/kube-rbac-proxy/pkg/authn"
	"github.com/brancz/kube-rbac-proxy/pkg/authz"

	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/request"
)

var _ authorizer.Authorizer = &krpAuthorizer{}

const kubeRBACProxyParamsKey = iota

// Config holds proxy authorization and authentication settings
type Config struct {
	Authentication *authn.AuthnConfig
	Authorization  *authz.Config
}

func NewKubeRBACProxyAuthorizer(delegate authorizer.Authorizer, authzConfig *authz.Config) *krpAuthorizer {
	return &krpAuthorizer{
		authzConfig: authzConfig,
		delegate:    delegate,
	}
}

type krpAuthorizer struct {
	authzConfig *authz.Config
	delegate    authorizer.Authorizer
}

// GetRequestAttributes populates authorizer attributes for the requests to kube-rbac-proxy.
func (n *krpAuthorizer) Authorize(ctx context.Context, attrs authorizer.Attributes) (authorizer.Decision, string, error) {
	proxyAttrs := n.getKubeRBACProxyAuthzAttributes(ctx, attrs)

	if len(proxyAttrs) == 0 {
		return authorizer.DecisionDeny,
			"The request or configuration is malformed.",
			fmt.Errorf("bad request. The request or configuration is malformed")
	}

	var (
		authorized authorizer.Decision
		reason     string
		err        error
	)
	for _, at := range proxyAttrs {
		authorized, reason, err = n.delegate.Authorize(ctx, at)
		if err != nil {
			return authorizer.DecisionDeny,
				"AuthorizationError",
				fmt.Errorf("authorization error (user=%s, verb=%s, resource=%s, subresource=%s): %w", at.GetName(), at.GetVerb(), at.GetResource(), at.GetSubresource(), err)
		}
		if authorized != authorizer.DecisionAllow {
			return authorizer.DecisionDeny,
				fmt.Sprintf("Forbidden (user=%s, verb=%s, resource=%s, subresource=%s): %s", at.GetName(), at.GetVerb(), at.GetResource(), at.GetSubresource(), reason),
				nil
		}
	}

	if authorized == authorizer.DecisionAllow {
		return authorized, "", nil
	}

	return authorizer.DecisionDeny,
		"No attribute combination matched",
		nil
}

func (n *krpAuthorizer) getKubeRBACProxyAuthzAttributes(ctx context.Context, origAttrs authorizer.Attributes) []authorizer.Attributes {
	u := origAttrs.GetUser()
	apiVerb := origAttrs.GetVerb()
	path := origAttrs.GetPath()

	attrs := []authorizer.Attributes{}
	if n.authzConfig.ResourceAttributes == nil {
		// Default attributes mirror the API attributes that would allow this access to kube-rbac-proxy
		return append(attrs,
			authorizer.AttributesRecord{
				User:            u,
				Verb:            apiVerb,
				ResourceRequest: false,
				Path:            path,
			})
	}

	if n.authzConfig.Rewrites == nil {
		return append(attrs,
			authorizer.AttributesRecord{
				User:            u,
				Verb:            apiVerb,
				Namespace:       n.authzConfig.ResourceAttributes.Namespace,
				APIGroup:        n.authzConfig.ResourceAttributes.APIGroup,
				APIVersion:      n.authzConfig.ResourceAttributes.APIVersion,
				Resource:        n.authzConfig.ResourceAttributes.Resource,
				Subresource:     n.authzConfig.ResourceAttributes.Subresource,
				Name:            n.authzConfig.ResourceAttributes.Name,
				ResourceRequest: true,
			})

	}

	params := GetKubeRBACProxyParams(ctx)
	if len(params) == 0 {
		return nil
	}

	for _, param := range params {
		attrs = append(attrs,
			authorizer.AttributesRecord{
				User:            u,
				Verb:            apiVerb,
				Namespace:       templateWithValue(n.authzConfig.ResourceAttributes.Namespace, param),
				APIGroup:        templateWithValue(n.authzConfig.ResourceAttributes.APIGroup, param),
				APIVersion:      templateWithValue(n.authzConfig.ResourceAttributes.APIVersion, param),
				Resource:        templateWithValue(n.authzConfig.ResourceAttributes.Resource, param),
				Subresource:     templateWithValue(n.authzConfig.ResourceAttributes.Subresource, param),
				Name:            templateWithValue(n.authzConfig.ResourceAttributes.Name, param),
				ResourceRequest: true,
			})
	}

	return attrs
}

func templateWithValue(templateString, value string) string {
	tmpl, _ := template.New("valueTemplate").Parse(templateString)
	out := bytes.NewBuffer(nil)
	err := tmpl.Execute(out, struct{ Value string }{Value: value})
	if err != nil {
		return ""
	}
	return out.String()
}

func WithKubeRBACProxyParamsHandler(handler http.Handler, authzConfig *authz.Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(WithKubeRBACProxyParams(r.Context(), requestToParams(authzConfig, r)))
		handler.ServeHTTP(w, r)
	})
}

func requestToParams(config *authz.Config, req *http.Request) []string {
	params := []string{}
	if config.Rewrites == nil {
		return nil
	}

	if config.Rewrites.ByQueryParameter != nil && config.Rewrites.ByQueryParameter.Name != "" {
		if ps, ok := req.URL.Query()[config.Rewrites.ByQueryParameter.Name]; ok {
			params = append(params, ps...)
		}
	}
	if config.Rewrites.ByHTTPHeader != nil && config.Rewrites.ByHTTPHeader.Name != "" {
		mimeHeader := textproto.MIMEHeader(req.Header)
		mimeKey := textproto.CanonicalMIMEHeaderKey(config.Rewrites.ByHTTPHeader.Name)
		if ps, ok := mimeHeader[mimeKey]; ok {
			params = append(params, ps...)
		}
	}
	return params
}

func WithKubeRBACProxyParams(ctx context.Context, params []string) context.Context {
	return request.WithValue(ctx, kubeRBACProxyParamsKey, params)
}

func GetKubeRBACProxyParams(ctx context.Context) []string {
	params, ok := ctx.Value(kubeRBACProxyParamsKey).([]string)
	if !ok {
		return nil
	}
	return params
}
