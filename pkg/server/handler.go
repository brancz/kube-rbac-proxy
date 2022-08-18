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

package server

import (
	"bytes"
	"fmt"
	"net/http"
	"net/textproto"
	"strings"
	"text/template"

	"github.com/brancz/kube-rbac-proxy/pkg/authn"
	"github.com/brancz/kube-rbac-proxy/pkg/authz"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/klog/v2"
)

// Config holds proxy authorization and authentication settings
type Config struct {
	Authentication *authn.AuthnConfig
	Authorization  *authz.Config
}

func WithAuthentication(handler http.Handler, authReq authenticator.Request, audiences []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
		if len(audiences) > 0 {
			ctx = authenticator.WithAudiences(ctx, audiences)
			req = req.WithContext(ctx)
		}

		res, ok, err := authReq.AuthenticateRequest(req)
		if err != nil {
			klog.Errorf("Unable to authenticate the request due to an error: %v", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		req = req.WithContext(request.WithUser(req.Context(), res.User))
		handler.ServeHTTP(w, req)
	})
}

func WithAuthorization(
	handler http.Handler,
	authz authorizer.Authorizer,
	cfg *authz.Config,
) http.Handler {
	authzAttrGetter := newKubeRBACProxyAuthorizerAttributesGetter(cfg).GetRequestAttributes
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		u, ok := request.UserFrom(req.Context())
		if !ok {
			http.Error(w, "user not in context", http.StatusUnauthorized)
			return
		}

		allAttrs := authzAttrGetter(u, req)
		if len(allAttrs) == 0 {
			msg := "Bad Request. The request or configuration is malformed."
			klog.V(2).Info(msg)
			http.Error(w, msg, http.StatusBadRequest)
			return
		}

		for _, attrs := range allAttrs {
			// Authorize
			authorized, reason, err := authz.Authorize(req.Context(), attrs)
			if err != nil {
				msg := fmt.Sprintf("Authorization error (user=%s, verb=%s, resource=%s, subresource=%s)", u.GetName(), attrs.GetVerb(), attrs.GetResource(), attrs.GetSubresource())
				klog.Errorf("%s: %s", msg, err)
				http.Error(w, msg, http.StatusInternalServerError)
				return
			}
			if authorized != authorizer.DecisionAllow {
				msg := fmt.Sprintf("Forbidden (user=%s, verb=%s, resource=%s, subresource=%s)", u.GetName(), attrs.GetVerb(), attrs.GetResource(), attrs.GetSubresource())
				klog.V(2).Infof("%s. Reason: %q.", msg, reason)
				http.Error(w, msg, http.StatusForbidden)
				return
			}
		}

		handler.ServeHTTP(w, req)
	})
}

// WithAuthHeaders adds identity information to the headers.
// Must not be used, if connection is not encrypted with TLS.
func WithAuthHeaders(handler http.Handler, cfg *authn.AuthnHeaderConfig) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if cfg.Enabled {
			u, ok := request.UserFrom(req.Context())
			if ok {
				// Seemingly well-known headers to tell the upstream about user's identity
				// so that the upstream can achieve the original goal of delegating RBAC authn/authz to kube-rbac-proxy
				req.Header.Set(cfg.UserFieldName, u.GetName())
				req.Header.Set(cfg.GroupsFieldName, strings.Join(u.GetGroups(), cfg.GroupSeparator))
			}
		}

		handler.ServeHTTP(w, req)
	})
}

func newKubeRBACProxyAuthorizerAttributesGetter(authzConfig *authz.Config) *krpAuthorizerAttributesGetter {
	return &krpAuthorizerAttributesGetter{authzConfig}
}

type krpAuthorizerAttributesGetter struct {
	authzConfig *authz.Config
}

// GetRequestAttributes populates authorizer attributes for the requests to kube-rbac-proxy.
func (n krpAuthorizerAttributesGetter) GetRequestAttributes(u user.Info, r *http.Request) []authorizer.Attributes {
	apiVerb := "*"
	switch r.Method {
	case "POST":
		apiVerb = "create"
	case "GET":
		apiVerb = "get"
	case "PUT":
		apiVerb = "update"
	case "PATCH":
		apiVerb = "patch"
	case "DELETE":
		apiVerb = "delete"
	}

	var allAttrs []authorizer.Attributes

	defer func() {
		for attrs := range allAttrs {
			klog.V(5).Infof("kube-rbac-proxy request attributes: attrs=%#+v", attrs)
		}
	}()

	if n.authzConfig.ResourceAttributes == nil {
		// Default attributes mirror the API attributes that would allow this access to kube-rbac-proxy
		allAttrs := append(allAttrs, authorizer.AttributesRecord{
			User:            u,
			Verb:            apiVerb,
			Namespace:       "",
			APIGroup:        "",
			APIVersion:      "",
			Resource:        "",
			Subresource:     "",
			Name:            "",
			ResourceRequest: false,
			Path:            r.URL.Path,
		})
		return allAttrs
	}

	if n.authzConfig.Rewrites == nil {
		allAttrs := append(allAttrs, authorizer.AttributesRecord{
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
		return allAttrs
	}

	params := []string{}
	if n.authzConfig.Rewrites.ByQueryParameter != nil && n.authzConfig.Rewrites.ByQueryParameter.Name != "" {
		if ps, ok := r.URL.Query()[n.authzConfig.Rewrites.ByQueryParameter.Name]; ok {
			params = append(params, ps...)
		}
	}
	if n.authzConfig.Rewrites.ByHTTPHeader != nil && n.authzConfig.Rewrites.ByHTTPHeader.Name != "" {
		mimeHeader := textproto.MIMEHeader(r.Header)
		mimeKey := textproto.CanonicalMIMEHeaderKey(n.authzConfig.Rewrites.ByHTTPHeader.Name)
		if ps, ok := mimeHeader[mimeKey]; ok {
			params = append(params, ps...)
		}
	}

	if len(params) == 0 {
		return allAttrs
	}

	for _, param := range params {
		attrs := authorizer.AttributesRecord{
			User:            u,
			Verb:            apiVerb,
			Namespace:       templateWithValue(n.authzConfig.ResourceAttributes.Namespace, param),
			APIGroup:        templateWithValue(n.authzConfig.ResourceAttributes.APIGroup, param),
			APIVersion:      templateWithValue(n.authzConfig.ResourceAttributes.APIVersion, param),
			Resource:        templateWithValue(n.authzConfig.ResourceAttributes.Resource, param),
			Subresource:     templateWithValue(n.authzConfig.ResourceAttributes.Subresource, param),
			Name:            templateWithValue(n.authzConfig.ResourceAttributes.Name, param),
			ResourceRequest: true,
		}
		allAttrs = append(allAttrs, attrs)
	}
	return allAttrs
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
