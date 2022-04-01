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
	"strings"
	"sync"
	"text/template"

	"github.com/brancz/kube-rbac-proxy/pkg/authn"
	"github.com/brancz/kube-rbac-proxy/pkg/authz"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
)

// Config holds proxy authorization and authentication settings
type Config struct {
	Authentication *authn.AuthnConfig
	Authorizations []*authz.Config
}

type kubeRBACProxy struct {
	// authenticator identifies the user for requests to kube-rbac-proxy
	authenticator.Request
	// authorizer determines whether a given authorization.Attributes is allowed
	authorizer.Authorizer
	// authorizerAttributesGetter implements retrieving authorization attributes for a respective request.
	authorizerAttributesGetter *krpAuthorizerAttributesGetter
	// config for kube-rbac-proxy
	Config Config
}

func new(authenticator authenticator.Request, authorizer authorizer.Authorizer, config Config) *kubeRBACProxy {
	return &kubeRBACProxy{authenticator, authorizer, newKubeRBACProxyAuthorizerAttributesGetter(config.Authorizations), config}
}

// New creates an authenticator, an authorizer, and a matching authorizer attributes getter compatible with the kube-rbac-proxy
func New(client clientset.Interface, config Config, authorizer authorizer.Authorizer, authenticator authenticator.Request) (*kubeRBACProxy, error) {
	return new(authenticator, authorizer, config), nil
}

// Handle authenticates the client and authorizes the request.
// If the authn fails, a 401 error is returned. If the authz fails, a 403 error is returned
func (h *kubeRBACProxy) Handle(w http.ResponseWriter, req *http.Request) bool {
	ctx := req.Context()
	if len(h.Config.Authentication.Token.Audiences) > 0 {
		ctx = authenticator.WithAudiences(ctx, h.Config.Authentication.Token.Audiences)
		req = req.WithContext(ctx)
	}

	// Authenticate
	u, ok, err := h.AuthenticateRequest(req)
	if err != nil {
		klog.Errorf("Unable to authenticate the request due to an error: %v", err)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return false
	}
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return false
	}

	// Get authorization attributes
	allAttrs := h.authorizerAttributesGetter.GetRequestAttributes(u.User, req)
	if len(allAttrs) == 0 {
		msg := "Bad Request. The request or configuration is malformed."
		klog.V(2).Info(msg)
		http.Error(w, msg, http.StatusBadRequest)
		return false
	}

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	for _, attrs := range allAttrs {
		// Authorize concurrently, as there can be many outbound requests to the kube API.
		wg.Add(1)
		go func(attrs authorizer.Attributes) {
			defer wg.Done()
			authorized, reason, err := h.Authorize(ctx, attrs)
			if err != nil {
				msg := fmt.Sprintf("Authorization error (user=%s, verb=%s, resource=%s, subresource=%s)", u.User.GetName(), attrs.GetVerb(), attrs.GetResource(), attrs.GetSubresource())
				klog.Errorf("%s: %s", msg, err)
				http.Error(w, msg, http.StatusInternalServerError)
				cancel()
				return
			}
			if authorized != authorizer.DecisionAllow {
				msg := fmt.Sprintf("Forbidden (user=%s, verb=%s, resource=%s, subresource=%s)", u.User.GetName(), attrs.GetVerb(), attrs.GetResource(), attrs.GetSubresource())
				klog.V(2).Infof("%s. Reason: %q.", msg, reason)
				http.Error(w, msg, http.StatusForbidden)
				cancel()
			}
		}(attrs)
	}
	wg.Wait()
	select {
	case <-ctx.Done():
		// If the context was cancelled by any goroutine, then there was an authz failure.
		return false
	default:
	}

	if h.Config.Authentication.Header.Enabled {
		// Seemingly well-known headers to tell the upstream about user's identity
		// so that the upstream can achieve the original goal of delegating RBAC authn/authz to kube-rbac-proxy
		headerCfg := h.Config.Authentication.Header
		req.Header.Set(headerCfg.UserFieldName, u.User.GetName())
		req.Header.Set(headerCfg.GroupsFieldName, strings.Join(u.User.GetGroups(), headerCfg.GroupSeparator))
	}

	return true
}

func newKubeRBACProxyAuthorizerAttributesGetter(authzConfigs []*authz.Config) *krpAuthorizerAttributesGetter {
	return &krpAuthorizerAttributesGetter{authzConfigs}
}

type krpAuthorizerAttributesGetter struct {
	authzConfigs []*authz.Config
}

// GetRequestAttributes populates authorizer attributes for the requests to kube-rbac-proxy.
func (n krpAuthorizerAttributesGetter) GetRequestAttributes(u user.Info, r *http.Request) []authorizer.Attributes {
	apiVerb := ""
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

	// Default attributes mirror the API attributes that would allow this access to kube-rbac-proxy
	defaultAttributesRecord := authorizer.AttributesRecord{
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
	}

	if len(n.authzConfigs) == 0 {
		allAttrs = append(allAttrs, defaultAttributesRecord)
		return allAttrs
	}

	for _, ac := range n.authzConfigs {
		if ac.ResourceAttributes == nil {
			allAttrs = append(allAttrs, defaultAttributesRecord)
			continue
		}

		if ac.Rewrites == nil {
			allAttrs = append(allAttrs, authorizer.AttributesRecord{
				User:            u,
				Verb:            apiVerb,
				Namespace:       ac.ResourceAttributes.Namespace,
				APIGroup:        ac.ResourceAttributes.APIGroup,
				APIVersion:      ac.ResourceAttributes.APIVersion,
				Resource:        ac.ResourceAttributes.Resource,
				Subresource:     ac.ResourceAttributes.Subresource,
				Name:            ac.ResourceAttributes.Name,
				ResourceRequest: true,
			})
			continue
		}

		params := []string{}
		if ac.Rewrites.ByQueryParameter != nil && ac.Rewrites.ByQueryParameter.Name != "" {
			if ps, ok := r.URL.Query()[ac.Rewrites.ByQueryParameter.Name]; ok {
				params = append(params, ps...)
			}
		}
		if ac.Rewrites.ByHTTPHeader != nil && ac.Rewrites.ByHTTPHeader.Name != "" {
			if p := r.Header.Get(ac.Rewrites.ByHTTPHeader.Name); p != "" {
				params = append(params, p)
			}
		}

		if len(params) == 0 {
			continue
		}

		for _, param := range params {
			attrs := authorizer.AttributesRecord{
				User:            u,
				Verb:            apiVerb,
				Namespace:       templateWithValue(ac.ResourceAttributes.Namespace, param),
				APIGroup:        templateWithValue(ac.ResourceAttributes.APIGroup, param),
				APIVersion:      templateWithValue(ac.ResourceAttributes.APIVersion, param),
				Resource:        templateWithValue(ac.ResourceAttributes.Resource, param),
				Subresource:     templateWithValue(ac.ResourceAttributes.Subresource, param),
				Name:            templateWithValue(ac.ResourceAttributes.Name, param),
				ResourceRequest: true,
			}
			allAttrs = append(allAttrs, attrs)
		}
	}
	return allAttrs
}

// DeepCopy of Proxy Configuration
func (c *Config) DeepCopy() *Config {
	res := &Config{
		Authentication: &authn.AuthnConfig{},
	}

	if c.Authentication != nil {
		res.Authentication = &authn.AuthnConfig{}

		if c.Authentication.X509 != nil {
			res.Authentication.X509 = &authn.X509Config{
				ClientCAFile: c.Authentication.X509.ClientCAFile,
			}
		}

		if c.Authentication.Header != nil {
			res.Authentication.Header = &authn.AuthnHeaderConfig{
				Enabled:         c.Authentication.Header.Enabled,
				UserFieldName:   c.Authentication.Header.UserFieldName,
				GroupsFieldName: c.Authentication.Header.GroupsFieldName,
				GroupSeparator:  c.Authentication.Header.GroupSeparator,
			}
		}
	}

	if len(c.Authorizations) != 0 {
		for _, a := range c.Authorizations {
			if a != nil && a.ResourceAttributes != nil {
				res.Authorizations = append(res.Authorizations, &authz.Config{
					ResourceAttributes: &authz.ResourceAttributes{
						Namespace:   a.ResourceAttributes.Namespace,
						APIGroup:    a.ResourceAttributes.APIGroup,
						APIVersion:  a.ResourceAttributes.APIVersion,
						Resource:    a.ResourceAttributes.Resource,
						Subresource: a.ResourceAttributes.Subresource,
						Name:        a.ResourceAttributes.Name,
					},
				})
			}
		}
	}

	return res
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
