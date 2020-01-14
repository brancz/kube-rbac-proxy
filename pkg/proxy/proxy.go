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
	"fmt"
	"net/http"
	"strings"
	"text/template"
	"time"

	"github.com/brancz/kube-rbac-proxy/pkg/authn"
	"github.com/brancz/kube-rbac-proxy/pkg/authz"
	utilcache "k8s.io/apimachinery/pkg/util/cache"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
)

// Config holds proxy authorization and authentication settings
type Config struct {
	Authentication *authn.AuthnConfig
	Authorization  *authz.Config
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
	// StaleCache for caching auth requests
	StaleCache    simpleCache
	StaleCacheTTL time.Duration
}

func new(authenticator authenticator.Request, authorizer authorizer.Authorizer, config Config, staleCacheTTL time.Duration) *kubeRBACProxy {
	proxy := kubeRBACProxy{
		Request:                    authenticator,
		Authorizer:                 authorizer,
		authorizerAttributesGetter: newKubeRBACProxyAuthorizerAttributesGetter(config.Authorization),
		Config:                     config,
		StaleCache:                 FakeCache{},
	}
	if staleCacheTTL > 0*time.Second {
		proxy.StaleCache = utilcache.NewLRUExpireCache(4096)
		proxy.StaleCacheTTL = staleCacheTTL
	}
	return &proxy
}

// New creates an authenticator, an authorizer, and a matching authorizer attributes getter compatible with the kube-rbac-proxy
func New(client clientset.Interface, config Config, authorizer authorizer.Authorizer, authenticator authenticator.Request, staleCacheTTL time.Duration) (*kubeRBACProxy, error) {
	return new(authenticator, authorizer, config, staleCacheTTL), nil
}

// Handle authenticates the client and authorizes the request.
// If the authn fails, a 401 error is returned. If the authz fails, a 403 error is returned
func (h *kubeRBACProxy) Handle(w http.ResponseWriter, req *http.Request) bool {
	token := getTokenFromRequest(req)
	if token == "" {
		klog.Errorf("Unable to get token from request")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return false
	}

	ctx := req.Context()
	if len(h.Config.Authentication.Token.Audiences) > 0 {
		ctx = authenticator.WithAudiences(ctx, h.Config.Authentication.Token.Audiences)
		req = req.WithContext(ctx)
	}

	// Authenticate
	u, ok, err := h.AuthenticateRequest(req)
	if err != nil {
		cachedUser, staleOk := h.StaleCache.Get(token)
		if !staleOk {
			klog.Errorf("Unable to authenticate the request due to an error: %v", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return false
		}
		userResponse := cachedUser.(authenticator.Response)
		u = &userResponse
	}
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		h.StaleCache.Remove(token)
		return false
	}

	// Get authorization attributes
	allAttrs := h.authorizerAttributesGetter.GetRequestAttributes(u.User, req)
	if len(allAttrs) == 0 {
		msg := "Bad Request. The request or configuration is malformed."
		klog.V(2).Info(msg)
		http.Error(w, msg, http.StatusBadRequest)
		h.StaleCache.Remove(token)
		return false
	}

	for _, attrs := range allAttrs {
		// Authorize
		authorized, reason, err := h.Authorize(ctx, attrs)
		if err != nil {
			_, staleOk := h.StaleCache.Get(token)
			if !staleOk {
				msg := fmt.Sprintf("Authorization error (user=%s, verb=%s, resource=%s, subresource=%s)", u.User.GetName(), attrs.GetVerb(), attrs.GetResource(), attrs.GetSubresource())
				klog.Errorf("%s: %s", msg, err)
				http.Error(w, msg, http.StatusInternalServerError)
				h.StaleCache.Remove(token)
				return false
			}
		}
		if authorized != authorizer.DecisionAllow {
			msg := fmt.Sprintf("Forbidden (user=%s, verb=%s, resource=%s, subresource=%s)", u.User.GetName(), attrs.GetVerb(), attrs.GetResource(), attrs.GetSubresource())
			klog.V(2).Infof("%s. Reason: %q.", msg, reason)
			http.Error(w, msg, http.StatusForbidden)
			h.StaleCache.Remove(token)
			return false
		}
	}
	h.StaleCache.Add(token, &u, h.StaleCacheTTL)

	if h.Config.Authentication.Header.Enabled {
		// Seemingly well-known headers to tell the upstream about user's identity
		// so that the upstream can achieve the original goal of delegating RBAC authn/authz to kube-rbac-proxy
		headerCfg := h.Config.Authentication.Header
		req.Header.Set(headerCfg.UserFieldName, u.User.GetName())
		req.Header.Set(headerCfg.GroupsFieldName, strings.Join(u.User.GetGroups(), headerCfg.GroupSeparator))
	}

	return true
}

func newKubeRBACProxyAuthorizerAttributesGetter(authzConfig *authz.Config) *krpAuthorizerAttributesGetter {
	return &krpAuthorizerAttributesGetter{authzConfig}
}

type krpAuthorizerAttributesGetter struct {
	authzConfig *authz.Config
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
		if p := r.Header.Get(n.authzConfig.Rewrites.ByHTTPHeader.Name); p != "" {
			params = append(params, p)
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

	for attrs := range allAttrs {
		klog.V(5).Infof("kube-rbac-proxy request attributes: attrs=%#v", attrs)
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

	if c.Authorization != nil {
		if c.Authorization.ResourceAttributes != nil {
			res.Authorization = &authz.Config{
				ResourceAttributes: &authz.ResourceAttributes{
					Namespace:   c.Authorization.ResourceAttributes.Namespace,
					APIGroup:    c.Authorization.ResourceAttributes.APIGroup,
					APIVersion:  c.Authorization.ResourceAttributes.APIVersion,
					Resource:    c.Authorization.ResourceAttributes.Resource,
					Subresource: c.Authorization.ResourceAttributes.Subresource,
					Name:        c.Authorization.ResourceAttributes.Name,
				},
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

func getTokenFromRequest(req *http.Request) string {
	auth := strings.TrimSpace(req.Header.Get("Authorization"))
	if auth == "" {
		return ""
	}
	parts := strings.Split(auth, " ")
	if len(parts) < 2 || strings.ToLower(parts[0]) != "bearer" {
		return ""
	}
	return parts[1]
}

type simpleCache interface {
	Add(key interface{}, value interface{}, ttl time.Duration)
	Get(key interface{}) (interface{}, bool)
	Remove(key interface{})
	Keys() []interface{}
}

type FakeCache struct{}

func (FakeCache) Add(key interface{}, value interface{}, ttl time.Duration) {}
func (FakeCache) Remove(key interface{})                                    {}
func (FakeCache) Get(key interface{}) (interface{}, bool) {
	return nil, false
}
func (FakeCache) Keys() []interface{} {
	return []interface{}{}
}
