/*
Copyright 2023 the kube-rbac-proxy maintainers. All rights reserved.

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

package rewrite

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/textproto"
	"text/template"

	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/request"
)

var _ authorizer.Authorizer = &rewritingAuthorizer{}

// TODO(enj): use a dedicated type
const rewriterParams = iota

type RewriteAttributesConfig struct {
	Rewrites           *SubjectAccessReviewRewrites `json:"rewrites,omitempty"`
	ResourceAttributes *ResourceAttributes          `json:"resourceAttributes,omitempty"`
}

// SubjectAccessReviewRewrites describes how SubjectAccessReview may be
// rewritten on a given request.
type SubjectAccessReviewRewrites struct {
	ByQueryParameter *QueryParameterRewriteConfig `json:"byQueryParameter,omitempty"`
	ByHTTPHeader     *HTTPHeaderRewriteConfig     `json:"byHttpHeader,omitempty"`
}

// QueryParameterRewriteConfig describes which HTTP URL query parameter is to
// be used to rewrite a SubjectAccessReview on a given request.
type QueryParameterRewriteConfig struct {
	Name string `json:"name,omitempty"`
}

// HTTPHeaderRewriteConfig describes which HTTP header is to
// be used to rewrite a SubjectAccessReview on a given request.
type HTTPHeaderRewriteConfig struct {
	Name string `json:"name,omitempty"`
}

// ResourceAttributes describes attributes available for resource request authorization
type ResourceAttributes struct {
	Namespace   string `json:"namespace,omitempty"`
	APIGroup    string `json:"apiGroup,omitempty"`
	APIVersion  string `json:"apiVersion,omitempty"`
	Resource    string `json:"resource,omitempty"`
	Subresource string `json:"subresource,omitempty"`
	Name        string `json:"name,omitempty"`
}

func NewRewritingAuthorizer(delegate authorizer.Authorizer, config *RewriteAttributesConfig) authorizer.Authorizer {
	return &rewritingAuthorizer{
		config:   config,
		delegate: delegate,
	}
}

type rewritingAuthorizer struct {
	config   *RewriteAttributesConfig
	delegate authorizer.Authorizer
}

// GetRequestAttributes populates authorizer attributes for the requests to kube-rbac-proxy.
func (n *rewritingAuthorizer) Authorize(ctx context.Context, attrs authorizer.Attributes) (authorizer.Decision, string, error) {
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
	// TODO(enj): describe that this is saying that all proxy attrs must be allowed for this overall statement to be allowed
	for _, at := range proxyAttrs {
		authorized, reason, err = n.delegate.Authorize(ctx, at)
		// TODO(enj): this fails on error unlike the regular union, so maybe we always want it to fail on error?
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
		return authorizer.DecisionAllow, "", nil
	}

	return authorizer.DecisionDeny,
		"No attribute combination matched",
		nil
}

func (n *rewritingAuthorizer) getKubeRBACProxyAuthzAttributes(ctx context.Context, origAttrs authorizer.Attributes) []authorizer.Attributes {
	u := origAttrs.GetUser()
	apiVerb := origAttrs.GetVerb()
	// path := origAttrs.GetPath()

	attrs := []authorizer.Attributes{}
	if n.config.ResourceAttributes == nil {
		// Default attributes mirror the API attributes that would allow this access to kube-rbac-proxy
		// TODO(enj): this seems to drop a bunch of data from origAttrs, is this on purpose?
		//  /apis/namespace/name would get changed from a resource request to a non-resource request?
		// return append(attrs,
		// 	authorizer.AttributesRecord{
		// 		User:            u,
		// 		Verb:            apiVerb,
		// 		ResourceRequest: false,
		// 		Path:            path,
		// 	})
		return []authorizer.Attributes{origAttrs}
	}

	// TODO(enj): describe that this turns a dynamic path based authz check into a static resource authz check
	if n.config.Rewrites == nil {
		return append(attrs,
			authorizer.AttributesRecord{
				User:            u,
				Verb:            apiVerb,
				Namespace:       n.config.ResourceAttributes.Namespace,
				APIGroup:        n.config.ResourceAttributes.APIGroup,
				APIVersion:      n.config.ResourceAttributes.APIVersion,
				Resource:        n.config.ResourceAttributes.Resource,
				Subresource:     n.config.ResourceAttributes.Subresource,
				Name:            n.config.ResourceAttributes.Name,
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
				Namespace:       templateWithValue(n.config.ResourceAttributes.Namespace, param),
				APIGroup:        templateWithValue(n.config.ResourceAttributes.APIGroup, param),
				APIVersion:      templateWithValue(n.config.ResourceAttributes.APIVersion, param),
				Resource:        templateWithValue(n.config.ResourceAttributes.Resource, param),
				Subresource:     templateWithValue(n.config.ResourceAttributes.Subresource, param),
				Name:            templateWithValue(n.config.ResourceAttributes.Name, param),
				ResourceRequest: true,
			})
	}

	return attrs
}

func templateWithValue(templateString, value string) string {
	// TODO(enj): make sure on process startup when rewrites are specified that these all valid templates
	//  and also pre-parse and have them ready for re-use instead of doing it on every request
	tmpl, _ := template.New("valueTemplate").Parse(templateString)
	out := bytes.NewBuffer(nil) // TODO(enj): consider using a sync.Pool with buffers that are reset
	err := tmpl.Execute(out, struct{ Value string }{Value: value})
	if err != nil {
		return ""
	}
	return out.String()
}

func WithKubeRBACProxyParamsHandler(handler http.Handler, config *RewriteAttributesConfig) http.Handler {
	if config == nil {
		return handler
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO(enj): this needs to describe why we are taking untrusted input and doing magic re-writes with it
		r = r.WithContext(WithKubeRBACProxyParams(r.Context(), requestToParams(config, r)))
		handler.ServeHTTP(w, r)
	})
}

func requestToParams(config *RewriteAttributesConfig, req *http.Request) []string {
	params := []string{}
	if config.Rewrites == nil {
		return nil
	}

	// TODO(enj): if this can be collapsed into either by query OR by header, this entire logic can be
	//  moved into a custom request info parser.  that would imply that there can only be a single
	//  query param as well.

	if config.Rewrites.ByQueryParameter != nil && config.Rewrites.ByQueryParameter.Name != "" {
		if ps, ok := req.URL.Query()[config.Rewrites.ByQueryParameter.Name]; ok {
			params = append(params, ps...)
		}
	}
	// TODO(enj): if you only support using a single header, make sure to fail if there is more than one
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
	if params == nil {
		return ctx
	}
	return request.WithValue(ctx, rewriterParams, params)
}

func GetKubeRBACProxyParams(ctx context.Context) []string {
	params, _ := ctx.Value(rewriterParams).([]string)
	return params
}
