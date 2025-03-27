/*
Copyright 2022 the kube-rbac-proxy maintainers. All rights reserved.

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

package options

import (
	"github.com/brancz/kube-rbac-proxy/pkg/authn/identityheaders"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"

	authz "github.com/brancz/kube-rbac-proxy/pkg/authorization"
	"github.com/brancz/kube-rbac-proxy/pkg/authorization/rewrite"
	"github.com/brancz/kube-rbac-proxy/pkg/authorization/static"
)

func Test_parseAuthorizationConfigFile(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "configfile.yaml")

	tests := []struct {
		name        string
		fileContent string
		want        *authz.AuthzConfig
		wantErr     bool
	}{
		{
			name: "resources",
			fileContent: `authorization:
  rewrites:
    byQueryParameter:
      name: "namespace"
  resourceAttributes:
    resource: namespaces
    subresource: metrics
    namespace: "{{ .Value }}"
  static:
    - user:
        name: system:serviceaccount:default:default
      resourceRequest: true
      resource: namespaces
      subresource: metrics
      namespace: default
      verb: get`,
			want: &authz.AuthzConfig{
				RewriteAttributesConfig: &rewrite.RewriteAttributesConfig{
					Rewrites: &rewrite.SubjectAccessReviewRewrites{
						ByQueryParameter: &rewrite.QueryParameterRewriteConfig{
							Name: "namespace",
						},
					},
					ResourceAttributes: &rewrite.ResourceAttributes{
						Resource:    "namespaces",
						Subresource: "metrics",
						Namespace:   "{{ .Value }}",
					},
				},
				Static: []static.StaticAuthorizationConfig{
					{
						User: static.UserConfig{
							Name: "system:serviceaccount:default:default",
						},
						ResourceRequest: true,
						Resource:        "namespaces",
						Subresource:     "metrics",
						Namespace:       "default",
						Verb:            "get",
					},
				},
			},
		},
		{
			name: "non-resources",
			fileContent: `authorization:
  static:
    - user:
        name: system:serviceaccount:default:default
      resourceRequest: false
      verb: get
      path: /metrics`,
			want: &authz.AuthzConfig{
				Static: []static.StaticAuthorizationConfig{
					{
						User: static.UserConfig{
							Name: "system:serviceaccount:default:default",
						},
						ResourceRequest: false,
						Verb:            "get",
						Path:            "/metrics",
					},
				},
				RewriteAttributesConfig: &rewrite.RewriteAttributesConfig{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := os.WriteFile(filePath, []byte(tt.fileContent), 0666); err != nil {
				t.Fatalf("failed to write file: %v", err)
			}

			got, err := parseAuthorizationConfigFile(filePath)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseAuthorizationConfigFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseAuthorizationConfigFile(): %s", cmp.Diff(got, tt.want))
			}
		})
	}
}

func TestProxyOptions_Validate(t *testing.T) {
	type fields struct {
		Upstream                        string
		UpstreamForceH2C                bool
		UpstreamCAFile                  string
		UpstreamClientCertFile          string
		UpstreamClientKeyFile           string
		UpstreamHeader                  *identityheaders.AuthnHeaderConfig
		AuthzConfigFileName             string
		AllowPaths                      []string
		IgnorePaths                     []string
		ProxyEndpointsPort              int
		TokenAudiences                  []string
		AllowLegacyServiceAccountTokens bool
		DisableHTTP2Serving             bool
	}

	userKey := "User"
	groupKey := "Group"

	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "valid config with explicit token audience",
			fields: fields{
				Upstream:                        "http://127.0.0.1",
				TokenAudiences:                  []string{"kube-apiserver"},
				AllowLegacyServiceAccountTokens: false,
				UpstreamHeader: &identityheaders.AuthnHeaderConfig{
					UserFieldName:   userKey,
					GroupsFieldName: groupKey,
				},
			},
			wantErr: false,
		},
		{
			name: "legacy tokens not allowed (empty audiences, flag false)",
			fields: fields{
				Upstream:                        "http://127.0.0.1",
				TokenAudiences:                  []string{},
				AllowLegacyServiceAccountTokens: false,
				UpstreamHeader: &identityheaders.AuthnHeaderConfig{
					UserFieldName:   userKey,
					GroupsFieldName: groupKey,
				},
			},
			wantErr: true,
		},
		{
			name: "legacy tokens allowed (empty audiences, flag true)",
			fields: fields{
				Upstream:                        "http://127.0.0.1",
				TokenAudiences:                  []string{},
				AllowLegacyServiceAccountTokens: true,
				UpstreamHeader: &identityheaders.AuthnHeaderConfig{
					UserFieldName:   userKey,
					GroupsFieldName: groupKey,
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &ProxyOptions{
				Upstream:                        tt.fields.Upstream,
				UpstreamForceH2C:                tt.fields.UpstreamForceH2C,
				UpstreamCAFile:                  tt.fields.UpstreamCAFile,
				UpstreamClientCertFile:          tt.fields.UpstreamClientCertFile,
				UpstreamClientKeyFile:           tt.fields.UpstreamClientKeyFile,
				UpstreamHeader:                  tt.fields.UpstreamHeader,
				AuthzConfigFileName:             tt.fields.AuthzConfigFileName,
				AllowPaths:                      tt.fields.AllowPaths,
				IgnorePaths:                     tt.fields.IgnorePaths,
				ProxyEndpointsPort:              tt.fields.ProxyEndpointsPort,
				TokenAudiences:                  tt.fields.TokenAudiences,
				AllowLegacyServiceAccountTokens: tt.fields.AllowLegacyServiceAccountTokens,
				DisableHTTP2Serving:             tt.fields.DisableHTTP2Serving,
			}
			errs := o.Validate()
			if (len(errs) > 0) != tt.wantErr {
				t.Errorf("Validate() errors = %v, wantErr %v", errs, tt.wantErr)
			}
		})
	}
}
