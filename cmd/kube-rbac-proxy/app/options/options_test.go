/*
Copyright 2024 the kube-rbac-proxy maintainers. All rights reserved.

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
	"strings"
	"testing"
)

func TestParseUnixUpstream(t *testing.T) {
	tests := []struct {
		name           string
		upstream       string
		wantSocketPath string
		wantHTTPPath   string
	}{
		{
			name:           "socket path only",
			upstream:       "unix:///var/run/app.sock",
			wantSocketPath: "/var/run/app.sock",
			wantHTTPPath:   "/",
		},
		{
			name:           "socket path with http path",
			upstream:       "unix:///var/run/app.sock:/metrics",
			wantSocketPath: "/var/run/app.sock",
			wantHTTPPath:   "/metrics",
		},
		{
			name:           "socket path with nested http path",
			upstream:       "unix:///var/run/app.sock:/api/v1/metrics",
			wantSocketPath: "/var/run/app.sock",
			wantHTTPPath:   "/api/v1/metrics",
		},
		{
			name:           "socket path with empty http path uses default",
			upstream:       "unix:///var/run/app.sock:",
			wantSocketPath: "/var/run/app.sock",
			wantHTTPPath:   "/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			socketPath, httpPath := ParseUnixUpstream(tt.upstream)
			if socketPath != tt.wantSocketPath {
				t.Errorf("socketPath = %q, want %q", socketPath, tt.wantSocketPath)
			}
			if httpPath != tt.wantHTTPPath {
				t.Errorf("httpPath = %q, want %q", httpPath, tt.wantHTTPPath)
			}
		})
	}
}

func TestValidateUnixUpstream(t *testing.T) {
	tests := []struct {
		name      string
		modify    func(o *ProxyRunOptions)
		wantErr   string
		wantNoErr bool
	}{
		{
			name: "valid unix upstream",
			modify: func(o *ProxyRunOptions) {
				o.Upstream = "unix:///var/run/app.sock"
			},
			wantNoErr: true,
		},
		{
			name: "relative socket path rejected",
			modify: func(o *ProxyRunOptions) {
				o.Upstream = "unix://relative/path.sock"
			},
			wantErr: "must be absolute",
		},
		{
			name: "upstream-force-h2c rejected with unix",
			modify: func(o *ProxyRunOptions) {
				o.Upstream = "unix:///var/run/app.sock"
				o.UpstreamForceH2C = true
			},
			wantErr: "--upstream-force-h2c cannot be used",
		},
		{
			name: "upstream-ca-file rejected with unix",
			modify: func(o *ProxyRunOptions) {
				o.Upstream = "unix:///var/run/app.sock"
				o.UpstreamCAFile = "/some/ca.pem"
			},
			wantErr: "--upstream-ca-file cannot be used",
		},
		{
			name: "upstream client cert rejected with unix",
			modify: func(o *ProxyRunOptions) {
				o.Upstream = "unix:///var/run/app.sock"
				o.TLS.UpstreamClientCertFile = "/some/cert.pem"
			},
			wantErr: "--upstream-client-cert-file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := NewProxyRunOptions()
			// Initialize flagSet by calling Flags(), required by validateDisabledFlags
			o.Flags()
			// Set required defaults to avoid unrelated validation noise
			o.TLS.CertFile = "cert.pem"
			o.TLS.KeyFile = "key.pem"
			o.SecureListenAddress = ":8443"
			tt.modify(o)

			err := o.Validate()
			if tt.wantNoErr {
				if err != nil {
					t.Errorf("expected no error, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expected error containing %q, got: %v", tt.wantErr, err)
			}
		})
	}
}
