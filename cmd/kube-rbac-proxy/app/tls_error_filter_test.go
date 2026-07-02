/*
Copyright 2026 the kube-rbac-proxy maintainers. All rights reserved.

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
	"testing"
)

func Test_isTCPResetHandshakeError(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			// Canonical message produced by a load balancer TCP health check:
			// the load balancer opens a TCP connection to verify liveness and
			// then closes it with a TCP RST before the TLS handshake completes.
			name:  "TCP reset during TLS handshake is demoted (load balancer health check)",
			input: "http: TLS handshake error from 10.131.0.8:55126: write tcp 10.129.2.17:9091->10.131.0.8:55126: write: connection reset by peer\n",
			want:  true,
		},
		{
			name:  "expired certificate TLS error is not demoted",
			input: "http: TLS handshake error from 10.0.0.1:1234: x509: certificate has expired or is not yet valid\n",
			want:  false,
		},
		{
			name:  "unknown certificate authority TLS error is not demoted",
			input: "http: TLS handshake error from 10.0.0.1:1234: x509: certificate signed by unknown authority\n",
			want:  false,
		},
		{
			name:  "unsupported TLS version error is not demoted",
			input: "http: TLS handshake error from 10.0.0.1:1234: tls: no supported versions satisfy MinVersion and MaxVersion\n",
			want:  false,
		},
		{
			name:  "unrelated server message is not demoted",
			input: "server is shutting down\n",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isTCPResetHandshakeError(tt.input); got != tt.want {
				t.Errorf("isTCPResetHandshakeError(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func Test_tlsHandshakeErrorFilter_Write(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "non-matching message is passed through",
			input: "any message\n",
		},
		{
			name:  "matching TCP-reset message is handled without error",
			input: "http: TLS handshake error from 10.131.0.8:55126: write tcp 10.129.2.17:9091->10.131.0.8:55126: write: connection reset by peer\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &tlsHandshakeErrorFilter{}
			n, err := f.Write([]byte(tt.input))
			if err != nil {
				t.Errorf("Write() returned unexpected error: %v", err)
			}
			if n != len(tt.input) {
				t.Errorf("Write() returned n=%d, want %d", n, len(tt.input))
			}
		})
	}
}
