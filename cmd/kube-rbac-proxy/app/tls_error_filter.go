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
	"strings"

	"k8s.io/klog/v2"
)

// tlsHandshakeErrorFilter is an io.Writer intended for use as http.Server.ErrorLog.
// It demotes TLS handshake errors caused by abruptly closed connections (e.g. TCP
// health checks from load balancers) to verbose logging, while preserving all other
// TLS errors (expired certificates, unsupported protocols, etc.) at the default log level.
type tlsHandshakeErrorFilter struct{}

// Write implements io.Writer.
func (f *tlsHandshakeErrorFilter) Write(p []byte) (n int, err error) {
	msg := string(p)
	if isTCPResetHandshakeError(msg) {
		klog.V(4).Info(msg)
		return len(p), nil
	}
	klog.InfoDepth(3, msg)
	return len(p), nil
}

// isTCPResetHandshakeError reports whether msg is a TLS handshake error caused
// by the remote side closing the connection before the handshake completed.
// This is the signature of TCP-level health checks performed by load balancers
// that open a connection to verify liveness and then immediately close it with
// a TCP RST, producing harmless log noise with no functional impact.
// All other TLS handshake errors (expired certificates, unknown authorities,
// unsupported protocol versions, etc.) return false and are logged normally.
func isTCPResetHandshakeError(msg string) bool {
	return strings.Contains(msg, "http: TLS handshake error") &&
		strings.Contains(msg, "connection reset by peer")
}
