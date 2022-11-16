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

package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"time"
)

func initTransport(upstreamCAPool *x509.CertPool, upstreamClientCert *tls.Certificate, upstreamUnixSocket string) (http.RoundTripper, error) {
	if upstreamCAPool == nil && upstreamClientCert == nil && upstreamUnixSocket == "" {
		return http.DefaultTransport, nil
	}

	builder := newHTTPTransportBuilder()

	if upstreamCAPool != nil {
		builder.withRootCAs(upstreamCAPool)
	}

	if upstreamClientCert != nil {
		builder.withClientCerts(*upstreamClientCert)
	}

	if upstreamUnixSocket != "" {
		builder.withUnixDialContext(upstreamUnixSocket)
	}

	return builder.build(), nil
}

type httpTransportBuilder struct {
	tlsClientConfig *tls.Config
	dialContext     func(ctx context.Context, network, addr string) (net.Conn, error)
}

func newHTTPTransportBuilder() *httpTransportBuilder {
	return &httpTransportBuilder{
		dialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
	}
}

func (b *httpTransportBuilder) withRootCAs(certs *x509.CertPool) *httpTransportBuilder {
	if b.tlsClientConfig != nil {
		b.tlsClientConfig.RootCAs = certs
	} else {
		b.tlsClientConfig = &tls.Config{RootCAs: certs}
	}
	return b
}

func (b *httpTransportBuilder) withClientCerts(certs ...tls.Certificate) *httpTransportBuilder {
	if b.tlsClientConfig != nil {
		b.tlsClientConfig.Certificates = certs
	} else {
		b.tlsClientConfig = &tls.Config{Certificates: certs}
	}
	return b
}

func (b *httpTransportBuilder) withUnixDialContext(socket string) *httpTransportBuilder {
	b.dialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext(ctx, "unix", socket)
	}
	return b
}

func (b *httpTransportBuilder) build() *http.Transport {
	// http.Transport sourced from go 1.10.7
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           b.dialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       b.tlsClientConfig,
	}
}
