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

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"golang.org/x/net/http2"
)

func initTransport(upstream upstreamConfig) (http.RoundTripper, error) {
	// Force http/2 for connections to the upstream i.e. do not start with HTTP1.1 UPGRADE req to
	// initialize http/2 session.
	// See https://github.com/golang/go/issues/14141#issuecomment-219212895 for more context
	if upstream.forceH2C {
		return &http2.Transport{
			// Allow http schema. This doesn't automatically disable TLS
			AllowHTTP: true,
			// Do disable TLS.
			// In combination with the schema check above. We could enforce h2c against the upstream server
			DialTLSContext: func(ctx context.Context, netw, addr string, cfg *tls.Config) (net.Conn, error) {
				return net.Dial(netw, addr)
			},
		}, nil
	}

	roots := x509.NewCertPool()

	if upstream.caFile != "" {
		rootPEM, err := os.ReadFile(upstream.caFile)
		if err != nil {
			return nil, fmt.Errorf("error reading upstream CA file: %v", err)
		}

		if ok := roots.AppendCertsFromPEM(rootPEM); !ok {
			return nil, errors.New("error parsing upstream CA certificate")
		}
	}

	// http.Transport sourced from go 1.19
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			RootCAs:            roots,
			InsecureSkipVerify: upstream.insecureSkipVerify,
		},
	}, nil
}
