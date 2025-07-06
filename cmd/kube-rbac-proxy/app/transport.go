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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
)

func initTransport(upstreamCAPool *x509.CertPool, upstreamClientCertPath, upstreamClientKeyPath string, upstreamInsecureSkipVerify bool) (http.RoundTripper, error) {
	var certKeyPair tls.Certificate
	if len(upstreamClientCertPath) > 0 {
		var err error
		certKeyPair, err = tls.LoadX509KeyPair(upstreamClientCertPath, upstreamClientKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read upstream client cert/key: %w", err)
		}
	}

	transport, ok := http.DefaultTransport.(*http.Transport)
	if ok {
		transport = transport.Clone()
	} else {
		return nil, fmt.Errorf("default transport is not of type *http.Transport")
	}

	transport.TLSClientConfig.RootCAs = upstreamCAPool
	transport.TLSClientConfig.InsecureSkipVerify = upstreamInsecureSkipVerify

	if certKeyPair.Certificate != nil {
		transport.TLSClientConfig.Certificates = []tls.Certificate{certKeyPair}
	}

	return transport, nil
}
