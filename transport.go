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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
)

func initTransport(upstreamCAFile string) (http.RoundTripper, error) {
	if upstreamCAFile == "" {
		return http.DefaultTransport, nil
	}

	rootPEM, err := ioutil.ReadFile(upstreamCAFile)
	if err != nil {
		return nil, fmt.Errorf("error reading upstream CA file: %v", err)
	}

	roots := x509.NewCertPool()
	if ok := roots.AppendCertsFromPEM([]byte(rootPEM)); !ok {
		return nil, errors.New("error parsing upstream CA certificate")
	}

	transport := (http.DefaultTransport.(*http.Transport)).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: roots}
	transport.ForceAttemptHTTP2 = false

	return transport, nil
}
