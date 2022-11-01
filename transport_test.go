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
	"net/http"
	"testing"

	"golang.org/x/net/http2"
)

func TestInitTransportWithDefault(t *testing.T) {
	roundTripper, err := initTransport(upstreamConfig{})
	if err != nil {
		t.Errorf("want err to be nil, but got %v", err)
		return
	}
	if roundTripper == nil {
		t.Error("expected roundtripper, got nil")
	}
}

func TestInitTransportWithCustomCA(t *testing.T) {
	roundTripper, err := initTransport(upstreamConfig{caFile: "test/ca.pem"})
	if err != nil {
		t.Errorf("want err to be nil, but got %v", err)
		return
	}
	transport := roundTripper.(*http.Transport)
	if transport.TLSClientConfig.RootCAs == nil {
		t.Error("expected root CA to be set, got nil")
	}
}

func TestInitTransportInsecure(t *testing.T) {
	roundTripper, err := initTransport(upstreamConfig{insecureSkipVerify: true})
	if err != nil {
		t.Errorf("want err to be nil, but got %v", err)
		return
	}
	transport := roundTripper.(*http.Transport)
	if transport.TLSClientConfig.InsecureSkipVerify == false {
		t.Error("expected insecure transport")
	}
}

func TestInitH2CTransport(t *testing.T) {
	roundTripper, err := initTransport(upstreamConfig{forceH2C: true})
	if err != nil {
		t.Errorf("want err to be nil, but got %v", err)
		return
	}
	if _, ok := roundTripper.(*http2.Transport); ok == false {
		t.Error("expected http2 transport")
	}
}
