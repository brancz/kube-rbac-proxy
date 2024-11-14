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

package app

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/brancz/kube-rbac-proxy/pkg/server"
	"github.com/google/go-cmp/cmp"
)

func Test_copyHeaderIfSet(t *testing.T) {
	tests := []struct {
		name           string
		headerKey      string
		inHeader       http.Header
		outHeader      http.Header
		expectedValues []string
	}{
		{
			name:      "src exists, dist does not",
			headerKey: "NONCanon",
			inHeader: http.Header{
				"Noncanon": []string{"here"},
			},
			expectedValues: []string{"here"},
		},
		{
			name:      "src exists, dist does too",
			headerKey: "NONCanon",
			inHeader: http.Header{
				"Noncanon": []string{"here"},
			},
			outHeader: http.Header{
				"Noncanon": []string{"there"},
			},
			expectedValues: []string{"there", "here"},
		},
		{
			name:      "src does not exist, dist does",
			headerKey: "nonCanon",
			outHeader: http.Header{
				"Noncanon": []string{"there"},
			},
			expectedValues: []string{"there"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inReq := http.Request{
				Header: tt.inHeader,
			}
			outReq := http.Request{
				Header: tt.outHeader,
			}

			copyHeaderIfSet(&inReq, &outReq, tt.headerKey)
			if gotVals := outReq.Header.Values(tt.headerKey); !reflect.DeepEqual(tt.expectedValues, gotVals) {
				t.Errorf("expected values: %v, got: %v", tt.expectedValues, gotVals)
			}
		})
	}
}

func TestProxyHandler(t *testing.T) {
	reqChan := make(chan http.Header, 1)
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		reqChan <- req.Header
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(testServer.Close)

	testServerURL, err := url.Parse(testServer.URL)
	if err != nil {
		t.Fatalf("failed to parse testserver URL")
	}

	config := &server.KubeRBACProxyInfo{
		UpstreamURL: testServerURL,
	}
	testHandler := setupProxyHandler(config)

	// the Golang implementation of an HTTP server passes the remote address of an
	// incoming connection into the HTTP request, we'll emulate this in the tests
	const (
		testRemoteIP   = "10.0.0.1"
		testRemoteAddr = testRemoteIP + ":10354"
	)

	tests := []struct {
		name       string
		header     http.Header
		wantHeader http.Header
	}{
		{
			name:   "no extra headers",
			header: make(http.Header),
			wantHeader: http.Header{
				"X-Forwarded-For":   []string{testRemoteIP},
				"X-Forwarded-Host":  []string{testServerURL.Host},
				"X-Forwarded-Proto": []string{"http"},
			},
		},
		{
			name: "X-Forwarded-For is set",
			header: http.Header{
				"X-Forwarded-For": []string{"10.0.0.2"},
			},
			wantHeader: http.Header{
				"X-Forwarded-For":   []string{"10.0.0.2, " + testRemoteIP},
				"X-Forwarded-Host":  []string{testServerURL.Host},
				"X-Forwarded-Proto": []string{"http"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testWriter := httptest.NewRecorder()
			req, err := http.NewRequest(http.MethodGet, testServer.URL, nil)
			if err != nil {
				t.Fatalf("failed to create an http request: %v", err)
			}
			req.Header = tt.header
			req.RemoteAddr = testRemoteAddr
			testHandler.ServeHTTP(testWriter, req)

			var gotHeaders http.Header
			select {
			case gotHeaders = <-reqChan:
			case <-time.After(5 * time.Second):
				t.Fatal("timeout: did not receive any response")
			}

			gotHeaders.Del("Content-Length")
			gotHeaders.Del("Accept-Encoding")
			gotHeaders.Del("Date")

			if !reflect.DeepEqual(gotHeaders, tt.wantHeader) {
				t.Errorf("got different headers than expected: %s", cmp.Diff(tt.wantHeader, gotHeaders))
			}
		})
	}
}
