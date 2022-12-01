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
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"testing"
	"time"

	certutil "k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/keyutil"
)

func TestInitTransportWithDefault(t *testing.T) {
	roundTripper, err := initTransport(nil, "", "")
	if err != nil {
		t.Errorf("want err to be nil, but got %v", err)
		return
	}
	if roundTripper == nil {
		t.Error("expected roundtripper, got nil")
	}
}

func TestInitTransportWithCustomCA(t *testing.T) {
	upstreamCAPEM, err := os.ReadFile("../../../test/ca.pem")
	if err != nil {
		t.Fatalf("failed to read '../../../test/ca.pem': %v", err)
	}

	upstreamCAPool := x509.NewCertPool()
	upstreamCAPool.AppendCertsFromPEM(upstreamCAPEM)

	roundTripper, err := initTransport(upstreamCAPool, "", "")
	if err != nil {
		t.Fatalf("want err to be nil, but got %v", err)
	}
	transport := roundTripper.(*http.Transport)
	if transport.TLSClientConfig.RootCAs == nil {
		t.Error("expected root CA to be set, got nil")
	}
}

func testHTTPHandler(w http.ResponseWriter, req *http.Request) {
	if len(req.TLS.PeerCertificates) > 0 {
		_, _ = w.Write([]byte("ok"))
		return
	} else {
		reqDump, _ := httputil.DumpRequest(req, false)
		resp := fmt.Sprintf("got request without client certificates:\n%s\n", reqDump)
		resp += fmt.Sprintf("TLS config: %#v\n", req.TLS)
		http.Error(w, resp, http.StatusBadRequest)
	}
}

func TestInitTransportWithClientCertAuth(t *testing.T) {
	tlsServer := http.Server{
		Handler: http.HandlerFunc(testHTTPHandler),
	}

	cert, key, err := certutil.GenerateSelfSignedCertKey("127.0.0.1", nil, nil)
	if err != nil {
		t.Fatalf("failed to create a new serving cert: %v", err)
	}

	tlsCert, err := tls.X509KeyPair(cert, key)
	if err != nil {
		t.Fatalf("failed to load a new serving cert: %v", err)
	}

	clientCert, clientKey, clientCA, err := generateClientCert(t)
	if err != nil {
		t.Fatalf("failed to generate client cert: %v", err)
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on secure address: %v", err)
	}
	defer l.Close()
	tlsListener := tls.NewListener(l, &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		ClientCAs:    clientCA,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	})
	defer tlsListener.Close()

	go func() {
		if err := tlsServer.Serve(tlsListener); err != nil {
			t.Logf("failed to run the test server: %v", err)
		}
	}()
	defer tlsServer.Close()

	tmpDir := t.TempDir()
	clientCertPath := filepath.Join(tmpDir, "client.crt")
	clientKeyPath := filepath.Join(tmpDir, "client.key")

	if err := certutil.WriteCert(clientCertPath, clientCert); err != nil {
		t.Fatalf("failed to write client cert: %v", err)
	}
	if err := keyutil.WriteKey(clientKeyPath, clientKey); err != nil {
		t.Fatalf("failed to write client key: %v", err)
	}

	serverCA := x509.NewCertPool()
	serverCA.AppendCertsFromPEM(cert)
	roundTripper, err := initTransport(serverCA, clientCertPath, clientKeyPath)
	if err != nil {
		t.Errorf("want err to be nil, but got %v", err)
		return
	}

	httpReq, err := http.NewRequest(http.MethodPost, fmt.Sprintf("https://127.0.0.1:%d", l.Addr().(*net.TCPAddr).Port), nil)
	if err != nil {
		t.Fatalf("failed to create an HTTP request: %v", err)
	}

	resp, err := roundTripper.RoundTrip(httpReq)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Logf("failed to read response body: %v", err)
		}
		t.Logf("response with failure logs:\n%s", respBody)
		t.Errorf("expected the response code to be '%d', but it is '%d'", http.StatusOK, resp.StatusCode)
	}
}

func generateClientCert(t *testing.T) ([]byte, []byte, *x509.CertPool, error) {
	t.Helper()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate private key: %v", err)
	}
	ca, err := certutil.NewSelfSignedCACert(certutil.Config{CommonName: "testing-ca"}, privKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate CA cert: %v", err)
	}

	privKeyClient, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	certDER, err := x509.CreateCertificate(rand.Reader,
		&x509.Certificate{
			Subject:      pkix.Name{CommonName: "testing-client"},
			SerialNumber: big.NewInt(15233),
			NotBefore:    time.Now().Add(-5 * time.Second),
			NotAfter:     time.Now().Add(1 * time.Minute),
			KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		},
		ca, privKeyClient.Public(), privKey,
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create a client cert: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	caPool := x509.NewCertPool()
	caPool.AddCert(ca)

	privKeyPEM, err := keyutil.MarshalPrivateKeyToPEM(privKeyClient)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to encode private key to pem: %v", err)
	}

	return certPEM, privKeyPEM, caPool, nil
}
