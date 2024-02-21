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
package kubetest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"

	"k8s.io/client-go/util/cert"
)

var (
	year              = 365 * 24 * time.Hour
	minimalRSAKeySize = 2048
)

type createCertsFunc func(*x509.Certificate, *rsa.PrivateKey, string) (*x509.Certificate, *rsa.PrivateKey, error)

func createSignedClientCert(cacert *x509.Certificate, caPrivateKey *rsa.PrivateKey, name string) (*x509.Certificate, *rsa.PrivateKey, error) {
	// Generate a private key.
	privateKey, err := rsa.GenerateKey(rand.Reader, minimalRSAKeySize)
	if err != nil {
		return nil, nil, err
	}

	template, err := certTemplate()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate cert template: %v", err)
	}
	template.Subject = pkix.Name{CommonName: name}
	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}

	// Sign Certificate
	derBytes, err := x509.CreateCertificate(
		rand.Reader,
		template,
		cacert,
		privateKey.Public(),
		caPrivateKey,
	)
	if err != nil {
		return nil, nil, err
	}

	// Parse Certificate into x509.Certificate.
	certs, err := x509.ParseCertificates(derBytes)
	if err != nil {
		return nil, nil, err
	}
	if len(certs) != 1 {
		return nil, nil, fmt.Errorf("expected 1 certificate, got %d", len(certs))
	}

	return certs[0], privateKey, nil
}

func createSignedServerCert(caCert *x509.Certificate, caPrivateKey *rsa.PrivateKey, dnsName string) (*x509.Certificate, *rsa.PrivateKey, error) {
	// Generate a private key.
	privateKey, err := rsa.GenerateKey(rand.Reader, minimalRSAKeySize)
	if err != nil {
		return nil, nil, err
	}

	template, err := certTemplate()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate cert template: %v", err)
	}
	template.Subject = pkix.Name{CommonName: dnsName}
	template.DNSNames = []string{dnsName}
	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}

	// Sign Certificate
	derBytes, err := x509.CreateCertificate(
		rand.Reader,
		template,
		caCert,
		privateKey.Public(),
		caPrivateKey,
	)
	if err != nil {
		return nil, nil, err
	}

	// Parse Certificate into x509.Certificate.
	certs, err := x509.ParseCertificates(derBytes)
	if err != nil {
		return nil, nil, err
	}
	if len(certs) != 1 {
		return nil, nil, fmt.Errorf("expected 1 certificate, got %d", len(certs))
	}

	return certs[0], privateKey, nil
}

// certTemplate creates a basic cert template to use in tests. The caller must
// add its own Subject and any extensions specific to their use.
func certTemplate() (*x509.Certificate, error) {
	// Generate serial number with at least 20 bits of entropy.
	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, err
	}

	return &x509.Certificate{
		NotBefore: time.Now().Add(-1 * time.Second),
		NotAfter:  time.Now().Add(year),

		SerialNumber: serialNumber,

		SignatureAlgorithm: x509.SHA256WithRSA,

		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},

		BasicConstraintsValid: true,
	}, nil
}

func createSelfSignedCA(name string) (*x509.Certificate, *rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, minimalRSAKeySize)
	if err != nil {
		return nil, nil, err
	}

	cert, err := cert.NewSelfSignedCACert(cert.Config{
		CommonName: name,
	}, privateKey)

	return cert, privateKey, err
}

func generateSerialNumber() (*big.Int, error) {
	max := new(big.Int).Lsh(big.NewInt(1), 63)
	serialNumber, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, err
	}

	return serialNumber, nil
}
