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
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"math/big"
	p12 "software.sslmate.com/src/go-pkcs12"
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

// extractCaCertFromConfigMap extracts the ca.crt and tls.crt from a ConfigMap
func extractCaCertFromConfigMap(certs *corev1.ConfigMap) (*x509.Certificate, error) {
	// Extract the CA PEM bytes from the config map and convert them to a cert object
	caCertPEM, ok := certs.Data["ca.crt"]
	if !ok {
		return nil, fmt.Errorf("failed to find ca.crt from configmap %s", certs.Name)
	}
	block, _ := pem.Decode([]byte(caCertPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode ca.crt from configmap %s", certs.Name)
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ca.crt bytes into certificate from configmap %s; %w", certs.Name, err)
	}

	return caCert, err
}

// extractCertAndKeyFromSecret extracts the ca.key and tls.key from a Secret
func extractCertAndKeyFromSecret(keys *corev1.Secret) (*x509.Certificate, *rsa.PrivateKey, error) {
	// Extract the PEM bytes from the secret and convert them to a cert object
	certPEM, ok := keys.Data["tls.crt"]
	if !ok {
		return nil, nil, fmt.Errorf("failed to find tls.crt in secret %s", keys.Name)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("failed to decode tls.crt from secret %s", keys.Name)
	}
	certs, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate from secret %s", keys.Name)
	}

	// Extract the PEM bytes from the secret and convert them to a cert object
	keyPEM, ok := keys.Data["tls.key"]
	if !ok {
		return nil, nil, fmt.Errorf("failed to find tls.key in secret %s", keys.Name)
	}
	block, _ = pem.Decode(keyPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("failed to decode tls.key from secret %s", keys.Name)
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse private key from secret %s", keys.Name)
	}

	return certs, key, nil
}

// wrapCertsInPKSC12 finds certificates and keys that were previously created and stored in a pair of ConfigMap and
// Secret, extracts their contents and repackages them into PKCS12 objects so they can be re-used by components that
// may not directly support PEM encoded certificates or key files and instead require a PKCS12 object.
func wrapCertsInPKCS12(client kubernetes.Interface, name string) Action {
	return func(ctx *ScenarioContext) error {
		// Fetch the cert and key which were stored in a secret
		certsName := fmt.Sprintf("%s-certs", name)
		secret, err := client.CoreV1().Secrets(ctx.Namespace).Get(context.TODO(), certsName, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("failed to get secret %s: %w", certsName, err)
		}

		// Fetch the CA certificate which was stored in a configmap
		trustName := fmt.Sprintf("%s-trust", name)
		trust, err := client.CoreV1().ConfigMaps(ctx.Namespace).Get(context.TODO(), trustName, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("failed to get configmap %s: %w", trustName, err)
		}

		// Parse out the certs and keys
		caCert, err := extractCaCertFromConfigMap(trust)
		if err != nil {
			return err
		}
		cert, key, err := extractCertAndKeyFromSecret(secret)
		if err != nil {
			return err
		}

		// Repackage the certs and keys into PKCS12 objects
		keyStore, err := p12.Modern.Encode(key, cert, []*x509.Certificate{caCert}, "password")
		if err != nil {
			return fmt.Errorf("failed to encode keystore: %w", err)
		}

		trustStore, err := p12.Modern.EncodeTrustStore([]*x509.Certificate{caCert}, "password")
		if err != nil {
			return fmt.Errorf("failed to encode truststore: %w", err)
		}

		configMapName := fmt.Sprintf("%s-truststore", name)
		_, err = client.CoreV1().ConfigMaps(ctx.Namespace).Create(context.TODO(), &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name: configMapName,
			},
			BinaryData: map[string][]byte{
				"truststore.p12": trustStore,
			},
		}, metav1.CreateOptions{})
		if err != nil {
			return err
		}
		ctx.AddCleanUp(func() error {
			return client.CoreV1().ConfigMaps(ctx.Namespace).Delete(context.TODO(), configMapName, metav1.DeleteOptions{})
		})

		secretName := fmt.Sprintf("%s-keystore", name)
		_, err = client.CoreV1().Secrets(ctx.Namespace).Create(context.TODO(), &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: secretName,
			},
			Data: map[string][]byte{
				"keystore.p12": keyStore,
			},
		}, metav1.CreateOptions{})
		ctx.AddCleanUp(func() error {
			return client.CoreV1().Secrets(ctx.Namespace).Delete(context.TODO(), secretName, metav1.DeleteOptions{})
		})

		return err
	}
}
