package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const testRootCert = `-----BEGIN CERTIFICATE-----
MIIDDzCCAfegAwIBAgIUF+6ZwWhZtK0v48w43OuCPyufoO4wDQYJKoZIhvcNAQEL
BQAwFzEVMBMGA1UEAwwMVGVzdCBSb290IENBMB4XDTI2MDQyNTA1MDUyOVoXDTI3
MDQyNTA1MDUyOVowFzEVMBMGA1UEAwwMVGVzdCBSb290IENBMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw9KY9KxbeACNAw2I+GC0ls3aoO8gJjaiE9kJ
x5/35hHJSSEIOgAmFlhx8MokJ1et/WUusyYFtAT7CuK0nKaQobAjBq1mms8ap0Xc
GQONZIJyu2Cb5M/dr5EqsTZ5cr9QzNEO4X/IFZ+6eSs9OPYy2yny7x8n8CT7Z66I
hQ1I0v81uZg2eiRVIl1ZriAYLYlZbZtl2D0AaT0Q2trjukDyag7Y9AbULiGhWOKF
BZxcZ4+8vDsmYQs/pmLEVcg1RoWwJrP4NFad1gj5wOoLz9/20of+BJhXJrU7OEKf
y4XnXOMX3UL5PPMgx/uLmobGPQv1BDg4ZsTxWcf+Du+5nN5IJQIDAQABo1MwUTAd
BgNVHQ4EFgQUwu44J0JXbB/tAL3u+b09IaBj5C8wHwYDVR0jBBgwFoAUwu44J0JX
bB/tAL3u+b09IaBj5C8wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOC
AQEAZAJew+8oe8y/wp+EYfCgQPb3Bz06viU9TedqN/4/Hqv2fIdWf7EjO/QrJry+
rktB7wVzp5c7fmVIgDDtNd4IDpGbwe7GtMaEdBbDQextmTmxYj4Isc0s3YG96ZpL
eQ8+tKV+Q4h9RfqgFrqFQUy+7FE+bgr5L1SX9Zlx4dBFrp7h1Jo76jCvJ0M4TwWH
S072Dw3KRn+0l8jKLQr8Wl6Nrxxf4dhU+0wXb2QaBOT5TUejesgkAH8GhM50b3ng
U3qft6UMZvoCzWL8Lb21X5GWStLLKZ7rNg/V6cr7L3cxSXtFdotxrT+3B62BDTg+
TAZ8f4U1owo2Mj1bm1qh/wsWWQ==
-----END CERTIFICATE-----
`

func TestTLSConfigFromEnvironmentLoadsExtraCert(t *testing.T) {
	resetTransportState()

	dir := t.TempDir()
	certPath := filepath.Join(dir, "root.pem")
	if err := os.WriteFile(certPath, []byte(testRootCert), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	t.Setenv("WAITEWAY_CA_CERT", certPath)

	tlsConfig, err := tlsConfigFromEnvironment()
	if err != nil {
		t.Fatalf("tlsConfigFromEnvironment returned error: %v", err)
	}
	if tlsConfig == nil || tlsConfig.RootCAs == nil {
		t.Fatal("expected root CAs to be loaded")
	}

	// Verify our specific cert is in the pool. The test cert is a self-signed
	// root, so it should successfully verify against a pool containing itself.
	cert := mustParseCert(t, testRootCert)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:       tlsConfig.RootCAs,
		CurrentTime: cert.NotBefore,
	}); err != nil {
		t.Fatalf("test cert was not added to the pool: %v", err)
	}
}

func TestTLSConfigFromEnvironmentRejectsBadCert(t *testing.T) {
	resetTransportState()

	dir := t.TempDir()
	certPath := filepath.Join(dir, "broken.pem")
	if err := os.WriteFile(certPath, []byte("not a certificate"), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	t.Setenv("WAITEWAY_CA_CERT", certPath)

	if _, err := tlsConfigFromEnvironment(); err == nil {
		t.Fatal("expected bad certificate file to fail")
	}
}

func TestTLSConfigFromEnvironmentRejectsDeprecatedVars(t *testing.T) {
	for _, name := range []string{"WAITEWAY_CA_CERT_FILE", "WAITEWAY_CA_CERT_DIR"} {
		t.Run(name, func(t *testing.T) {
			resetTransportState()
			t.Setenv(name, "/some/path")

			_, err := tlsConfigFromEnvironment()
			if err == nil {
				t.Fatalf("expected error when %s is set", name)
			}
			if !strings.Contains(err.Error(), "WAITEWAY_CA_CERT") {
				t.Fatalf("error should mention the new variable, got: %v", err)
			}
		})
	}
}

func mustParseCert(t *testing.T, pemData string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		t.Fatal("failed to decode test cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse test cert: %v", err)
	}
	return cert
}

func resetTransportState() {
	gatewayTransportOnce = sync.Once{}
	gatewayTransport = nil
	gatewayTransportErr = nil
}
