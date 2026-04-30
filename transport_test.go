package main

import (
	"os"
	"path/filepath"
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
	certPath := filepath.Join(dir, "corp-root.pem")
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
	if subjects := tlsConfig.RootCAs.Subjects(); len(subjects) == 0 {
		t.Fatal("expected at least one trusted root certificate")
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

func resetTransportState() {
	gatewayTransportOnce = sync.Once{}
	gatewayTransport = nil
	gatewayTransportErr = nil
}
