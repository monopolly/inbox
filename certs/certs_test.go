package certs

import (
	"crypto/x509"
	"net"
	"testing"
	"time"
)

func TestSelfSigned(t *testing.T) {
	cert, err := SelfSigned("Test", "mx.example.com", "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := c.VerifyHostname("mx.example.com"); err != nil {
		t.Error(err)
	}
	if !c.IPAddresses[0].Equal(net.ParseIP("192.0.2.1")) {
		t.Errorf("IPs = %v", c.IPAddresses)
	}
	if c.NotAfter.Before(time.Now().AddDate(5, 0, 0)) {
		t.Errorf("NotAfter = %v", c.NotAfter)
	}
}

func TestAutocert(t *testing.T) {
	cfg, h := Autocert(t.TempDir(), "admin@example.com", "mx.example.com")
	if cfg.GetCertificate == nil || h == nil {
		t.Fatal("empty config")
	}
}
