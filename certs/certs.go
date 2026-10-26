package inbox

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// TLSAutocert returns a STARTTLS config with Let's Encrypt certificates for
// domains, cached in cacheDir. ACME can't validate over SMTP, so the returned
// handler must serve the HTTP-01 challenge on port 80 of this host:
//
//	cfg, h := inbox.TLSAutocert("/var/lib/inbox/certs", "admin@example.com", "mx.example.com")
//	go http.ListenAndServe(":80", h)
//
// Sending MTAs often omit SNI or use another name, such handshakes get
// the certificate of the first domain.
func TLSAutocert(cacheDir, email string, domains ...string) (*tls.Config, http.Handler) {
	if len(domains) == 0 {
		panic("inbox: TLSAutocert needs at least one domain")
	}

	manager := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(domains...),
		Cache:      autocert.DirCache(cacheDir),
		Email:      email,
	}

	known := make(map[string]bool, len(domains))
	for _, d := range domains {
		known[strings.ToLower(d)] = true
	}

	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if !known[strings.ToLower(hello.ServerName)] {
				hello.ServerName = domains[0]
			}
			return manager.GetCertificate(hello)
		},
	}
	return cfg, manager.HTTPHandler(nil)
}

// selfSigned creates a self-signed certificate for hosts. Sending MTAs rarely
// verify certificates, so it is enough for opportunistic STARTTLS.
func selfSigned(company string, hosts ...string) (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{company},
			CommonName:   hosts[0],
		},
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.AddDate(10, 0, 0),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, nil
}
