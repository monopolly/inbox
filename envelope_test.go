package inbox

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net"
	"strings"
	"testing"

	"github.com/emersion/go-msgauth/dkim"
)

// fakeDNS answers TXT queries from a map, everything else is not found.
type fakeDNS map[string][]string

func (f fakeDNS) LookupTXT(ctx context.Context, name string) ([]string, error) {
	if txt, ok := f[strings.TrimSuffix(name, ".")]; ok {
		return txt, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (f fakeDNS) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (f fakeDNS) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func (f fakeDNS) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	return nil, &net.DNSError{Err: "no such host", Name: addr, IsNotFound: true}
}

func useDNS(t *testing.T, dns fakeDNS) {
	old := resolver
	resolver = dns
	t.Cleanup(func() { resolver = old })
}

func message(from string) []byte {
	return []byte("From: " + from + "\r\nTo: a@example.com\r\nSubject: hi\r\n\r\nbody\r\n")
}

func TestValidFrom(t *testing.T) {
	for _, tt := range []struct {
		from  string
		valid bool
		utf   string
	}{
		{"support@apple.com", true, "support@apple.com"},
		{"Apple <Support@Apple.com>", true, "Support@apple.com"},
		{`"support@apple.com" <support@apple.com>`, true, "support@apple.com"},
		{"support@аpple.com", false, "support@xn--pple-43d.com"},   // Cyrillic а
		{"support@аррӏе.com", false, "support@xn--80ak6aa92e.com"}, // all Cyrillic
		{"suppоrt@apple.com", false, "supp\\u043ert@apple.com"},    // Cyrillic о
		{"support@ɑpple.com", false, "support@xn--pple-p5b.com"},   // Latin alpha
		{"support@ap\u200bple.com", false, "support@apple.com"},    // zero-width space, DNS drops it
		{`"support@apple.com" <x@evil.com>`, false, "x@evil.com"},
		{`"Apple (support@apple.com)" <x@evil.com>`, false, "x@evil.com"},
		{`"x@tickets.example.com via RT" <support@example.com>`, true, "support@example.com"},
		{"=?UTF-8?B?0J/QvtC00LTQtdGA0LbQutCw?= <help@example.com>", true, "help@example.com"},
		{"info@почта.рф", true, "info@xn--80a1acny.xn--p1ai"},
		{"иван@пример.рф", true, "\\u0438\\u0432\\u0430\\u043d@xn--e1afmkfd.xn--p1ai"},
		{"info@münchen.de", true, "info@xn--mnchen-3ya.de"},
		{"a@b.com, c@d.com", false, ""},
		{"", false, ""},
	} {
		e := &Envelope{Data: message(tt.from)}
		valid, utf := e.ValidFrom()
		if valid != tt.valid || utf != tt.utf {
			t.Errorf("ValidFrom(%q) = %v %q, want %v %q", tt.from, valid, utf, tt.valid, tt.utf)
		}
	}

	twoFrom := &Envelope{Data: []byte("From: a@apple.com\r\nFrom: b@evil.com\r\n\r\nx\r\n")}
	if valid, _ := twoFrom.ValidFrom(); valid {
		t.Error("two From headers are valid")
	}
}

func sign(t *testing.T, key ed25519.PrivateKey, domain string, msg []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	err := dkim.Sign(&b, bytes.NewReader(msg), &dkim.SignOptions{Domain: domain, Selector: "s", Signer: key})
	if err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestValidDKIM(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	record := []string{"v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString(pub)}
	useDNS(t, fakeDNS{"s._domainkey.example.com": record, "s._domainkey.evil.com": record})

	signed := sign(t, key, "example.com", message("user@example.com"))
	for _, tt := range []struct {
		name  string
		data  []byte
		valid bool
	}{
		{"signed by From domain", signed, true},
		{"From subdomain", sign(t, key, "example.com", message("user@mail.example.com")), true},
		{"signed by another domain", sign(t, key, "evil.com", message("user@example.com")), false},
		{"body changed", bytes.Replace(signed, []byte("body"), []byte("evil"), 1), false},
		{"not signed", message("user@example.com"), false},
		{"unknown key", sign(t, key, "nokey.com", message("user@nokey.com")), false},
	} {
		if got := (&Envelope{Data: tt.data}).ValidDKIM(); got != tt.valid {
			t.Errorf("%s: ValidDKIM = %v", tt.name, got)
		}
	}
}

func TestValidSPF(t *testing.T) {
	useDNS(t, fakeDNS{
		"example.com":    {"v=spf1 ip4:192.0.2.1 -all"},
		"mx.example.com": {"v=spf1 ip4:192.0.2.1 -all"},
		"evil.com":       {"v=spf1 +all"},
	})
	ip := func(s string) net.Addr { return &net.TCPAddr{IP: net.ParseIP(s), Port: 25} }

	for _, tt := range []struct {
		name       string
		addr       net.Addr
		mailFrom   string
		helo       string
		headerFrom string
		valid      bool
	}{
		{"allowed IP", ip("192.0.2.1"), "bounce@example.com", "mx.example.com", "user@example.com", true},
		{"subdomain From", ip("192.0.2.1"), "bounce@example.com", "mx", "user@news.example.com", true},
		{"other IP", ip("192.0.2.99"), "bounce@example.com", "mx", "user@example.com", false},
		{"pass for foreign domain", ip("192.0.2.99"), "x@evil.com", "mx", "user@example.com", false},
		{"bounce checks HELO", ip("192.0.2.1"), "", "mx.example.com", "mailer-daemon@example.com", true},
		{"no SPF record", ip("192.0.2.1"), "x@nospf.com", "mx", "x@nospf.com", false},
		{"no IP", nil, "bounce@example.com", "mx", "user@example.com", false},
	} {
		e := &Envelope{RemoteAddr: tt.addr, From: tt.mailFrom, Helo: tt.helo, Data: message(tt.headerFrom)}
		if got := e.ValidSPF(); got != tt.valid {
			t.Errorf("%s: ValidSPF = %v", tt.name, got)
		}
	}
}

func TestEnvelopeEmail(t *testing.T) {
	data := []byte("From: Sender <sender@example.org>\r\n" +
		"To: a@example.com\r\n" +
		"Cc: B <b@example.com>\r\n" +
		"Date: Sun, 25 Oct 2026 16:00:00 +0300\r\n" +
		"Subject: hello\r\n" +
		"\r\n" +
		"text\r\n")
	e := &Envelope{
		RemoteAddr: &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1234},
		To:         []string{"a@example.com", "b@example.com", "hidden@example.com"},
		Data:       data,
	}

	m, err := e.Email()
	if err != nil {
		t.Fatal(err)
	}
	if m.Subj != "hello" || m.From.Address != "sender@example.org" || m.To.Address != "a@example.com" {
		t.Errorf("headers: %q %q %q", m.Subj, m.From.Address, m.To.Address)
	}
	if strings.TrimSpace(m.Text) != "text" {
		t.Errorf("Text = %q", m.Text)
	}
	if m.IP != "192.0.2.1" || !bytes.Equal(m.EML, data) {
		t.Errorf("IP = %q, EML = %q", m.IP, m.EML)
	}
	if m.Date == nil || m.Date.UTC().Hour() != 13 {
		t.Errorf("Date = %v", m.Date)
	}
	if len(m.CC) != 1 || m.CC[0].Address != "b@example.com" {
		t.Errorf("CC = %v", m.CC)
	}
	if len(m.BCC) != 1 || m.BCC[0].Address != "hidden@example.com" {
		t.Errorf("BCC = %v", m.BCC)
	}
}
