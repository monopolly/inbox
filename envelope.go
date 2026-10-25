package inbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/bits"
	"mime"
	"net"
	"net/mail"
	"slices"
	"strings"
	"time"
	"unicode"

	"blitiri.com.ar/go/spf"
	"github.com/emersion/go-msgauth/dkim"
	"github.com/monopolly/email"
	"golang.org/x/net/html/charset"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

const lookupTimeout = 10 * time.Second // DNS for one SPF or DKIM check

// resolver is used for SPF and DKIM lookups, tests replace it.
var resolver spf.DNSResolver = net.DefaultResolver

// addressParser decodes =?charset?...?= display names in any charset.
var addressParser = mail.AddressParser{WordDecoder: &mime.WordDecoder{CharsetReader: charset.NewReaderLabel}}

// Email parses the message into email.Email and adds what only the envelope
// knows: IP, BCC (recipients that are not in To or Cc headers) and the original EML.
func (a *Envelope) Email() (*email.Email, error) {
	m, err := email.ParseRawEmail(a.Data)
	if err != nil {
		return nil, err
	}
	if m == nil {
		return nil, errors.New("inbox: can't parse message")
	}

	m.EML = a.Data
	if ip := remoteIP(a.RemoteAddr); ip != nil {
		m.IP = ip.String()
	}

	visible := map[string]bool{}
	if h, err := a.header(); err == nil {
		if d, err := h.Date(); err == nil {
			m.Date = &d
		}
		m.CC = parseList(h.Get("Cc"))
		for _, x := range append(parseList(h.Get("To")), m.CC...) {
			visible[strings.ToLower(x.Address)] = true
		}
	}

	for _, rcpt := range a.To {
		if !visible[rcpt] {
			m.BCC = append(m.BCC, &mail.Address{Address: rcpt})
		}
	}
	return m, nil
}

// ValidDKIM reports whether the message has a valid DKIM signature of the
// From header domain or its organization (mail.apple.com for apple.com).
// Anyone can sign with their own domain, such signatures don't count.
func (a *Envelope) ValidDKIM() (valid bool) {
	from, err := a.headerFrom()
	if err != nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	defer cancel()

	list, _ := dkim.VerifyWithOptions(bytes.NewReader(a.Data), &dkim.VerifyOptions{
		LookupTXT:        func(domain string) ([]string, error) { return resolver.LookupTXT(ctx, domain) },
		MaxVerifications: 5,
	})

	fromDomain := domainOf(from.Address)
	for _, v := range list {
		signedFrom := slices.ContainsFunc(v.HeaderKeys, func(k string) bool { return strings.EqualFold(k, "From") })
		if v.Err == nil && signedFrom && aligned(v.Domain, fromDomain) {
			return true
		}
	}
	return
}

// ValidSPF reports whether the client IP may send mail for the MAIL FROM
// domain (HELO for bounces) and that domain belongs to the organization of
// the From header. An SPF pass for a foreign domain doesn't make From genuine.
func (a *Envelope) ValidSPF() (valid bool) {
	from, err := a.headerFrom()
	if err != nil {
		return
	}
	ip := remoteIP(a.RemoteAddr)
	if ip == nil {
		return
	}

	domain := domainOf(a.From)
	if a.From == "" {
		domain = a.Helo
	}
	if !aligned(domain, domainOf(from.Address)) {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	defer cancel()

	res, _ := spf.CheckHostWithSender(ip, a.Helo, a.From, spf.WithContext(ctx), spf.WithResolver(resolver))
	return res == spf.Pass
}

// ValidFrom checks the From header for look-alike spoofing like
// support@аpple.com with a Cyrillic "а". utf is the address in ASCII:
// the domain in punycode (support@xn--pple-43d.com) and non-ASCII letters
// of the local part as \uXXXX, show it instead of the original when !valid.
//
// valid is false when the local part or a domain label mixes Latin with
// Cyrillic, Greek or Armenian (аpple), consists only of letters imitating
// Latin under an ASCII TLD (аррӏе.com), has invisible characters, or the
// display name shows an address of another organization
// ("support@apple.com" <x@evil.com>).
// Latin letters with diacritics (àpple) are not detected, utf still shows them.
func (a *Envelope) ValidFrom() (valid bool, utf string) {
	from, err := a.headerFrom()
	if err != nil {
		return
	}

	i := strings.LastIndexByte(from.Address, '@')
	if i < 0 {
		return
	}
	local, domain := from.Address[:i], from.Address[i+1:]

	ascii, err := idna.Lookup.ToASCII(domain)
	if err != nil {
		ascii = escapeASCII(strings.ToLower(domain))
	}
	utf = escapeASCII(local) + "@" + ascii

	labels := strings.Split(strings.ToLower(domain), ".")
	asciiTLD := isASCII(labels[len(labels)-1])
	for _, l := range append(labels, strings.ToLower(local)) {
		if lookalike(l, asciiTLD) {
			return false, utf
		}
	}

	if foreignName(from) {
		return false, utf
	}
	return true, utf
}

// foreignName reports a display name with an address of another organization,
// "x@tickets.example.com via RT" <support@example.com> is fine.
func foreignName(from *mail.Address) bool {
	for _, word := range strings.Fields(from.Name) {
		domain := domainOf(strings.Trim(word, `"'<>()[],;:`))
		if orgDomain(domain) != "" && !aligned(domain, domainOf(from.Address)) {
			return true
		}
	}
	return false
}

// header parses the message headers.
func (a *Envelope) header() (mail.Header, error) {
	m, err := mail.ReadMessage(bytes.NewReader(a.Data))
	if err != nil {
		return nil, err
	}
	return m.Header, nil
}

// headerFrom returns the address of the From header. Several From headers or
// addresses are refused: DKIM may cover one while the reader sees another.
func (a *Envelope) headerFrom() (*mail.Address, error) {
	h, err := a.header()
	if err != nil {
		return nil, err
	}
	if len(h["From"]) != 1 {
		return nil, errors.New("inbox: need exactly one From header")
	}
	list := parseList(h.Get("From"))
	if len(list) != 1 {
		return nil, errors.New("inbox: need exactly one From address")
	}
	return list[0], nil
}

func parseList(s string) []*mail.Address {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	list, _ := addressParser.ParseList(s)
	return list
}

const (
	scriptLatin = 1 << iota
	scriptCyrillic
	scriptGreek
	scriptArmenian
)

// Cyrillic, Greek and Armenian lowercase letters that look like Latin ones
const imitations = "асԁеһіјӏорԛѕԝхуьҽпгѵѡүк" + "αικνορτυχ" + "օսհոցզա"

// lookalike reports a domain label or local part that can pass for a Latin one.
func lookalike(s string, asciiTLD bool) bool {
	var scripts int
	only := true // every letter imitates Latin
	for _, r := range s {
		switch {
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r), unicode.IsSpace(r):
			return true // zero-width, bidi overrides
		case !unicode.IsLetter(r):
			continue
		case r >= 0x0250 && r <= 0x02AF, r >= 0x1D00 && r <= 0x1DBF:
			return true // IPA and phonetic small caps: ɑ ɡ ᴀ
		}
		switch {
		case unicode.Is(unicode.Latin, r):
			scripts |= scriptLatin
		case unicode.Is(unicode.Cyrillic, r):
			scripts |= scriptCyrillic
		case unicode.Is(unicode.Greek, r):
			scripts |= scriptGreek
		case unicode.Is(unicode.Armenian, r):
			scripts |= scriptArmenian
		}
		if !strings.ContainsRune(imitations, r) {
			only = false
		}
	}

	if bits.OnesCount(uint(scripts)) > 1 {
		return true // аpple
	}
	return asciiTLD && scripts != 0 && scripts != scriptLatin && only // аррӏе.com
}

// escapeASCII replaces non-ASCII and control characters with \uXXXX.
func escapeASCII(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\u%04x`, r)
		case r < 0x80:
			b.WriteRune(r)
		case r <= 0xffff:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			fmt.Fprintf(&b, `\U%08x`, r)
		}
	}
	return b.String()
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func domainOf(addr string) string {
	if i := strings.LastIndexByte(addr, '@'); i >= 0 {
		return addr[i+1:]
	}
	return ""
}

// aligned reports whether two domains share the organizational domain
// (DMARC relaxed alignment, RFC 7489 section 3.1).
func aligned(a, b string) bool {
	oa := orgDomain(a)
	return oa != "" && oa == orgDomain(b)
}

func orgDomain(domain string) string {
	d, err := idna.Lookup.ToASCII(strings.TrimSuffix(domain, "."))
	if err != nil || d == "" {
		return ""
	}
	org, err := publicsuffix.EffectiveTLDPlusOne(d)
	if err != nil {
		return ""
	}
	return org
}

func remoteIP(addr net.Addr) net.IP {
	if addr == nil {
		return nil
	}
	if tcp, ok := addr.(*net.TCPAddr); ok {
		return tcp.IP
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}
