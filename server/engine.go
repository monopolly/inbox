package server

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"

	"github.com/monopolly/inbox/certs"
)

// Engine is an inbound SMTP server: it accepts mail for Options.Domains
// and passes every message to Options.Handler.
type Engine struct {
	opt      Options
	hostname string
	maxSize  int // bytes
	tls      *tls.Config
	log      *slog.Logger

	paused  atomic.Bool
	closing atomic.Bool

	total, rejected, messages, acceptErrors atomic.Int64

	mu        sync.Mutex
	listeners map[net.Listener]struct{}
	sessions  map[*session]struct{}
	perIP     map[string]int
	wg        sync.WaitGroup
}

// Stats is a snapshot of the server counters.
type Stats struct {
	Total    int64 // connections accepted since start
	Active   int   // connections being served now
	Rejected int64 // connections refused because of pause, limits or shutdown
	Messages int64 // messages accepted by Handler
	Errors   int64 // listener accept errors
}

func New(p *Options) (*Engine, error) {

	o := *p
	if err := o.valid(); err != nil {
		return nil, err
	}

	a := &Engine{
		opt:       o,
		hostname:  o.Domains[0],
		maxSize:   o.MaxSizeMB << 20,
		tls:       o.TLS,
		log:       o.Logger,
		listeners: make(map[net.Listener]struct{}),
		sessions:  make(map[*session]struct{}),
		perIP:     make(map[string]int),
	}

	if a.tls == nil {
		cert, err := certs.SelfSigned(o.App, o.Domains...)
		if err != nil {
			return nil, fmt.Errorf("inbox: self-signed certificate: %w", err)
		}
		a.tls = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
	}

	// Go also enables CBC_SHA suites for TLS 1.2, NCSC-NL rates them insufficient.
	// An explicit list in Options.TLS is kept. TLS 1.3 suites are not configurable
	// in Go and all of them are good.
	if a.tls.CipherSuites == nil {
		a.tls = a.tls.Clone()
		a.tls.CipherSuites = cipherSuites
	}

	return a, nil
}

// cipherSuites are the TLS 1.2 suites rated "sufficient" by NCSC-NL
// (Transport Layer Security guidelines 2025-05, appendix B).
var cipherSuites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
}

// Pause makes the server refuse new connections with 421 while v is true.
// Sessions already in progress are not affected.
func (a *Engine) Pause(v bool) {
	a.paused.Store(v)
}

func (a *Engine) Stats() Stats {
	a.mu.Lock()
	active := len(a.sessions)
	a.mu.Unlock()
	return Stats{
		Total:    a.total.Load(),
		Active:   active,
		Rejected: a.rejected.Load(),
		Messages: a.messages.Load(),
		Errors:   a.acceptErrors.Load(),
	}
}
