package inbox

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"
)

type Options struct {
	App     string   // name in the banner and Received header, default "smtpd"
	Domains []string // the first one is the server hostname, default os.Hostname()
	Handler Handler  // must

	// Checker decides whether mail for name@domain is accepted, nil accepts everything.
	Checker func(name, domain string, ip net.Addr) bool

	Port      int // 25
	MaxSizeMB int // 30

	Timeout        time.Duration // per command and per data chunk, 5m
	SessionTimeout time.Duration // whole connection, 30m, negative disables

	MaxConns      int // simultaneous connections, 0 is unlimited
	MaxConnsPerIP int // simultaneous connections from one IP, 0 is unlimited

	TLS *tls.Config // STARTTLS, default is a self-signed certificate for Domains

	// Logger gets server events; protocol lines are logged at debug level.
	Logger *slog.Logger // slog.Default()
}

func (a *Options) valid() error {

	if a.Handler == nil {
		return errors.New("inbox: Handler must be")
	}

	if a.Port == 0 {
		a.Port = 25
	}

	if a.App == "" {
		a.App = "smtpd"
	}

	if len(a.Domains) == 0 {
		p, err := os.Hostname()
		if err != nil {
			return fmt.Errorf("inbox: no Domains and no hostname: %w", err)
		}
		a.Domains = []string{p}
	}

	if a.Logger == nil {
		a.Logger = slog.Default()
	}

	if a.MaxSizeMB <= 0 {
		a.MaxSizeMB = 30
	}

	if a.Checker == nil {
		a.Checker = func(name, domain string, ip net.Addr) bool {
			return true
		}
	}

	if a.Timeout <= 0 {
		a.Timeout = time.Minute * 5
	}

	if a.SessionTimeout == 0 {
		a.SessionTimeout = time.Minute * 30
	}

	return nil
}
