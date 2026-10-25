package inbox

import (
	"crypto/tls"
	"log"
	"net"
	"os"
	"time"
)

type Options struct {
	Dev       bool
	App       string   //must
	Domains   []string //must
	Handler   Handler  //must
	Checker   func(name, domain string, ip net.Addr) bool
	MaxSizeMB int

	Port int //25

	Timeout time.Duration

	Log   func(string, ...any)
	Error func(string, ...any)

	TLS *tls.Config
}

func (a *Options) valid() {

	if a.Handler == nil {
		panic("Handler must be")
	}

	if a.Port == 0 {
		a.Port = 25
	}

	if a.App == "" {
		a.App = "smtpd"
	}

	if len(a.Domains) == 0 {
		p, _ := os.Hostname()
		a.Domains = []string{p}
	}

	if a.Log == nil {
		a.Log = log.Printf
	}

	if a.Error == nil {
		a.Error = func(s string, a ...any) {
			log.Printf("ERROR: "+s, a...)
		}
	}

	if a.MaxSizeMB == 0 {
		a.MaxSizeMB = 30 * 1024 * 1024
	}

	if a.Checker == nil {
		a.Checker = func(name, domain string, ip net.Addr) bool {
			return true
		}
	}

	if a.Timeout == 0 {
		a.Timeout = time.Minute * 5
	}

}
