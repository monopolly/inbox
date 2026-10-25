package inbox

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/mail"
	"strings"
)

func New(p *Options) (a *Engine) {

	p.valid()

	a = new(Engine)

	// smtp
	a.smtp = &server{}
	a.smtp.MaxSize = p.MaxSizeMB
	a.smtp.Addr = fmt.Sprintf(":%d", p.Port)
	a.smtp.Appname = p.App
	a.smtp.Handler = p.Handler
	a.smtp.Hostname = p.Domains[0]
	a.smtp.Timeout = p.Timeout

	switch p.TLS != nil {
	case true:
		a.smtp.TLSConfig = p.TLS
	default:
		a.smtp.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{certs(p.App, p.Domains...)},
			ServerName:   p.Domains[0],
			MinVersion:   tls.VersionTLS12,
		}
	}

	a.smtp.Log = func(s string, arg ...any) { p.Log("SMTP: "+s, arg...) }
	a.smtp.Error = func(s string, arg ...any) { p.Error("SMTP: "+s, arg...) }
	a.smtp.HandlerRcpt = a.checker(p)
	return
}

type Engine struct {
	smtp *server
}

// проверяет адрес name @ domain, только после
func (a *Engine) checker(p *Options) HandlerRcpt {
	return func(remoteAddr net.Addr, from string, to string) bool {
		ad, err := mail.ParseAddress(to)
		if err != nil {
			return false
		}
		i := strings.Index(ad.Address, "@")
		if i == -1 {
			return false
		}
		return p.Checker(ad.Address[:i], ad.Address[i+1:], remoteAddr)
	}
}

func (a *Engine) Settings() *server {
	return a.smtp
}

func (a *Engine) ListenAndServe() {

	a.smtp.Log("Start %s", a.smtp.Addr)
	err := a.smtp.ListenAndServe()
	if err != nil {
		log.Panic(err)
	}
}

func (a *Engine) Pause(v bool) {
	a.smtp.pause = v
}
