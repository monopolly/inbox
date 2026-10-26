// Package inbox is an inbound SMTP server (MX). It is a thin entry point,
// the parts are importable on their own:
//
//	server    the SMTP server, its sessions and stats
//	envelope  a received message with DKIM, SPF and From checks
//	certs     self-signed and Let's Encrypt certificates for STARTTLS
package inbox

import (
	"github.com/monopolly/inbox/envelope"
	"github.com/monopolly/inbox/server"
)

type (
	Options  = server.Options
	Engine   = server.Engine
	Stats    = server.Stats
	Handler  = server.Handler
	Envelope = envelope.Envelope
)

var (
	ErrRejected     = server.ErrRejected
	ErrServerClosed = server.ErrServerClosed
)

func New(p *Options) (*Engine, error) {
	return server.New(p)
}
