// Package convert turns a received envelope into email.Email. It is separate
// from envelope so the server doesn't link github.com/monopolly/email.
package convert

import (
	"errors"
	"net/mail"
	"strings"

	"github.com/monopolly/email"
	"github.com/monopolly/inbox/envelope"
)

// Email parses the message into email.Email and adds what only the envelope
// knows: IP, BCC (recipients that are not in To or Cc headers) and the original EML.
func Email(e *envelope.Envelope) (*email.Email, error) {
	m, err := email.ParseRawEmail(e.Data)
	if err != nil {
		return nil, err
	}
	if m == nil {
		return nil, errors.New("inbox: can't parse message")
	}

	m.EML = e.Data
	if ip := e.IP(); ip != nil {
		m.IP = ip.String()
	}

	if h, err := e.Header(); err == nil {
		if d, err := h.Date(); err == nil {
			m.Date = &d
		}
	}
	m.CC = e.Addresses("Cc")

	visible := map[string]bool{}
	for _, x := range append(e.Addresses("To"), m.CC...) {
		visible[strings.ToLower(x.Address)] = true
	}
	for _, rcpt := range e.To {
		if !visible[rcpt] {
			m.BCC = append(m.BCC, &mail.Address{Address: rcpt})
		}
	}
	return m, nil
}
