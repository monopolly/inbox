package inbox

import (
	"errors"
	"fmt"
	"net"
)

// Envelope is a received message together with its SMTP envelope.
// Recipients from RCPT TO are the only source of BCC addresses:
// they never appear in the message headers.
type Envelope struct {
	RemoteAddr net.Addr
	RemoteHost string   // reverse DNS of the client, "unknown" if none
	Helo       string   // name the client gave in HELO/EHLO
	From       string   // MAIL FROM, empty for bounces
	To         []string // accepted RCPT TO, lowercased
	TLS        bool     // message was received over STARTTLS

	// Received is the trace header of this hop (RFC 5321 section 4.4),
	// ending with CRLF. It is not part of Data; prepend it if needed.
	Received string

	// Data is the original message exactly as sent by the client
	// (only the SMTP dot-stuffing is removed).
	Data []byte
}

// Handler is called synchronously after DATA, before the client gets the reply.
// nil means the message is accepted (250), ErrRejected rejects it permanently (554),
// any other error makes the sender retry later (451).
type Handler func(e *Envelope) error

var (
	// ErrRejected is returned (or wrapped) by Handler to reject a message permanently.
	ErrRejected = errors.New("inbox: message rejected")

	// ErrServerClosed is returned by Serve and ListenAndServe after Shutdown.
	ErrServerClosed = errors.New("inbox: server closed")
)

type maxSizeExceededError struct {
	limit int
}

func maxSizeExceeded(limit int) maxSizeExceededError {
	return maxSizeExceededError{limit}
}

// Error uses the RFC 5321 response message in preference to RFC 1870.
// RFC 3463 defines enhanced status code x.3.4 as "Message too big for system".
func (err maxSizeExceededError) Error() string {
	return fmt.Sprintf("552 5.3.4 Requested mail action aborted: exceeded storage allocation (%d)", err.limit)
}
