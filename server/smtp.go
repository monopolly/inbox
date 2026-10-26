package server

import (
	"errors"
	"fmt"

	"github.com/monopolly/inbox/envelope"
)

// Handler is called synchronously after DATA, before the client gets the reply.
// nil means the message is accepted (250), ErrRejected rejects it permanently (554),
// any other error makes the sender retry later (451).
type Handler func(e *envelope.Envelope) error

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
