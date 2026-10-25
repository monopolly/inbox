package inbox

import (
	"fmt"

	//"io/ioutil"

	"net"
	"regexp"
)

var (
	// debug `true` enables verbose logging.
	debug      = false
	rcptToRE   = regexp.MustCompile(`[Tt][Oo]:\s?<(.+)>`)
	mailFromRE = regexp.MustCompile(`[Ff][Rr][Oo][Mm]:\s?<(.*)>(\s(.*))?`) // Delivery Status Notifications are sent with "MAIL FROM:<>"
	mailSizeRE = regexp.MustCompile(`[Ss][Ii][Zz][Ee]=(\d+)`)
)

func (srv *server) Debug(v bool) {
	debug = v
}

// Handler function called upon successful receipt of an email.
// type Handler func(remoteAddr net.Addr, from string, to []string, data []byte)
type Handler func(eml []byte)

// HandlerRcpt function called on RCPT. Return accept status.
type HandlerRcpt func(remoteAddr net.Addr, from string, to string) bool

// AuthHandler function called when a login attempt is performed. Returns true if credentials are correct.
type AuthHandler func(remoteAddr net.Addr, mechanism string, username []byte, password []byte, shared []byte) (bool, error)

// ListenAndServe listens on the TCP network address addr
// and then calls Serve with handler to handle requests
// on incoming connections.
// func ListenAndServe(addr string, handler Handler, appname string, hostname string) error {
// 	srv := &server{Addr: addr, Handler: handler, Appname: appname, Hostname: hostname}
// 	return srv.ListenAndServe()
// }

// ListenAndServeTLS listens on the TCP network address addr
// and then calls Serve with handler to handle requests
// on incoming connections. Connections may be upgraded to TLS if the client requests it.
// func ListenAndServeTLS(addr string, certFile string, keyFile string, handler Handler, appname string, hostname string) error {
// 	srv := &server{Addr: addr, Handler: handler, Appname: appname, Hostname: hostname}
// 	err := srv.ConfigureTLS(certFile, keyFile)
// 	if err != nil {
// 		return err
// 	}
// 	return srv.ListenAndServe()
// }

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

// LogFunc is a function capable of logging the client-server communication.
type LogFunc func(remoteIP, verb, line string)
