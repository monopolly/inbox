package inbox

import (
	"bufio"
	"crypto/tls"

	//"io/ioutil"

	"net"
	"time"
)

// Server is an SMTP server.
type server struct {
	Addr         string // TCP address to listen on, defaults to ":25" (all addresses, port 25) if empty
	Appname      string
	AuthHandler  AuthHandler
	AuthMechs    map[string]bool // Override list of allowed authentication mechanisms. Currently supported: LOGIN, PLAIN, CRAM-MD5. Enabling LOGIN and PLAIN will reduce RFC 4954 compliance.
	AuthRequired bool            // Require authentication for every command except AUTH, EHLO, HELO, NOOP, RSET or QUIT as per RFC 4954. Ignored if AuthHandler is not configured.
	Handler      Handler
	HandlerRcpt  HandlerRcpt
	Hostname     string
	LogRead      LogFunc
	LogWrite     LogFunc
	Log          func(string, ...any)
	Error        func(string, ...any)
	MaxSize      int // Maximum message size allowed, in bytes
	Timeout      time.Duration
	TLSConfig    *tls.Config
	TLSListener  bool // Listen for incoming TLS connections only (not recommended as it may reduce compatibility). Ignored if TLS is not configured.
	TLSRequired  bool // Require TLS for every command except NOOP, EHLO, STARTTLS, or QUIT as per RFC 3207. Ignored if TLS is not configured.
	Volume       string

	pause bool

	count struct {
		conn   int
		errors int
	}
}

// ConfigureTLS creates a TLS configuration from certificate and key files.
// func (a *server) ConfigureTLS(certFile string, keyFile string) error {
// 	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
// 	if err != nil {
// 		return err
// 	}
// 	a.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
// 	return nil
// }

// ConfigureTLSWithPassphrase creates a TLS configuration from a certificate,
// an encrypted key file and the associated passphrase:
// func (a *server) ConfigureTLSWithPassphrase(
// 	certFile string,
// 	keyFile string,
// 	passphrase string,
// ) error {

// 	certPEMBlock, err := os.ReadFile(certFile)
// 	if err != nil {
// 		return err
// 	}
// 	keyPEMBlock, err := os.ReadFile(keyFile)
// 	if err != nil {
// 		return err
// 	}
// 	keyDERBlock, _ := pem.Decode(keyPEMBlock)

// 	keyPEMDecrypted, err := x509.DecryptPEMBlock(keyDERBlock, []byte(passphrase))
// 	if err != nil {
// 		return err
// 	}
// 	var pemBlock pem.Block
// 	pemBlock.Type = keyDERBlock.Type
// 	pemBlock.Bytes = keyPEMDecrypted
// 	keyPEMBlock = pem.EncodeToMemory(&pemBlock)
// 	cert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
// 	if err != nil {
// 		return err
// 	}
// 	a.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
// 	return nil
// }

// ListenAndServe listens on the TCP network address a.Addr and then
// calls Serve to handle requests on incoming connections.  If
// a.Addr is blank, ":25" is used.
func (a *server) ListenAndServe() error {

	var ln net.Listener
	var err error

	// If TLSListener is enabled, listen for TLS connections only.
	if a.TLSConfig != nil && a.TLSListener {
		ln, err = tls.Listen("tcp", a.Addr, a.TLSConfig)
	} else {
		ln, err = net.Listen("tcp", a.Addr)
	}
	if err != nil {
		return err
	}
	return a.Serve(ln)
}

// Serve creates a new SMTP session after a network connection is established.
func (a *server) Serve(ln net.Listener) error {
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			a.Error("%s IP: %s", err.Error(), ln.Addr().String())
			a.count.errors++
			continue
		}
		if a.pause {
			// Немедленно закрываем соединение с SMTP error
			conn.Write([]byte("421 Service temporarily unavailable\r\n"))
			conn.Close()
			continue
		}

		session := a.newSession(conn)
		session.volume = a.Volume
		session.log = a.Log
		session.errors = a.Error
		a.count.conn++
		go session.serve()
	}
}

// Create new session from connection.
func (a *server) newSession(conn net.Conn) (s *session) {
	s = &session{
		srv:  a,
		conn: conn,
		br:   bufio.NewReader(conn),
		bw:   bufio.NewWriter(conn),
	}

	// Get remote end info for the Received header.
	s.remoteIP, _, _ = net.SplitHostPort(s.conn.RemoteAddr().String())
	names, err := net.LookupAddr(s.remoteIP)
	if err == nil && len(names) > 0 {
		s.remoteHost = names[0]
	} else {
		s.remoteHost = "unknown"
	}

	// Set tls = true if TLS is already in use.
	_, s.tls = s.conn.(*tls.Conn)
	return
}
