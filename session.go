package inbox

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"

	//"io/ioutil"

	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type session struct {
	srv           *server
	conn          net.Conn
	br            *bufio.Reader
	bw            *bufio.Writer
	remoteIP      string // Remote IP address
	remoteHost    string // Remote hostname according to reverse DNS lookup
	remoteName    string // Remote hostname as supplied with EHLO
	tls           bool
	authenticated bool
	volume        string
	log           func(string, ...any)
	errors        func(string, ...any)
}

// Function called to handle connection requests.
func (a *session) serve() {
	//id := fmt.Sprintf("mail%d.txt", time.Now().Unix())
	//source := fmt.Sprintf(filepath.Join(s.volume, id))
	defer a.conn.Close()
	var from string
	var gotFrom bool
	var to []string
	var buffer bytes.Buffer
	//fmt.Println(source)
	// Send banner.
	a.writef("220 %s %s ESMTP Service ready", a.srv.Hostname, a.srv.Appname)

	// NEW CONN: 149.521.235.2 email5.jamesmiller.com
	a.log("CONNECT: %s %s", a.remoteIP, a.remoteHost)

	// var index int

loop:
	for {
		// Attempt to read a line from the socket.
		// On timeout, send a timeout message and return from serve().
		// On error, assume the client has gone away i.e. return from serve().
		// index++
		// fmt.Printf("\rinbox/mail/line/%d", index)
		line, err := a.readLine()
		if err != nil {
			// fmt.Println(a.readData())
			if err.Error() != "EOF" {
				a.errors("%s", err)
			} else {
				a.log("DISCONNECT: %s %s %s", a.remoteIP, a.remoteName, a.remoteHost)
			}

			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				a.errors("Timeout: %s %s %s", a.remoteIP, a.remoteName, a.remoteHost)
				// log.Println("inbox/serve/timeout")
				a.writef("421 4.4.2 %s %s ESMTP Service closing transmission channel after timeout exceeded", a.srv.Hostname, a.srv.Appname)
			}
			break
		}
		verb, args := a.parseLine(line)
		switch verb {
		case "HELO":
			a.remoteName = args
			a.writef("250 %s greets %s", a.srv.Hostname, a.remoteName)

			// RFC 2821 section 4.1.4 specifies that EHLO has the same effect as RSET, so reset for HELO too.
			from = ""
			gotFrom = false
			to = nil
			buffer.Reset()
		case "EHLO":
			a.remoteName = args
			a.writef(a.makeEHLOResponse())

			// RFC 2821 section 4.1.4 specifies that EHLO has the same effect as RSET.
			from = ""
			gotFrom = false
			to = nil
			buffer.Reset()
		case "MAIL":
			if a.srv.TLSConfig != nil && a.srv.TLSRequired && !a.tls {
				a.writef("530 5.7.0 Must issue a STARTTLS command first")
				break
			}
			if a.srv.AuthHandler != nil && a.srv.AuthRequired && !a.authenticated {
				a.writef("530 5.7.0 Authentication required")
				break
			}
			match := mailFromRE.FindStringSubmatch(args)
			if match == nil {
				a.writef("501 5.5.4 Syntax error in parameters or arguments (invalid FROM parameter)")
			} else {
				// Validate the SIZE parameter if one was sent.
				if len(match[2]) > 0 { // A parameter is present
					sizeMatch := mailSizeRE.FindStringSubmatch(match[3])
					if sizeMatch == nil {
						a.writef("501 5.5.4 Syntax error in parameters or arguments (invalid SIZE parameter)")
					} else {
						// Enforce the maximum message size if one is set.
						size, err := strconv.Atoi(sizeMatch[1])
						if err != nil { // Bad SIZE parameter
							a.writef("501 5.5.4 Syntax error in parameters or arguments (invalid SIZE parameter)")
						} else if a.srv.MaxSize > 0 && size > a.srv.MaxSize { // SIZE above maximum size, if set
							err = maxSizeExceeded(a.srv.MaxSize)
							a.writef(err.Error())
						} else { // SIZE ok
							from = match[1]
							gotFrom = true
							a.writef("250 2.1.0 Ok")
						}
					}
				} else { // No parameters after FROM
					from = match[1]
					gotFrom = true
					a.writef("250 2.1.0 Ok")
				}
			}
			to = nil
			buffer.Reset()
		case "RCPT":
			if a.srv.TLSConfig != nil && a.srv.TLSRequired && !a.tls {
				a.writef("530 5.7.0 Must issue a STARTTLS command first")
				break
			}
			if a.srv.AuthHandler != nil && a.srv.AuthRequired && !a.authenticated {
				a.writef("530 5.7.0 Authentication required")
				break
			}
			if !gotFrom {
				a.writef("503 5.5.1 Bad sequence of commands (MAIL required before RCPT)")
				break
			}

			match := rcptToRE.FindStringSubmatch(args)
			for i := range match {
				match[i] = strings.ToLower(match[i])
			}
			if match == nil {
				a.writef("501 5.5.4 Syntax error in parameters or arguments (invalid TO parameter)")
			} else {
				// RFC 5321 specifies 100 minimum recipients
				if len(to) == 100 {
					a.writef("452 4.5.3 Too many recipients")
				} else {
					accept := true
					if a.srv.HandlerRcpt != nil {
						accept = a.srv.HandlerRcpt(a.conn.RemoteAddr(), from, match[1])
					}
					if accept {
						to = append(to, match[1])
						a.writef("250 2.1.5 Ok")
					} else {
						a.writef("550 5.1.0 Requested action not taken: mailbox unavailable")
					}
				}
			}
		case "DATA":

			if a.srv.TLSConfig != nil && a.srv.TLSRequired && !a.tls {
				a.writef("530 5.7.0 Must issue a STARTTLS command first")
				break
			}
			if a.srv.AuthHandler != nil && a.srv.AuthRequired && !a.authenticated {
				a.writef("530 5.7.0 Authentication required")
				break
			}
			if !gotFrom || len(to) == 0 {
				a.writef("503 5.5.1 Bad sequence of commands (MAIL & RCPT required before DATA)")
				break
			}

			a.writef("354 Start mail input; end with <CR><LF>.<CR><LF>")

			// Attempt to read message body from the socket.
			// On timeout, send a timeout message and return from serve().
			// On net.Error, assume the client has gone away i.e. return from serve().
			// On other errors, allow the client to try again.
			data, err := a.readData()
			//fmt.Println(string(data))
			//file.Save(source, data)
			raw := data
			if err != nil {
				a.errors(err.Error())
				// log.Println("smtp", err)
				switch err := err.(type) {
				case net.Error:
					if err.Timeout() {
						a.writef("421 4.4.2 %s %s ESMTP Service closing transmission channel after timeout exceeded", a.srv.Hostname, a.srv.Appname)
					}
					break loop
				case maxSizeExceededError:
					a.writef(err.Error())
					continue
				default:
					a.writef("451 4.3.0 Requested action aborted: local error in processing")
					continue
				}
			}
			a.log("Read Raw Data - OK")
			// fmt.Println("read raw data OK")

			// Pass mail on to handler.
			if a.srv.Handler != nil {
				go a.srv.Handler(raw)
			}

			// Create Received header & write message body into buffer.
			buffer.Reset()
			buffer.Write(a.makeHeaders(to))
			buffer.Write(data)
			a.writef("250 2.0.0 Ok: queued")

			// Reset for next mail.
			from = ""
			gotFrom = false
			to = nil
			buffer.Reset()
		case "QUIT":
			a.writef("221 2.0.0 %s %s ESMTP Service closing transmission channel", a.srv.Hostname, a.srv.Appname)
			break loop
		case "RSET":
			if a.srv.TLSConfig != nil && a.srv.TLSRequired && !a.tls {
				a.writef("530 5.7.0 Must issue a STARTTLS command first")
				break
			}
			a.writef("250 2.0.0 Ok")
			from = ""
			gotFrom = false
			to = nil
			buffer.Reset()
		case "NOOP":
			a.writef("250 2.0.0 Ok")
		case "HELP", "VRFY", "EXPN":
			// See RFC 5321 section 4.2.4 for usage of 500 & 502 response codea.
			a.writef("502 5.5.1 Command not implemented")
		case "STARTTLS":
			// Parameters are not allowed (RFC 3207 section 4).
			if args != "" {
				a.writef("501 5.5.2 Syntax error (no parameters allowed)")
				break
			}

			// Handle case where TLS is requested but not configured (and therefore not listed as a service extension).
			if a.srv.TLSConfig == nil {
				a.writef("502 5.5.1 Command not implemented")
				break
			}

			// Handle case where STARTTLS is received when TLS is already in use.
			if a.tls {
				a.writef("503 5.5.1 Bad sequence of commands (TLS already in use)")
				break
			}

			a.writef("220 2.0.0 Ready to start TLS")
			a.log("Start TLS: %s %s %s", a.remoteIP, a.remoteName, a.remoteHost)

			// Establish a TLS connection with the client.
			tlsConn := tls.Server(a.conn, a.srv.TLSConfig)
			err := tlsConn.Handshake()
			if err != nil {
				a.writef("403 4.7.0 TLS handshake failed")
				break
			}

			// TLS handshake succeeded, switch to using the TLS connection.
			a.conn = tlsConn
			a.br = bufio.NewReader(a.conn)
			a.bw = bufio.NewWriter(a.conn)
			a.tls = true

			// RFC 3207 specifies that the server must discard any prior knowledge obtained from the client.
			a.remoteName = ""
			from = ""
			gotFrom = false
			to = nil
			buffer.Reset()
		case "AUTH":
			if a.srv.TLSConfig != nil && a.srv.TLSRequired && !a.tls {
				a.writef("530 5.7.0 Must issue a STARTTLS command first")
				break
			}
			// Handle case where AUTH is requested but not configured (and therefore not listed as a service extension).
			if a.srv.AuthHandler == nil {
				a.writef("502 5.5.1 Command not implemented")
				break
			}

			// Handle case where AUTH is received when already authenticated.
			if a.authenticated {
				a.writef("503 5.5.1 Bad sequence of commands (already authenticated for this session)")
				break
			}

			// RFC 4954 specifies that AUTH is not permitted during mail transactiona.
			if gotFrom || len(to) > 0 {
				a.writef("503 5.5.1 Bad sequence of commands (AUTH not permitted during mail transaction)")
				break
			}

			// RFC 4954 requires a mechanism parameter.
			authType, authArgs := a.parseLine(args)
			if authType == "" {
				a.writef("501 5.5.4 Malformed AUTH input (argument required)")
				break
			}

			// RFC 4954 requires rejecting unsupported authentication mechanisms with a 504 response.
			allowedAuth := a.authMechs()
			if allowed, found := allowedAuth[authType]; !found || !allowed {
				a.writef("504 5.5.4 Unrecognized authentication type")
				break
			}

			// RFC 4954 also specifies that ESMTP code 5.5.4 ("Invalid command arguments") should be returned
			// when attempting to use an unsupported authentication type.
			// Many servers return 5.7.4 ("Security features not supported") instead.
			switch authType {
			case "PLAIN":
				a.authenticated, err = a.handleAuthPlain(authArgs)
			case "LOGIN":
				a.authenticated, err = a.handleAuthLogin(authArgs)
			case "CRAM-MD5":
				a.authenticated, err = a.handleAuthCramMD5()
			}

			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					a.writef("421 4.4.2 %s %s ESMTP Service closing transmission channel after timeout exceeded", a.srv.Hostname, a.srv.Appname)
					break loop
				}

				a.writef(err.Error())
				break
			}

			if a.authenticated {
				a.writef("235 2.7.0 Authentication successful")
			} else {
				a.writef("535 5.7.8 Authentication credentials invalid")
			}
		default:
			// See RFC 5321 section 4.2.4 for usage of 500 & 502 response codea.
			a.writef("500 5.5.2 Syntax error, command unrecognized")
		}
	}
}

// Wrapper function for writing a complete line to the socket.
func (a *session) writef(format string, args ...interface{}) error {
	if a.srv.Timeout > 0 {
		a.conn.SetWriteDeadline(time.Now().Add(a.srv.Timeout))
	}

	line := fmt.Sprintf(format, args...)
	fmt.Fprintf(a.bw, line+"\r\n")
	err := a.bw.Flush()

	if debug {
		verb := "WROTE"
		if a.srv.LogWrite != nil {
			a.srv.LogWrite(a.remoteIP, verb, line)
		} else {
			a.log("%s %s %s", a.remoteIP, verb, line)
			// log.Println(a.remoteIP, verb, line)
		}
	}

	return err
}

// Read a complete line from the socket.
func (a *session) readLine() (string, error) {
	if a.srv.Timeout > 0 {
		a.conn.SetReadDeadline(time.Now().Add(a.srv.Timeout))
	}
	// a.conn.SetReadDeadline(0)

	line, err := a.br.ReadString('\n')
	if err != nil {
		return "", err
	}
	line = strings.TrimSpace(line) // Strip trailing \r\n

	if debug {
		verb := "READ"
		if a.srv.LogRead != nil {
			a.srv.LogRead(a.remoteIP, verb, line)
		} else {
			a.log("%s %s %s", a.remoteIP, verb, line)
			// log.Println(a.remoteIP, verb, line)
		}
	}

	return line, err
}

// Parse a line read from the socket.
func (a *session) parseLine(line string) (verb string, args string) {
	if idx := strings.Index(line, " "); idx != -1 {
		verb = strings.ToUpper(line[:idx])
		args = strings.TrimSpace(line[idx+1:])
	} else {
		verb = strings.ToUpper(line)
		args = ""
	}
	return verb, args
}

// Read the message data following a DATA command.
func (a *session) readData() ([]byte, error) {
	var data []byte
	for {
		if a.srv.Timeout > 0 {
			a.conn.SetReadDeadline(time.Now().Add(a.srv.Timeout))
		}

		line, err := a.br.ReadBytes('\n')
		if err != nil {
			a.errors("%s - Read data func error", err.Error())
			// fmt.Println("read data func error", err)
			return nil, err
		}
		// Handle end of data denoted by lone period (\r\n.\r\n)
		if bytes.Equal(line, []byte(".\r\n")) {
			break
		}
		// Remove leading period (RFC 5321 section 4.5.2)
		if line[0] == '.' {
			line = line[1:]
		}

		// Enforce the maximum message size limit.
		if a.srv.MaxSize > 0 {
			if len(data)+len(line) > a.srv.MaxSize {
				_, _ = a.br.Discard(a.br.Buffered()) // Discard the buffer remnanta.
				return nil, maxSizeExceeded(a.srv.MaxSize)
			}
		}

		data = append(data, line...)
	}
	return data, nil
}

// Create the Received header to comply with RFC 2821 section 3.8.2.
// TODO: Work out what to do with multiple to addresses.
func (a *session) makeHeaders(to []string) []byte {
	var buffer bytes.Buffer
	now := time.Now().Format("Mon, _2 Jan 2006 15:04:05 -0700 (MST)")
	buffer.WriteString(fmt.Sprintf("Received: from %s (%s [%s])\r\n", a.remoteName, a.remoteHost, a.remoteIP))
	buffer.WriteString(fmt.Sprintf("        by %s (%s) with SMTP\r\n", a.srv.Hostname, a.srv.Appname))
	buffer.WriteString(fmt.Sprintf("        for <%s>; %s\r\n", to[0], now))
	return buffer.Bytes()
}

// Determine allowed authentication mechanisma.
// RFC 4954 specifies that plaintext authentication mechanisms such as LOGIN and PLAIN require a TLS connection.
// This can be explicitly overridden e.g. setting a.srv.AuthMechs["LOGIN"] = true.
func (a *session) authMechs() (mechs map[string]bool) {
	mechs = map[string]bool{"LOGIN": a.tls, "PLAIN": a.tls, "CRAM-MD5": true}

	for mech := range mechs {
		allowed, found := a.srv.AuthMechs[mech]
		if found {
			mechs[mech] = allowed
		}
	}

	return
}

// Create the greeting string sent in response to an EHLO command.
func (a *session) makeEHLOResponse() (response string) {
	response = fmt.Sprintf("250-%s greets %s\r\n", a.srv.Hostname, a.remoteName)

	// RFC 1870 specifies that "SIZE 0" indicates no maximum size is in force.
	response += fmt.Sprintf("250-SIZE %d\r\n", a.srv.MaxSize)

	// Only list STARTTLS if TLS is configured, but not currently in use.
	if a.srv.TLSConfig != nil && !a.tls {
		response += "250-STARTTLS\r\n"
	}

	// Only list AUTH if an AuthHandler is configured and at least one mechanism is allowed.
	if a.srv.AuthHandler != nil {
		var mechs []string
		for mech, allowed := range a.authMechs() {
			if allowed {
				mechs = append(mechs, mech)
			}
		}
		if len(mechs) > 0 {
			response += "250-AUTH " + strings.Join(mechs, " ") + "\r\n"
		}
	}

	response += "250 ENHANCEDSTATUSCODES"
	return
}

func (a *session) handleAuthLogin(arg string) (bool, error) {
	var err error

	if arg == "" {
		a.writef("334 " + base64.StdEncoding.EncodeToString([]byte("Username:")))
		arg, err = a.readLine()
		if err != nil {
			return false, err
		}
	}

	username, err := base64.StdEncoding.DecodeString(arg)
	if err != nil {
		return false, errors.New("501 5.5.2 Syntax error (unable to decode)")
	}

	a.writef("334 " + base64.StdEncoding.EncodeToString([]byte("Password:")))
	line, err := a.readLine()
	if err != nil {
		return false, err
	}

	password, err := base64.StdEncoding.DecodeString(line)
	if err != nil {
		return false, errors.New("501 5.5.2 Syntax error (unable to decode)")
	}

	// Validate credentials.
	authenticated, err := a.srv.AuthHandler(a.conn.RemoteAddr(), "LOGIN", username, password, nil)

	return authenticated, err
}

func (a *session) handleAuthPlain(arg string) (bool, error) {
	var err error

	// If fast mode (AUTH PLAIN [arg]) is not used, prompt for credentiala.
	if arg == "" {
		a.writef("334 ")
		arg, err = a.readLine()
		if err != nil {
			return false, err
		}
	}

	data, err := base64.StdEncoding.DecodeString(arg)
	if err != nil {
		return false, errors.New("501 5.5.2 Syntax error (unable to decode)")
	}

	parts := bytes.Split(data, []byte{0})
	if len(parts) != 3 {
		return false, errors.New("501 5.5.2 Syntax error (unable to parse)")
	}

	// Validate credentials.
	authenticated, err := a.srv.AuthHandler(a.conn.RemoteAddr(), "PLAIN", parts[1], parts[2], nil)

	return authenticated, err
}

func (a *session) handleAuthCramMD5() (bool, error) {
	shared := "<" + strconv.Itoa(os.Getpid()) + "." + strconv.Itoa(time.Now().Nanosecond()) + "@" + a.srv.Hostname + ">"

	a.writef("334 " + base64.StdEncoding.EncodeToString([]byte(shared)))

	data, err := a.readLine()
	if err != nil {
		return false, err
	}

	if data == "*" {
		return false, errors.New("501 5.7.0 Authentication cancelled")
	}

	buf, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return false, errors.New("501 5.5.2 Syntax error (unable to decode)")
	}

	fields := strings.Split(string(buf), " ")
	if len(fields) < 2 {
		return false, errors.New("501 5.5.2 Syntax error (unable to parse)")
	}

	// Validate credentials.
	authenticated, err := a.srv.AuthHandler(a.conn.RemoteAddr(), "CRAM-MD5", []byte(fields[0]), []byte(fields[1]), []byte(shared))

	return authenticated, err
}
