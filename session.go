package inbox

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	lineLimit     = 4096 // max command line incl. CRLF, RFC 5321 minimum is 512
	maxRecipients = 100  // RFC 5321 section 4.5.3.1.8
	maxErrors     = 20   // error replies before the connection is dropped
	dnsTimeout    = 5 * time.Second
)

var (
	errShutdown    = errors.New("server shutting down")
	errLineTooLong = errors.New("line too long")
)

type session struct {
	srv  *Engine
	raw  net.Conn // TCP connection: deadlines and forced close
	conn net.Conn // raw or TLS on top of it
	br   *bufio.Reader
	bw   *bufio.Writer
	log  *slog.Logger
	end  time.Time // session deadline, zero if unlimited

	remoteIP   string
	remoteHost string // reverse DNS or "unknown"
	helo       string // name from HELO/EHLO, empty until greeted
	esmtp      bool
	tls        bool
	errCount   int

	// current mail transaction
	from    string
	gotFrom bool
	to      []string

	mu   sync.Mutex // guards busy against Shutdown
	busy bool       // receiving DATA or running Handler, must not be interrupted
}

func (a *Engine) newSession(conn net.Conn, id int64) (s *session) {
	s = &session{
		srv:        a,
		raw:        conn,
		conn:       conn,
		br:         bufio.NewReaderSize(conn, lineLimit),
		bw:         bufio.NewWriter(conn),
		remoteHost: "unknown",
	}
	s.remoteIP, _, _ = net.SplitHostPort(conn.RemoteAddr().String())
	s.log = a.log.With("sid", id, "ip", s.remoteIP)
	if a.opt.SessionTimeout > 0 {
		s.end = time.Now().Add(a.opt.SessionTimeout)
	}
	return
}

func (s *session) serve() {
	defer func() { s.conn.Close() }()
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("session panic", "panic", r, "stack", string(debug.Stack()))
		}
	}()

	s.lookupHost()
	s.reply("220 %s %s ESMTP Service ready", s.srv.hostname, s.srv.opt.App)
	s.log.Info("connect", "host", s.remoteHost)

	for {
		line, err := s.readLine()
		switch {
		case errors.Is(err, errLineTooLong):
			s.fail("500 5.5.2 Line too long")
		case err != nil:
			s.readFailed(err)
			return
		case !s.command(line):
			return
		}
		if s.errCount >= maxErrors {
			s.log.Warn("too many errors")
			s.reply("421 4.7.0 %s Too many errors, closing connection", s.srv.hostname)
			return
		}
	}
}

// command runs one SMTP command and reports whether the session goes on.
func (s *session) command(line string) bool {
	verb, args, _ := strings.Cut(line, " ")
	args = strings.TrimSpace(args)

	switch verb = strings.ToUpper(verb); verb {
	case "HELO", "EHLO":
		s.cmdHelo(verb == "EHLO", args)
	case "MAIL":
		s.cmdMail(args)
	case "RCPT":
		s.cmdRcpt(args)
	case "DATA":
		return s.cmdData(args)
	case "STARTTLS":
		return s.cmdStartTLS(args)
	case "RSET":
		s.reset()
		s.reply("250 2.0.0 Ok")
	case "NOOP":
		s.reply("250 2.0.0 Ok")
	case "VRFY":
		s.reply("252 2.5.0 Cannot VRFY user, but will accept message")
	case "HELP", "EXPN":
		// See RFC 5321 section 4.2.4 for usage of 500 & 502 response codes.
		s.reply("502 5.5.1 Command not implemented")
	case "QUIT":
		s.reply("221 2.0.0 %s %s ESMTP Service closing transmission channel", s.srv.hostname, s.srv.opt.App)
		return false
	default:
		s.fail("500 5.5.2 Syntax error, command unrecognized")
	}
	return true
}

func (s *session) cmdHelo(ehlo bool, args string) {
	name, _, _ := strings.Cut(args, " ")
	if name == "" || strings.ContainsFunc(name, unicode.IsControl) {
		s.fail("501 5.5.4 Syntax: HELO/EHLO hostname")
		return
	}

	// RFC 5321 section 4.1.4: EHLO has the same effect as RSET.
	s.helo, s.esmtp = name, ehlo
	s.reset()

	if !ehlo {
		s.reply("250 %s", s.srv.hostname)
		return
	}

	ext := []string{
		s.srv.hostname + " greets " + name,
		"SIZE " + strconv.Itoa(s.srv.maxSize),
		"8BITMIME",
		"PIPELINING",
		"SMTPUTF8",
	}
	if !s.tls {
		ext = append(ext, "STARTTLS")
	}
	ext = append(ext, "ENHANCEDSTATUSCODES")

	lines := make([]string, len(ext))
	for i, e := range ext {
		sep := "-"
		if i == len(ext)-1 {
			sep = " "
		}
		lines[i] = "250" + sep + e
	}
	s.send(lines...)
}

func (s *session) cmdMail(args string) {
	switch {
	case s.helo == "":
		s.fail("503 5.5.1 Error: send HELO/EHLO first")
		return
	case s.gotFrom:
		s.fail("503 5.5.1 Error: nested MAIL command")
		return
	}

	from, params, ok := parsePath(args, "FROM:")
	if !ok {
		s.fail("501 5.5.4 Syntax error in parameters or arguments (invalid FROM parameter)")
		return
	}

	for _, p := range params {
		key, val, hasVal := strings.Cut(p, "=")
		switch strings.ToUpper(key) {
		case "SIZE":
			size, err := strconv.ParseInt(val, 10, 64)
			if err != nil || size < 0 {
				s.fail("501 5.5.4 Syntax error in parameters or arguments (invalid SIZE parameter)")
				return
			}
			if size > int64(s.srv.maxSize) {
				s.fail("%s", maxSizeExceeded(s.srv.maxSize))
				return
			}
		case "BODY":
			if v := strings.ToUpper(val); v != "7BIT" && v != "8BITMIME" {
				s.fail("501 5.5.4 Syntax error in parameters or arguments (invalid BODY parameter)")
				return
			}
		case "SMTPUTF8":
			if hasVal {
				s.fail("501 5.5.4 Syntax error in parameters or arguments (invalid SMTPUTF8 parameter)")
				return
			}
		default:
			s.fail("555 5.5.4 Unsupported parameter %s", key)
			return
		}
	}

	s.from, s.gotFrom, s.to = from, true, nil
	s.reply("250 2.1.0 Ok")
}

func (s *session) cmdRcpt(args string) {
	if !s.gotFrom {
		s.fail("503 5.5.1 Bad sequence of commands (MAIL required before RCPT)")
		return
	}

	to, params, ok := parsePath(args, "TO:")
	if !ok || to == "" {
		s.fail("501 5.5.4 Syntax error in parameters or arguments (invalid TO parameter)")
		return
	}
	if len(params) > 0 {
		s.fail("555 5.5.4 Unsupported parameter %s", params[0])
		return
	}
	if len(s.to) >= maxRecipients {
		// not counted as an error: the client sends the rest in another transaction
		s.reply("452 4.5.3 Too many recipients")
		return
	}

	to = strings.ToLower(to)
	name, domain := to, s.srv.hostname // RFC 5321 section 4.5.1: bare <postmaster>
	if i := strings.LastIndexByte(to, '@'); i >= 0 {
		name, domain = to[:i], to[i+1:]
	} else if to != "postmaster" {
		s.fail("501 5.1.3 Bad recipient address syntax")
		return
	}
	if name == "" || domain == "" {
		s.fail("501 5.1.3 Bad recipient address syntax")
		return
	}

	if !s.srv.opt.Checker(name, domain, s.raw.RemoteAddr()) {
		s.fail("550 5.1.1 Requested action not taken: mailbox unavailable")
		return
	}

	s.to = append(s.to, to)
	s.reply("250 2.1.5 Ok")
}

func (s *session) cmdData(args string) bool {
	switch {
	case args != "":
		s.fail("501 5.5.4 Syntax error (no parameters allowed)")
		return true
	case !s.gotFrom:
		s.fail("503 5.5.1 Bad sequence of commands (MAIL required before DATA)")
		return true
	case len(s.to) == 0:
		s.fail("554 5.5.1 Error: no valid recipients")
		return true
	}

	s.setBusy(true)
	defer s.setBusy(false)

	s.reply("354 Start mail input; end with <CRLF>.<CRLF>")

	data, err := s.readData()
	var tooBig maxSizeExceededError
	switch {
	case errors.As(err, &tooBig):
		s.log.Warn("message too big", "from", s.from)
		s.reply("%s", tooBig)
		s.reset()
		return true
	case err != nil:
		s.readFailed(err)
		return false
	}

	e := &Envelope{
		RemoteAddr: s.raw.RemoteAddr(),
		RemoteHost: s.remoteHost,
		Helo:       s.helo,
		From:       s.from,
		To:         s.to,
		TLS:        s.tls,
		Received:   s.received(),
		Data:       data,
	}

	switch err := s.deliver(e); {
	case err == nil:
		s.srv.messages.Add(1)
		s.log.Info("message", "from", e.From, "to", e.To, "size", len(data))
		s.reply("250 2.0.0 Ok: queued")
	case errors.Is(err, ErrRejected):
		s.log.Info("message rejected", "from", e.From, "to", e.To, "err", err)
		s.reply("554 5.7.1 Message rejected")
	default:
		s.log.Error("handler", "from", e.From, "to", e.To, "err", err)
		s.reply("451 4.3.0 Requested action aborted: local error in processing")
	}

	s.reset()
	return true
}

func (s *session) cmdStartTLS(args string) bool {
	switch {
	case args != "":
		// Parameters are not allowed (RFC 3207 section 4).
		s.fail("501 5.5.2 Syntax error (no parameters allowed)")
		return true
	case s.tls:
		s.fail("503 5.5.1 Bad sequence of commands (TLS already in use)")
		return true
	case s.br.Buffered() > 0:
		// The client must wait for the reply; anything sent before could be
		// plaintext injected into the TLS session (CVE-2011-0411).
		s.log.Warn("pipelined data after STARTTLS")
		s.reply("554 5.5.1 Error: pipelining after STARTTLS is not allowed")
		return false
	}

	s.reply("220 2.0.0 Ready to start TLS")

	conn := tls.Server(s.raw, s.srv.tls)
	s.readDeadline()
	if err := conn.Handshake(); err != nil {
		s.log.Info("tls handshake failed", "err", err)
		return false
	}

	s.conn, s.tls = conn, true
	s.br.Reset(conn)
	s.bw.Reset(conn)

	// RFC 3207 section 4.2: discard any knowledge obtained from the client.
	s.helo, s.esmtp = "", false
	s.reset()

	st := conn.ConnectionState()
	s.log.Info("tls", "version", tls.VersionName(st.Version), "cipher", tls.CipherSuiteName(st.CipherSuite))
	return true
}

// deliver passes the message to Handler, a panic there becomes an error.
func (s *session) deliver(e *Envelope) (err error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("handler panic", "panic", r, "stack", string(debug.Stack()))
			err = fmt.Errorf("handler panic: %v", r)
		}
	}()
	return s.srv.opt.Handler(e)
}

func (s *session) reset() {
	s.from, s.gotFrom, s.to = "", false, nil
}

// readFailed answers a failed read where possible.
func (s *session) readFailed(err error) {
	switch {
	case errors.Is(err, errShutdown), s.srv.closing.Load() && isTimeout(err):
		s.reply("421 4.3.2 %s Service shutting down", s.srv.hostname)
	case isTimeout(err):
		s.log.Info("timeout")
		s.reply("421 4.4.2 %s %s ESMTP Service closing transmission channel after timeout exceeded", s.srv.hostname, s.srv.opt.App)
	case errors.Is(err, io.EOF):
		s.log.Info("disconnect")
	default:
		s.log.Warn("read", "err", err)
	}
}

// reply sends one response line. format must be constant, client data goes into args only.
func (s *session) reply(format string, args ...any) {
	s.send(fmt.Sprintf(format, args...))
}

// fail is reply for client errors, too many of them drop the connection.
func (s *session) fail(format string, args ...any) {
	s.errCount++
	s.reply(format, args...)
}

func (s *session) send(lines ...string) {
	s.raw.SetWriteDeadline(time.Now().Add(s.srv.opt.Timeout))
	for _, line := range lines {
		s.bw.WriteString(line)
		s.bw.WriteString("\r\n")
		s.log.Debug("send", "line", line)
	}
	if err := s.bw.Flush(); err != nil {
		s.log.Debug("write", "err", err)
	}
}

// readDeadline limits the next read by Timeout and by the session deadline.
func (s *session) readDeadline() {
	d := time.Now().Add(s.srv.opt.Timeout)
	if !s.end.IsZero() && s.end.Before(d) {
		d = s.end
	}
	s.raw.SetReadDeadline(d)
}

// Read a command line, at most lineLimit bytes.
func (s *session) readLine() (string, error) {
	s.mu.Lock()
	if s.srv.closing.Load() {
		s.mu.Unlock()
		return "", errShutdown
	}
	s.readDeadline()
	s.mu.Unlock()

	line, err := s.br.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		// skip the rest of the line without keeping it in memory
		for errors.Is(err, bufio.ErrBufferFull) {
			_, err = s.br.ReadSlice('\n')
		}
		if err == nil {
			err = errLineTooLong
		}
		return "", err
	}
	if err != nil {
		return "", err
	}

	str := strings.TrimSpace(string(line))
	s.log.Debug("recv", "line", str)
	return str, nil
}

// readData reads the message after DATA up to <CRLF>.<CRLF>.
// A dot line ends the data only after CRLF: "\n.\r\n" after a bare LF stays
// content, so one message can't be split into two (SMTP smuggling).
// An oversized message is read to the end and dropped, so its rest is never
// taken as commands.
func (s *session) readData() ([]byte, error) {
	var data []byte
	tooBig := false
	lineStart, afterCRLF := true, true
	prev := byte('\n')

	for {
		s.readDeadline()
		raw, err := s.br.ReadSlice('\n')
		if err != nil && !errors.Is(err, bufio.ErrBufferFull) {
			return nil, err
		}
		complete := err == nil

		chunk := raw
		if lineStart {
			if complete && afterCRLF && string(raw) == ".\r\n" {
				break
			}
			// Remove leading period (RFC 5321 section 4.5.2)
			if chunk[0] == '.' {
				chunk = chunk[1:]
			}
		}

		if !tooBig {
			if len(data)+len(chunk) > s.srv.maxSize {
				tooBig, data = true, nil
			} else {
				data = append(data, chunk...)
			}
		}

		if complete {
			n := len(raw)
			afterCRLF = n >= 2 && raw[n-2] == '\r' || n == 1 && prev == '\r'
		}
		lineStart = complete
		prev = raw[len(raw)-1]
	}

	if tooBig {
		return nil, maxSizeExceeded(s.srv.maxSize)
	}
	return data, nil
}

func (s *session) setBusy(v bool) {
	s.mu.Lock()
	s.busy = v
	s.mu.Unlock()
}

// interrupt wakes a session waiting for a command so it can close with 421.
func (s *session) interrupt() {
	s.mu.Lock()
	if !s.busy {
		s.raw.SetReadDeadline(time.Now())
	}
	s.mu.Unlock()
}

func (s *session) lookupHost() {
	ctx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(ctx, s.remoteIP)
	if err == nil && len(names) > 0 {
		s.remoteHost = strings.TrimSuffix(names[0], ".")
	}
}

// received builds the trace header of RFC 5321 section 4.4.
func (s *session) received() string {
	proto := "SMTP"
	if s.esmtp {
		proto = "ESMTP"
		if s.tls {
			proto = "ESMTPS"
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Received: from %s (%s [%s])\r\n", s.helo, s.remoteHost, s.remoteIP)
	fmt.Fprintf(&b, "\tby %s (%s) with %s", s.srv.hostname, s.srv.opt.App, proto)
	if len(s.to) == 1 {
		fmt.Fprintf(&b, "\r\n\tfor <%s>", s.to[0])
	}
	fmt.Fprintf(&b, "; %s\r\n", time.Now().Format(time.RFC1123Z))
	return b.String()
}

// parsePath parses "FROM:<addr> PARAM=VALUE ..." for MAIL and RCPT.
// The prefix is case-insensitive, spaces before "<" are tolerated.
func parsePath(args, prefix string) (addr string, params []string, ok bool) {
	if len(args) < len(prefix) || !strings.EqualFold(args[:len(prefix)], prefix) {
		return
	}
	rest := strings.TrimLeft(args[len(prefix):], " ")
	if !strings.HasPrefix(rest, "<") {
		return
	}
	end := strings.IndexByte(rest, '>')
	if end < 0 {
		return
	}
	addr = rest[1:end]

	// obsolete source route <@a,@b:user@host>
	if strings.HasPrefix(addr, "@") {
		i := strings.IndexByte(addr, ':')
		if i < 0 {
			return "", nil, false
		}
		addr = addr[i+1:]
	}

	return addr, strings.Fields(rest[end+1:]), true
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
