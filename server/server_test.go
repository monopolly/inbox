package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/textproto"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/monopolly/inbox/envelope"
)

type testServer struct {
	*Engine
	addr string
	mail chan *envelope.Envelope
}

func start(t *testing.T, o Options) *testServer {
	t.Helper()
	ts := &testServer{mail: make(chan *envelope.Envelope, 10)}
	if o.Handler == nil {
		o.Handler = func(e *envelope.Envelope) error {
			ts.mail <- e
			return nil
		}
	}
	if o.Domains == nil {
		o.Domains = []string{"mx.example.com"}
	}
	o.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))

	e, err := New(&o)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go e.Serve(ln)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		e.Shutdown(ctx)
	})

	ts.Engine, ts.addr = e, ln.Addr().String()
	return ts
}

func (ts *testServer) next(t *testing.T) *envelope.Envelope {
	t.Helper()
	select {
	case e := <-ts.mail:
		return e
	case <-time.After(5 * time.Second):
		t.Fatal("no message delivered")
		return nil
	}
}

func (ts *testServer) waitIdle(t *testing.T) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); ts.Stats().Active > 0; {
		if time.Now().After(deadline) {
			t.Fatal("sessions still active")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type client struct {
	t    *testing.T
	conn net.Conn
	text *textproto.Conn
}

func newClient(t *testing.T, conn net.Conn) *client {
	t.Cleanup(func() { conn.Close() })
	return &client{t: t, conn: conn, text: textproto.NewConn(conn)}
}

func (ts *testServer) dial(t *testing.T, code int) *client {
	t.Helper()
	conn, err := net.Dial("tcp", ts.addr)
	if err != nil {
		t.Fatal(err)
	}
	c := newClient(t, conn)
	c.expect(code)
	return c
}

func (c *client) read() (int, string, error) {
	c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	return c.text.ReadResponse(0)
}

func (c *client) expect(code int) string {
	c.t.Helper()
	got, msg, err := c.read()
	if err != nil {
		c.t.Fatalf("want %d, got error %v", code, err)
	}
	if got != code {
		c.t.Fatalf("want %d, got %d %s", code, got, msg)
	}
	return msg
}

func (c *client) send(s string) {
	c.t.Helper()
	if _, err := io.WriteString(c.conn, s); err != nil {
		c.t.Fatal(err)
	}
}

func (c *client) cmd(line string, code int) string {
	c.t.Helper()
	c.send(line + "\r\n")
	return c.expect(code)
}

// message runs one transaction, body must end with CRLF.
func (c *client) message(body string, code int) {
	c.t.Helper()
	c.cmd("MAIL FROM:<sender@example.org>", 250)
	c.cmd("RCPT TO:<user@example.com>", 250)
	c.cmd("DATA", 354)
	c.send(body + ".\r\n")
	c.expect(code)
}

func (c *client) expectClosed() {
	c.t.Helper()
	if _, _, err := c.read(); !errors.Is(err, io.EOF) {
		c.t.Fatalf("want closed connection, got %v", err)
	}
}

func TestNewWithoutHandler(t *testing.T) {
	if _, err := New(&Options{}); err == nil {
		t.Fatal("want error")
	}
}

func TestDelivery(t *testing.T) {
	ts := start(t, Options{})
	c := ts.dial(t, 220)

	ehlo := c.cmd("EHLO client.example.org", 250)
	for _, ext := range []string{"SIZE 31457280", "8BITMIME", "PIPELINING", "SMTPUTF8", "STARTTLS", "ENHANCEDSTATUSCODES"} {
		if !strings.Contains(ehlo, ext) {
			t.Errorf("EHLO has no %s:\n%s", ext, ehlo)
		}
	}

	c.cmd("MAIL FROM:<Sender@Example.org> BODY=8BITMIME SIZE=100", 250)
	c.cmd("RCPT TO:<User@Example.com>", 250)
	c.cmd("RCPT TO:<bcc@example.com>", 250)
	c.cmd("DATA", 354)
	c.send("Subject: hi\r\n\r\n..dot\r\nbody\r\n.\r\n")
	c.expect(250)

	e := ts.next(t)
	if want := "Subject: hi\r\n\r\n.dot\r\nbody\r\n"; string(e.Data) != want {
		t.Errorf("Data = %q, want %q", e.Data, want)
	}
	if e.From != "Sender@Example.org" || e.Helo != "client.example.org" || e.TLS {
		t.Errorf("envelope = %+v", e)
	}
	if strings.Join(e.To, ",") != "user@example.com,bcc@example.com" {
		t.Errorf("To = %v", e.To)
	}
	if !strings.HasPrefix(e.Received, "Received: from client.example.org (") ||
		!strings.Contains(e.Received, "with ESMTP;") || !strings.HasSuffix(e.Received, "\r\n") {
		t.Errorf("Received = %q", e.Received)
	}

	// a second message in the same session
	c.message("Subject: two\r\n\r\n", 250)
	if e := ts.next(t); !strings.Contains(e.Received, "for <user@example.com>") {
		t.Errorf("Received = %q", e.Received)
	}

	c.cmd("QUIT", 221)
	if s := ts.Stats(); s.Messages != 2 || s.Total != 1 {
		t.Errorf("stats = %+v", s)
	}
}

func TestCommands(t *testing.T) {
	ts := start(t, Options{})
	c := ts.dial(t, 220)

	for _, tt := range []struct {
		cmd  string
		code int
	}{
		{"MAIL FROM:<a@b.c>", 503}, // no HELO
		{"HELO", 501},
		{"HELO client", 250},
		{"RCPT TO:<x@example.com>", 503},
		{"DATA", 503},
		{"MAIL FROM:<>", 250},
		{"MAIL FROM:<a@b.c>", 503}, // nested
		{"RSET", 250},
		{"MAIL FROM:a@b.c", 501},
		{"MAIL FROM:<a@b.c> SIZE=abc", 501},
		{"MAIL FROM:<a@b.c> SIZE=99999999999", 552},
		{"MAIL FROM:<a@b.c> BODY=BINARYMIME", 501},
		{"MAIL FROM:<a@b.c> FOO=1", 555},
		{"MAIL FROM: <a@b.c> SMTPUTF8", 250},
		{"DATA", 554}, // no recipients
		{"RCPT TO:<>", 501},
		{"RCPT TO:<nobody>", 501},
		{"RCPT TO:<x@example.com> NOTIFY=NEVER", 555},
		{"RCPT TO:<@relay.org:x@example.com>", 250},
		{"RCPT TO:<Postmaster>", 250},
		{"DATA x", 501},
		{"VRFY x", 252},
		{"EXPN x", 502},
		{"NOOP", 250},
		{"BDAT 10 LAST", 500},
		{"STARTTLS x", 501},
	} {
		c.cmd(tt.cmd, tt.code)
	}

	// client data must not be used as a format string
	if msg := c.cmd("EHLO %d%s", 250); !strings.Contains(msg, "greets %d%s") {
		t.Errorf("EHLO reply: %q", msg)
	}
}

func TestChecker(t *testing.T) {
	ts := start(t, Options{
		Checker: func(name, domain string, ip net.Addr) bool {
			return name == "ok" && domain == "example.com" && ip != nil
		},
	})
	c := ts.dial(t, 220)
	c.cmd("EHLO client", 250)
	c.cmd("MAIL FROM:<a@b.c>", 250)
	c.cmd("RCPT TO:<ok@example.com>", 250)
	c.cmd("RCPT TO:<OK@EXAMPLE.COM>", 250)
	if msg := c.cmd("RCPT TO:<no@example.com>", 550); !strings.HasPrefix(msg, "5.1.1") {
		t.Errorf("reply: %q", msg)
	}
	c.cmd("RCPT TO:<ok@other.com>", 550)
}

func TestTooManyRecipients(t *testing.T) {
	ts := start(t, Options{})
	c := ts.dial(t, 220)
	c.cmd("EHLO client", 250)
	c.cmd("MAIL FROM:<a@b.c>", 250)
	for i := range maxRecipients {
		c.cmd(fmt.Sprintf("RCPT TO:<u%d@example.com>", i), 250)
	}
	// the overflow is answered with 452 but doesn't count as errors
	for range maxErrors + 5 {
		c.cmd("RCPT TO:<more@example.com>", 452)
	}
	c.cmd("NOOP", 250)
}

func TestMaxSize(t *testing.T) {
	ts := start(t, Options{MaxSizeMB: 1})
	c := ts.dial(t, 220)
	c.cmd("EHLO client", 250)
	c.cmd("MAIL FROM:<a@b.c>", 250)
	c.cmd("RCPT TO:<u@example.com>", 250)
	c.cmd("DATA", 354)

	// one line without LF bigger than the limit, then commands inside the body
	c.send(strings.Repeat("x", 2<<20) + "\r\nQUIT\r\nRSET\r\n.\r\n")
	c.expect(552)

	// the rest of the body was not taken as commands
	c.cmd("HELP", 502)
	c.message("Subject: small\r\n\r\n", 250)
	ts.next(t)
}

func TestSmuggling(t *testing.T) {
	ts := start(t, Options{})
	c := ts.dial(t, 220)
	c.cmd("EHLO client", 250)
	c.message("Subject: a\r\n\r\nfirst\n.\r\nMAIL FROM:<evil@x.y>\r\nRCPT TO:<v@example.com>\r\nDATA\r\nevil\r\n", 250)

	// a smuggled transaction would answer 250 to MAIL here
	c.cmd("HELP", 502)

	e := ts.next(t)
	if !bytes.Contains(e.Data, []byte("MAIL FROM:<evil@x.y>")) {
		t.Errorf("Data = %q", e.Data)
	}
	select {
	case e := <-ts.mail:
		t.Fatalf("smuggled message: %q", e.Data)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestHandlerErrors(t *testing.T) {
	var mode atomic.Int32
	ts := start(t, Options{
		Handler: func(e *envelope.Envelope) error {
			switch mode.Load() {
			case 0:
				return errors.New("disk full")
			case 1:
				return fmt.Errorf("spam: %w", ErrRejected)
			default:
				panic("boom")
			}
		},
	})
	c := ts.dial(t, 220)
	c.cmd("EHLO client", 250)

	c.message("Subject: x\r\n\r\n", 451)
	mode.Store(1)
	c.message("Subject: x\r\n\r\n", 554)
	mode.Store(2)
	c.message("Subject: x\r\n\r\n", 451)

	c.cmd("NOOP", 250)
	ts.dial(t, 220)
}

func TestLongLine(t *testing.T) {
	ts := start(t, Options{})
	c := ts.dial(t, 220)
	c.cmd(strings.Repeat("A", 3*lineLimit), 500)
	c.cmd("NOOP", 250)
}

func TestTooManyErrors(t *testing.T) {
	ts := start(t, Options{})
	c := ts.dial(t, 220)
	for range maxErrors - 1 {
		c.cmd("XXXX", 500)
	}
	c.cmd("XXXX", 500)
	c.expect(421)
	c.expectClosed()
}

func TestStartTLS(t *testing.T) {
	ts := start(t, Options{})
	c := ts.dial(t, 220)
	c.cmd("EHLO client", 250)
	c.cmd("STARTTLS", 220)

	conn := tls.Client(c.conn, &tls.Config{InsecureSkipVerify: true, ServerName: "mx.example.com"})
	if err := conn.Handshake(); err != nil {
		t.Fatal(err)
	}
	c = newClient(t, conn)

	c.cmd("MAIL FROM:<a@b.c>", 503) // EHLO again after TLS
	if ehlo := c.cmd("EHLO client", 250); strings.Contains(ehlo, "STARTTLS") {
		t.Errorf("STARTTLS offered over TLS:\n%s", ehlo)
	}
	c.cmd("STARTTLS", 503)
	c.message("Subject: tls\r\n\r\n", 250)

	e := ts.next(t)
	if !e.TLS || !strings.Contains(e.Received, "with ESMTPS") {
		t.Errorf("envelope = %+v", e)
	}
}

func TestStartTLSPipelined(t *testing.T) {
	ts := start(t, Options{})
	c := ts.dial(t, 220)
	c.cmd("EHLO client", 250)
	c.send("STARTTLS\r\nMAIL FROM:<a@b.c>\r\n")
	c.expect(554)
	c.expectClosed()
}

func TestStartTLSHandshakeFailure(t *testing.T) {
	ts := start(t, Options{})
	c := ts.dial(t, 220)
	c.cmd("EHLO client", 250)
	c.cmd("STARTTLS", 220)
	c.send("NOOP\r\n") // not a ClientHello
	c.expectClosed()
}

func TestConnLimits(t *testing.T) {
	ts := start(t, Options{MaxConnsPerIP: 1})
	c := ts.dial(t, 220)
	ts.dial(t, 421)
	c.cmd("QUIT", 221)
	ts.waitIdle(t)
	ts.dial(t, 220)

	ts = start(t, Options{MaxConns: 2})
	ts.dial(t, 220)
	ts.dial(t, 220)
	ts.dial(t, 421)
	if s := ts.Stats(); s.Rejected != 1 || s.Active != 2 {
		t.Errorf("stats = %+v", s)
	}
}

func TestPause(t *testing.T) {
	ts := start(t, Options{})
	ts.Pause(true)
	ts.dial(t, 421)
	ts.Pause(false)
	ts.dial(t, 220)
}

func TestTimeouts(t *testing.T) {
	ts := start(t, Options{Timeout: 200 * time.Millisecond})
	c := ts.dial(t, 220)
	if msg := c.expect(421); !strings.Contains(msg, "timeout") {
		t.Errorf("reply: %q", msg)
	}

	// an active client is still cut by the session timeout (slowloris)
	ts = start(t, Options{SessionTimeout: 300 * time.Millisecond})
	c = ts.dial(t, 220)
	deadline := time.Now().Add(3 * time.Second)
	for {
		c.send("NOOP\r\n")
		code, _, err := c.read()
		if err != nil {
			t.Fatal(err)
		}
		if code == 421 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("session timeout didn't fire")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestShutdown(t *testing.T) {
	ts := start(t, Options{})

	idle := ts.dial(t, 220)
	idle.cmd("EHLO client", 250)

	busy := ts.dial(t, 220)
	busy.cmd("EHLO client", 250)
	busy.cmd("MAIL FROM:<a@b.c>", 250)
	busy.cmd("RCPT TO:<u@example.com>", 250)
	busy.cmd("DATA", 354)
	busy.send("Subject: x\r\n")

	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		done <- ts.Shutdown(ctx)
	}()

	idle.expect(421)
	idle.expectClosed()

	// the message in progress is finished, then the session is closed
	busy.send("\r\nbody\r\n.\r\n")
	busy.expect(250)
	busy.expect(421)
	ts.next(t)

	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := net.Dial("tcp", ts.addr); err == nil {
		t.Error("listener still open")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := ts.Serve(ln); !errors.Is(err, ErrServerClosed) {
		t.Errorf("Serve after Shutdown: %v", err)
	}
}

func TestShutdownForce(t *testing.T) {
	ts := start(t, Options{})
	c := ts.dial(t, 220)
	c.cmd("EHLO client", 250)
	c.cmd("MAIL FROM:<a@b.c>", 250)
	c.cmd("RCPT TO:<u@example.com>", 250)
	c.cmd("DATA", 354)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := ts.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown: %v", err)
	}
	c.expectClosed()
}

func TestServeClosedListener(t *testing.T) {
	e, err := New(&Options{Handler: func(*envelope.Envelope) error { return nil }, Domains: []string{"mx"}})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	errc := make(chan error, 1)
	go func() { errc <- e.Serve(ln) }()
	time.Sleep(50 * time.Millisecond)
	ln.Close()

	select {
	case err := <-errc:
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("Serve: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve keeps running on a closed listener")
	}
}

func TestParsePath(t *testing.T) {
	for _, tt := range []struct {
		in, addr string
		params   []string
		ok       bool
	}{
		{"FROM:<a@b>", "a@b", nil, true},
		{"from: <a@b> SIZE=1 BODY=8BITMIME", "a@b", []string{"SIZE=1", "BODY=8BITMIME"}, true},
		{"FROM:<>", "", nil, true},
		{"FROM:<@x,@y:a@b>", "a@b", nil, true},
		{"FROM:<@x>", "", nil, false},
		{"FROM:a@b", "", nil, false},
		{"FROM:<a@b", "", nil, false},
		{"TO:<a@b>", "", nil, false},
		{"", "", nil, false},
	} {
		addr, params, ok := parsePath(tt.in, "FROM:")
		if addr != tt.addr || ok != tt.ok || strings.Join(params, " ") != strings.Join(tt.params, " ") {
			t.Errorf("parsePath(%q) = %q %q %v", tt.in, addr, params, ok)
		}
	}
}
