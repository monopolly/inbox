package inbox

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

// ListenAndServe listens on Options.Port and serves connections until Shutdown.
func (a *Engine) ListenAndServe() error {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", a.opt.Port))
	if err != nil {
		return err
	}
	a.log.Info("start", "addr", ln.Addr().String())
	return a.Serve(ln)
}

// Serve accepts connections on ln. It returns ErrServerClosed after Shutdown,
// or the error when ln is closed by someone else.
func (a *Engine) Serve(ln net.Listener) error {
	if !a.addListener(ln) {
		ln.Close()
		return ErrServerClosed
	}
	defer a.removeListener(ln)
	defer ln.Close()

	var delay time.Duration
	for {
		conn, err := ln.Accept()
		if err != nil {
			if a.closing.Load() {
				return ErrServerClosed
			}
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			// temporary failure like EMFILE: back off instead of spinning
			a.acceptErrors.Add(1)
			delay = min(max(2*delay, 5*time.Millisecond), time.Second)
			a.log.Error("accept", "err", err, "retry", delay)
			time.Sleep(delay)
			continue
		}
		delay = 0
		go a.handle(conn)
	}
}

// Shutdown stops accepting connections, closes idle sessions with 421 and
// waits for messages in progress. If ctx ends first, the remaining
// connections are closed and ctx.Err() is returned.
func (a *Engine) Shutdown(ctx context.Context) error {
	a.mu.Lock()
	a.closing.Store(true)
	for ln := range a.listeners {
		ln.Close()
	}
	for s := range a.sessions {
		s.interrupt()
	}
	a.mu.Unlock()

	done := make(chan struct{})
	go func() {
		a.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		a.mu.Lock()
		for s := range a.sessions {
			s.raw.Close()
		}
		a.mu.Unlock()
		return ctx.Err()
	}
}

func (a *Engine) handle(conn net.Conn) {
	s := a.newSession(conn, a.total.Add(1))
	if reason := a.register(s); reason != "" {
		a.rejected.Add(1)
		s.log.Debug("refused", "reason", reason)
		conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		fmt.Fprintf(conn, "421 4.3.2 %s %s\r\n", a.hostname, reason)
		conn.Close()
		return
	}
	defer a.unregister(s)
	s.serve()
}

// register admits a session or returns why it is refused.
func (a *Engine) register(s *session) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch {
	case a.closing.Load():
		return "Service shutting down"
	case a.paused.Load():
		return "Service temporarily unavailable"
	case a.opt.MaxConns > 0 && len(a.sessions) >= a.opt.MaxConns:
		return "Too many connections"
	case a.opt.MaxConnsPerIP > 0 && a.perIP[s.remoteIP] >= a.opt.MaxConnsPerIP:
		return "Too many connections from your address"
	}
	a.sessions[s] = struct{}{}
	a.perIP[s.remoteIP]++
	a.wg.Add(1)
	return ""
}

func (a *Engine) unregister(s *session) {
	a.mu.Lock()
	delete(a.sessions, s)
	a.perIP[s.remoteIP]--
	if a.perIP[s.remoteIP] <= 0 {
		delete(a.perIP, s.remoteIP)
	}
	a.mu.Unlock()
	a.wg.Done()
}

func (a *Engine) addListener(ln net.Listener) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closing.Load() {
		return false
	}
	a.listeners[ln] = struct{}{}
	return true
}

func (a *Engine) removeListener(ln net.Listener) {
	a.mu.Lock()
	delete(a.listeners, ln)
	a.mu.Unlock()
}
