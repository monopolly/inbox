package inbox

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	e, err := New(&Options{
		Domains: []string{"mx.example.com"},
		Handler: func(e *Envelope) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go e.Serve(ln)
	defer e.Shutdown(context.Background())

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	banner, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || !strings.HasPrefix(banner, "220 mx.example.com") {
		t.Fatalf("banner %q, %v", banner, err)
	}
}
