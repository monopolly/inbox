package convert

import (
	"bytes"
	"net"
	"strings"
	"testing"

	"github.com/monopolly/inbox/envelope"
)

func TestEmail(t *testing.T) {
	data := []byte("From: Sender <sender@example.org>\r\n" +
		"To: a@example.com\r\n" +
		"Cc: B <b@example.com>\r\n" +
		"Date: Sun, 25 Oct 2026 16:00:00 +0300\r\n" +
		"Subject: hello\r\n" +
		"\r\n" +
		"text\r\n")
	e := &envelope.Envelope{
		RemoteAddr: &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1234},
		To:         []string{"a@example.com", "b@example.com", "hidden@example.com"},
		Data:       data,
	}

	m, err := Email(e)
	if err != nil {
		t.Fatal(err)
	}
	if m.Subj != "hello" || m.From.Address != "sender@example.org" || m.To.Address != "a@example.com" {
		t.Errorf("headers: %q %q %q", m.Subj, m.From.Address, m.To.Address)
	}
	if strings.TrimSpace(m.Text) != "text" {
		t.Errorf("Text = %q", m.Text)
	}
	if m.IP != "192.0.2.1" || !bytes.Equal(m.EML, data) {
		t.Errorf("IP = %q, EML = %q", m.IP, m.EML)
	}
	if m.Date == nil || m.Date.UTC().Hour() != 13 {
		t.Errorf("Date = %v", m.Date)
	}
	if len(m.CC) != 1 || m.CC[0].Address != "b@example.com" {
		t.Errorf("CC = %v", m.CC)
	}
	if len(m.BCC) != 1 || m.BCC[0].Address != "hidden@example.com" {
		t.Errorf("BCC = %v", m.BCC)
	}
}
