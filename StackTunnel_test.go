package main

import (
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// Simulate a peer whose selected handshake packet never reaches the wire.
type dropHandshakePacket struct {
	net.Conn
	code byte
}

func (c dropHandshakePacket) Write(p []byte) (int, error) {
	if len(p) > 5 && p[0] == 0 && p[5] == c.code {
		return len(p), nil
	}
	return c.Conn.Write(p)
}

func TestHandshakeTimeoutAfterBanner(t *testing.T) {
	for _, client := range []bool{true, false} {
		role := "server"
		ecdh := byte(30)
		if client {
			role = "client"
			ecdh = 31
		}
		for _, tc := range []struct {
			stage string
			code  byte
		}{{"KEXINIT", 20}, {"ECDH", ecdh}, {"NEWKEYS", 21}} {
			t.Run(role+"/"+tc.stage, func(t *testing.T) {
				a, b := net.Pipe()
				defer a.Close()
				defer b.Close()
				watchdog := time.AfterFunc(time.Second, func() { a.Close(); b.Close() })
				defer watchdog.Stop()
				peerDone := make(chan struct{})
				go func() {
					defer close(peerDone)
					handshakeWithTimeout(dropHandshakePacket{b, tc.code}, "test-key", !client, 2*time.Second)
				}()
				start := time.Now()
				_, err := handshakeWithTimeout(a, "test-key", client, 100*time.Millisecond)
				elapsed := time.Since(start)
				a.Close()
				b.Close()
				<-peerDone
				var ne net.Error
				if !errors.As(err, &ne) || !ne.Timeout() {
					t.Fatalf("expected timeout, got %v", err)
				}
				if !strings.Contains(err.Error(), "handshake "+tc.stage+" (") {
					t.Fatalf("missing stage %s: %v", tc.stage, err)
				}
				if elapsed > time.Second {
					t.Fatalf("handshake deadline lost: elapsed %v", elapsed)
				}
			})
		}
	}
}

func TestHandshakeClearsDeadlineOnSuccess(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	type result struct {
		conn *secConn
		err  error
	}
	serverDone := make(chan result, 1)
	go func() {
		c, err := handshakeWithTimeout(b, "test-key", false, 100*time.Millisecond)
		serverDone <- result{c, err}
	}()
	client, err := handshakeWithTimeout(a, "test-key", true, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	server := <-serverDone
	if server.err != nil {
		t.Fatal(server.err)
	}
	time.Sleep(150 * time.Millisecond)
	// An independent watchdog bounds the test without replacing the deadlines.
	watchdog := time.AfterFunc(2*time.Second, func() { a.Close(); b.Close() })
	defer watchdog.Stop()
	for _, pair := range [][2]*secConn{{client, server.conn}, {server.conn, client}} {
		done := make(chan error, 1)
		go func(c *secConn) { _, err := c.Write([]byte("alive")); done <- err }(pair[0])
		buf := make([]byte, 5)
		if _, err := io.ReadFull(pair[1], buf); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if string(buf) != "alive" {
			t.Fatalf("unexpected plaintext: %q", buf)
		}
	}
}
