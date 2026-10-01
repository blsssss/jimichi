package client_test

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/jimichi-org/jimichi/client"
	"github.com/jimichi-org/jimichi/crypto/c25519"
)

func dialWithin(t *testing.T, cfg client.Config, limit time.Duration) error {
	t.Helper()
	result := make(chan error, 1)
	go func() {
		c, err := client.Dial(cfg)
		if c != nil {
			_ = c.Close()
		}
		result <- err
	}()
	select {
	case err := <-result:
		return err
	case <-time.After(limit):
		t.Fatalf("Dial still waiting after %v", limit)
		return nil
	}
}

func silentNode(t *testing.T) client.Node {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	held := make(chan net.Conn, 4)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			held <- conn
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		for {
			select {
			case conn := <-held:
				_ = conn.Close()
			default:
				return
			}
		}
	})
	_, pub, err := c25519.New().GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	return client.Node{Addr: ln.Addr().String(), StaticPub: pub}
}

func TestDialGivesUpOnASilentEntry(t *testing.T) {
	cfg := client.Config{
		Provider:         c25519.New(),
		Chain:            []client.Node{silentNode(t)},
		HandshakeTimeout: 200 * time.Millisecond,
	}
	err := dialWithin(t, cfg, 3*time.Second)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Dial returned %v, want a deadline error", err)
	}
}

func TestDialHookGetsTheDialTimeout(t *testing.T) {
	cfg := client.Config{
		Provider:    c25519.New(),
		Chain:       []client.Node{silentNode(t)},
		DialTimeout: 200 * time.Millisecond,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	err := dialWithin(t, cfg, 3*time.Second)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Dial returned %v, want the dial deadline", err)
	}
}
