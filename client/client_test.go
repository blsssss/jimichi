package client

import (
	"errors"
	"net"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/suite"
)

func TestDialRefusesMissingOrMisSizedKeys(t *testing.T) {
	for _, s := range []jcrypto.Suite{jcrypto.SuiteC25519, jcrypto.SuiteGOST} {
		t.Run(s.String(), func(t *testing.T) {
			p, err := suite.New(s)
			if err != nil {
				t.Fatal(err)
			}
			key := func() []byte {
				_, pub, err := p.GenerateEphemeral()
				if err != nil {
					t.Fatal(err)
				}
				return pub
			}
			good := func(addr string) Node { return Node{Addr: addr, StaticPub: key()} }
			errDialed := errors.New("dialed")
			dial := func(string, string) (net.Conn, error) { return nil, errDialed }

			for _, c := range []struct {
				name  string
				entry Node
				want  error
			}{
				{"empty static key", Node{Addr: "relay-1:9000"}, ErrNodeKey},
				{"empty static key with a link key", Node{Addr: "relay-1:9000", LinkPub: key()}, ErrNodeKey},
				{"short static key", Node{Addr: "relay-1:9000", StaticPub: key()[1:]}, ErrNodeKey},
				{"long link key", Node{Addr: "relay-1:9000", StaticPub: key(), LinkPub: append(key(), 0)}, ErrNodeKey},
				{"empty link key falls back to the static key", good("relay-1:9000"), errDialed},
				{"separate link key", Node{Addr: "relay-1:9000", StaticPub: key(), LinkPub: key()}, errDialed},
			} {
				chain := []Node{c.entry, good("relay-2:9000"), good("relay-3:9000")}
				_, err := Dial(Config{Provider: p, Chain: chain, Dial: dial})
				if !errors.Is(err, c.want) {
					t.Errorf("%s: Dial = %v, want %v", c.name, err, c.want)
				}
			}

			chain := []Node{good("relay-1:9000"), {Addr: "relay-2:9000"}, good("relay-3:9000")}
			if _, err := Dial(Config{Provider: p, Chain: chain, Dial: dial}); !errors.Is(err, ErrNodeKey) {
				t.Errorf("empty key in the middle: Dial = %v, want %v", err, ErrNodeKey)
			}
		})
	}
}
