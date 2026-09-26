package suite_test

import (
	"testing"

	jcrypto "github.com/blsssss/jimichi/crypto"
	"github.com/blsssss/jimichi/crypto/suite"
)

func TestEveryNameGivesItsSuite(t *testing.T) {
	for _, name := range []string{"gost", "c25519"} {
		s, err := suite.Parse(name)
		if err != nil {
			t.Fatalf("Parse(%q): %v", name, err)
		}
		p, err := suite.New(s)
		if err != nil || p.Suite() != s || p.Suite().String() != name {
			t.Fatalf("New(%v) gave %v, %v", s, p, err)
		}
	}
	if _, err := suite.Parse("rot13"); err == nil {
		t.Fatal("Parse accepted an unknown suite")
	}
	if _, err := suite.New(jcrypto.Suite(99)); err == nil {
		t.Fatal("New accepted an unknown suite")
	}
}
