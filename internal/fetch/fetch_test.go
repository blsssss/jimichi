package fetch

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/pki"
)

const testAddr = "relay-1.jimichi.svc.cluster.local:9000"

func bundle(t *testing.T) []byte {
	t.Helper()
	p, err := suite.New(jcrypto.SuiteC25519)
	if err != nil {
		t.Fatal(err)
	}
	priv, pub, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	priv.Release()
	b, err := pki.Unsigned(p, pub, pub)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func serve(t *testing.T, path string, answer func(n int32, w http.ResponseWriter)) (string, *atomic.Int32) {
	t.Helper()
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path {
			http.NotFound(w, r)
			return
		}
		answer(n.Add(1), w)
	}))
	t.Cleanup(srv.Close)
	return srv.URL + path, &n
}

func TestBundle(t *testing.T) {
	good := bundle(t)
	web := NewClient()

	t.Run("published after enrollment", func(t *testing.T) {
		url, n := serve(t, "/descriptor", func(n int32, w http.ResponseWriter) {
			if n < 3 {
				http.Error(w, "no valid certificate", http.StatusServiceUnavailable)
				return
			}
			_, _ = w.Write(good)
		})
		b, err := Bundle(web, url, 5, time.Millisecond)
		if err != nil || !bytes.Equal(b, good) || n.Load() != 3 {
			t.Fatalf("Bundle = %d bytes, %v after %d requests", len(b), err, n.Load())
		}
	})

	t.Run("never enrolled", func(t *testing.T) {
		url, n := serve(t, "/descriptor", func(_ int32, w http.ResponseWriter) {
			http.Error(w, "no valid certificate", http.StatusServiceUnavailable)
		})
		if _, err := Bundle(web, url, 4, time.Millisecond); err == nil || n.Load() != 4 {
			t.Fatalf("Bundle = %v after %d requests, want an error after 4", err, n.Load())
		}
	})

	for _, c := range []struct {
		name   string
		answer func(w http.ResponseWriter)
	}{
		{"not found", func(w http.ResponseWriter) { http.Error(w, "gone", http.StatusNotFound) }},
		{"redirect", func(w http.ResponseWriter) {
			w.Header().Set("Location", "http://elsewhere.invalid/descriptor")
			w.WriteHeader(http.StatusFound)
		}},
		{"over the size limit", func(w http.ResponseWriter) { _, _ = w.Write(bytes.Repeat([]byte("a"), MaxBundle+1)) }},
		{"loose json", func(w http.ResponseWriter) { _, _ = w.Write(append(good, '\n')) }},
		{"not json", func(w http.ResponseWriter) { _, _ = w.Write([]byte("pub=abc")) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			url, n := serve(t, "/descriptor", func(_ int32, w http.ResponseWriter) { c.answer(w) })
			_, err := Bundle(web, url, 5, time.Millisecond)
			if err == nil || n.Load() != 1 {
				t.Fatalf("Bundle = %v after %d requests, want one request and an error", err, n.Load())
			}
			if c.name == "over the size limit" && !strings.Contains(err.Error(), "answer over the size limit of 16384 bytes") {
				t.Fatalf("Bundle = %v, want the size limit named", err)
			}
		})
	}

	t.Run("nobody listening", func(t *testing.T) {
		srv := httptest.NewServer(http.NotFoundHandler())
		url := srv.URL + "/descriptor"
		srv.Close()
		start := time.Now()
		if _, err := Bundle(web, url, 3, 20*time.Millisecond); err == nil {
			t.Fatal("Bundle from a closed port succeeded")
		}
		if time.Since(start) < 40*time.Millisecond {
			t.Fatal("a connection error was not retried")
		}
	})
}

func TestMirror(t *testing.T) {
	b := bundle(t)
	good, err := pki.MarshalMirror([]pki.MirrorEntry{{Addr: testAddr, Bundle: b}})
	if err != nil {
		t.Fatal(err)
	}
	web := NewClient()

	t.Run("published once every node is known", func(t *testing.T) {
		url, n := serve(t, "/descriptors", func(n int32, w http.ResponseWriter) {
			if n < 3 {
				http.Error(w, "incomplete", http.StatusServiceUnavailable)
				return
			}
			_, _ = w.Write(good)
		})
		entries, err := Mirror(web, url, 5, time.Millisecond)
		if err != nil || len(entries) != 1 || entries[0].Addr != testAddr || !bytes.Equal(entries[0].Bundle, b) || n.Load() != 3 {
			t.Fatalf("Mirror = %v, %v after %d requests", entries, err, n.Load())
		}
	})

	for _, c := range []struct {
		name   string
		answer func(w http.ResponseWriter)
	}{
		{"not found", func(w http.ResponseWriter) { http.Error(w, "gone", http.StatusNotFound) }},
		{"redirect", func(w http.ResponseWriter) {
			w.Header().Set("Location", "http://elsewhere.invalid/descriptors")
			w.WriteHeader(http.StatusFound)
		}},
		{"over the size limit", func(w http.ResponseWriter) { _, _ = w.Write(bytes.Repeat([]byte("a"), MaxMirror+1)) }},
		{"loose json", func(w http.ResponseWriter) { _, _ = w.Write(append(good, '\n')) }},
		{"a single bundle", func(w http.ResponseWriter) { _, _ = w.Write(b) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			url, n := serve(t, "/descriptors", func(_ int32, w http.ResponseWriter) { c.answer(w) })
			_, err := Mirror(web, url, 5, time.Millisecond)
			if err == nil || n.Load() != 1 {
				t.Fatalf("Mirror = %v after %d requests, want one request and an error", err, n.Load())
			}
			if c.name == "over the size limit" && !strings.Contains(err.Error(), "answer over the size limit of 262144 bytes") {
				t.Fatalf("Mirror = %v, want the size limit named", err)
			}
		})
	}
}

// a node that accepts the connection and never answers costs one timeout per
// try, and the request never goes through a proxy from the environment
func TestClientIsBoundedAndDirect(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	web := NewClient()
	tr := web.Transport.(*http.Transport)
	if web.Timeout != Timeout || tr.Proxy != nil {
		t.Fatalf("timeout %v, proxy set %v, want %v and none", web.Timeout, tr.Proxy != nil, Timeout)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
		}
	}()
	web.Timeout = 100 * time.Millisecond
	start := time.Now()
	_, err = Bundle(web, "http://"+ln.Addr().String()+"/descriptor", 2, 0)
	if err == nil {
		t.Fatal("Bundle from a silent node succeeded")
	}
	if d := time.Since(start); d < 150*time.Millisecond || d > 3*time.Second {
		t.Fatalf("two tries at a silent node took %v, want two timeouts of 100ms", d)
	}
}

func TestURL(t *testing.T) {
	for _, c := range []struct{ addr, path, want string }{
		{testAddr, "/descriptor", "http://relay-1.jimichi.svc.cluster.local:9100/descriptor"},
		{testAddr, "/descriptors", "http://relay-1.jimichi.svc.cluster.local:9100/descriptors"},
		{"[::1]:9000", "/descriptor", "http://[::1]:9100/descriptor"},
	} {
		if got, err := URL(c.addr, "9100", c.path); err != nil || got != c.want {
			t.Errorf("URL(%q) = %q, %v, want %q", c.addr, got, err, c.want)
		}
	}
	if _, err := URL("relay-1", "9100", "/descriptor"); err == nil {
		t.Error("URL accepted an address without a port")
	}
	for _, c := range []struct{ addr, port string }{
		{"relay-1/x:9000", "9100"},
		{"relay-1?x=1:9000", "9100"},
		{"relay-1#x:9000", "9100"},
		{"user@relay-1:9000", "9100"},
		{"user:pass@relay-1:9000", "9100"},
		{"relay-1%2fx:9000", "9100"},
		{"relay 1:9000", "9100"},
		{"relay-1:9000", "9100/x"},
		{"relay-1:9000", "9100?x"},
		{"relay-1:9000", "9100#x"},
		{"relay-1:9000", "80@elsewhere"},
		{"relay-1:9000", ""},
	} {
		if got, err := URL(c.addr, c.port, "/descriptor"); err == nil {
			t.Errorf("URL(%q, %q) = %q, want it refused", c.addr, c.port, got)
		}
	}
}

// the text of a status line is the other side's to choose, so only the code
// reaches the error, and an answer cannot make the client read headers
// without end
func TestStatusTextAndHeaderSizeStayOut(t *testing.T) {
	answer := func(t *testing.T, raw []byte) string {
		t.Helper()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					defer conn.Close()
					_, _ = conn.Read(make([]byte, 4096))
					_, _ = conn.Write(raw)
				}()
			}
		}()
		return "http://" + ln.Addr().String() + "/descriptor"
	}
	web := NewClient()
	if got := web.Transport.(*http.Transport).MaxResponseHeaderBytes; got != MaxHeader {
		t.Fatalf("header limit %d, want %d", got, MaxHeader)
	}

	url := answer(t, []byte("HTTP/1.1 404 gone \x1b[2J\x07 for good\r\nContent-Length: 0\r\n\r\n"))
	_, err := Bundle(web, url, 3, 0)
	var status *StatusError
	if !errors.As(err, &status) || status.Code != http.StatusNotFound || err.Error() != "request answered status 404" {
		t.Fatalf("Bundle = %q, want the status code alone", err)
	}

	long := append([]byte("HTTP/1.1 404 "), bytes.Repeat([]byte("A\x1b"), 1<<20)...)
	url = answer(t, append(long, "\r\nContent-Length: 0\r\n\r\n"...))
	_, err = Bundle(web, url, 1, 0)
	if err == nil || errors.As(err, &status) || len(err.Error()) > 512 {
		t.Fatalf("Bundle after a status line of 2 MiB = %.80q (%d bytes), want a short transport error", err, len(err.Error()))
	}

	url = answer(t, []byte("HTTP/1.1 503 later\r\nContent-Length: 0\r\n\r\n"))
	_, err = Bundle(web, url, 2, 0)
	if !errors.As(err, &status) || status.Code != http.StatusServiceUnavailable || !strings.Contains(err.Error(), "no descriptor published") {
		t.Fatalf("Bundle = %v, want a 503 that says what is not published", err)
	}
}

// the info port may be longer than the cell port, so a host that only just
// fits an address with a short port must still be reachable
func TestURLOfAHostNearTheAddressLimit(t *testing.T) {
	host := strings.Repeat("a", 30) + "." + strings.Repeat("b", 31)
	if len(host+":1") != 64 {
		t.Fatalf("test host is %d bytes with its port, want 64", len(host+":1"))
	}
	got, err := URL(host+":1", "9100", "/descriptor")
	if err != nil {
		t.Fatalf("URL: %v", err)
	}
	if want := "http://" + host + ":9100/descriptor"; got != want {
		t.Fatalf("URL = %q, want %q", got, want)
	}
}

// the signed bundle of a node enrolled under ca, for a day
func signedBundle(t *testing.T, p jcrypto.CryptoProvider, ca *pki.CA, name, addr string) []byte {
	t.Helper()
	id, err := pki.NewIdentity(p, name, addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(id.Close)
	var nonce [pki.NonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	raw, err := id.Request(nonce)
	if err != nil {
		t.Fatal(err)
	}
	req, err := pki.ParseRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	cert, err := ca.Issue(req, now, now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := id.Install(cert.Marshal(), now); err != nil {
		t.Fatal(err)
	}
	priv, pub, err := p.GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	priv.Release()
	id.SetKeys(pub, pub, 0)
	if err := id.Refresh(now, time.Hour); err != nil {
		t.Fatal(err)
	}
	b, ok := id.Bundle()
	if !ok {
		t.Fatal("no bundle")
	}
	return b
}

// the roster a node accepts bounds how many bundles a mirror carries: 58 nodes
// of the testbed form on c25519 and 57 on GOST (pki.TestRosterOfTheTestbedForm).
// A mirror of that many signed bundles has to pass the client's limit with room
// to spare, and one of five takes a few KiB of it
func TestMirrorOfTheLargestRosterFitsTheLimit(t *testing.T) {
	for _, c := range []struct {
		suite jcrypto.Suite
		nodes int
	}{{jcrypto.SuiteC25519, 58}, {jcrypto.SuiteGOST, 57}} {
		t.Run(c.suite.String(), func(t *testing.T) {
			p, err := suite.New(c.suite)
			if err != nil {
				t.Fatal(err)
			}
			ca, err := pki.NewCA(p)
			if err != nil {
				t.Fatal(err)
			}
			defer ca.Close()
			roster := pki.Roster{Anchor: ca.Anchor()}
			entries := make([]pki.MirrorEntry, c.nodes)
			for i := range entries {
				name := fmt.Sprintf("relay-%d", i+1)
				addr := name + ".jimichi.svc.cluster.local:9000"
				roster.Nodes = append(roster.Nodes, pki.RosterNode{Name: name, Addr: addr})
				entries[i] = pki.MirrorEntry{Addr: addr, Bundle: signedBundle(t, p, ca, name, addr)}
				if len(entries[i].Bundle) > MaxBundle/8 {
					t.Fatalf("bundle of %s takes %d bytes of the %d a node accepts from a peer", name, len(entries[i].Bundle), MaxBundle)
				}
			}
			if size := len(roster.Marshal()); size > pki.MaxRoster {
				t.Fatalf("the roster of %d nodes takes %d bytes, no node accepts it", c.nodes, size)
			}
			five, err := pki.MarshalMirror(entries[:5])
			if err != nil {
				t.Fatal(err)
			}
			full, err := pki.MarshalMirror(entries)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("mirror of 5 nodes %d bytes, of %d nodes %d bytes, limit %d", len(five), c.nodes, len(full), MaxMirror)
			if len(five) > MaxMirror/32 || len(full) > MaxMirror/4 {
				t.Fatalf("mirror of 5 nodes takes %d bytes and of %d nodes %d, want under %d and %d", len(five), c.nodes, len(full), MaxMirror/32, MaxMirror/4)
			}

			url, _ := serve(t, "/descriptors", func(_ int32, w http.ResponseWriter) { _, _ = w.Write(full) })
			got, err := Mirror(NewClient(), url, 1, 0)
			if err != nil || len(got) != c.nodes {
				t.Fatalf("Mirror = %d entries, %v, want all %d", len(got), err, c.nodes)
			}
			policy := pki.Policy{Anchor: ca.Anchor(), Skew: pki.Skew}
			for _, e := range got {
				if _, err := pki.Verify(p, policy, e.Addr, e.Bundle, time.Now()); err != nil {
					t.Fatalf("bundle of %s does not verify after the fetch: %v", e.Addr, err)
				}
			}
		})
	}
}
