// Package fetch reads node bundles from an info port, for a client and for a
// node that keeps the descriptors of its peers.
package fetch

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/jimichi-org/jimichi/pki"
)

const (
	MaxBundle = 16 << 10
	// one bundle per node of a roster, and a roster fits 4 KiB
	MaxMirror = 256 << 10
	// status line and headers of an answer; an info port sends a few dozen bytes
	MaxHeader = 4 << 10
	Timeout   = 5 * time.Second
)

var ErrTooLarge = errors.New("answer over the size limit")

// an answer other than 200. Only the code is kept: the text after it on the
// status line is whatever the other side chose to send
type StatusError struct {
	Code int
	// what a 503 means for the thing asked for
	unpublished string
}

func (e *StatusError) Error() string {
	if e.Code == http.StatusServiceUnavailable && e.unpublished != "" {
		return e.unpublished
	}
	return fmt.Sprintf("request answered status %d", e.Code)
}

// an info port is asked directly: a proxy from the environment or a redirect
// would send the request somewhere else. Timeout bounds the dial and the whole
// request, so a silent node holds neither a client nor a node's refresh
func NewClient() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	tr.DialContext = (&net.Dialer{Timeout: Timeout}).DialContext
	tr.MaxResponseHeaderBytes = MaxHeader
	return &http.Client{
		Transport: tr,
		Timeout:   Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// the info port of the node dialled at addr. A host or port that a URL would
// read as a path, a query or user information is refused: the request must go
// to this port of this host and nowhere else
func URL(addr, port, path string) (string, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}
	hostport := net.JoinHostPort(host, port)
	u := url.URL{Scheme: "http", Host: hostport, Path: path}
	back, err := url.Parse(u.String())
	if !pki.ValidAddr(hostport) || err != nil || back.Hostname() != host || back.Port() != port ||
		back.Path != path || back.User != nil || back.RawQuery != "" || back.Fragment != "" {
		return "", fmt.Errorf("fetch: %q with port %q does not name one host and port", addr, port)
	}
	return u.String(), nil
}

func Bundle(web *http.Client, url string, attempts int, pause time.Duration) ([]byte, error) {
	return retried(attempts, pause, func() ([]byte, bool, error) {
		return get(web, url, MaxBundle, "no descriptor published, the node has no valid certificate", func(body []byte) error {
			_, err := pki.ParseBundle(body)
			return err
		})
	})
}

func Mirror(web *http.Client, url string, attempts int, pause time.Duration) ([]pki.MirrorEntry, error) {
	var entries []pki.MirrorEntry
	_, err := retried(attempts, pause, func() ([]byte, bool, error) {
		return get(web, url, MaxMirror, "no descriptors published, the node does not hold a valid descriptor of every roster node", func(body []byte) (err error) {
			entries, err = pki.ParseMirror(body)
			return err
		})
	})
	if err != nil {
		return nil, err
	}
	return entries, nil
}

// only a failed connection or a node that has nothing to publish yet is worth
// another try; anything else it answered stays wrong on the next one
func retried(attempts int, pause time.Duration, once func() ([]byte, bool, error)) ([]byte, error) {
	var lastErr error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			time.Sleep(pause)
		}
		body, retry, err := once()
		if err == nil {
			return body, nil
		}
		if !retry {
			return nil, err
		}
		lastErr = err
	}
	return nil, lastErr
}

func get(web *http.Client, url string, limit int, unpublished string, parse func([]byte) error) (body []byte, retry bool, err error) {
	resp, err := web.Get(url)
	if err != nil {
		return nil, true, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusServiceUnavailable:
		return nil, true, &StatusError{Code: resp.StatusCode, unpublished: unpublished}
	default:
		return nil, false, &StatusError{Code: resp.StatusCode}
	}
	body, err = io.ReadAll(io.LimitReader(resp.Body, int64(limit)+1))
	if err != nil {
		return nil, true, err
	}
	if len(body) > limit {
		return nil, false, fmt.Errorf("%w of %d bytes", ErrTooLarge, limit)
	}
	if err := parse(body); err != nil {
		return nil, false, err
	}
	return body, false, nil
}
