// Package fetch reads node bundles from an info port, for a client and for a
// node that keeps the descriptors of its peers.
package fetch

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/jimichi-org/jimichi/pki"
)

const (
	MaxBundle = 16 << 10
	// one bundle per node of a roster, and a roster fits 4 KiB
	MaxMirror = 256 << 10
	Timeout   = 5 * time.Second
)

// an info port is asked directly: a proxy from the environment or a redirect
// would send the request somewhere else. Timeout bounds the dial and the whole
// request, so a silent node holds neither a client nor a node's refresh
func NewClient() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	tr.DialContext = (&net.Dialer{Timeout: Timeout}).DialContext
	return &http.Client{
		Transport: tr,
		Timeout:   Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// the info port of the node dialled at addr
func URL(addr, port, path string) (string, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}
	return "http://" + net.JoinHostPort(host, port) + path, nil
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
		return nil, true, errors.New(unpublished)
	default:
		return nil, false, fmt.Errorf("request answered %s", resp.Status)
	}
	body, err = io.ReadAll(io.LimitReader(resp.Body, int64(limit)+1))
	if err != nil {
		return nil, true, err
	}
	if len(body) > limit {
		return nil, false, fmt.Errorf("answer over %d bytes", limit)
	}
	if err := parse(body); err != nil {
		return nil, false, err
	}
	return body, false, nil
}
