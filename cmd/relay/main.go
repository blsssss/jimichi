package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/blsssss/jimichi/crypto/c25519"
	"github.com/blsssss/jimichi/crypto/secmem"
	"github.com/blsssss/jimichi/relay"
)

func main() {
	listen := flag.String("listen", ":9000", "address for cells")
	info := flag.String("info", ":9100", "address for the public key and counters")
	harden := flag.Bool("harden", true, "lock key memory and disable core dumps")
	echo := flag.Bool("echo", true, "as an exit, send the payload back along the circuit")
	period := flag.Duration("period", 0, "send one frame per circuit and direction every period, padding when idle; 0 forwards at once")
	queue := flag.Int("queue", 64, "cells a circuit may queue per direction when -period is set")
	flag.Parse()

	logger := log.New(os.Stdout, "", log.LstdFlags|log.LUTC)

	if *harden {
		if err := secmem.HardenProcess(); err != nil {
			logger.Fatalf("harden: %v", err)
		}
	}

	provider := c25519.New()
	staticPriv, staticPub, err := provider.GenerateEphemeral()
	if err != nil {
		logger.Fatalf("static key: %v", err)
	}
	defer staticPriv.Release()

	if *harden && !staticPriv.Locked() {
		logger.Fatal("key memory is not locked, refusing to start")
	}

	r, err := relay.New(relay.Config{
		Provider:   provider,
		StaticPriv: staticPriv,
		// the payload is never logged: that would hand out exactly the metadata
		// the node exists to withhold
		Deliver: func(_ uint64, payload []byte) []byte {
			if *echo {
				return payload
			}
			return nil
		},
		Period:     *period,
		QueueCells: *queue,
	})
	if err != nil {
		logger.Fatalf("relay: %v", err)
	}
	defer r.Close()

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		logger.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go serveInfo(*info, staticPub, r, logger)

	logger.Printf("relay listening on %s, info on %s, locked=%v, period=%v", *listen, *info, staticPriv.Locked(), *period)
	go func() {
		if err := r.Serve(ln); err != nil {
			logger.Printf("serve: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	logger.Print("shutting down")
}

func serveInfo(addr string, pub []byte, r *relay.Relay, logger *log.Logger) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/key", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]string{"pub": base64.StdEncoding.EncodeToString(pub)})
	})
	mux.HandleFunc("/stats", func(w http.ResponseWriter, _ *http.Request) {
		s := r.Stats().Snapshot()
		writeJSON(w, map[string]uint64{
			"accepted":  s.Accepted,
			"forwarded": s.Forwarded,
			"delivered": s.Delivered,
			"dropped":   s.Dropped,
			"padding":   s.Padding,
		})
	})

	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Printf("info: %v", err)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
