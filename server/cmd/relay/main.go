package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"faraday/internal/relay"
	"faraday/internal/store"
)

func main() {
	addr := flag.String("addr", listenAddr(), "listen address (FARADAY_ADDR, or 0.0.0.0:$PORT, else 127.0.0.1:43147)")
	data := flag.String("data", env("FARADAY_DATA", "data/relay.json"), "mailbox file only (never ciphertext)")
	web := flag.String("web", env("FARADAY_WEB", "web"), "transparency dashboard directory")
	flag.Parse()

	st, err := store.Open(*data)
	if err != nil {
		log.Fatal(err)
	}
	webDir := *web
	if _, err := os.Stat(webDir); err != nil {
		if alt := filepath.Join(filepath.Dir(*data), "..", "web"); fileExists(alt) {
			webDir = alt
		}
	}
	go func() {
		tick := time.NewTicker(time.Minute)
		defer tick.Stop()
		for range tick.C {
			if n := st.Sweep(); n > 0 {
				log.Printf("expired %d uncollected envelope(s) after %s TTL", n, store.EnvelopeTTL)
			}
		}
	}()
	srv := relay.New(st, webDir)
	s := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 8 * time.Second,
		// Access logs intentionally omit bodies, tokens, and mailbox ids.
	}
	log.Printf("listening on http://%s  (ephemeral relay — RAM only, delete on delivery, %s TTL)", *addr, store.EnvelopeTTL)
	log.Printf("transparency dashboard: http://%s/", *addr)
	if err := s.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func listenAddr() string {
	if v := os.Getenv("FARADAY_ADDR"); v != "" {
		return v
	}
	if port := os.Getenv("PORT"); port != "" {
		return "0.0.0.0:" + port
	}
	return "127.0.0.1:43147"
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
