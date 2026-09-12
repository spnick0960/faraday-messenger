package relay

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"faraday/internal/store"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

type Server struct {
	Store *store.Store
	Hub   *Hub
	mux   *http.ServeMux
	limit sync.Map
}

type wsIn struct {
	V        int      `json:"v"`
	Op       string   `json:"op"`
	Mailbox  string   `json:"mailbox,omitempty"`
	Token    string   `json:"token,omitempty"`
	To       string   `json:"to,omitempty"`
	Blob     string   `json:"blob,omitempty"`
	IDs      []string `json:"ids,omitempty"`
}

type wsOut struct {
	V     int      `json:"v"`
	Op    string   `json:"op"`
	ID    string   `json:"id,omitempty"`
	Blob  string   `json:"blob,omitempty"`
	Bytes int      `json:"bytes,omitempty"`
	At    int64    `json:"at,omitempty"`
	Err   string   `json:"err,omitempty"`
	N     int      `json:"n,omitempty"`
}

func New(st *store.Store, webDir string) *Server {
	s := &Server{Store: st, Hub: NewHub(), mux: http.NewServeMux()}
	s.mux.HandleFunc("/v1/health", s.handleHealth)
	s.mux.HandleFunc("/v1/transparency", s.handleTransparency)
	s.mux.HandleFunc("/v1/mailbox", s.handleMailbox)
	s.mux.HandleFunc("POST /v1/drop", s.handleDrop)
	s.mux.HandleFunc("GET /v1/inbox", s.handleInbox)
	s.mux.HandleFunc("POST /v1/ack", s.handleAck)
	s.mux.HandleFunc("/v1/ws", s.handleWS)
	if webDir != "" {
		s.mux.Handle("/", spa(webDir))
	} else {
		s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" {
				http.NotFound(w, r)
				return
			}
			http.Redirect(w, r, "/v1/transparency", http.StatusFound)
		})
	}
	return s
}

func (s *Server) Handler() http.Handler { return withSecurity(s.mux) }

func spa(dir string) http.Handler {
	fs := http.FileServer(http.Dir(dir))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/") {
			http.NotFound(w, r)
			return
		}
		p := dir + r.URL.Path
		if r.URL.Path != "/" {
			if _, err := os.Stat(p); err != nil {
				http.ServeFile(w, r, dir+"/index.html")
				return
			}
		}
		fs.ServeHTTP(w, r)
	})
}

func withSecurity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "name": "faraday-relay", "version": "1"})
}

func (s *Server) handleTransparency(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.Store.Transparency())
}

type mailboxReq struct {
	Mailbox string `json:"mailbox"`
	Token   string `json:"token"`
}

func (s *Server) handleMailbox(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var req mailboxReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	tok, err := hex.DecodeString(req.Token)
	if err != nil || len(tok) != 32 || !hexMailbox(req.Mailbox) {
		http.Error(w, "bad mailbox", http.StatusBadRequest)
		return
	}
	sum := sha256.Sum256(tok)
	if err := s.Store.PutMailbox(req.Mailbox, sum[:]); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	// Do not echo the token.
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "mailbox": req.Mailbox})
}

func (s *Server) handleDrop(w http.ResponseWriter, r *http.Request) {
	if !s.allow(r, 40) {
		http.Error(w, "rate", http.StatusTooManyRequests)
		return
	}
	var req struct {
		To   string `json:"to"`
		Blob string `json:"blob"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	env, err := s.drop(req.To, req.Blob)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"id": env.ID, "bytes": env.Bytes})
}

func (s *Server) drop(to, blobB64 string) (*store.Envelope, error) {
	if !hexMailbox(to) {
		return nil, errBad("invalid destination")
	}
	blob, err := base64.StdEncoding.DecodeString(blobB64)
	if err != nil {
		blob, err = base64.RawURLEncoding.DecodeString(blobB64)
	}
	if err != nil {
		return nil, errBad("invalid blob")
	}
	env, err := s.Store.Drop(to, blob)
	if err != nil {
		return nil, err
	}
	out, _ := json.Marshal(wsOut{
		V: 1, Op: "deliver", ID: env.ID,
		Blob:  base64.StdEncoding.EncodeToString(env.Blob),
		Bytes: env.Bytes, At: env.CreatedAt,
	})
	s.Hub.Publish(to, out)
	return env, nil
}

func (s *Server) handleInbox(w http.ResponseWriter, r *http.Request) {
	mb, ok := s.authorize(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	envs := s.Store.Inbox(mb)
	type item struct {
		ID        string `json:"id"`
		Blob      string `json:"blob"`
		Bytes     int    `json:"bytes"`
		At        int64  `json:"at"`
		ExpiresAt int64  `json:"expiresAt"`
	}
	list := make([]item, 0, len(envs))
	for _, e := range envs {
		list = append(list, item{
			ID: e.ID, Blob: base64.StdEncoding.EncodeToString(e.Blob),
			Bytes: e.Bytes, At: e.CreatedAt, ExpiresAt: e.ExpiresAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"envelopes": list})
}

func (s *Server) handleAck(w http.ResponseWriter, r *http.Request) {
	mb, ok := s.authorize(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	n := s.Store.Ack(mb, req.IDs)
	writeJSON(w, http.StatusOK, map[string]any{"acked": n})
}

func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return
	}
	defer c.Close(websocket.StatusNormalClosure, "")

	ctx := r.Context()
	var hello wsIn
	if err := wsjson.Read(ctx, c, &hello); err != nil {
		return
	}
	if hello.Op != "auth" || !hexMailbox(hello.Mailbox) {
		_ = wsjson.Write(ctx, c, wsOut{V: 1, Op: "err", Err: "auth required"})
		return
	}
	tok, err := hex.DecodeString(hello.Token)
	if err != nil || len(tok) != 32 {
		_ = wsjson.Write(ctx, c, wsOut{V: 1, Op: "err", Err: "bad token"})
		return
	}
	sum := sha256.Sum256(tok)
	if !s.Store.Auth(hello.Mailbox, sum[:]) {
		_ = wsjson.Write(ctx, c, wsOut{V: 1, Op: "err", Err: "unauthorized"})
		return
	}
	mb := hello.Mailbox
	if err := wsjson.Write(ctx, c, wsOut{V: 1, Op: "ok"}); err != nil {
		return
	}

	ch := s.Hub.Subscribe(mb)
	defer s.Hub.Unsubscribe(mb, ch)

	for _, env := range s.Store.Inbox(mb) {
		_ = wsjson.Write(ctx, c, wsOut{
			V: 1, Op: "deliver", ID: env.ID,
			Blob:  base64.StdEncoding.EncodeToString(env.Blob),
			Bytes: env.Bytes, At: env.CreatedAt,
		})
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			var msg wsIn
			if err := wsjson.Read(ctx, c, &msg); err != nil {
				return
			}
			switch msg.Op {
			case "ping":
				_ = wsjson.Write(ctx, c, wsOut{V: 1, Op: "pong"})
			case "send":
				if !s.allow(r, 40) {
					_ = wsjson.Write(ctx, c, wsOut{V: 1, Op: "err", Err: "rate"})
					continue
				}
				env, err := s.drop(msg.To, msg.Blob)
				if err != nil {
					_ = wsjson.Write(ctx, c, wsOut{V: 1, Op: "err", Err: err.Error()})
					continue
				}
				_ = wsjson.Write(ctx, c, wsOut{V: 1, Op: "queued", ID: env.ID, Bytes: env.Bytes})
			case "ack":
				n := s.Store.Ack(mb, msg.IDs)
				_ = wsjson.Write(ctx, c, wsOut{V: 1, Op: "acked", N: n})
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case payload, ok := <-ch:
			if !ok {
				return
			}
			if err := c.Write(ctx, websocket.MessageText, payload); err != nil {
				return
			}
		}
	}
}

func (s *Server) authorize(r *http.Request) (string, bool) {
	mb := r.Header.Get("X-Faraday-Mailbox")
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if mb == "" || token == "" {
		mb, token, _ = strings.Cut(r.URL.Query().Get("auth"), ":")
	}
	if !hexMailbox(mb) {
		return "", false
	}
	tok, err := hex.DecodeString(token)
	if err != nil || len(tok) != 32 {
		return "", false
	}
	sum := sha256.Sum256(tok)
	if !s.Store.Auth(mb, sum[:]) {
		return "", false
	}
	return mb, true
}

func (s *Server) allow(r *http.Request, perMin int) bool {
	ip := r.RemoteAddr
	if i := strings.LastIndex(ip, ":"); i > 0 {
		ip = ip[:i]
	}
	type bucket struct {
		n    int
		from time.Time
	}
	now := time.Now()
	v, _ := s.limit.LoadOrStore(ip, &bucket{from: now})
	b := v.(*bucket)
	if now.Sub(b.from) > time.Minute {
		b.n = 0
		b.from = now
	}
	b.n++
	return b.n <= perMin
}

func hexMailbox(s string) bool {
	if len(s) != 32 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

type simpleError string

func (e simpleError) Error() string { return string(e) }

func errBad(s string) error { return simpleError(s) }

func init() {
	log.SetFlags(log.LstdFlags)
	// Default logs never include envelope bodies or tokens.
	log.SetPrefix("faraday-relay ")
}
