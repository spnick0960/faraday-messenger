package relay

import "sync"

type Hub struct {
	mu    sync.Mutex
	subs  map[string]map[chan []byte]struct{}
}

func NewHub() *Hub {
	return &Hub{subs: map[string]map[chan []byte]struct{}{}}
}

func (h *Hub) Subscribe(mailbox string) chan []byte {
	ch := make(chan []byte, 8)
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.subs[mailbox] == nil {
		h.subs[mailbox] = map[chan []byte]struct{}{}
	}
	h.subs[mailbox][ch] = struct{}{}
	return ch
}

func (h *Hub) Unsubscribe(mailbox string, ch chan []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if m, ok := h.subs[mailbox]; ok {
		delete(m, ch)
		if len(m) == 0 {
			delete(h.subs, mailbox)
		}
	}
	close(ch)
}

func (h *Hub) Publish(mailbox string, payload []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs[mailbox] {
		select {
		case ch <- payload:
		default:
		}
	}
}

func (h *Hub) Online(mailbox string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subs[mailbox]) > 0
}
