// Package main implements the Tote relay server.
// A dumb ciphertext mailbox — holds NO keys, can NEVER read envelope contents.
package main

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
	"github.com/gorilla/websocket"
	"crypto/sha256"
)

const (
	MaxEnvelopeBytes = 4 * 1024 * 1024
	DefaultTTL       = 7 * 24 * 3600
	TTLSweepInterval = 5 * time.Minute
	PoWTarget        = 20
	RateLimitPerMin  = 30
	WSHeartbeat      = 30 * time.Second
)

type EnvelopeUpload struct {
	SenderID   string `json:"sender_id"`
	ReceiverID string `json:"receiver_id"`
	Ciphertext  string `json:"ciphertext"`
	TTL         int    `json:"ttl"`
	PoWNonce    string `json:"pow_nonce"`
}

type Relay struct {
	db          *sql.DB
	wsHub       *WSHub
	rateLimiter *RateLimiter
}

type WSHub struct {
	mu      sync.Mutex
	clients map[string][]*websocket.Conn
}

func NewWSHub() *WSHub { return &WSHub{clients: make(map[string][]*websocket.Conn)} }

func (h *WSHub) register(inboxID string, conn *websocket.Conn) {
	h.mu.Lock(); defer h.mu.Unlock()
	h.clients[inboxID] = append(h.clients[inboxID], conn)
}

func (h *WSHub) unregister(inboxID string, conn *websocket.Conn) {
	h.mu.Lock(); defer h.mu.Unlock()
	conns := h.clients[inboxID]
	for i, c := range conns {
		if c == conn { h.clients[inboxID] = append(conns[:i], conns[i+1:]...); break }
	}
	if len(h.clients[inboxID]) == 0 { delete(h.clients, inboxID) }
}

func (h *WSHub) notify(inboxID, envID string) {
	h.mu.Lock(); defer h.mu.Unlock()
	for _, c := range h.clients[inboxID] { c.WriteJSON(map[string]string{"type":"envelope","id":envID}) }
}

type RateLimiter struct {
	mu     sync.Mutex
	counts map[string][]time.Time
}

func NewRateLimiter() *RateLimiter { return &RateLimiter{counts: make(map[string][]time.Time)} }

func (r *RateLimiter) Allow(ip string) bool {
	r.mu.Lock(); defer r.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-time.Minute)
	var recent []time.Time
	for _, t := range r.counts[ip] { if t.After(cutoff) { recent = append(recent, t) } }
	if len(recent) >= RateLimitPerMin { return false }
	r.counts[ip] = append(recent, now)
	return true
}

func initDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil { return nil, err }
	db.SetMaxOpenConns(1)
	schema := `CREATE TABLE IF NOT EXISTS envelopes (
		id TEXT PRIMARY KEY, sender_id TEXT NOT NULL, receiver_id TEXT NOT NULL,
		ciphertext BLOB NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
		delivered INTEGER DEFAULT 0, delivered_at INTEGER, size_class TEXT NOT NULL);
	CREATE INDEX IF NOT EXISTS idx_receiver ON envelopes(receiver_id, delivered);
	CREATE INDEX IF NOT EXISTS idx_expires ON envelopes(expires_at);`
	_, err = db.Exec(schema)
	return db, err
}

func genID() string {
	b := make([]byte, 16)
	for i := range b { b[i] = byte(time.Now().UnixNano() >> uint(i*8)) }
	return hex.EncodeToString(b)
}

func verifyPoW(inboxID, ct, nonce string) bool {
	h := sha256.Sum256([]byte(inboxID + ct + nonce))
	return new(big.Int).SetBytes(h[:]).Cmp(new(big.Int).Lsh(big.NewInt(1), 256-PoWTarget)) < 0
}

func (r *Relay) sweep() {
	t := time.NewTicker(TTLSweepInterval)
	defer t.Stop()
	for range t.C {
		n, _ := r.db.Exec(`DELETE FROM envelopes WHERE expires_at < ?`, time.Now().Unix())
		if rows, _ := n.RowsAffected(); rows > 0 { log.Printf("TTL: purged %d", rows) }
	}
}

// ===== Handlers =====

func (r *Relay) healthz(w http.ResponseWriter, _ *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (r *Relay) upload(w http.ResponseWriter, req *http.Request) {
	ip, _, _ := net.SplitHostPort(req.RemoteAddr)
	if !r.rateLimiter.Allow(ip) { http.Error(w, `{"error":"rate_limited"}`, 429); return }
	var u EnvelopeUpload
	if err := json.NewDecoder(req.Body).Decode(&u); err != nil { http.Error(w, `{"error":"bad_json"}`, 400); return }
	if u.SenderID == "" || u.ReceiverID == "" || u.Ciphertext == "" { http.Error(w, `{"error":"missing"}`, 400); return }
	ct, err := hex.DecodeString(u.Ciphertext)
	if err != nil { http.Error(w, `{"error":"bad_hex"}`, 400); return }
	if len(ct) > MaxEnvelopeBytes { http.Error(w, `{"error":"too_large"}`, 413); return }
	if !verifyPoW(u.ReceiverID, u.Ciphertext, u.PoWNonce) { http.Error(w, `{"error":"pow"}`, 400); return }
	id := genID()
	now := time.Now().Unix()
	ttl := DefaultTTL
	if u.TTL > 0 && u.TTL < DefaultTTL { ttl = u.TTL }
	sc := "small"; if len(ct) > 65536 { sc = "medium" }; if len(ct) > 1<<20 { sc = "large" }
	_, err = r.db.Exec(`INSERT INTO envelopes (id,sender_id,receiver_id,ciphertext,created_at,expires_at,delivered,size_class) VALUES(?,?,?,?,?,?,0,?)`, id, u.SenderID, u.ReceiverID, ct, now, now+int64(ttl), sc)
	if err != nil { http.Error(w, `{"error":"db"}`, 500); return }
	r.wsHub.notify(u.ReceiverID, id)
	json.NewEncoder(w).Encode(map[string]string{"id": id})
	log.Printf("UPLOAD %s s=%s r=%s %dB", id[:8], u.SenderID[:8], u.ReceiverID[:8], len(ct))
}

func (r *Relay) get(w http.ResponseWriter, req *http.Request) {
	id := strings.TrimPrefix(req.URL.Path, "/envelope/")
	dev := req.Header.Get("X-Device-ID")
	if dev == "" { http.Error(w, `{"error":"no_device"}`, 401); return }
	var ct []byte; var recv string; var exp int64
	err := r.db.QueryRow(`SELECT ciphertext,receiver_id,expires_at FROM envelopes WHERE id=? AND delivered=0`, id).Scan(&ct, &recv, &exp)
	if err == sql.ErrNoRows { http.Error(w, `{"error":"not_found"}`, 404); return }
	if err != nil { http.Error(w, `{"error":"db"}`, 500); return }
	if dev != recv { http.Error(w, `{"error":"unauthorized"}`, 403); return }
	if time.Now().Unix() > exp { r.db.Exec(`DELETE FROM envelopes WHERE id=?`, id); http.Error(w, `{"error":"expired"}`, 410); return }
	r.db.Exec(`UPDATE envelopes SET delivered=1,delivered_at=? WHERE id=?`, time.Now().Unix(), id)
	json.NewEncoder(w).Encode(map[string]string{"id": id, "ciphertext": hex.EncodeToString(ct)})
	log.Printf("GET %s dev=%s", id[:8], dev[:8])
}

func (r *Relay) delete(w http.ResponseWriter, req *http.Request) {
	id := strings.TrimPrefix(req.URL.Path, "/envelope/")
	dev := req.Header.Get("X-Device-ID")
	if dev == "" { http.Error(w, `{"error":"no_device"}`, 401); return }
	var recv string
	err := r.db.QueryRow(`SELECT receiver_id FROM envelopes WHERE id=?`, id).Scan(&recv)
	if err == sql.ErrNoRows { http.Error(w, `{"error":"not_found"}`, 404); return }
	if dev != recv { http.Error(w, `{"error":"unauthorized"}`, 403); return }
	r.db.Exec(`DELETE FROM envelopes WHERE id=?`, id)
	w.WriteHeader(204)
	log.Printf("DEL %s dev=%s", id[:8], dev[:8])
}

func (r *Relay) poll(w http.ResponseWriter, req *http.Request) {
	inbox := strings.TrimPrefix(strings.TrimSuffix(req.URL.Path, "/"), "/inbox/")
	dev := req.Header.Get("X-Device-ID")
	if dev != inbox { http.Error(w, `{"error":"unauthorized"}`, 403); return }
	since := int64(0); fmt.Sscanf(req.URL.Query().Get("since"), "%d", &since)
	rows, err := r.db.Query(`SELECT id,sender_id,size_class,created_at FROM envelopes WHERE receiver_id=? AND delivered=0 AND created_at>? AND expires_at>? ORDER BY created_at`, inbox, since, time.Now().Unix())
	if err != nil { http.Error(w, `{"error":"db"}`, 500); return }
	defer rows.Close()
	type S struct{ ID, Sender, Class string; Created int64 }
	var res []S
	for rows.Next() { var s S; rows.Scan(&s.ID, &s.Sender, &s.Class, &s.Created); res = append(res, s) }
	json.NewEncoder(w).Encode(map[string]interface{}{"inbox_id": inbox, "count": len(res), "envelopes": res})
}

var up = websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}

func (r *Relay) ws(w http.ResponseWriter, req *http.Request) {
	parts := strings.Split(strings.Trim(req.URL.Path, "/"), "/")
	if len(parts) < 3 { http.Error(w, `{"error":"missing"}`, 400); return }
	inbox := parts[1]
	dev := req.Header.Get("X-Device-ID")
	if dev != inbox { http.Error(w, `{"error":"unauthorized"}`, 403); return }
	conn, err := up.Upgrade(w, req, nil)
	if err != nil { return }
	defer conn.Close()
	r.wsHub.register(inbox, conn)
	defer r.wsHub.unregister(inbox, conn)
	conn.SetReadDeadline(time.Now().Add(WSHeartbeat))
	// Send existing
	rows, _ := r.db.Query(`SELECT id FROM envelopes WHERE receiver_id=? AND delivered=0 AND expires_at>?`, inbox, time.Now().Unix())
	if rows != nil { defer rows.Close(); for rows.Next() { var id string; rows.Scan(&id); conn.WriteJSON(map[string]string{"type":"envelope","id":id}) } }
	for { if _, _, err := conn.ReadMessage(); err != nil { break } }
}

func main() {
	dbPath := os.Getenv("TOTE_RELAY_DB"); if dbPath == "" { dbPath = "tote-relay.db" }
	port := os.Getenv("TOTE_RELAY_PORT"); if port == "" { port = "8443" }
	db, err := initDB(dbPath)
	if err != nil { log.Fatalf("DB: %v", err) }
	defer db.Close()
	r := &Relay{db: db, wsHub: NewWSHub(), rateLimiter: NewRateLimiter()}
	go r.sweep()
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", r.healthz)
	mux.HandleFunc("/envelope", func(w http.ResponseWriter, req *http.Request) {
		if req.Method == "POST" { r.upload(w, req) } else { http.Error(w, `{"error":"method"}`, 405) }
	})
	mux.HandleFunc("/envelope/", func(w http.ResponseWriter, req *http.Request) {
		switch req.Method {
		case "GET": r.get(w, req)
		case "DELETE": r.delete(w, req)
		default: http.Error(w, `{"error":"method"}`, 405)
		}
	})
	mux.HandleFunc("/inbox/", func(w http.ResponseWriter, req *http.Request) {
		if strings.Contains(req.URL.Path, "/events") { r.ws(w, req) } else { r.poll(w, req) }
	})
	log.Printf("Tote relay on :%s (db=%s)", port, dbPath)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}
