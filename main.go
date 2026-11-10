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
        // Peer-pubkey records expire after 30 days of inactivity.
        PeerTTL = 30 * 24 * 3600
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
        CREATE INDEX IF NOT EXISTS idx_expires ON envelopes(expires_at);
        CREATE TABLE IF NOT EXISTS peers (
                device_id TEXT PRIMARY KEY, x25519_pub TEXT NOT NULL, ed25519_pub TEXT,
                display_name TEXT, updated_at INTEGER NOT NULL, expires_at INTEGER NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_peers_expires ON peers(expires_at);`
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
                now := time.Now().Unix()
                n, _ := r.db.Exec(`DELETE FROM envelopes WHERE expires_at < ?`, now)
                if rows, _ := n.RowsAffected(); rows > 0 { log.Printf("TTL: purged %d envelopes", rows) }
                np, _ := r.db.Exec(`DELETE FROM peers WHERE expires_at < ?`, now)
                if rows, _ := np.RowsAffected(); rows > 0 { log.Printf("TTL: purged %d peers", rows) }
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
        // JSON shape MUST match what the Android RelayClient regex expects:
        //   {"id":"...","size":N,"received_at":N,"sender_id":"<hex>"}
        // (sender_id is the sender's Ed25519 pubkey hex, 64 chars)
        type S struct {
                ID         string `json:"id"`
                SenderID   string `json:"sender_id"`
                SizeClass  string `json:"size_class"`
                Size       int    `json:"size"`
                ReceivedAt int64  `json:"received_at"`
        }
        var res []S
        for rows.Next() {
                var s S
                var ctLen int
                // We don't have the ciphertext size in this query — re-query for it.
                // For the alpha we map size_class → approximate size.
                // TODO v1.0.0: include the actual byte count in the SELECT.
                rows.Scan(&s.ID, &s.SenderID, &s.SizeClass, &s.ReceivedAt)
                switch s.SizeClass {
                case "small":
                        s.Size = 1024
                case "medium":
                        s.Size = 65536
                case "large":
                        s.Size = 1048576
                default:
                        s.Size = 0
                }
                _ = ctLen
                res = append(res, s)
        }
        if res == nil { res = []S{} }
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

// ===== Peer-pubkey exchange (for relay-mediated ECDH handshake) =====
//
// Per CRYPTO-SPEC-FINAL §3: after QR scan, the receiver needs the sender's
// X25519 pubkey. The QR already carries it, but the REVERSE direction
// (sender needs receiver's X25519 pubkey) requires a relay round-trip.
// We expose:
//   PUT  /peer/<deviceId>     — publish your X25519 pub (idempotent)
//   GET  /peer/<deviceId>     — fetch a peer's X25519 pub
//   DELETE /peer/<deviceId>   — revoke your pub (e.g., on nuke)
//
// Auth: PUT/DELETE require X-Device-ID header == deviceId in path.
// No PoW required (these are tiny records, not envelopes).
//
// Stored record: {deviceId, x25519_pub, ed25519_pub, display_name, updated_at, expires_at}

func (r *Relay) putPeer(w http.ResponseWriter, req *http.Request) {
        id := strings.TrimPrefix(req.URL.Path, "/peer/")
        dev := req.Header.Get("X-Device-ID")
        if dev == "" { http.Error(w, `{"error":"no_device"}`, 401); return }
        if dev != id { http.Error(w, `{"error":"unauthorized"}`, 403); return }
        var body struct {
                X25519Pub   string `json:"x25519_pub"`
                Ed25519Pub  string `json:"ed25519_pub"`
                DisplayName string `json:"display_name"`
        }
        if err := json.NewDecoder(req.Body).Decode(&body); err != nil { http.Error(w, `{"error":"bad_json"}`, 400); return }
        if body.X25519Pub == "" { http.Error(w, `{"error":"missing_x25519"}`, 400); return }
        now := time.Now().Unix()
        _, err := r.db.Exec(`INSERT INTO peers (device_id, x25519_pub, ed25519_pub, display_name, updated_at, expires_at)
                VALUES(?,?,?,?,?,?)
                ON CONFLICT(device_id) DO UPDATE SET
                x25519_pub=excluded.x25519_pub,
                ed25519_pub=excluded.ed25519_pub,
                display_name=excluded.display_name,
                updated_at=excluded.updated_at,
                expires_at=excluded.expires_at`,
                id, body.X25519Pub, body.Ed25519Pub, body.DisplayName, now, now+int64(PeerTTL))
        if err != nil { http.Error(w, `{"error":"db"}`, 500); return }
        json.NewEncoder(w).Encode(map[string]string{"status":"ok","device_id":id})
        log.Printf("PEER PUT %s", id[:8])
}

func (r *Relay) getPeer(w http.ResponseWriter, req *http.Request) {
        id := strings.TrimPrefix(req.URL.Path, "/peer/")
        var x25519, ed25519, name string; var updated, expires int64
        err := r.db.QueryRow(`SELECT x25519_pub, ed25519_pub, display_name, updated_at, expires_at FROM peers WHERE device_id=?`, id).
                Scan(&x25519, &ed25519, &name, &updated, &expires)
        if err == sql.ErrNoRows { http.Error(w, `{"error":"not_found"}`, 404); return }
        if err != nil { http.Error(w, `{"error":"db"}`, 500); return }
        if time.Now().Unix() > expires { r.db.Exec(`DELETE FROM peers WHERE device_id=?`, id); http.Error(w, `{"error":"expired"}`, 410); return }
        json.NewEncoder(w).Encode(map[string]interface{}{
                "device_id":    id,
                "x25519_pub":   x25519,
                "ed25519_pub":  ed25519,
                "display_name": name,
                "updated_at":   updated,
                "expires_at":   expires,
        })
        log.Printf("PEER GET %s", id[:8])
}

func (r *Relay) deletePeer(w http.ResponseWriter, req *http.Request) {
        id := strings.TrimPrefix(req.URL.Path, "/peer/")
        dev := req.Header.Get("X-Device-ID")
        if dev == "" { http.Error(w, `{"error":"no_device"}`, 401); return }
        if dev != id { http.Error(w, `{"error":"unauthorized"}`, 403); return }
        r.db.Exec(`DELETE FROM peers WHERE device_id=?`, id)
        w.WriteHeader(204)
        log.Printf("PEER DEL %s", id[:8])
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
        mux.HandleFunc("/peer/", func(w http.ResponseWriter, req *http.Request) {
                switch req.Method {
                case "GET": r.getPeer(w, req)
                case "PUT": r.putPeer(w, req)
                case "DELETE": r.deletePeer(w, req)
                default: http.Error(w, `{"error":"method"}`, 405)
                }
        })
        log.Printf("Tote relay on :%s (db=%s)", port, dbPath)
        log.Fatal(http.ListenAndServe(":"+port, mux))
}
