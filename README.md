# Tote Relay

A dumb ciphertext mailbox. Stores encrypted blobs (envelopes) and delivers them to recipients. Holds NO keys and can NEVER read envelope contents.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| POST | /envelope | Upload encrypted blob (with PoW) |
| GET | /envelope/{id} | Fetch blob (requires X-Device-ID header) |
| DELETE | /envelope/{id} | Delete after ACK |
| GET | /inbox/{id}?since= | Poll for new blobs |
| WS | /inbox/{id}/events | Real-time WebSocket push |
| GET | /healthz | Health check |

## Run

```bash
go run main.go
# or
TOTE_RELAY_PORT=8443 TOTE_RELAY_DB=tote-relay.db go run main.go
```

## Deploy

```bash
docker build -t tote-relay .
docker run -p 8443:8443 -v relay-data:/data tote-relay
```

## Security

- Per-IP rate limiting (30/min)
- SHA-256 PoW (20-bit target) on uploads
- 4 MiB max envelope size
- TTL sweeper (default 7 days)
- Device-ID ownership verification on all reads/deletes
- Relay holds NO encryption keys — E2E encrypted by clients

## License

MIT
