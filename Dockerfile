FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod .
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o tote-relay .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /app/tote-relay .
EXPOSE 8443
ENV TOTE_RELAY_PORT=8443
ENV TOTE_RELAY_DB=/data/tote-relay.db
VOLUME /data
CMD ["./tote-relay"]
