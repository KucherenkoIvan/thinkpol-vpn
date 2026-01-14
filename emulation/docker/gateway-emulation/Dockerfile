# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build all required binaries
RUN go build -o bin/gateway cmd/gateway/main.go
RUN go build -o bin/encoding-service cmd/encoding-service/main.go
RUN go build -o bin/transport-service cmd/transport-service/main.go

# Runtime stage
FROM alpine:latest

WORKDIR /app

# Copy binaries from builder
COPY --from=builder /build/bin/gateway /app/bin/gateway
COPY --from=builder /build/bin/encoding-service /app/bin/encoding-service
COPY --from=builder /build/bin/transport-service /app/bin/transport-service

# Copy configs
COPY emulation/configs /app/configs

# Copy entrypoint script
COPY emulation/docker/gateway-emulation/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]

