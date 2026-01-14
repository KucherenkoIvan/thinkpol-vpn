#!/bin/sh
set -e

ENCODING_PID=""
TRANSPORT_PID=""
CLIENT_PID=""

# Function to handle shutdown
cleanup() {
    echo "Shutting down services..."
    [ -n "$ENCODING_PID" ] && kill $ENCODING_PID 2>/dev/null || true
    [ -n "$TRANSPORT_PID" ] && kill $TRANSPORT_PID 2>/dev/null || true
    [ -n "$CLIENT_PID" ] && kill $CLIENT_PID 2>/dev/null || true
    wait $ENCODING_PID $TRANSPORT_PID $CLIENT_PID 2>/dev/null || true
    exit 0
}

# Trap signals for graceful shutdown
trap cleanup SIGTERM SIGINT

# Start encoding service
echo "Starting encoding service..."
/app/bin/encoding-service -port=50051 &
ENCODING_PID=$!
sleep 2

# Check if encoding service started successfully
if ! kill -0 $ENCODING_PID 2>/dev/null; then
    echo "Failed to start encoding service"
    exit 1
fi

# Start transport service
echo "Starting transport service..."
/app/bin/transport-service -port=50052 -gateway=gateway-emulation:50052 &
TRANSPORT_PID=$!
sleep 2

# Check if transport service started successfully
if ! kill -0 $TRANSPORT_PID 2>/dev/null; then
    echo "Failed to start transport service"
    cleanup
    exit 1
fi

# Start client
echo "Starting client..."
/app/bin/client \
    -interface-config=/app/configs/interface.json \
    -encoding-config=/app/configs/encoding.json \
    -transport-config=/app/configs/transport.json &
CLIENT_PID=$!
sleep 1

# Check if client started successfully
if ! kill -0 $CLIENT_PID 2>/dev/null; then
    echo "Failed to start client"
    cleanup
    exit 1
fi

echo "All services started successfully"

# Wait for all processes
wait $ENCODING_PID $TRANSPORT_PID $CLIENT_PID

