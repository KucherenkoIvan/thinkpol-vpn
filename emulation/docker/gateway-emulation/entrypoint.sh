#!/bin/sh
set -e

ENCODING_PID=""
GATEWAY_PID=""
TRANSPORT_PID=""

# Function to handle shutdown
cleanup() {
    echo "Shutting down services..."
    [ -n "$ENCODING_PID" ] && kill $ENCODING_PID 2>/dev/null || true
    [ -n "$GATEWAY_PID" ] && kill $GATEWAY_PID 2>/dev/null || true
    [ -n "$TRANSPORT_PID" ] && kill $TRANSPORT_PID 2>/dev/null || true
    wait $ENCODING_PID $GATEWAY_PID $TRANSPORT_PID 2>/dev/null || true
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

# Start gateway
echo "Starting gateway..."
/app/bin/gateway -port=8080 &
GATEWAY_PID=$!
sleep 2

# Check if gateway started successfully
if ! kill -0 $GATEWAY_PID 2>/dev/null; then
    echo "Failed to start gateway"
    cleanup
    exit 1
fi

# Start transport service (connects to gateway)
echo "Starting transport service..."
/app/bin/transport-service -port=50052 -gateway=localhost:8080 &
TRANSPORT_PID=$!
sleep 2

# Check if transport service started successfully
if ! kill -0 $TRANSPORT_PID 2>/dev/null; then
    echo "Failed to start transport service"
    cleanup
    exit 1
fi

echo "All services started successfully"

# Wait for all processes
wait $ENCODING_PID $GATEWAY_PID $TRANSPORT_PID

