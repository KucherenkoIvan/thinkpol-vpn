package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"thinkpol-vpn/interface/internal/proxy"
	"thinkpol-vpn/interface/internal/tun"
)

func main() {
	// Parse command line flags
	logFile := flag.String("log", "logs/vpn-interface.log", "Log file path")
	addr := flag.String("transport-addr", "localhost:8888", "address for websocket proxy server to listen to")
	flag.Parse()

	log.Println("⚙️ Configuring for start up")
	log.Println("")

	log.Println("Configuring websocket transport...")
	transport := proxy.NewRawWebSocketVpnProxy()

	log.Println("Setting up HTTP server...")
	http.HandleFunc("/transport", transport.UpgradeConnection)
	go func() {
		log.Printf("Http server starting up on %s", *addr)
		log.Fatal(http.ListenAndServe(*addr, nil))
	}()
	log.Println("Starting websocket handlers...")
	transport.Start()
	log.Println("Transport set up!")
	log.Println("")

	log.Println("Configuring interface manager...")
	im := tun.NewInterfaceManager("utun9", 1500, "10.0.0.1", "255.255.255.0", transport)

	log.Println("Creating TUN interface...")
	im.Create()

	log.Println("Creating routes for 10th subnet...")
	im.CreateRouteFor10Subnet()

	log.Println("Starting packets capture...")
	im.Start()

	log.Println("")
	log.Println("✅ Started succesfully")
	log.Printf("📝 Logs are being written to: %s", *logFile)

	log.Println("")
	log.Println("Press Ctrl+C to stop gracefully")

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	// Wait for shutdown signal
	sig := <-sigChan
	log.Printf("Received signal %v, shutting down gracefully...", sig)

	log.Println("Deleting routes for 10th subnet...")
	im.RemoveRouteFor10Subnet()

	log.Println("Cleaning up...")
	im.Cleanup()

	log.Println("Stopping websocket handlers...")
	transport.Stop()

	log.Println("")
	log.Println("Shutdown complete")
}
