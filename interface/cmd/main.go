package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"thinkpol-vpn/interface/internal/api"
	"thinkpol-vpn/interface/internal/logger"
)

func main() {
	// Parse command line flags
	port := flag.Int("port", 8080, "Port to listen on")
	unsafe := flag.Bool("unsafe", false, "Enable unsafe features (traffic interception)")
	logFile := flag.String("log", "logs/vpn-interface.log", "Log file path")
	flag.Parse()

	// Initialize logger
	appLogger, err := logger.NewLogger(*logFile)
	if err != nil {
		log.Fatal("Failed to initialize logger:", err)
	}
	defer appLogger.Close()

	appLogger.Info("ThinkPol VPN Interface starting...")

	// Create and start the API server
	server := api.NewServer(*port, *unsafe)

	appLogger.Info("Starting ThinkPol VPN Interface on port %d", *port)
	appLogger.Info("Available endpoints:")
	appLogger.Info("  POST   /api/interface/create     - Create the TUN interface")
	appLogger.Info("  GET    /api/interface/status     - Get interface status")
	appLogger.Info("  POST   /api/interface/start      - Start packet processing")
	appLogger.Info("  POST   /api/interface/stop       - Stop packet processing")
	appLogger.Info("  DELETE /api/interface/delete     - Delete the interface")
	if *unsafe {
		appLogger.Warn("  POST   /api/interface/intercept  - Intercept ALL internet traffic (UNSAFE)")
	}
	appLogger.Info("  GET    /health                   - Health check")
	appLogger.Info("")
	appLogger.Info("Interface configuration: %s/%s (MTU: %d)", api.InterfaceIP, api.InterfaceMask, api.InterfaceMTU)
	appLogger.Info("Press Ctrl+C to stop gracefully")
	appLogger.Info("Logs are being written to: %s", *logFile)

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	// Start server in a goroutine
	go func() {
		if err := server.Start(); err != nil {
			appLogger.Error("Failed to start server: %v", err)
			os.Exit(1)
		}
	}()

	// Wait for shutdown signal
	sig := <-sigChan
	appLogger.Info("Received signal %v, shutting down gracefully...", sig)

	// Perform cleanup
	if err := server.Cleanup(); err != nil {
		appLogger.Error("Cleanup error: %v", err)
	}

	appLogger.Info("Shutdown complete")
}
