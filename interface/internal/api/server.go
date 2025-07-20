package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"

	"thinkpol-vpn/interface/internal/tun"
)

// Static interface configuration
const (
	InterfaceName = "utun9"
	InterfaceIP   = "10.0.0.1"
	InterfaceMask = "255.255.255.0"
	InterfaceMTU  = 1500
)

// Server handles HTTP API requests for TUN interface management
type Server struct {
	manager *tun.InterfaceManager
	port    int
	unsafe  bool
}

// NewServer creates a new API server
func NewServer(port int, unsafe bool) *Server {
	return &Server{
		port:   port,
		unsafe: unsafe,
	}
}

// Start starts the HTTP server
func (s *Server) Start() error {
	// Set up routes
	http.HandleFunc("/api/interface/create", s.handleCreateInterface)
	http.HandleFunc("/api/interface/status", s.handleGetStatus)
	http.HandleFunc("/api/interface/start", s.handleStartInterface)
	http.HandleFunc("/api/interface/stop", s.handleStopInterface)
	http.HandleFunc("/api/interface/delete", s.handleDeleteInterface)

	// Only register unsafe endpoints if unsafe mode is enabled
	if s.unsafe {
		http.HandleFunc("/api/interface/intercept", s.handleInterceptTraffic)
		log.Printf("⚠️  UNSAFE MODE ENABLED - Traffic interception endpoint available")
	}

	http.HandleFunc("/health", s.handleHealth)

	log.Printf("API server starting on port %d", s.port)
	return http.ListenAndServe(fmt.Sprintf(":%d", s.port), nil)
}

// handleHealth handles health check requests
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "healthy",
		"service": "thinkpol-vpn-interface",
	})
}

// handleCreateInterface handles interface creation requests
func (s *Server) handleCreateInterface(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check if interface already exists
	if s.manager != nil {
		http.Error(w, "Interface already exists", http.StatusConflict)
		return
	}

	// Parse IP addresses
	addr := net.ParseIP(InterfaceIP)
	mask := net.ParseIP(InterfaceMask)
	if addr == nil || mask == nil {
		http.Error(w, "Invalid static IP configuration", http.StatusInternalServerError)
		return
	}

	// Create interface manager with static configuration
	s.manager = tun.NewInterfaceManager(InterfaceName, InterfaceMTU, addr, mask)

	// Create the interface
	if err := s.manager.Create(); err != nil {
		s.manager = nil
		http.Error(w, fmt.Sprintf("Failed to create interface: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": fmt.Sprintf("Interface %s created successfully", InterfaceName),
	})
}

// handleGetStatus handles status requests
func (s *Server) handleGetStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.manager == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "no_interface",
			"message": "No interface has been created",
		})
		return
	}

	status := s.manager.GetStatus()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// handleStartInterface handles interface start requests
func (s *Server) handleStartInterface(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.manager == nil {
		http.Error(w, "No interface to start", http.StatusBadRequest)
		return
	}

	if err := s.manager.Start(); err != nil {
		http.Error(w, fmt.Sprintf("Failed to start interface: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "Interface started successfully",
	})
}

// handleStopInterface handles interface stop requests
func (s *Server) handleStopInterface(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.manager == nil {
		http.Error(w, "No interface to stop", http.StatusBadRequest)
		return
	}

	if err := s.manager.Stop(); err != nil {
		http.Error(w, fmt.Sprintf("Failed to stop interface: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "Interface stopped successfully",
	})
}

// handleDeleteInterface handles interface deletion requests
func (s *Server) handleDeleteInterface(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.manager == nil {
		http.Error(w, "No interface to delete", http.StatusBadRequest)
		return
	}

	// Perform cleanup
	if err := s.manager.Cleanup(); err != nil {
		log.Printf("Warning: failed to cleanup interface: %v", err)
	}

	s.manager = nil

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "Interface deleted successfully",
	})
}

// Cleanup performs cleanup when the server shuts down
func (s *Server) Cleanup() error {
	if s.manager != nil {
		return s.manager.Cleanup()
	}
	return nil
}

// handleInterceptTraffic handles traffic interception requests
func (s *Server) handleInterceptTraffic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.manager == nil {
		http.Error(w, "No interface to configure for interception", http.StatusBadRequest)
		return
	}

	if err := s.manager.InterceptAllTraffic(); err != nil {
		http.Error(w, fmt.Sprintf("Failed to intercept traffic: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "All traffic is now being intercepted",
	})
}
