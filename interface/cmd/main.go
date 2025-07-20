package main

import (
	"fmt"
	"log"
	"net/http"
)

func main() {
	fmt.Println("ThinkPol VPN Interface starting...")

	// Basic HTTP server setup
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "ThinkPol VPN Interface is running!")
	})

	log.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
