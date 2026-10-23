//go:build darwin || linux

package main

import (
	"errors"
	"os"
	"testing"
)

// The judge's decode, as tcpdump -n -A -r printed it in a lab node for the
// recorded capture (lab/devicetest/safety/testdata/marker.pcap).
func TestTheDecodeCheckOnARecordedDecode(t *testing.T) {
	text, err := os.ReadFile("testdata/selftest/marker.txt")
	if err != nil {
		t.Fatal(err)
	}
	const positive, negative = "fedcba9876543210", "0123456789abcdef"
	if err := decodedMarkers(text, positive, negative, nil); err != nil {
		t.Errorf("the recorded decode: %v", err)
	}
	for name, err := range map[string]error{
		// Device run 4's bug: a decode to empty text.
		"empty text":             decodedMarkers(nil, positive, negative, nil),
		"tcpdump failed":         decodedMarkers(text, positive, negative, errors.New("exit status 1")),
		"the filtered one shows": decodedMarkers(text, positive, positive, nil),
		"another run's marker":   decodedMarkers(text, negative, "x", nil),
	} {
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
