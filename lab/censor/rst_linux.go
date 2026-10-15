//go:build linux

package censor

import (
	"fmt"
	"net/netip"
	"syscall"

	"golang.org/x/sys/unix"
)

// rstSender sends the RSTs of Reset verdicts from raw sockets: a queued
// packet gets a verdict, not a rewrite, so the censor sends the RST
// itself.
type rstSender struct {
	v4, v6 int // the sockets, -1 when unused
}

func newRSTSender() (*rstSender, error) {
	s := &rstSender{v4: -1, v6: -1}
	fd, err := openRaw(unix.AF_INET, unix.IPPROTO_RAW, unix.IPPROTO_IP, unix.IP_HDRINCL)
	if err != nil {
		s.close()
		return nil, err
	}
	s.v4 = fd
	fd, err = openRaw(unix.AF_INET6, unix.IPPROTO_RAW, unix.IPPROTO_IPV6, unix.IPV6_HDRINCL)
	if err != nil {
		s.close()
		return nil, err
	}
	s.v6 = fd
	return s, nil
}

func openRaw(family, proto, hdrinclLevel, hdrincl int) (int, error) {
	fd, err := syscall.Socket(family, syscall.SOCK_RAW, proto)
	if err != nil {
		return -1, fmt.Errorf("censor: raw socket: %w", err)
	}
	if err := unix.SetsockoptInt(fd, hdrinclLevel, hdrincl, 1); err != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("censor: hdrincl: %w", err)
	}
	return fd, nil
}

// send sends the RST that answers p.
func (s *rstSender) send(p *Packet) error {
	if p.Dst.Is4() {
		return sendRaw(s.v4, buildRST(p), p.Dst)
	}
	return sendRaw(s.v6, buildRST(p), p.Dst)
}

func sendRaw(fd int, b []byte, to netip.Addr) error {
	if to.Is4() {
		var sa unix.SockaddrInet4
		copy(sa.Addr[:], to.AsSlice())
		return unix.Sendto(fd, b, 0, &sa)
	}
	var sa unix.SockaddrInet6
	copy(sa.Addr[:], to.AsSlice())
	return unix.Sendto(fd, b, 0, &sa)
}

func (s *rstSender) close() {
	for _, fd := range []*int{&s.v4, &s.v6} {
		if *fd >= 0 {
			_ = unix.Close(*fd)
			*fd = -1
		}
	}
}
