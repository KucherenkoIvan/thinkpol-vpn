package blobs

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

var (
	// errProtocol is a peer answering outside the protocol: a status it
	// can't send, or a length other than the blob's.
	errProtocol = errors.New("blobs: the peer broke the protocol")
	errNotHere  = errors.New("blobs: the peer doesn't hold it")
	errBusy     = errors.New("blobs: the peer is busy")
	errNoSource = errors.New("blobs: no overlay address of the peer's family")
)

// resumes bounds how often a transfer that broke after making progress is
// resumed from the same peer.
const resumes = 3

// fetchFrom gets ref from one peer, trying its addresses in order, and
// resuming a transfer that breaks after making progress. What it returns
// is unchecked.
func (s *Service) fetchFrom(ctx context.Context, p Plan, peer Peer, ref netmap.BlobRef) ([]byte, error) {
	var buf []byte
	err := errNoSource
	for _, addr := range peer.Addrs {
		local, ok := sourceFor(p.Listen, addr)
		if !ok {
			continue
		}
		for attempt := 0; ; attempt++ {
			before := len(buf)
			err = s.fetchOnce(ctx, p.Interface, local, netip.AddrPortFrom(addr, s.port), ref, &buf)
			if err == nil {
				return buf, nil
			}
			if errors.Is(err, errNotHere) || errors.Is(err, errBusy) || errors.Is(err, errProtocol) || ctx.Err() != nil {
				return nil, err
			}
			if len(buf) == before || attempt == resumes {
				break
			}
		}
		if len(buf) > 0 {
			return nil, err // the peer had it; another address won't fare better
		}
	}
	return nil, err
}

// sourceFor picks the node's overlay address of addr's family.
func sourceFor(own []netip.Addr, addr netip.Addr) (netip.Addr, bool) {
	for _, a := range own {
		if a.Is4() == addr.Is4() {
			return a, true
		}
	}
	return netip.Addr{}, false
}

// fetchOnce makes one request for ref from len(*buf) on, appending what
// arrives to *buf.
func (s *Service) fetchOnce(ctx context.Context, iface string, local netip.Addr, remote netip.AddrPort, ref netmap.BlobRef, buf *[]byte) error {
	dctx, cancel := context.WithTimeout(ctx, s.limits.DialTimeout)
	conn, err := s.dial(dctx, iface, local, remote)
	cancel()
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	offset := uint64(len(*buf))
	idle := func() { _ = conn.SetDeadline(time.Now().Add(s.limits.IdleTimeout)) }
	idle()
	req := request{sha256: ref.SHA256, offset: offset}.encode()
	if _, err := conn.Write(req[:]); err != nil {
		return err
	}
	var st [1]byte
	if _, err := io.ReadFull(conn, st[:]); err != nil {
		return err
	}
	switch status(st[0]) {
	case statusOK:
	case statusNotHere:
		return errNotHere
	case statusBusy:
		return errBusy
	default:
		return fmt.Errorf("%w: status %d", errProtocol, st[0])
	}
	var n [8]byte
	if _, err := io.ReadFull(conn, n[:]); err != nil {
		return err
	}
	if length := binary.BigEndian.Uint64(n[:]); length != ref.Size-offset {
		return fmt.Errorf("%w: %d bytes announced from offset %d of a %d-byte blob", errProtocol, length, offset, ref.Size)
	}
	if *buf == nil {
		*buf = make([]byte, 0, min(ref.Size, 64<<10))
	}
	chunk := make([]byte, 32<<10)
	for uint64(len(*buf)) < ref.Size {
		idle()
		want := min(uint64(len(chunk)), ref.Size-uint64(len(*buf)))
		k, err := conn.Read(chunk[:want])
		*buf = append(*buf, chunk[:k]...)
		if err != nil {
			if errors.Is(err, io.EOF) && uint64(len(*buf)) < ref.Size {
				return io.ErrUnexpectedEOF
			}
			if uint64(len(*buf)) < ref.Size {
				return err
			}
		}
	}
	return nil
}

func (s *Service) dial(ctx context.Context, iface string, local netip.Addr, remote netip.AddrPort) (net.Conn, error) {
	if s.o.Dial != nil {
		return s.o.Dial(ctx, local, remote)
	}
	d := net.Dialer{LocalAddr: net.TCPAddrFromAddrPort(netip.AddrPortFrom(local, 0)), Control: bindTo(iface)}
	return d.DialContext(ctx, "tcp", remote.String())
}
