//go:build darwin || linux

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/ifbind"
	"github.com/KucherenkoIvan/thinkpol-vpn/lab/devicetest/plan"
	"github.com/KucherenkoIvan/thinkpol-vpn/lab/devicetest/safety"
)

// selfTestBudget bounds the capture checks: a capture that sees nothing
// fails in the run's first seconds, before any change, not after it.
const selfTestBudget = 10 * time.Second

// markerPort is where markers go: the discard port of the interface's
// IPv4 broadcast address. One datagram each, and none leaves the LAN.
const markerPort = 9

// captureCheck is one capture's self-test, as selftest/selftest.json
// records it.
type captureCheck struct {
	Iface    string `json:"iface"`
	Filter   string `json:"filter"`
	OK       bool   `json:"ok"`
	Why      string `json:"why,omitempty"`
	Took     string `json:"took"`
	Tries    int    `json:"tries"`
	Positive string `json:"positive_nonce"`
	Negative string `json:"negative_nonce"`
	Copy     string `json:"copy"`
	Decode   string `json:"decode"`
}

// selfTest checks the machinery before any change: one harmless change
// goes into the journal and out through it, then the plan's capture must
// see a marker, must not see one its filter excludes, and must decode
// through the evidence path (`tcpdump -n -A -r`), within selfTestBudget.
func (r *runner) selfTest(ctx context.Context) error {
	start := time.Now()
	if err := r.harmlessChange(); err != nil {
		return fmt.Errorf("a harmless change through the journal: %w", err)
	}
	if r.plan.Capture.Iface == "" {
		r.ev.Logf("self-test ok: the plan has no capture")
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, selfTestBudget)
	defer cancel()
	check := r.checkCapture(ctx, r.plan.Capture)
	took := time.Since(start)
	_ = r.ev.WriteJSON("selftest/selftest.json", map[string]any{"took": took.String(), "budget": selfTestBudget.String(), "capture": check})
	if !check.OK {
		return fmt.Errorf("the capture on %s: %s", check.Iface, check.Why)
	}
	r.ev.Logf("self-test ok in %v: the capture sees its marker, misses the filtered one, decodes", took.Round(time.Millisecond))
	return nil
}

func (r *runner) harmlessChange() error {
	params, _ := json.Marshal(map[string]string{"name": "selftest-" + nonce(), "content": r.runID})
	if _, err := r.c.call(safety.Request{Op: safety.OpDo, Change: &safety.Spec{Kind: safety.KindFile, Params: params}}); err != nil {
		return err
	}
	_, err := r.c.call(safety.Request{Op: safety.OpUndoLast})
	return err
}

func (r *runner) checkCapture(ctx context.Context, c plan.Capture) captureCheck {
	start := time.Now()
	res := captureCheck{Iface: c.Iface}
	if c.Iface == plan.Physical {
		res.Iface = r.phys
	}
	if err := r.runCaptureCheck(ctx, c.Filter, &res); err != nil {
		res.Why = err.Error()
	} else {
		res.OK = true
	}
	res.Took = time.Since(start).Round(time.Millisecond).String()
	return res
}

func (r *runner) runCaptureCheck(ctx context.Context, filter string, res *captureCheck) error {
	bcast, neg, pos, err := markerSockets(ctx, res.Iface)
	if err != nil {
		return err
	}
	defer func() { _ = neg.Close(); _ = pos.Close() }()
	res.Filter = controlFilter(filter, strconv.Itoa(neg.LocalAddr().(*net.UDPAddr).Port))
	if _, err := r.c.call(safety.Request{Op: safety.OpCaptureStart, Iface: res.Iface, Filter: res.Filter}); err != nil {
		return fmt.Errorf("start: %w", err)
	}
	res.Copy = "selftest/" + res.Iface + ".pcap"
	if _, err := r.c.call(safety.Request{Op: safety.OpCutStart, Iface: res.Iface, Name: res.Copy}); err != nil {
		return err
	}
	seen, negSeen, err := r.sendMarkers(ctx, res, bcast, neg, pos)
	if _, cerr := r.c.call(safety.Request{Op: safety.OpCutEnd, Iface: res.Iface}); cerr != nil {
		return cerr
	}
	switch {
	case err != nil:
		return err
	case !seen:
		return fmt.Errorf("a marker sent on %s wasn't captured (%d tries): the capture sees nothing", res.Iface, res.Tries)
	case negSeen:
		return errors.New("a marker the filter excludes was captured: the check could never fail")
	}
	return r.checkDecode(ctx, res)
}

// sendMarkers sends the negative control, then the positive one (again
// once, inside the budget, if it isn't seen): the negative went first, so
// by the time the positive is seen, a negative that passed the filter has
// been seen too.
func (r *runner) sendMarkers(ctx context.Context, res *captureCheck, bcast netip.AddrPort, neg, pos *net.UDPConn) (seen, negSeen bool, err error) {
	res.Negative = nonce()
	if err := r.sendMarker(neg, bcast, res, res.Negative, "negative"); err != nil {
		return false, false, err
	}
	for !seen && res.Tries < 2 && ctx.Err() == nil {
		res.Tries++
		res.Positive = nonce()
		if err := r.sendMarker(pos, bcast, res, res.Positive, "positive"); err != nil {
			return false, false, err
		}
		resp, err := r.c.call(safety.Request{Op: safety.OpCaptureSeen, Iface: res.Iface, Nonce: res.Positive, TimeoutMS: 2000})
		if err != nil {
			return false, false, err
		}
		seen = resp.Seen
	}
	resp, err := r.c.call(safety.Request{Op: safety.OpCaptureSeen, Iface: res.Iface, Nonce: res.Negative, TimeoutMS: 100})
	return seen, resp.Seen, err
}

func (r *runner) sendMarker(conn *net.UDPConn, to netip.AddrPort, res *captureCheck, n, control string) error {
	payload := fmt.Sprintf("%s%s %s", safety.MarkerPrefix, r.runID, n)
	_, err := conn.WriteToUDPAddrPort([]byte(payload), to)
	_ = r.ev.AppendJSONL("captures/markers.jsonl", map[string]any{"time": time.Now().UTC(), "iface": res.Iface,
		"control": control, "nonce": n, "to": to.String(), "error": errString(err)})
	if err != nil {
		return fmt.Errorf("sending the %s marker: %w", control, err)
	}
	return nil
}

// checkDecode decodes the self-test's copy of the capture exactly as a
// judge will, stderr kept: the positive marker must be in the text, the
// negative not.
func (r *runner) checkDecode(ctx context.Context, res *captureCheck) error {
	res.Decode = "selftest/decode-" + res.Iface + ".txt"
	cmd := exec.CommandContext(ctx, safety.Tcpdump(), "-n", "-A", "-r", filepath.Join(r.ev.Path, res.Copy))
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	_ = r.ev.WriteFile(res.Decode, stdout.Bytes())
	_ = r.ev.WriteFile(res.Decode+".err", stderr.Bytes())
	return decodedMarkers(stdout.Bytes(), res.Positive, res.Negative, err)
}

// decodedMarkers judges a decode's text: it worked, shows the positive
// marker and not the negative one.
func decodedMarkers(text []byte, positive, negative string, runErr error) error {
	switch {
	case runErr != nil:
		return fmt.Errorf("the decode (tcpdump -n -A -r) failed: %w", runErr)
	case !bytes.Contains(text, []byte(positive)):
		return errors.New("the decode (tcpdump -n -A -r) doesn't show the marker the capture saw")
	case bytes.Contains(text, []byte(negative)):
		return errors.New("the decode shows the marker the filter excludes")
	}
	return nil
}

// controlFilter is the plan's filter with the self-test's controls: the
// positive marker always passes it, the negative never does.
func controlFilter(filter, negativePort string) string {
	if filter == "" {
		return fmt.Sprintf("not (udp src port %s)", negativePort)
	}
	return fmt.Sprintf("not (udp src port %s) and ((%s) or (udp dst port %d))", negativePort, filter, markerPort)
}

// markerSockets are two UDP sockets on iface's IPv4 address, bound to
// the interface, allowed to broadcast; and where markers go.
func markerSockets(ctx context.Context, iface string) (netip.AddrPort, *net.UDPConn, *net.UDPConn, error) {
	ifc, err := net.InterfaceByName(iface)
	if err != nil {
		return netip.AddrPort{}, nil, nil, fmt.Errorf("%s: %w", iface, err)
	}
	addrs, err := ifc.Addrs()
	if err != nil {
		return netip.AddrPort{}, nil, nil, err
	}
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok || n.IP.To4() == nil {
			continue
		}
		local, _ := netip.AddrFromSlice(n.IP.To4())
		b := n.IP.To4()
		bcast := netip.AddrFrom4([4]byte{b[0] | ^n.Mask[0], b[1] | ^n.Mask[1], b[2] | ^n.Mask[2], b[3] | ^n.Mask[3]})
		lc := net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error {
			if err := ifbind.ByName(iface)(network, address, c); err != nil {
				return err
			}
			var serr error
			err := c.Control(func(fd uintptr) { serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1) })
			return errors.Join(err, serr)
		}}
		var conns [2]*net.UDPConn
		for i := range conns {
			pc, err := lc.ListenPacket(ctx, "udp4", netip.AddrPortFrom(local, 0).String())
			if err != nil {
				if conns[0] != nil {
					_ = conns[0].Close()
				}
				return netip.AddrPort{}, nil, nil, err
			}
			conns[i] = pc.(*net.UDPConn)
		}
		return netip.AddrPortFrom(bcast, markerPort), conns[0], conns[1], nil
	}
	return netip.AddrPort{}, nil, nil, fmt.Errorf("%s has no IPv4 address to send markers from", iface)
}

func nonce() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
