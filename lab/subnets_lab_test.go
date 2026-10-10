//go:build lab

package lab

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// A network removed by someone else between the list and the inspect
// doesn't fail allocation: two throwaway networks of the test's own, one of
// them removed right after `docker network ls`.
func TestUsedSubnetsSurvivesANetworkRemovedMidway(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	suffix := make([]byte, 4)
	_, _ = rand.Read(suffix)
	subnetOf, idOf := map[string]netip.Prefix{}, map[string]string{}
	for _, role := range []string{"gone", "kept"} {
		name := ProjectPrefix + "subnet-race-" + role + "-" + hex.EncodeToString(suffix)
		t.Cleanup(func() { _, _ = docker(context.Background(), "network", "rm", name) })
		res, err := docker(ctx, "network", "create", name)
		if err != nil {
			t.Fatal(err)
		}
		idOf[role] = strings.TrimSpace(res.Stdout)
		res, err = docker(ctx, "network", "inspect", "--format", "{{range .IPAM.Config}}{{.Subnet}}{{end}}", name)
		if err != nil {
			t.Fatal(err)
		}
		p, err := netip.ParsePrefix(strings.TrimSpace(res.Stdout))
		if err != nil {
			t.Fatalf("%s: subnet %q: %v", name, res.Stdout, err)
		}
		subnetOf[role] = p.Masked()
	}
	removed := false
	racing := func(ctx context.Context, args ...string) (Result, error) {
		res, err := docker(ctx, args...)
		if err == nil && !removed && slices.Equal(args, []string{"network", "ls", "-q", "--no-trunc"}) {
			if !slices.Contains(strings.Fields(res.Stdout), idOf["gone"]) {
				t.Fatal("the throwaway network isn't listed")
			}
			if _, err := docker(ctx, "network", "rm", idOf["gone"]); err != nil {
				t.Fatal(err)
			}
			removed = true
		}
		return res, err
	}
	used, err := usedSubnetsVia(ctx, racing)
	if err != nil {
		t.Fatalf("a network removed mid-allocation failed it: %v", err)
	}
	if !removed {
		t.Fatal("the network was never removed")
	}
	if !slices.Contains(used, subnetOf["kept"]) {
		t.Errorf("the kept network's %v is missing from %v", subnetOf["kept"], used)
	}
	if slices.Contains(used, subnetOf["gone"]) {
		t.Errorf("the removed network's %v still counts as used", subnetOf["gone"])
	}
}
