package lab

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestStandardTopologyIsValid(t *testing.T) {
	if err := Standard().Validate(); err != nil {
		t.Fatal(err)
	}
	if err := GoTestTopology().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestTopologyValidateRejects(t *testing.T) {
	base := Topology{Networks: []Network{{Name: "net"}}}
	for name, topo := range map[string]Topology{
		"no nodes":          base,
		"bad name":          base.With(NodeSpec{Name: "Device_A", Networks: []string{"net"}}),
		"no network":        base.With(NodeSpec{Name: "a"}),
		"unknown network":   base.With(NodeSpec{Name: "a", Networks: []string{"other"}}),
		"unknown gateway":   base.With(NodeSpec{Name: "a", Networks: []string{"net"}, Gateway: "gw"}),
		"duplicate network": base.WithNetworks(Network{Name: "net"}).With(NodeSpec{Name: "a", Networks: []string{"net"}}),
		"gateway elsewhere": base.WithNetworks(Network{Name: "other"}).With(
			NodeSpec{Name: "a", Networks: []string{"net"}, Gateway: "gw"},
			NodeSpec{Name: "gw", Networks: []string{"other"}},
		),
	} {
		if err := topo.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestWithReplacesAndAddsWithoutTouchingTheOriginal(t *testing.T) {
	std := Standard()
	topo := std.With(
		NodeSpec{Name: Server1, Networks: []string{NetServers}, Command: []string{"sleep", "infinity"}},
		NodeSpec{Name: "server-3", Networks: []string{NetServers}, Gateway: Router},
	)
	if len(topo.Nodes) != len(std.Nodes)+1 {
		t.Fatalf("%d nodes", len(topo.Nodes))
	}
	if got := topo.Nodes[topo.nodeIndex(Server1)].Command; len(got) != 2 {
		t.Errorf("server-1 not replaced: %v", got)
	}
	if std.Nodes[std.nodeIndex(Server1)].Command != nil {
		t.Error("With changed the original topology")
	}
}

// A lab start's bounds: the part before the slot counts from the start's
// beginning, across prepare and beforeSlot; the slot wait has its own,
// longer bound; and the start counts from when the slot is held, so a wait
// longer than the whole start bound leaves the start all of it.
func TestStartBudgetCountsFromTheSlot(t *testing.T) {
	base := time.Now()
	now := base
	b := startBudget{before: time.Minute, wait: time.Hour, start: time.Minute, teardown: time.Minute}
	c := b.clock(func() time.Time { return now }, time.Time{})

	now = base.Add(40 * time.Second)
	if dl, cut := c.deadline(phaseBeforeSlot); !dl.Equal(base.Add(b.before)) || cut {
		t.Errorf("before the slot: deadline %v after the start began, want %v", dl.Sub(base), b.before)
	}
	now = base.Add(b.before)
	if dl, cut := c.deadline(phaseSlotWait); !dl.Equal(now.Add(b.wait)) || cut {
		t.Errorf("the slot wait: deadline %v after it began, want %v", dl.Sub(now), b.wait)
	}
	now = now.Add(50 * time.Minute)
	if dl, cut := c.deadline(phaseAfterSlot); !dl.Equal(now.Add(b.start)) || cut {
		t.Errorf("the start: deadline %v after the slot, want %v", dl.Sub(now), b.start)
	}
}

// Under make lab-test's LAB_TIMEOUT (60m), a lab beginning at any minute of
// the run, each phase taking all the time it is given, ends before the
// test binary's deadline with the tear-down's time to spare, and its slot
// wait leaves the start its whole bound: a lab still waiting fails with
// what it waited for, not in the timeout's panic.
func TestLabStartEndsBeforeTheTestDeadline(t *testing.T) {
	const labTimeout = 60 * time.Minute
	base := time.Now()
	deadline := base.Add(labTimeout)
	end := deadline.Add(-labBudget.teardown)
	for offset := time.Duration(0); offset < labTimeout; offset += time.Minute {
		now := base.Add(offset)
		c := labBudget.clock(func() time.Time { return now }, deadline)
		now, _ = c.deadline(phaseBeforeSlot)
		waitEnd, _ := c.deadline(phaseSlotWait)
		if waitEnd.After(end.Add(-labBudget.start)) {
			t.Errorf("a lab begun at %v: its slot wait ends %v before the deadline, leaving the start less than %v", offset, deadline.Sub(waitEnd), labBudget.start)
		}
		if waitEnd.After(now) {
			now = waitEnd
		}
		now, _ = c.deadline(phaseAfterSlot)
		if now.After(end) {
			t.Errorf("a lab begun at %v ends %v after the deadline less the tear-down", offset, now.Sub(end))
		}
		if offset == 0 && !waitEnd.After(c.began.Add(labBudget.before)) {
			t.Errorf("a lab begun with the run has no time to wait for a slot")
		}
	}
	if labBudget.wait <= labBudget.start {
		t.Errorf("lab budget %+v: the slot wait must be longer than the start", labBudget)
	}
}

// A phase that runs out of time says which bound it was; an error with
// time left, or after the caller gave up, is the phase's own.
func TestLabStartSaysWhichBoundExpired(t *testing.T) {
	b := startBudget{before: time.Minute, wait: 20 * time.Millisecond, start: time.Minute, teardown: time.Minute}
	waitDone := func(ctx context.Context) error {
		<-ctx.Done()
		return fmt.Errorf("lab: waiting for a free lab slot: %w", ctx.Err())
	}

	err := b.clock(time.Now, time.Time{}).run(t.Context(), "tplab-x", phaseSlotWait, waitDone)
	if want := "lab tplab-x: no lab slot within 20ms: lab: waiting for a free lab slot: context deadline exceeded"; err == nil || err.Error() != want {
		t.Errorf("slot wait: %v, want %q", err, want)
	}
	past := b.clock(time.Now, time.Now().Add(-time.Hour))
	err = past.run(t.Context(), "tplab-x", phaseAfterSlot, waitDone)
	if want := "lab tplab-x: start not done 0s after the slot, cut short by the test's deadline"; err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Errorf("start: %v, want %q", err, want)
	}
	err = past.run(t.Context(), "tplab-x", phaseBeforeSlot, waitDone)
	if want := "lab tplab-x: not ready for a lab slot within 0s"; err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Errorf("before the slot: %v, want %q", err, want)
	}

	refused := errors.New("refused")
	if err := b.clock(time.Now, time.Time{}).run(t.Context(), "tplab-x", phaseAfterSlot, func(context.Context) error { return refused }); err != refused {
		t.Errorf("an error with time left: %v, want it as is", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := b.clock(time.Now, time.Time{}).run(ctx, "tplab-x", phaseSlotWait, waitDone); err == nil || strings.Contains(err.Error(), "within") {
		t.Errorf("a cancelled wait: %v, want no bound named", err)
	}
}

func TestOnlyKeepsTheNamedNodesAndTheirNetworks(t *testing.T) {
	topo := Upstream().Only(Router, Server1, Camouflage)
	var nodes, nets []string
	for _, n := range topo.Nodes {
		nodes = append(nodes, n.Name)
	}
	for _, n := range topo.Networks {
		nets = append(nets, n.Name)
	}
	if want := []string{Router, Server1, Camouflage}; !slices.Equal(nodes, want) {
		t.Errorf("nodes %v, want %v", nodes, want)
	}
	// Every kept node is the topology's own, settings and all.
	upstream := Upstream()
	for _, n := range topo.Nodes {
		if want := upstream.Nodes[upstream.nodeIndex(n.Name)]; !reflect.DeepEqual(n, want) {
			t.Errorf("Only changed %s: %+v, want %+v", n.Name, n, want)
		}
	}
	// The router is still on the devices network, so it stays.
	if want := []string{NetDevices, NetServers, NetWorld}; !slices.Equal(nets, want) {
		t.Errorf("networks %v, want %v", nets, want)
	}
	if err := topo.Validate(); err != nil {
		t.Error(err)
	}
	if got := Standard().Only(Server1, Internet).With(NodeSpec{Name: Router, Networks: []string{NetServers}}).Networks; len(got) != 1 || got[0].Name != NetServers {
		t.Errorf("networks of server-side nodes: %v, want servers only", got)
	}
	if err := Standard().Only(DeviceA, Server1).Validate(); err == nil {
		t.Error("a topology without the nodes' gateway is valid")
	}
	defer func() {
		if recover() == nil {
			t.Error("Only of a node the topology doesn't have didn't panic")
		}
	}()
	Standard().Only(Router, "server-3")
}

func TestRenderCompose(t *testing.T) {
	topo := Standard().WithNetworks(Network{Name: "v4", IPv4Only: true}).With(NodeSpec{Name: "phone", Networks: []string{"v4"}})
	subnets, err := allocateSubnets(topo.Networks, netip.MustParsePrefix("172.16.0.0/16"), nil)
	if err != nil {
		t.Fatal(err)
	}
	out, err := renderCompose("tplab-a", topo, image{ref: "thinkpol-lab:test", platform: "linux/arm64"}, "/checkout", "/checkout/lab/bin/run-x", subnets)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out, []byte("container_name")) || bytes.Contains(out, []byte("network_mode")) {
		t.Error("compose file fixes container names or shares a network namespace")
	}
	var f composeFile
	if err := json.Unmarshal(out, &f); err != nil {
		t.Fatal(err)
	}
	if f.Name != "tplab-a" || len(f.Services) != len(topo.Nodes) {
		t.Fatalf("project %q with %d services", f.Name, len(f.Services))
	}
	for name, net := range f.Networks {
		if net.Labels[LabelLab] != "1" || net.Labels[LabelRoot] != "/checkout" {
			t.Errorf("network %s labels %v", name, net.Labels)
		}
		if net.DriverOpts["com.docker.network.bridge.enable_ip_masquerade"] != "false" {
			t.Errorf("network %s masquerades", name)
		}
		if net.DriverOpts["com.docker.network.bridge.gateway_mode_ipv4"] != "routed" || net.DriverOpts["com.docker.network.bridge.gateway_mode_ipv6"] != "routed" {
			t.Errorf("network %s: gateway modes are not routed: %v", name, net.DriverOpts)
		}
		want := 2
		if name == "v4" {
			want = 1
		}
		if net.EnableIPv6 != (want == 2) || len(net.IPAM.Config) != want {
			t.Errorf("network %s: ipv6 %v, subnets %v", name, net.EnableIPv6, net.IPAM.Config)
		}
	}
	for name, svc := range f.Services {
		if svc.Labels[LabelLab] != "1" || svc.Privileged || svc.Platform != "linux/arm64" {
			t.Errorf("service %s: labels %v, privileged %v, platform %q", name, svc.Labels, svc.Privileged, svc.Platform)
		}
		if !slices.Contains(svc.SecurityOpt, "seccomp=/checkout/lab/seccomp.json") || !slices.Equal(svc.DNS, []string{DeadEndNameserver}) {
			t.Errorf("service %s: security options %v, nameservers %v; want seccomp=/checkout/lab/seccomp.json among them, nameservers [%s]", name, svc.SecurityOpt, svc.DNS, DeadEndNameserver)
		}
	}
	router := f.Services[Router]
	if router.Sysctls["net.ipv4.ip_forward"] != "1" || router.Sysctls["net.ipv6.conf.all.forwarding"] != "1" {
		t.Errorf("router doesn't forward: %v", router.Sysctls)
	}
	if router.Devices[0] != "/dev/net/tun" || !slices.Contains(router.CapAdd, "NET_ADMIN") {
		t.Error("router has no TUN device or NET_ADMIN")
	}
	if router.Volumes[0] != "/checkout/lab/bin/run-x:"+BinDir+":ro" {
		t.Errorf("binaries mounted as %s", router.Volumes[0])
	}
	if _, ok := f.Services[DeviceA].Networks[NetServers]; ok {
		t.Error("device-a is on the servers network")
	}
}

func TestSeccompProfileAllowsPivotRootOnlyWithSysAdmin(t *testing.T) {
	root, err := Root()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, seccompProfilePath))
	if err != nil {
		t.Fatal(err)
	}
	var profile struct {
		DefaultAction string                       `json:"defaultAction"`
		Syscalls      []map[string]json.RawMessage `json:"syscalls"`
	}
	if err := json.Unmarshal(data, &profile); err != nil {
		t.Fatal(err)
	}
	// The profile must still be Docker's default: deny unless a rule allows.
	if profile.DefaultAction != "SCMP_ACT_ERRNO" {
		t.Fatalf("default action %s, want SCMP_ACT_ERRNO", profile.DefaultAction)
	}
	const sysAdminOnly = `{"action":"SCMP_ACT_ALLOW","includes":{"caps":["CAP_SYS_ADMIN"]}}`
	// What Docker's default (moby/profiles seccomp v0.2.4) allows of the
	// syscalls that matter most to the lab's isolation, each rule without
	// its names; an errno rule allows nothing and isn't listed.
	dockerAllows := map[string][]string{
		"mount":   {sysAdminOnly},
		"unshare": {sysAdminOnly},
		"setns":   {sysAdminOnly},
		"bpf":     {sysAdminOnly, `{"action":"SCMP_ACT_ALLOW","includes":{"caps":["CAP_BPF"]}}`},
		// Without CAP_SYS_ADMIN, clone only with none of the namespace
		// flags (2114060288 = 0x7E020000: CLONE_NEWNS, NEWCGROUP, NEWUTS,
		// NEWIPC, NEWUSER, NEWPID and NEWNET masked to zero).
		"clone": {
			sysAdminOnly,
			`{"action":"SCMP_ACT_ALLOW","args":[{"index":0,"value":2114060288,"op":"SCMP_CMP_MASKED_EQ"}],"excludes":{"caps":["CAP_SYS_ADMIN"],"arches":["s390","s390x"]}}`,
			`{"action":"SCMP_ACT_ALLOW","args":[{"index":1,"value":2114060288,"op":"SCMP_CMP_MASKED_EQ"}],"comment":"s390 parameter ordering for clone is different","excludes":{"caps":["CAP_SYS_ADMIN"]},"includes":{"arches":["s390","s390x"]}}`,
		},
		"clone3":     {sysAdminOnly},
		"keyctl":     nil,
		"ptrace":     {`{"action":"SCMP_ACT_ALLOW","includes":{"minKernel":"4.8"}}`, `{"action":"SCMP_ACT_ALLOW","includes":{"caps":["CAP_SYS_PTRACE"]}}`},
		"pivot_root": {sysAdminOnly},
	}
	allows := map[string][]string{}
	pivotRules := 0
	for _, r := range profile.Syscalls {
		var names []string
		if err := json.Unmarshal(r["names"], &names); err != nil {
			t.Fatal(err)
		}
		delete(r, "names")
		cond, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if slices.Contains(names, "pivot_root") {
			pivotRules++
			if !slices.Equal(names, []string{"pivot_root"}) {
				t.Errorf("the pivot_root rule also names %v", names)
			}
		}
		var action string
		if err := json.Unmarshal(r["action"], &action); err != nil {
			t.Fatal(err)
		}
		if action == "SCMP_ACT_ERRNO" {
			continue
		}
		for _, n := range names {
			if _, ok := dockerAllows[n]; ok {
				allows[n] = append(allows[n], string(cond))
			}
		}
	}
	if pivotRules != 1 {
		t.Errorf("%d rules name pivot_root, want 1", pivotRules)
	}
	for name, want := range dockerAllows {
		if got := allows[name]; !slices.Equal(got, want) {
			t.Errorf("%s allowed by %q, want %q", name, got, want)
		}
	}
}

func TestAllocateSubnetsAvoidsUsedOnesAndEachOther(t *testing.T) {
	pool := netip.MustParsePrefix("172.16.0.0/22") // four /24s
	used := []netip.Prefix{netip.MustParsePrefix("172.16.1.0/24"), netip.MustParsePrefix("172.16.0.0/16").Masked()}
	if _, err := allocateSubnets([]Network{{Name: "a"}}, pool, used); err == nil {
		t.Fatal("allocated inside a used /16")
	}
	used = used[:1]
	nets := []Network{{Name: "a"}, {Name: "b"}, {Name: "c", IPv4Only: true}}
	got, err := allocateSubnets(nets, pool, used)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[netip.Prefix]bool{}
	for _, n := range nets {
		s := got[n.Name]
		if !pool.Contains(s.v4.Addr()) || s.v4.Bits() != 24 || s.v4.Overlaps(used[0]) || seen[s.v4] {
			t.Errorf("%s: v4 %v", n.Name, s.v4)
		}
		seen[s.v4] = true
		if n.IPv4Only != !s.v6.IsValid() {
			t.Errorf("%s: v6 %v", n.Name, s.v6)
		}
		if s.v6.IsValid() && (s.v6.Bits() != 64 || s.v6.Addr().As16()[0] != 0xfd || seen[s.v6]) {
			t.Errorf("%s: v6 %v is not a fresh ULA /64", n.Name, s.v6)
		}
		seen[s.v6] = true
	}
	if _, err := allocateSubnets(append(nets, Network{Name: "d"}), pool, used); err == nil {
		t.Error("allocated five /24s from a pool with three free")
	}
}

func TestProjectNames(t *testing.T) {
	t.Setenv(ProjectEnv, "")
	a, _ := CheckoutProject("/x/worktrees/tp-002-lab-harness")
	b, _ := CheckoutProject("/y/worktrees/tp-002-lab-harness")
	if a == b || !strings.HasPrefix(a, ProjectPrefix+"tp-002-lab-harness-") {
		t.Errorf("checkout projects %q, %q", a, b)
	}
	if odd, _ := CheckoutProject("/x/---"); odd != ProjectPrefix+"checkout-"+shortHash("/x/---") {
		t.Errorf("a checkout without usable characters: %q", odd)
	}
	p1 := testProject(a, "r1", "p1", "/x/lab", "TestSmoke/IPv4 over UDP")
	p2 := testProject(a, "r1", "p1", "/x/other", "TestSmoke/IPv4 over UDP")
	if p1 == p2 || !belongsTo(p1, a) || belongsTo(p1, b) || !startedByTests(p1, a) || startedByTests(a, a) {
		t.Errorf("test projects %q, %q", p1, p2)
	}
	if !startedByTests(goTestPackageProject(a, "r1", "p1", "example.net/x"), a) {
		t.Error("labctl gotest's labs don't count as started by tests")
	}
	if belongsTo(a+"x", a) {
		t.Error("a checkout whose name extends another's belongs to it")
	}
	for _, p := range []string{a, p1, goTestPackageProject(a, "r1", "p1", "example.net/x")} {
		if slug(p, 100) != p {
			t.Errorf("%q is not a valid Compose project name", p)
		}
	}
	t.Setenv(ProjectEnv, "second-run")
	if got, err := CheckoutProject("/x"); err != nil || got != ProjectPrefix+"second-run" {
		t.Errorf("override gave %q, %v", got, err)
	}
	for _, bad := range []string{"infra", "Second", "-x", "a/b", "a b", strings.Repeat("a", 41)} {
		t.Setenv(ProjectEnv, bad)
		if got, err := CheckoutProject("/x"); err == nil && bad != "infra" {
			t.Errorf("override %q accepted as %q", bad, got)
		} else if bad == "infra" && got != ProjectPrefix+"infra" {
			t.Errorf("override %q gave %q, which escapes the prefix", bad, got)
		}
	}
}

// Two runs from one checkout name the same test's, or package's, lab apart,
// and a run's labs are told apart from another run's, from lab-up's and
// from another checkout's, even when one run id extends the other.
func TestRunProjectNames(t *testing.T) {
	t.Parallel()
	a, _ := checkoutProject("/x/a", "")
	b, _ := checkoutProject("/x/b", "")
	mine := []string{
		testProject(a, "r1", "p1", "/x/a/lab", "TestSmoke"),
		goTestPackageProject(a, "r1", "p1", "example.net/x"),
	}
	theirs := []string{
		testProject(a, "r12", "p1", "/x/a/lab", "TestSmoke"),
		goTestPackageProject(a, "r12", "p1", "example.net/x"),
		testProject(a, "r2", "p1", "/x/a/lab", "TestSmoke"),
		goTestPackageProject(a, "r2", "p1", "example.net/x"),
		testProject(b, "r1", "p1", "/x/b/lab", "TestSmoke"),
		goTestPackageProject(b, "r1", "p1", "example.net/x"),
		a,
	}
	for i, p := range mine {
		if !startedByRun(p, a, "r1") {
			t.Errorf("%q is not run r1's", p)
		}
		if p == theirs[i] || p == theirs[i+2] {
			t.Errorf("two runs share the project %q", p)
		}
	}
	for _, p := range theirs {
		if startedByRun(p, a, "r1") {
			t.Errorf("%q counts as run r1's", p)
		}
	}
	// Another process of the same run (make lab-test's other phase, a retry,
	// a shard) names the same test's and package's labs apart, still the run's.
	for i, p := range []string{
		testProject(a, "r1", "p2", "/x/a/lab", "TestSmoke"),
		goTestPackageProject(a, "r1", "p2", "example.net/x"),
	} {
		if p == mine[i] || !startedByRun(p, a, "r1") {
			t.Errorf("process p2's %q: process p1's is %q", p, mine[i])
		}
	}
}

const printOwnProjectsEnv = "THINKPOL_LAB_TEST_PRINT_OWN_PROJECTS"

// ownProjects names a test's and a package's labs as this process would
// start them.
func ownProjects() string {
	return ownTestProject("tplab-a", "r1", "/x/a/lab", "TestSmoke") + "\n" +
		ownGoTestPackageProject("tplab-a", "r1", "example.net/x") + "\n"
}

// Two processes of one run name the same test's and package's labs apart
// through the names start and GoTestEach use, not only when handed
// different process ids.
func TestProcessesOfOneRunNameTheirLabsApart(t *testing.T) {
	if os.Getenv(printOwnProjectsEnv) != "" {
		t.Skip("the child of this test")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestPrintOwnProjects$")
	cmd.Env = append(os.Environ(), printOwnProjectsEnv+"=1")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
	theirs := strings.Split(string(out), "\n")
	mine := strings.Split(ownProjects(), "\n")
	for i, p := range mine[:2] {
		if !startedByRun(p, "tplab-a", "r1") {
			t.Errorf("%q is not run r1's", p)
		}
		if slices.Contains(theirs, p) {
			t.Errorf("the other process also names its lab %q", p)
		}
		if i >= len(theirs) || !startedByRun(theirs[i], "tplab-a", "r1") {
			t.Errorf("the other process's lab names: %q", out)
		}
	}
}

func TestPrintOwnProjects(t *testing.T) {
	if os.Getenv(printOwnProjectsEnv) == "" {
		t.Skip("the child of TestProcessesOfOneRunNameTheirLabsApart")
	}
	fmt.Print(ownProjects())
}

// longestOverride, longestRunID and longestTestProject make the longest
// project names the harness can give: the longest override and run id, a
// test name past the slug's cap, and claimProject's number. Docker
// accepting them is TestHarnessDownRunRemovesOnlyItsRun (a lab test).
var (
	longestOverride = strings.Repeat("a", 40)
	longestRunID    = strings.Repeat("9", 8)
)

func longestTestProject(checkout, run string) string {
	return testProject(checkout, run, "p1", "/x/lab", strings.Repeat("T", 100)) + "-99"
}

// The longest names are valid project names of their run. Their length
// can't be checked here: Docker's acceptance is proven by the lab test.
func TestLongestProjectNames(t *testing.T) {
	t.Parallel()
	checkout, err := checkoutProject("/x", longestOverride)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateRunID(longestRunID); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{
		longestTestProject(checkout, longestRunID),
		goTestPackageProject(checkout, longestRunID, "p1", "example.net/x"),
	} {
		if slug(p, 200) != p || !startedByRun(p, checkout, longestRunID) {
			t.Errorf("%q is not a valid Compose project name of the run", p)
		}
	}
}

func TestRunIDs(t *testing.T) {
	for range 100 {
		if id := NewRunID(); ValidateRunID(id) != nil {
			t.Fatalf("NewRunID gave %q, which isn't a valid run id", id)
		}
	}
	for _, bad := range []string{"", "a-b", "ABC", "123456789", "a/b"} {
		if ValidateRunID(bad) == nil {
			t.Errorf("run id %q accepted", bad)
		}
	}
}

func TestLinkLocalFromMAC(t *testing.T) {
	got, err := linkLocalFromMAC("02:42:fc:f9:a9:69")
	if err != nil || got != netip.MustParseAddr("fe80::42:fcff:fef9:a969") {
		t.Errorf("got %v, %v", got, err)
	}
}

func TestDownRefusesProjectsWithoutThePrefix(t *testing.T) {
	for _, p := range []string{"infra", "docker", "", "tplab"} {
		err := downProject(t.Context(), p, "/x")
		if err == nil || !strings.Contains(err.Error(), "refusing") {
			t.Errorf("down %q: %v", p, err)
		}
	}
}
