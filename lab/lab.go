package lab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// KeepEnv, when set, leaves a failed test's lab running for inspection;
// make lab-down removes it.
const KeepEnv = "THINKPOL_LAB_KEEP"

// Lab is one running topology: a Compose project of its own.
type Lab struct {
	Project  string
	Topology Topology
	root     string
	stateDir string // lab/.run/<project>: its Compose file, a detached lab's binaries
	binDir   string // mounted at BinDir
	nodes    map[string]*Node
	gateways map[string][]netip.Addr // Docker's bridge addresses, by network
	bridges  map[string]Bridge       // by network
	release  func()                  // the host-wide lab slot
	subnets  *reservation            // held until the lab is down or kept
	// The last docker compose up's start and end, and its attempt number.
	upFrom, upTo time.Time
	upAttempt    int
	// The last start's steps, kept only for TestLabStartTimes (the
	// timeline has them too, as text).
	started startTimes
}

// Bridge is Docker's own end of a lab network: the bridge in the Docker VM.
// It is the way out of the lab, so every node is cut off from it.
type Bridge struct {
	IPv4, IPv6 netip.Addr // the network's gateway addresses (IPv6 invalid on IPv4Only)
	LinkLocal  netip.Addr // its fe80:: address, derived from MAC
	MAC        string
}

// Start brings up a lab for the test and tears it down when the test ends.
// When the test fails, the containers' logs go to the test log. All the
// labs one top-level test starts share one slot of the cap, so a test
// starting a second lab never waits for itself.
func Start(t testing.TB, topo Topology) *Lab {
	return start(t, topo, "test:"+strings.SplitN(t.Name(), "/", 2)[0])
}

// StartOwnSlot is Start with one slot per test or subtest (keyed by its
// full name) instead of one per top-level test, held until that test ends:
// a test whose subtests each start one lab gives each subtest its own
// slot, so the cap bounds its labs like every other run's. Don't mix it
// with Start, or nest it under a test that holds a slot of its own: the
// parent holds its slot while its subtests wait here.
func StartOwnSlot(t testing.TB, topo Topology) *Lab {
	return start(t, topo, "own:"+t.Name())
}

func start(t testing.TB, topo Topology, slotKey string) *Lab {
	t.Helper()
	return startAs(t, topo, slotKey, os.Getenv(ProjectEnv))
}

// startAs is start with override in ProjectEnv's place (checkoutProject).
func startAs(t testing.TB, topo Topology, slotKey, override string) *Lab {
	t.Helper()
	if err := mainCalled(); err != nil {
		t.Fatal(err)
	}
	l, bins, keep, err := launch(context.Background(), t, topo, func(string) string { return slotKey }, t.Name(), override)
	if l != nil {
		t.Cleanup(func() { l.cleanup(t, bins, keep, time.Time{}) })
	}
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// launch brings up a lab for t, named after name, holding the slot
// slotKey gives for its project, without tying its tear-down to t: Start
// ties it to the test, a Pool keeps the lab for the tests after. It
// returns the run's binaries the lab mounts and whether KeepEnv is set;
// a lab returned with an error still needs its clean-up. ctx carries
// whether StartFirst began the start (asFirstStart).
func launch(ctx context.Context, t testing.TB, topo Topology, slotKey func(project string) string, name, override string) (*Lab, *runBinaries, bool, error) {
	t.Helper()
	if err := mainCalled(); err != nil {
		return nil, nil, false, err
	}
	root, err := Root()
	if err != nil {
		return nil, nil, false, err
	}
	checkout, err := checkoutProject(root, override)
	if err != nil {
		return nil, nil, false, err
	}
	run, err := runID()
	if err != nil {
		return nil, nil, false, err
	}
	cwd, _ := os.Getwd()
	project := claimProject(ownTestProject(checkout, run, cwd, name))
	clock := labBudget.begin(testDeadline(t))
	// The run's directory, for .kept; up gets the same one, within the
	// same bound.
	var p preparedRun
	err = clock.run(context.Background(), project, phaseBeforeSlot, func(ctx context.Context) (err error) {
		p, err = prepare(ctx, root)
		return err
	})
	if err != nil {
		return nil, nil, false, err
	}
	// With KeepEnv set, the lab may outlive the run (kept, or left up by a
	// -timeout panic): .kept lists it before it starts, so its binaries stay
	// until labctl down finds it down (except for one accepted gap, see
	// sweepBinRoot). Without KeepEnv, a lab the run leaves up loses its
	// binaries to the next sweep; its run's clean-up (labctl down -run,
	// at the end of make lab-test) or make lab-down removes it.
	keep := os.Getenv(KeepEnv) != ""
	if keep {
		if err := p.bin.recordLab(project); err != nil {
			return nil, nil, false, err
		}
	}
	l, err := up(ctx, clock, root, project, topo, slotKey(project), runInputs)
	return l, p.bin, keep, err
}

// mainCalled is an error unless the test binary runs through Main.
func mainCalled() error {
	if !mainInstalled.Load() {
		return errors.New("lab: this package's TestMain must call lab.Main(m), or the binaries its labs run are never removed")
	}
	return nil
}

var (
	claimedMu sync.Mutex
	claimed   = map[string]int{}
)

// claimProject numbers the second and later labs a test starts.
func claimProject(project string) string {
	claimedMu.Lock()
	defer claimedMu.Unlock()
	claimed[project]++
	if n := claimed[project]; n > 1 {
		return fmt.Sprintf("%s-%d", project, n)
	}
	return project
}

// cleanup tears the lab down, or with keep (KeepEnv) keeps a failed
// test's lab and the run directory bins it mounts. A failed test's log
// gets the containers' logs since since (all of them when zero: a lab
// that served other tests before has theirs too).
func (l *Lab) cleanup(t labUser, bins *runBinaries, keep bool, since time.Time) {
	ctx, cancel := context.WithTimeout(context.Background(), labBudget.teardown)
	defer cancel()
	if t.Failed() {
		logs := []string{"docker", "compose", "-f", l.ComposeFile(), "-p", l.Project, "logs", "--no-color", "--timestamps"}
		if !since.IsZero() {
			logs = append(logs, "--since", since.UTC().Format(time.RFC3339Nano))
		}
		if res, err := runEnv(ctx, nil, environWithoutCompose(), logs[0], logs[1:]...); err == nil {
			t.Logf("lab %s logs:\n%s", l.Project, res.Stdout)
		}
		if keep && l.keepRunning(t, bins) {
			return
		}
	}
	if err := l.Down(ctx); err != nil {
		t.Errorf("lab %s: tear down: %v", l.Project, err)
	}
}

// keepRunning keeps the lab up for inspection, and the run directory bins
// it mounts (KeepEnv), letting go of its slot and subnets; false when it
// couldn't, the lab still up for the caller to tear down.
func (l *Lab) keepRunning(t labUser, bins *runBinaries) bool {
	if err := bins.keep(l.Project); err != nil {
		t.Errorf("lab %s: can't keep it, tearing it down: %v", l.Project, err)
		return false
	}
	t.Logf("lab %s kept: docker compose -p %s exec <node> bash; make lab-down removes it", l.Project, l.Project)
	l.releaseSubnets()
	l.releaseSlot()
	return true
}

// UpDetached brings up a topology, for a lab that outlives this process
// (make lab-up), as the Compose project named project (see up). Its
// binaries are its own, built into its directory under lab/.run, and go
// with it (Down, or labctl down).
func UpDetached(ctx context.Context, root, project string, topo Topology) (*Lab, error) {
	return up(ctx, labBudget.begin(time.Time{}), root, project, topo, "", detachedInputs)
}

// labBudget bounds a lab's start in three phases, each with a bound of its
// own: what comes before the lab slot (a leftover lab removed, the image
// and binaries ready), the wait for the slot, and the start once the slot
// is held, so a lab queued behind others under load doesn't fail its start
// before it began. In a test, none runs past the test binary's deadline
// (go test -timeout, make lab-test's LAB_TIMEOUT) less the tear-down, and
// the slot wait ends early enough to leave the start its whole bound: a
// lab still waiting fails with what it waited for, not in the timeout's
// panic.
var labBudget = startBudget{before: 15 * time.Minute, wait: 45 * time.Minute, start: 10 * time.Minute, teardown: 2 * time.Minute}

type startBudget struct {
	before   time.Duration // everything before the slot, counted from the start's beginning
	wait     time.Duration // for a lab slot
	start    time.Duration // from when the slot is held until the lab is sealed
	teardown time.Duration // a test lab's clean-up (Lab.cleanup)
}

// testDeadline is the test binary's deadline, if t has one.
func testDeadline(t testing.TB) time.Time {
	if d, ok := t.(interface{ Deadline() (time.Time, bool) }); ok {
		if dl, ok := d.Deadline(); ok {
			return dl
		}
	}
	return time.Time{}
}

// begin fixes one lab start's bounds from now; deadline is its test's
// (zero for none).
func (b startBudget) begin(deadline time.Time) startClock {
	return b.clock(time.Now, deadline)
}

func (b startBudget) clock(now func() time.Time, deadline time.Time) startClock {
	c := startClock{b: b, now: now, began: now()}
	if !deadline.IsZero() {
		c.end = deadline.Add(-b.teardown)
	}
	return c
}

type startPhase int

const (
	phaseBeforeSlot startPhase = iota
	phaseSlotWait
	phaseAfterSlot
)

// startClock is one lab start's bounds (startBudget.begin).
type startClock struct {
	b     startBudget
	now   func() time.Time
	began time.Time
	end   time.Time // the test's deadline less the tear-down; zero without one
	// slotWait, when set, gets how long the start waited for its slot,
	// whether or not it got one.
	slotWait *time.Duration
}

// deadline is when phase p, beginning now, must end, and whether the
// test's deadline cut it short.
func (c startClock) deadline(p startPhase) (time.Time, bool) {
	var dl time.Time
	var reserve time.Duration
	switch p {
	case phaseBeforeSlot:
		dl = c.began.Add(c.b.before)
	case phaseSlotWait:
		dl, reserve = c.now().Add(c.b.wait), c.b.start
	case phaseAfterSlot:
		dl = c.now().Add(c.b.start)
	}
	if !c.end.IsZero() && c.end.Add(-reserve).Before(dl) {
		return c.end.Add(-reserve), true
	}
	return dl, false
}

// run runs f under phase p's bound. An error of f's once the bound has
// passed says which bound it was; the slot wait still takes a free slot
// with no time left when no waiter is queued ahead of it (acquireSlotLock
// tries once).
func (c startClock) run(ctx context.Context, project string, p startPhase, f func(context.Context) error) error {
	from := c.now()
	if p == phaseBeforeSlot {
		from = c.began
	}
	dl, cut := c.deadline(p)
	pctx, cancel := context.WithDeadline(ctx, dl)
	defer cancel()
	err := f(pctx)
	if err == nil || pctx.Err() == nil || ctx.Err() != nil {
		return err
	}
	within := max(dl.Sub(from), 0).Round(time.Millisecond)
	if within >= time.Second {
		within = within.Round(time.Second)
	}
	var what string
	switch p {
	case phaseBeforeSlot:
		what = fmt.Sprintf("not ready for a lab slot within %v (removing a leftover lab, building the image and binaries, reading the daemon's subnets)", within)
	case phaseSlotWait:
		what = fmt.Sprintf("no lab slot within %v", within)
	case phaseAfterSlot:
		what = fmt.Sprintf("start not done %v after the slot", within)
	}
	if cut {
		what += ", cut short by the test's deadline"
	}
	return fmt.Errorf("lab %s: %s: %w", project, what, err)
}

// errSlotWaitStopped is a lab start's error when it gave up its slot wait
// (withSlotWaitStop).
var errSlotWaitStopped = errors.New("lab: the start was no longer needed, so it left the slot queue")

type slotWaitStopKey struct{}

// withSlotWaitStop marks a lab start's ctx: once stop is closed, its slot
// wait gives up (leaving the slot queue and the process's share of it)
// with errSlotWaitStopped, whether it has begun yet or not. A start that
// holds its slot already goes on.
func withSlotWaitStop(ctx context.Context, stop <-chan struct{}) context.Context {
	return context.WithValue(ctx, slotWaitStopKey{}, stop)
}

// waitForSlot is a lab start's wait for its slot (acquireSlot) under
// clock's bound, noted in the timeline whether or not it got one.
func waitForSlot(ctx context.Context, clock startClock, project, slotKey string) (release func(), err error) {
	from := time.Now()
	if stop, ok := ctx.Value(slotWaitStopKey{}).(<-chan struct{}); ok {
		wctx, cancel := context.WithCancelCause(ctx)
		defer cancel(nil)
		go func() {
			select {
			case <-stop:
				cancel(errSlotWaitStopped)
			case <-wctx.Done():
			}
		}()
		select {
		case <-stop:
			cancel(errSlotWaitStopped)
		default:
		}
		ctx = wctx
	}
	err = clock.run(ctx, project, phaseSlotWait, func(ctx context.Context) (err error) {
		release, err = acquireSlot(ctx, slotKey)
		return err
	})
	if err != nil && context.Cause(ctx) == errSlotWaitStopped {
		err = errors.Join(errSlotWaitStopped, err)
	}
	to := time.Now()
	noteSlotWait(project, from, to, err)
	if clock.slotWait != nil {
		*clock.slotWait = to.Sub(from)
	}
	return release, err
}

// labInputs builds the image and the binaries a lab runs, and returns the
// directory it mounts at BinDir; stateDir is the lab's lab/.run/<project>.
type labInputs func(ctx context.Context, root, stateDir string) (image, string, error)

// runInputs are this run's, shared by its labs (prepare): such a lab must
// be down, or kept, before the run removes them (RemoveRunBinaries).
func runInputs(ctx context.Context, root, _ string) (image, string, error) {
	p, err := prepare(ctx, root)
	if err != nil {
		return image{}, "", err
	}
	return p.img, p.bin.path, nil
}

// detachedInputs are the lab's own, in stateDir/bin.
func detachedInputs(ctx context.Context, root, stateDir string) (image, string, error) {
	t, img, err := prepareImage(ctx, root)
	if err != nil {
		return image{}, "", err
	}
	dir := filepath.Join(stateDir, "bin")
	return img, dir, buildTools(ctx, root, t, dir)
}

// up brings up a topology as the Compose project named project (which must
// start with ProjectPrefix), and returns once every node is running and
// sealed into the lab. A lab of this checkout left over under the same name
// is removed first; another checkout's lab under that name is an error. On
// error the returned Lab, if any, still needs Down. clock bounds each phase.
func up(ctx context.Context, clock startClock, root, project string, topo Topology, slotKey string, inputs labInputs) (*Lab, error) {
	if !strings.HasPrefix(project, ProjectPrefix) {
		return nil, fmt.Errorf("lab: project %q doesn't start with %q", project, ProjectPrefix)
	}
	if err := topo.Validate(); err != nil {
		return nil, err
	}
	stateDir := filepath.Join(root, "lab", ".run", project)
	var img image
	var binDir string
	var onDaemon []netip.Prefix
	err := clock.run(ctx, project, phaseBeforeSlot, func(ctx context.Context) (err error) {
		if img, binDir, err = beforeSlot(ctx, root, project, stateDir, inputs); err != nil {
			return err
		}
		// Read before the slot rather than holding one through it: under
		// load the daemon answers network reads behind every network it is
		// creating or removing, which took 20 s and more.
		from := time.Now()
		onDaemon, err = daemonSubnets.get(ctx, time.Time{})
		noteSubnetRead(project, from, time.Now(), err)
		if err != nil {
			return errors.Join(err, os.RemoveAll(stateDir))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	release, err := waitForSlot(ctx, clock, project, slotKey)
	if err != nil {
		return nil, errors.Join(err, os.RemoveAll(stateDir))
	}
	l := &Lab{
		Project:  project,
		Topology: topo,
		root:     root,
		stateDir: stateDir,
		binDir:   binDir,
		nodes:    map[string]*Node{},
		release:  release,
	}
	return l, clock.run(ctx, project, phaseAfterSlot, func(ctx context.Context) error {
		st := startTimes{slot: time.Now()}
		err := l.startOnSlot(ctx, img, onDaemon, &st)
		l.started = st
		noteStart(l, st, err)
		return err
	})
}

// startTimes marks the end of each step of a lab's start once it holds its
// slot, for the timeline (noteStart); a step that never ran stays zero.
type startTimes struct {
	slot, created, inspected, bridged, sealed time.Time
}

// startOnSlot creates the lab and seals its nodes; onDaemon is the
// daemon's subnets, as read before the slot.
func (l *Lab) startOnSlot(ctx context.Context, img image, onDaemon []netip.Prefix, st *startTimes) error {
	if err := l.create(ctx, img, onDaemon); err != nil {
		return err
	}
	st.created = time.Now()
	if err := l.inspect(ctx); err != nil {
		return err
	}
	st.inspected = time.Now()
	if err := l.learnBridges(ctx); err != nil {
		return err
	}
	st.bridged = time.Now()
	if err := l.configure(ctx); err != nil {
		return err
	}
	st.sealed = time.Now()
	return nil
}

// beforeSlot removes a leftover lab of the name and gets the lab's inputs.
// Until the lab is created nothing of it is up: on error its state
// directory goes, a detached lab's binaries with it.
func beforeSlot(ctx context.Context, root, project, stateDir string, inputs labInputs) (image, string, error) {
	if err := downProject(ctx, project, root); err != nil {
		return image{}, "", err
	}
	img, binDir, err := inputs(ctx, root, stateDir)
	if err != nil {
		return image{}, "", errors.Join(err, os.RemoveAll(stateDir))
	}
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return image{}, "", errors.Join(fmt.Errorf("lab: %w", err), os.RemoveAll(stateDir))
	}
	return img, binDir, nil
}

// create reserves the lab's subnets and starts it. Only the reservation is
// serialized host-wide (reserveSubnets); docker compose up runs outside the
// allocation lock, beside other labs' start-ups.
func (l *Lab) create(ctx context.Context, img image, onDaemon []netip.Prefix) error {
	pool, err := subnetPool()
	if err != nil {
		return err
	}
	dir, err := lockDir()
	if err != nil {
		return err
	}
	return createTries(ctx, onDaemon, daemonSubnets.get,
		func(ctx context.Context, used func(context.Context) ([]netip.Prefix, error)) (err error) {
			l.releaseSubnets()
			l.subnets, err = reserveSubnets(ctx, dir, l.Topology.Networks, pool, used)
			return err
		},
		func(ctx context.Context, attempt int) error {
			if err := l.composeUp(ctx, img, l.subnets, attempt); err != nil {
				return fmt.Errorf("lab %s: up: %w", l.Project, err)
			}
			return nil
		},
		func(ctx context.Context) error { return downProject(ctx, l.Project, l.root) })
}

// createTries is create's tries: reserve, then up. The first try avoids
// onDaemon, the daemon's subnets as read before the slot, and the live
// reservations, which cover every lab of the host's slots started since. A
// subnet another daemon user took in the meantime (an overlap from up)
// means another try after down, on a read that began after the overlap.
// onDaemon is as old as the slot wait: a pool it shows full gets one more
// try on a read that began after.
func createTries(ctx context.Context, onDaemon []netip.Prefix,
	read func(ctx context.Context, notBefore time.Time) ([]netip.Prefix, error),
	reserve func(ctx context.Context, used func(context.Context) ([]netip.Prefix, error)) error,
	up func(ctx context.Context, attempt int) error,
	down func(context.Context) error,
) error {
	var notBefore time.Time
	for attempt := 1; ; attempt++ {
		used := func(ctx context.Context) ([]netip.Prefix, error) {
			if attempt == 1 {
				return onDaemon, nil
			}
			return read(ctx, notBefore)
		}
		if err := reserve(ctx, used); err != nil {
			if attempt == 1 && errors.Is(err, errNoFreeSubnet) {
				notBefore = time.Now()
				continue
			}
			return err
		}
		err := up(ctx, attempt)
		if err == nil {
			return nil
		}
		if !isOverlap(err) || attempt == 5 {
			return err
		}
		notBefore = time.Now()
		if err := down(ctx); err != nil {
			return err
		}
	}
}

// composeUp starts the lab on r's subnets, and notes when in the timeline.
func (l *Lab) composeUp(ctx context.Context, img image, r *reservation, attempt int) error {
	file, err := renderCompose(l.Project, l.Topology, img, l.root, l.binDir, r.subnets)
	if err != nil {
		return err
	}
	if err := os.WriteFile(l.ComposeFile(), file, 0o644); err != nil {
		return err
	}
	from := time.Now()
	// No --wait: it polls the containers every half second after they
	// started; a node that died at once fails the sealing instead.
	_, err = runEnv(ctx, nil, environWithoutCompose(), "docker", "compose", "-f", l.ComposeFile(), "-p", l.Project, "up", "-d")
	l.upFrom, l.upTo, l.upAttempt = from, time.Now(), attempt
	noteTimeline(l.Project, attempt, r, from, l.upTo, err)
	return err
}

// ComposeFile is the generated Compose file, under lab/.run.
func (l *Lab) ComposeFile() string { return filepath.Join(l.stateDir, "compose.json") }

// Down removes the lab's containers and networks.
func (l *Lab) Down(ctx context.Context) error {
	defer l.releaseSlot()
	from := time.Now()
	err := downProject(ctx, l.Project, l.root)
	noteDown(l.Project, from, time.Now(), err)
	if err != nil {
		return err
	}
	l.releaseSubnets()
	return os.RemoveAll(l.stateDir)
}

// releaseSubnets gives up the lab's subnet reservation: its networks are
// gone, or stay on the daemon, which every allocation reads.
func (l *Lab) releaseSubnets() {
	l.subnets.release()
	l.subnets = nil
}

func (l *Lab) releaseSlot() {
	if l.release != nil {
		l.release()
		l.release = nil
	}
}

// Node returns a node of the lab's topology; an unknown name is a bug in the
// test and panics.
func (l *Lab) Node(name string) *Node {
	n, ok := l.nodes[name]
	if !ok {
		panic(fmt.Sprintf("lab %s: no node %q", l.Project, name))
	}
	return n
}

// DockerGateways are the addresses Docker gave its own bridge on a lab
// network. Every node has them blackholed: they are the way out of the lab.
func (l *Lab) DockerGateways(network string) []netip.Addr { return l.gateways[network] }

// DockerBridge is Docker's own end of a lab network, which every node is
// cut off from.
func (l *Lab) DockerBridge(network string) Bridge { return l.bridges[network] }

// Nodes lists the lab's nodes by name.
func (l *Lab) Nodes() []*Node {
	out := make([]*Node, 0, len(l.nodes))
	for _, n := range l.nodes {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

type inspectedContainer struct {
	ID     string
	Config struct {
		Labels map[string]string
	}
	NetworkSettings struct {
		Networks map[string]struct {
			IPAddress         string
			GlobalIPv6Address string
			MacAddress        string
		}
	}
}

// inspect learns each node's container and addresses, and each network's
// Docker gateway.
func (l *Lab) inspect(ctx context.Context) error {
	res, err := docker(ctx, "ps", "-a", "-q", "--filter", "label=com.docker.compose.project="+l.Project)
	if err != nil {
		return err
	}
	ids := strings.Fields(res.Stdout)
	if len(ids) == 0 {
		return fmt.Errorf("lab %s: no containers", l.Project)
	}
	res, err = docker(ctx, append([]string{"inspect"}, ids...)...)
	if err != nil {
		return err
	}
	var containers []inspectedContainer
	if err := json.Unmarshal([]byte(res.Stdout), &containers); err != nil {
		return fmt.Errorf("lab %s: docker inspect: %w", l.Project, err)
	}
	for _, c := range containers {
		name := c.Config.Labels["com.docker.compose.service"]
		n := &Node{Name: name, Container: c.ID, lab: l, addrs: map[string]NodeAddr{}}
		for key, net := range c.NetworkSettings.Networks {
			network := strings.TrimPrefix(key, l.Project+"_")
			var a NodeAddr
			a.IPv4, _ = netip.ParseAddr(net.IPAddress)
			a.IPv6, _ = netip.ParseAddr(net.GlobalIPv6Address)
			a.mac = strings.ToLower(net.MacAddress)
			n.addrs[network] = a
		}
		l.nodes[name] = n
	}
	for _, n := range l.Topology.Nodes {
		if _, ok := l.nodes[n.Name]; !ok {
			return fmt.Errorf("lab %s: node %q has no container", l.Project, n.Name)
		}
	}

	args := []string{"network", "inspect", "--format", "{{.Name}} {{range .IPAM.Config}}{{.Gateway}} {{end}}"}
	for _, net := range l.Topology.Networks {
		args = append(args, l.Project+"_"+net.Name)
	}
	res, err = docker(ctx, args...)
	if err != nil {
		return err
	}
	l.gateways, err = parseGateways(l.Project, res.Stdout)
	return err
}

// parseGateways reads one docker network inspect of a lab's networks, a
// line of name and gateways per network, into gateways by network.
func parseGateways(project, out string) (map[string][]netip.Addr, error) {
	gateways := map[string][]netip.Addr{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		network, ok := strings.CutPrefix(f[0], project+"_")
		if !ok {
			return nil, fmt.Errorf("lab %s: docker network inspect: unexpected network %q", project, f[0])
		}
		for _, s := range f[1:] {
			s, _, _ = strings.Cut(s, "/")
			if a, err := netip.ParseAddr(s); err == nil {
				gateways[network] = append(gateways[network], a)
			}
		}
	}
	return gateways, nil
}

// learnBridges finds each network's bridge MAC from a node on it, before
// any node is sealed: the bridge answers ARP for the network's gateway
// address. The MAC also gives the bridge's link-local address. Networks
// are asked all at once.
func (l *Lab) learnBridges(ctx context.Context) error {
	bridges := make([]Bridge, len(l.Topology.Networks))
	errs := make([]error, len(l.Topology.Networks))
	var wg sync.WaitGroup
	for i, net := range l.Topology.Networks {
		wg.Go(func() { bridges[i], errs[i] = l.learnBridge(ctx, net) })
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		return err
	}
	l.bridges = map[string]Bridge{}
	for i, net := range l.Topology.Networks {
		l.bridges[net.Name] = bridges[i]
	}
	return nil
}

// learnBridge is learnBridges for one network.
func (l *Lab) learnBridge(ctx context.Context, network Network) (Bridge, error) {
	var b Bridge
	for _, gw := range l.gateways[network.Name] {
		if gw.Is4() {
			b.IPv4 = gw
		} else {
			b.IPv6 = gw
		}
	}
	if !b.IPv4.IsValid() {
		return b, fmt.Errorf("lab %s: network %s has no IPv4 gateway", l.Project, network.Name)
	}
	i := slices.IndexFunc(l.Topology.Nodes, func(n NodeSpec) bool { return slices.Contains(n.Networks, network.Name) })
	if i < 0 {
		return b, nil
	}
	n := l.nodes[l.Topology.Nodes[i].Name]
	res, err := n.Exec(ctx, "sh", "-c", `ping -c 1 -W 1 "$0" >/dev/null 2>&1; ip -j neigh show "$0"`, b.IPv4.String())
	if err != nil {
		return b, fmt.Errorf("lab %s: network %s: %w", l.Project, network.Name, err)
	}
	var neigh []struct {
		LLAddr string `json:"lladdr"`
	}
	if err := json.Unmarshal([]byte(res.Stdout), &neigh); err != nil || len(neigh) == 0 || neigh[0].LLAddr == "" {
		return b, fmt.Errorf("lab %s: network %s: no MAC for the bridge at %s: %q", l.Project, network.Name, b.IPv4, res.Stdout)
	}
	b.MAC = strings.ToLower(neigh[0].LLAddr)
	b.LinkLocal, err = linkLocalFromMAC(b.MAC)
	return b, err
}

// linkLocalFromMAC is the EUI-64 link-local address Linux gives an
// interface with this MAC.
func linkLocalFromMAC(mac string) (netip.Addr, error) {
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) != 6 {
		return netip.Addr{}, fmt.Errorf("lab: bad MAC %q", mac)
	}
	a := [16]byte{0: 0xfe, 1: 0x80}
	copy(a[8:], []byte{hw[0] ^ 2, hw[1], hw[2], 0xff, 0xfe, hw[3], hw[4], hw[5]})
	return netip.AddrFrom16(a), nil
}

// sealedMarker is written once a node is sealed; a node's Command waits for
// it (see renderCompose).
const sealedMarker = "/run/lab/sealed"

// configure seals every node into the lab (see configureNode), all at once.
func (l *Lab) configure(ctx context.Context) error {
	var wg sync.WaitGroup
	errs := make([]error, len(l.Topology.Nodes))
	for i, spec := range l.Topology.Nodes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := l.configureNode(ctx, spec); err != nil {
				errs[i] = fmt.Errorf("lab %s: node %s: %w", l.Project, spec.Name, err)
			}
		}()
	}
	wg.Wait()
	return errors.Join(errs...)
}

// configureNode seals a node into the lab, replacing what Docker set up to
// connect a container to the outside. The default routes go (a gateway
// node's take their place). Docker's bridge, the Docker VM's end of every
// lab network, becomes unreachable: its addresses are blackholed, and
// nftables drops every frame to or from its MAC, which also covers its
// link-local address. DNS points at nothing (Docker's resolver, asked
// directly, forwards to DeadEndNameserver from the node, where the routes stop
// it); lab nodes find each other through /etc/hosts.
// /proc/sys/net becomes writable, so tests and thinkpol can set network
// sysctls in the node and its namespaces without the rest of /proc/sys.
// Last, the marker that lets the node's Command start.
func (l *Lab) configureNode(ctx context.Context, spec NodeSpec) error {
	n := l.nodes[spec.Name]
	res, err := n.Exec(ctx, "ip", "-j", "link", "show")
	if err != nil {
		return err
	}
	var links []struct {
		Index   int    `json:"ifindex"`
		Name    string `json:"ifname"`
		Address string `json:"address"`
	}
	if err := json.Unmarshal([]byte(res.Stdout), &links); err != nil {
		return fmt.Errorf("ip -j link: %w", err)
	}
	n.ifaces = map[int]string{}
	n.ifnames = map[string]string{}
	for network, a := range n.addrs {
		for _, link := range links {
			if a.mac != "" && strings.EqualFold(link.Address, a.mac) {
				n.ifaces[link.Index] = network
				n.ifnames[network] = link.Name
			}
		}
	}

	var script strings.Builder
	script.WriteString("while ip -4 route del default 2>/dev/null; do :; done\n")
	script.WriteString("while ip -6 route del default 2>/dev/null; do :; done\n")
	for _, net := range spec.Networks {
		b, ifname := l.bridges[net], n.ifnames[net]
		if ifname == "" {
			return fmt.Errorf("no interface for network %s", net)
		}
		fmt.Fprintf(&script, "ip -4 route add blackhole %s/32\n", b.IPv4)
		if b.IPv6.IsValid() {
			fmt.Fprintf(&script, "ip -6 route add blackhole %s/128\n", b.IPv6)
		}
		fmt.Fprintf(&script, "nft -f - <<'EOF'\ntable netdev tplab_%[1]s {\n"+
			"  chain in { type filter hook ingress device %[1]q priority -500; ether saddr %[2]s drop; }\n"+
			"  chain out { type filter hook egress device %[1]q priority -500; ether daddr %[2]s drop; }\n"+
			"}\nEOF\n", ifname, b.MAC)
	}
	if spec.Gateway != "" {
		gw := l.Topology.Nodes[l.Topology.nodeIndex(spec.Gateway)]
		addr := l.nodes[gw.Name].addrs[sharedNetwork(spec, gw)]
		fmt.Fprintf(&script, "ip -4 route add default via %s\n", addr.IPv4)
		if addr.IPv6.IsValid() {
			fmt.Fprintf(&script, "ip -6 route add default via %s\n", addr.IPv6)
		}
	}
	script.WriteString("printf 'nameserver 127.0.0.1\\noptions timeout:1 attempts:1\\n' > /etc/resolv.conf\n")
	fmt.Fprintf(&script, "cat > /etc/hosts <<'EOF'\n%sEOF\n", l.hostsFor(spec))
	script.WriteString("mount --bind /proc/sys/net /proc/sys/net && mount -o remount,bind,rw /proc/sys/net\n")
	fmt.Fprintf(&script, "mkdir -p %s && touch %s\n", path.Dir(sealedMarker), sealedMarker)
	if spec.Systemd {
		// Kept for the node's next start, which runs it before systemd.
		fmt.Fprintf(&script, "mkdir -p %s && cat > %s <<'SEAL' && chmod 700 %[2]s\n#!/bin/sh\nset -e\n%sSEAL\n",
			path.Dir(sealScript), sealScript, script.String())
	}
	_, err = n.Exec(ctx, "sh", "-ec", script.String())
	return err
}

// checkSealed checks from inside a node that it is sealed as
// configureNode left it, for a node that sealed itself again on a restart
// rather than trusting Docker to give back what it had: its addresses the
// ones the lab knows (other nodes' /etc/hosts name them), each network's
// frame filter and blackholed bridge, and no default route but the
// gateway's.
func (l *Lab) checkSealed(ctx context.Context, n *Node) error {
	spec := l.Topology.Nodes[l.Topology.nodeIndex(n.Name)]
	var problems []string
	routes, err := n.Exec(ctx, "sh", "-c", "ip -4 route show; ip -6 route show")
	if err != nil {
		return err
	}
	for _, net := range spec.Networks {
		a, ifname, b := n.addrs[net], n.ifnames[net], l.bridges[net]
		// Each address on its own interface: the filters below are per
		// interface, so interfaces that swapped would leave them on the
		// wrong network.
		addrs, err := n.Exec(ctx, "ip", "-o", "addr", "show", "dev", ifname)
		if err != nil {
			return err
		}
		if !strings.Contains(addrs.Stdout, " "+a.IPv4.String()+"/") || a.IPv6.IsValid() && !strings.Contains(addrs.Stdout, " "+a.IPv6.String()+"/") {
			problems = append(problems, fmt.Sprintf("%s: %s is not at %s, %s any more", net, ifname, a.IPv4, a.IPv6))
		}
		if _, err := n.Exec(ctx, "nft", "list", "table", "netdev", "tplab_"+ifname); err != nil {
			problems = append(problems, fmt.Sprintf("%s: no frame filter tplab_%s", net, ifname))
		}
		for _, br := range []netip.Addr{b.IPv4, b.IPv6} {
			if br.IsValid() && !strings.Contains(routes.Stdout, "blackhole "+br.String()+" ") && !strings.Contains(routes.Stdout, "blackhole "+br.String()+"\n") {
				problems = append(problems, fmt.Sprintf("%s: the bridge %s isn't blackholed", net, br))
			}
		}
	}
	var want []string
	if spec.Gateway != "" {
		gw := l.Topology.Nodes[l.Topology.nodeIndex(spec.Gateway)]
		addr := l.nodes[gw.Name].addrs[sharedNetwork(spec, gw)]
		want = append(want, "default via "+addr.IPv4.String()+" ")
		if addr.IPv6.IsValid() {
			want = append(want, "default via "+addr.IPv6.String()+" ")
		}
	}
	for _, line := range strings.Split(routes.Stdout, "\n") {
		if !strings.HasPrefix(line, "default ") {
			continue
		}
		if !slices.ContainsFunc(want, func(w string) bool { return strings.HasPrefix(line, w) }) {
			problems = append(problems, "a default route that isn't the gateway's: "+line)
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("%s: not sealed after its restart: %s", n.Name, strings.Join(problems, "; "))
	}
	return nil
}

// hostsFor is reader's /etc/hosts: every node by name, at its address on the
// first network it shares with reader, or else on its first network.
func (l *Lab) hostsFor(reader NodeSpec) string {
	var b strings.Builder
	b.WriteString("127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n")
	for _, other := range l.Topology.Nodes {
		net := sharedNetwork(other, reader)
		if net == "" {
			net = other.Networks[0]
		}
		a := l.nodes[other.Name].addrs[net]
		for _, ip := range []netip.Addr{a.IPv4, a.IPv6} {
			if ip.IsValid() {
				fmt.Fprintf(&b, "%s\t%s\n", ip, other.Name)
			}
		}
	}
	return b.String()
}
