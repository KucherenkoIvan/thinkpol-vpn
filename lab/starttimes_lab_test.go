//go:build lab

package lab

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// StartTimesEnv, set to n, has TestLabStartTimes start n labs of each
// topology it measures; StartTimesParallelEnv, set to k, starts them k at
// once (default 1, one after another).
const (
	StartTimesEnv         = "THINKPOL_LAB_START_TIMES"
	StartTimesParallelEnv = "THINKPOL_LAB_START_TIMES_PARALLEL"
)

// TestLabStartTimes measures lab starts rather than testing anything: for
// a gotest node (1 node), a censor matrix row's lab (4) and lab.Upstream()
// (7), it starts StartTimesEnv labs each and logs every start's steps from
// its slot to the sealed lab and how docker compose up spent its time by
// Docker's own events (networks created, containers created and started,
// counted from when up began), then the median of each.
// Without StartTimesEnv it skips. THINKPOL_LAB_TIMELINE gets the same
// starts' lines.
func TestLabStartTimes(t *testing.T) {
	n, _ := strconv.Atoi(os.Getenv(StartTimesEnv))
	if n <= 0 {
		t.Skip(StartTimesEnv + " is not set: nothing to measure")
	}
	par, _ := strconv.Atoi(os.Getenv(StartTimesParallelEnv))
	par = max(par, 1)
	topos := []struct {
		name string
		topo Topology
	}{
		{"gotest", GoTestTopology()},
		{"matrix-row", Upstream().Only(Router, DeviceA, Server1, Camouflage)},
		{"upstream", Upstream()},
	}
	for _, tc := range topos {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var all []startSample
			for batch := 0; batch*par < n; batch++ {
				t.Run(fmt.Sprintf("batch-%d", batch), func(t *testing.T) {
					for i := batch * par; i < min((batch+1)*par, n); i++ {
						t.Run(fmt.Sprintf("start-%d", i), func(t *testing.T) {
							t.Parallel()
							s := measureStart(t, tc.topo)
							t.Log(s)
							mu.Lock()
							all = append(all, s)
							mu.Unlock()
						})
					}
				})
			}
			t.Logf("%s: %d starts, %d at once; medians: %s", tc.name, len(all), par, medianSample(all))
		})
	}
}

// startSample is one lab start, each field counted from when its slot was
// held.
type startSample struct {
	sealed, created, inspected, bridged time.Duration
	// Within docker compose up, from when it began: the last network
	// created, the first and last container created and started, and up's
	// return.
	netsCreated, firstCreated, lastCreated, firstStarted, lastStarted, upDone time.Duration
}

func (s startSample) String() string {
	return fmt.Sprintf("sealed %v (created %v, inspected %v, bridged %v); up: networks %v, containers created %v..%v, started %v..%v, returned %v",
		ms(s.sealed), ms(s.created), ms(s.inspected), ms(s.bridged),
		ms(s.netsCreated), ms(s.firstCreated), ms(s.lastCreated), ms(s.firstStarted), ms(s.lastStarted), ms(s.upDone))
}

func ms(d time.Duration) time.Duration { return d.Round(10 * time.Millisecond) }

func medianSample(all []startSample) startSample {
	med := func(f func(startSample) time.Duration) time.Duration {
		if len(all) == 0 {
			return 0
		}
		ds := make([]time.Duration, len(all))
		for i, s := range all {
			ds[i] = f(s)
		}
		slices.Sort(ds)
		return ds[len(ds)/2]
	}
	return startSample{
		sealed:       med(func(s startSample) time.Duration { return s.sealed }),
		created:      med(func(s startSample) time.Duration { return s.created }),
		inspected:    med(func(s startSample) time.Duration { return s.inspected }),
		bridged:      med(func(s startSample) time.Duration { return s.bridged }),
		netsCreated:  med(func(s startSample) time.Duration { return s.netsCreated }),
		firstCreated: med(func(s startSample) time.Duration { return s.firstCreated }),
		lastCreated:  med(func(s startSample) time.Duration { return s.lastCreated }),
		firstStarted: med(func(s startSample) time.Duration { return s.firstStarted }),
		lastStarted:  med(func(s startSample) time.Duration { return s.lastStarted }),
		upDone:       med(func(s startSample) time.Duration { return s.upDone }),
	}
}

// measureStart starts one lab of topo, reads Docker's events for its
// docker compose up. Its tear-down, when the test ends, is in the
// timeline (noteDown).
func measureStart(t *testing.T, topo Topology) startSample {
	l := StartOwnSlot(t, topo)
	st := l.started
	s := startSample{
		sealed:    st.sealed.Sub(st.slot),
		created:   st.created.Sub(st.slot),
		inspected: st.inspected.Sub(st.slot),
		bridged:   st.bridged.Sub(st.slot),
		upDone:    l.upTo.Sub(l.upFrom),
	}
	stamp := func(at time.Time) string { return strconv.FormatFloat(float64(at.UnixNano())/1e9, 'f', 3, 64) }
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	res, err := docker(ctx, "events", "--since", stamp(l.upFrom.Add(-time.Second)), "--until", stamp(l.upTo.Add(time.Second)), "--format", "{{json .}}")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(res.Stdout), "\n") {
		var e struct {
			Type, Action string
			Actor        struct{ Attributes map[string]string }
			TimeNano     int64 `json:"timeNano"`
		}
		if line == "" || json.Unmarshal([]byte(line), &e) != nil {
			continue
		}
		name := e.Actor.Attributes["name"]
		if !strings.HasPrefix(name, l.Project+"_") && !strings.HasPrefix(name, l.Project+"-") {
			continue
		}
		at := time.Unix(0, e.TimeNano).Sub(l.upFrom)
		first := func(d *time.Duration) {
			if *d == 0 || at < *d {
				*d = at
			}
		}
		last := func(d *time.Duration) { *d = max(*d, at) }
		switch e.Type + " " + e.Action {
		case "network create":
			last(&s.netsCreated)
		case "container create":
			first(&s.firstCreated)
			last(&s.lastCreated)
		case "container start":
			first(&s.firstStarted)
			last(&s.lastStarted)
		}
	}
	return s
}
