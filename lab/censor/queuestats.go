package censor

import (
	"fmt"
	"strconv"
	"strings"
)

// QueueStats is one queue's line of /proc/net/netfilter/nfnetlink_queue,
// the kernel's account of what it lost on the way to censord.
type QueueStats struct {
	// Waiting is how many packets wait for a verdict now.
	Waiting uint64
	// QueueDropped counts packets dropped because the queue was full.
	QueueDropped uint64
	// UserDropped counts packets netlink failed to deliver to censord.
	UserDropped uint64
}

// ParseQueueStats finds queue's line in the contents of
// /proc/net/netfilter/nfnetlink_queue, whose columns are queue_number,
// peer_portid, queue_total, copy_mode, copy_range, queue_dropped,
// user_dropped, id_sequence and a constant 1.
func ParseQueueStats(proc string, queue uint16) (QueueStats, error) {
	for _, line := range strings.Split(proc, "\n") {
		f := strings.Fields(line)
		if len(f) < 7 || f[0] != strconv.Itoa(int(queue)) {
			continue
		}
		var n [3]uint64
		for i, col := range []int{2, 5, 6} {
			v, err := strconv.ParseUint(f[col], 10, 64)
			if err != nil {
				return QueueStats{}, fmt.Errorf("nfnetlink_queue line %q: %w", line, err)
			}
			n[i] = v
		}
		return QueueStats{Waiting: n[0], QueueDropped: n[1], UserDropped: n[2]}, nil
	}
	return QueueStats{}, fmt.Errorf("queue %d not in nfnetlink_queue", queue)
}
