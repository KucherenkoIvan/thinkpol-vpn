package dns

import (
	"container/list"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	// maxCachedSize skips caching answers larger than this, packed, so
	// the cache stays within a few megabytes.
	maxCachedSize = 4096
	// maxTTL and maxNegativeTTL cap how long an answer is kept, and
	// negativeTTL is a negative answer's without an SOA to say.
	maxTTL         = time.Hour
	maxNegativeTTL = 5 * time.Minute
	negativeTTL    = 30 * time.Second
)

// cacheKey is one question asked by one route: a direct upstream's answer
// is never served for a name that goes through the tunnel.
type cacheKey struct {
	name          string
	qtype, qclass uint16
	do, cd        bool
	route         string
}

type cached struct {
	key     cacheKey
	msg     *dns.Msg
	stored  time.Time
	expires time.Time
}

// cache is a bounded LRU cache of answers.
type cache struct {
	mu    sync.Mutex
	size  int
	order *list.List // front: most recently used
	items map[cacheKey]*list.Element
}

func newCache(size int) *cache {
	return &cache{size: size, order: list.New(), items: map[cacheKey]*list.Element{}}
}

func (c *cache) flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.order.Init()
	clear(c.items)
}

// get returns a copy of the cached answer with its TTLs aged.
func (c *cache) get(k cacheKey, now time.Time) (*dns.Msg, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.items[k]
	if !ok {
		return nil, false
	}
	it := e.Value.(*cached)
	if !now.Before(it.expires) {
		c.order.Remove(e)
		delete(c.items, k)
		return nil, false
	}
	c.order.MoveToFront(e)
	m := it.msg.Copy()
	age := uint32(now.Sub(it.stored) / time.Second)
	for _, section := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range section {
			if h := rr.Header(); h.Rrtype != dns.TypeOPT {
				h.Ttl -= min(h.Ttl, age)
			}
		}
	}
	return m, true
}

func (c *cache) put(k cacheKey, m *dns.Msg, now time.Time) {
	if c.size == 0 || m.Truncated || m.Rcode != dns.RcodeSuccess && m.Rcode != dns.RcodeNameError || m.Len() > maxCachedSize {
		return
	}
	ttl := cacheTTL(m)
	if ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.items[k]; ok {
		c.order.Remove(e)
		delete(c.items, k)
	}
	c.items[k] = c.order.PushFront(&cached{key: k, msg: m.Copy(), stored: now, expires: now.Add(ttl)})
	for c.order.Len() > c.size {
		e := c.order.Back()
		c.order.Remove(e)
		delete(c.items, e.Value.(*cached).key)
	}
}

// cacheTTL is how long an answer may be kept: the lowest TTL of its
// records, or for a negative answer its SOA's (RFC 2308), capped.
func cacheTTL(m *dns.Msg) time.Duration {
	negative := m.Rcode == dns.RcodeNameError || len(m.Answer) == 0
	if negative {
		for _, rr := range m.Ns {
			if soa, ok := rr.(*dns.SOA); ok {
				return min(time.Duration(min(soa.Minttl, soa.Hdr.Ttl))*time.Second, maxNegativeTTL)
			}
		}
		return negativeTTL
	}
	lowest := uint32(1<<32 - 1)
	for _, rr := range m.Answer {
		lowest = min(lowest, rr.Header().Ttl)
	}
	return min(time.Duration(lowest)*time.Second, maxTTL)
}
