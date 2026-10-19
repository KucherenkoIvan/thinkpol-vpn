// Command labdns is a lab resolver that stands in for one out in the
// world (a domestic ISP's, an exit's upstream): it answers every A and
// AAAA question with fixed addresses, so an answer tells which resolver it
// came from, and prints every question it gets with its source, so a test
// can tell who asked what. With -server it is instead a client that asks
// one A question of -query and prints the reply's rcode (with ` aa` when
// authoritative). Lab use only: a real node never logs names.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

func main() {
	listen := flag.String("listen", ":53", "address to serve on, UDP and TCP")
	a := flag.String("a", "", "the address of every A answer")
	aaaa := flag.String("aaaa", "", "the address of every AAAA answer")
	server := flag.String("server", "", "client mode: ask this server (host:port) one A question for -query and exit")
	query := flag.String("query", "", "the name the client asks (with -server)")
	flag.Parse()
	if (*server == "") != (*query == "") {
		log.Fatal("-server and -query go together")
	}
	if *server != "" {
		ask(*server, *query)
		return
	}
	var answer4, answer6 netip.Addr
	if *a != "" {
		answer4 = netip.MustParseAddr(*a)
	}
	if *aaaa != "" {
		answer6 = netip.MustParseAddr(*aaaa)
	}
	var mu sync.Mutex
	h := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.RecursionAvailable = true
		if len(r.Question) == 1 {
			q := r.Question[0]
			mu.Lock()
			fmt.Printf("query %s %s from %s over %s\n", strings.ToLower(q.Name), dns.TypeToString[q.Qtype], w.RemoteAddr(), w.RemoteAddr().Network())
			_ = os.Stdout.Sync()
			mu.Unlock()
			hdr := dns.RR_Header{Name: q.Name, Rrtype: q.Qtype, Class: dns.ClassINET, Ttl: 60}
			switch {
			case q.Qtype == dns.TypeA && answer4.IsValid():
				m.Answer = append(m.Answer, &dns.A{Hdr: hdr, A: net.IP(answer4.AsSlice())})
			case q.Qtype == dns.TypeAAAA && answer6.IsValid():
				m.Answer = append(m.Answer, &dns.AAAA{Hdr: hdr, AAAA: net.IP(answer6.AsSlice())})
			}
		}
		_ = w.WriteMsg(m)
	})
	errs := make(chan error, 2)
	for _, network := range []string{"udp", "tcp"} {
		srv := &dns.Server{Addr: *listen, Net: network, Handler: h}
		srv.NotifyStartedFunc = func() { fmt.Printf("listening on %s/%s\n", *listen, network) }
		go func() { errs <- srv.ListenAndServe() }()
	}
	log.Fatal(<-errs)
}

// ask exits non-zero only when no reply arrives.
func ask(server, name string) {
	m := new(dns.Msg)
	m.SetQuestion(dns.CanonicalName(name), dns.TypeA)
	c := &dns.Client{Timeout: 5 * time.Second}
	resp, _, err := c.Exchange(m, server)
	if err != nil {
		log.Fatal(err)
	}
	rc := dns.RcodeToString[resp.Rcode]
	if resp.Authoritative {
		rc += " aa"
	}
	fmt.Println(rc)
}
