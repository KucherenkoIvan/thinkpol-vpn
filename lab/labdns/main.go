// Command labdns is a lab resolver that stands in for one out in the
// world (a domestic ISP's, an exit's upstream): it answers every A and
// AAAA question with fixed addresses, so an answer tells which resolver it
// came from, and prints every question it gets with its source, so a test
// can tell who asked what. With -server it is instead a client that asks
// one A question of a resolver and prints its answers. Lab use only: a
// real node never logs names.
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

// ask sends one A question to the server and prints the answers'
// addresses, one per line; a missing answer (NXDOMAIN, SERVFAIL, no A
// records) exits non-zero.
func ask(server, name string) {
	m := new(dns.Msg)
	m.SetQuestion(dns.CanonicalName(name), dns.TypeA)
	c := &dns.Client{Timeout: 5 * time.Second}
	resp, _, err := c.Exchange(m, server)
	if err != nil {
		log.Fatal(err)
	}
	var answers []string
	for _, rr := range resp.Answer {
		if rec, ok := rr.(*dns.A); ok {
			answers = append(answers, rec.A.String())
		}
	}
	if len(answers) == 0 {
		fmt.Printf("rcode %s\n", dns.RcodeToString[resp.Rcode])
		os.Exit(1)
	}
	for _, answer := range answers {
		fmt.Println(answer)
	}
}
