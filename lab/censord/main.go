// Command censord is the lab's censor, run in the router container: nftables
// hands it every forwarded packet through an NFQUEUE, its modules decide,
// and it writes every decision to the verdict log. A test starts it with a
// config that picks the modules and reads the log back.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab/censor"
)

var configPath = flag.String("config", "", "the censor's JSON config")

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)
	flag.Parse()
	if *configPath == "" {
		log.Fatal("censord: no -config")
	}
	b, err := os.ReadFile(*configPath)
	if err != nil {
		log.Fatalf("censord: %v", err)
	}
	var cfg censor.Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		log.Fatalf("censord: %s: %v", *configPath, err)
	}
	passives, actives, err := censor.Build(cfg)
	if err != nil {
		log.Fatalf("censord: %v", err)
	}

	var verdicts *os.File
	if cfg.Log != "" {
		if verdicts, err = os.Create(cfg.Log); err != nil {
			log.Fatalf("censord: %v", err)
		}
		defer verdicts.Close()
	}
	names := make([]string, 0, len(passives)+len(actives))
	for _, m := range passives {
		names = append(names, m.Name())
	}
	for _, m := range actives {
		names = append(names, m.Name())
	}
	log.Printf("censord: starting: queue=%d modules=%v", cfg.Queue, names)

	eng := censor.NewEngine(passives, actives, verdicts)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := censor.Run(ctx, cfg, eng); err != nil {
		log.Fatalf("censord: %v", err)
	}
	log.Printf("censord: stopped")
}
