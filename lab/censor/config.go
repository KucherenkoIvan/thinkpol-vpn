package censor

import (
	"encoding/json"
	"fmt"
	"sync"
)

// Config is what censord starts with. A test picks the modules by writing
// the config and starting censord with it.
type Config struct {
	// Queue is the NFQUEUE number the router's queue rule sends to.
	Queue uint16 `json:"queue"`
	// Log is the path of the verdict log, "" for none.
	Log     string         `json:"log"`
	Modules []ModuleConfig `json:"modules"`
}

// ModuleConfig names one module and carries its own settings.
type ModuleConfig struct {
	Name     string          `json:"name"`
	Settings json.RawMessage `json:"settings"`
}

var (
	registryMu sync.Mutex
	passives   = map[string]func(json.RawMessage) (Passive, error){}
	actives    = map[string]func(json.RawMessage) (Active, error){}
)

// RegisterPassive makes a passive module buildable from config. It is
// called from init; a second module of a name is a bug and panics.
func RegisterPassive(name string, build func(settings json.RawMessage) (Passive, error)) {
	register(&registryMu, passives, name, build)
}

// RegisterActive makes an active module buildable from config.
func RegisterActive(name string, build func(settings json.RawMessage) (Active, error)) {
	register(&registryMu, actives, name, build)
}

func register[T any](mu *sync.Mutex, into map[string]func(json.RawMessage) (T, error), name string, build func(json.RawMessage) (T, error)) {
	mu.Lock()
	defer mu.Unlock()
	if name == "" {
		panic("censor: module with no name")
	}
	if _, dup := into[name]; dup {
		panic(fmt.Sprintf("censor: module %q registered twice", name))
	}
	into[name] = build
}

// Build builds the config's modules. An unknown name is an error: a test
// asking for a censor that does not exist must not silently censor less.
func Build(cfg Config) (builtPassives []Passive, builtActives []Active, err error) {
	registryMu.Lock()
	defer registryMu.Unlock()
	for _, mc := range cfg.Modules {
		if build, ok := passives[mc.Name]; ok {
			m, err := build(mc.Settings)
			if err != nil {
				return nil, nil, fmt.Errorf("censor: module %s: %w", mc.Name, err)
			}
			builtPassives = append(builtPassives, m)
		} else if build, ok := actives[mc.Name]; ok {
			m, err := build(mc.Settings)
			if err != nil {
				return nil, nil, fmt.Errorf("censor: module %s: %w", mc.Name, err)
			}
			builtActives = append(builtActives, m)
		} else {
			return nil, nil, fmt.Errorf("censor: no module %q", mc.Name)
		}
	}
	return builtPassives, builtActives, nil
}
