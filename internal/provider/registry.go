package provider

import (
	"fmt"
	"sync"
)

var (
	mu        sync.RWMutex
	providers = make(map[string]Provider)
)

func Register(p Provider) {
	mu.Lock()
	defer mu.Unlock()
	info := p.Info()
	providers[info.ID] = p
}

func Get(id string) (Provider, error) {
	mu.RLock()
	defer mu.RUnlock()
	p, ok := providers[id]
	if !ok {
		return nil, fmt.Errorf("provider %q not registered", id)
	}
	return p, nil
}

func List() []ProviderInfo {
	mu.RLock()
	defer mu.RUnlock()
	result := make([]ProviderInfo, 0, len(providers))
	for _, p := range providers {
		result = append(result, p.Info())
	}
	return result
}
