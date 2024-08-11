package internal

import (
	"context"
	"log/slog"
	"net"
	"sync"

	"github.com/ozraru/v4v6tlsproxy/internal/logw"
)

var whitelistCache = make(map[string]bool)
var whitelistCacheMutex = &sync.RWMutex{}

func IsAllowed(ctx context.Context, name string) bool {
	if isWhitelisted(name) {
		logw.Get(ctx).Debug("Whitelisted: ", slog.Any("name", name))
		return true
	}

	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", name)
	if err != nil {
		logw.Get(ctx).Warn("Failed to lookup host: ", slog.Any("error", err))
		return false
	}

	for _, record := range addrs {
		for _, self := range Config.AllowRule.IPv4Addr {
			if self.Contains(record) {
				return true
			}
		}
	}
	return false
}

func IsWhitelisted(name string) bool {
	whitelistCacheMutex.RLock()
	if entry, ok := whitelistCache[name]; ok {
		whitelistCacheMutex.RUnlock()
		return entry
	}
	whitelistCacheMutex.RUnlock()

	whitelistCacheMutex.Lock()
	defer whitelistCacheMutex.Unlock()

	whitelistCache[name] = isWhitelisted(name)

	return whitelistCache[name]
}

func isWhitelisted(name string) bool {
	if _, ok := Config.AllowRule.DomainWhitelist.Plain[name]; ok {
		return true
	}
	for _, v := range Config.AllowRule.DomainWhitelist.Regex {
		if v.MatchString(name) {
			return true
		}
	}
	return false
}
