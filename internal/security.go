package internal

import (
	"context"
	"log"
	"log/slog"
	"net"
	"net/netip"
	"sync"

	"github.com/ozraru/v4v6tlsproxy/internal/logw"
)

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
		for _, rule := range Config.AllowRule.IPv4Addr {
			if rule.Contains(record) {
				return true
			}
		}
	}
	return false
}

func IsDenied(addr *net.IPAddr) bool {
	ipnetAddr, ok := netip.AddrFromSlice(addr.IP)
	if !ok {
		log.Panic("Failed to convert remote ip")
	}
	for _, rule := range Config.DenyRule.IPv6Addr {
		if rule.Contains(ipnetAddr) {
			return true
		}
	}
	return false
}

var whitelistCache = make(map[string]bool)
var whitelistCacheMutex = &sync.RWMutex{}

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
