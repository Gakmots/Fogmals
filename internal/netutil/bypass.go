package netutil

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"time"
)

var localNetworks = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("fec0::/10"),
}

// LocalIP is a routing rule, distinct from CCIP's stricter PublicIP allowlist.
// Reserved documentation/benchmark ranges are not automatically local routes.
func LocalIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() {
		return false
	}
	if !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return true
	}
	for _, prefix := range localNetworks {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

type lookupIPs func(context.Context, string, string) ([]netip.Addr, error)

func interfaceIPs() map[netip.Addr]bool {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		// Restricted containers may forbid interface enumeration. Standard
		// local/private ranges and local DNS classification still work.
		return nil
	}
	ips := make(map[netip.Addr]bool, len(addresses))
	for _, address := range addresses {
		if prefix, err := netip.ParsePrefix(address.String()); err == nil {
			ips[prefix.Addr().Unmap().WithZone("")] = true
		}
	}
	return ips
}

func localName(host string) bool {
	if !strings.Contains(host, ".") { // Single-label hosts use local search domains.
		return true
	}
	for _, suffix := range []string{"localhost", "local", "lan", "internal", "home.arpa"} {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}

// bypassLocal selects a route before dialing. A locally resolved private address
// is pinned, avoiding a second DNS lookup that could change the destination.
func bypassLocal(direct, proxy DialContextFunc, lookup lookupIPs, interfaces map[netip.Addr]bool) DialContextFunc {
	isLocal := func(ip netip.Addr) bool { return LocalIP(ip) || interfaces[ip.Unmap().WithZone("")] }
	return func(ctx context.Context, network, target string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(target)
		if err != nil {
			return nil, err
		}
		if ip, err := netip.ParseAddr(host); err == nil {
			if isLocal(ip) {
				return direct(ctx, network, target)
			}
			return proxy(ctx, network, target)
		}
		name := strings.TrimSuffix(strings.ToLower(host), ".")
		var addresses []netip.Addr
		if name == "localhost" || strings.HasSuffix(name, ".localhost") {
			addresses = []netip.Addr{netip.IPv6Loopback(), netip.MustParseAddr("127.0.0.1")}
		} else if localName(name) {
			return direct(ctx, network, target)
		} else {
			resolve, cancel := context.WithTimeout(ctx, 5*time.Second)
			ips, err := lookup(resolve, "ip", host)
			cancel()
			if ctx.Err() != nil {
				return nil, context.Cause(ctx)
			}
			if err == nil {
				for _, ip := range ips {
					if isLocal(ip) {
						addresses = append(addresses, ip.Unmap())
					}
				}
			}
		}
		if len(addresses) == 0 {
			// Public or remote-only names retain proxy-side DNS. A DNS failure
			// never creates a direct route to an otherwise unknown destination.
			return proxy(ctx, network, target)
		}
		for _, ip := range addresses {
			var conn net.Conn
			conn, err = direct(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
			if ctx.Err() != nil {
				return nil, context.Cause(ctx)
			}
		}
		return nil, err // A local route must never fall through to the proxy.
	}
}
