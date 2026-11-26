package netutil

import (
	"context"
	"net"
	"net/url"

	"golang.org/x/net/proxy"
)

func IsSOCKS(u *url.URL) bool { return u.Scheme == "socks5" || u.Scheme == "socks5h" }

// SOCKSDialer sends hostnames to the next hop without local DNS resolution.
// The same context-aware dialer serves HTTP transports and opaque tunnels.
func SOCKSDialer(u *url.URL, forward DialContextFunc) (proxy.ContextDialer, error) {
	address, err := EndpointAddress(u)
	if err != nil {
		return nil, err
	}
	return DialContextFunc(func(ctx context.Context, network, target string) (net.Conn, error) {
		var transport net.Conn
		connect := DialContextFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
			var err error
			transport, err = forward(ctx, network, address)
			return transport, err
		})
		d, err := proxy.SOCKS5("tcp", address, nil, connect)
		if err != nil {
			return nil, err
		}
		if _, err := d.(proxy.ContextDialer).DialContext(ctx, network, target); err != nil {
			return nil, err
		}
		// x/net's result only adds the SOCKS bound address. Keep the negotiated
		// transport itself so TCP CloseWrite survives this layer and proxy chains.
		return transport, nil
	}), nil
}
