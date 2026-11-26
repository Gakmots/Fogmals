package netutil

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

type DialContextFunc func(context.Context, string, string) (net.Conn, error)

func (f DialContextFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

// Dial also implements x/net/proxy.Dialer; SOCKS5 uses DialContext when available.
func (f DialContextFunc) Dial(network, address string) (net.Conn, error) {
	return f(context.Background(), network, address)
}

func directDialer() DialContextFunc {
	return (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext
}

// NewDialer bypasses the program proxy for local/private upstreams. A nil
// endpoint uses direct TCP throughout. Proxy failures never trigger direct TCP.
func NewDialer(endpoint *url.URL) (DialContextFunc, error) {
	direct := directDialer()
	if endpoint == nil {
		return direct, nil
	}
	if _, err := EndpointAddress(endpoint); err != nil {
		return nil, err
	}
	local := interfaceIPs()
	var dial DialContextFunc
	if IsSOCKS(endpoint) {
		socks, err := SOCKSDialer(endpoint, direct)
		if err != nil {
			return nil, err
		}
		dial = socks.DialContext
	} else {
		dial = func(ctx context.Context, _ string, target string) (net.Conn, error) {
			return HTTPConnect(ctx, endpoint, target, direct, nil)
		}
	}
	dial = bypassLocal(direct, dial, net.DefaultResolver.LookupNetIP, local)
	return func(ctx context.Context, network, target string) (_ net.Conn, err error) {
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		conn, err := dial(ctx, network, target)
		if err != nil && ctx.Err() != nil {
			err = fmt.Errorf("program proxy: %w", context.Cause(ctx))
		}
		return conn, err
	}, nil
}

// HTTPConnect is shared by the program proxy and HTTP(S) TON/fallback tunnels.
// Dial connects to the proxy, never the target, and may itself use a proxy.
func HTTPConnect(ctx context.Context, endpoint *url.URL, target string, dial DialContextFunc, settings *tls.Config) (_ net.Conn, err error) {
	address, err := EndpointAddress(endpoint)
	if err != nil {
		return nil, err
	}
	c, err := dial(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	ok := false
	defer func() {
		if !ok {
			c.Close()
		}
		if err != nil && ctx.Err() != nil {
			err = fmt.Errorf("upstream CONNECT: %w", context.Cause(ctx))
		}
	}()
	deadline, _ := ctx.Deadline()
	c.SetDeadline(deadline)
	var conn net.Conn = c
	if endpoint.Scheme == "https" {
		config := &tls.Config{MinVersion: tls.VersionTLS12}
		if settings != nil {
			config = settings.Clone()
		}
		config.ServerName = endpoint.Hostname()
		config.NextProtos = []string{"http/1.1"}
		secured := tls.Client(c, config)
		if err = secured.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		conn = secured
	}
	r := &http.Request{Method: http.MethodConnect, URL: &url.URL{Host: target}, Host: target, Header: make(http.Header)}
	if err = r.Write(conn); err != nil {
		return nil, err
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, r)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		resp.Body.Close()
		if resp.StatusCode == http.StatusGatewayTimeout {
			return nil, fmt.Errorf("upstream CONNECT returned %d: %w", resp.StatusCode, context.DeadlineExceeded)
		}
		return nil, fmt.Errorf("upstream CONNECT returned %d", resp.StatusCode)
	}
	conn.SetDeadline(time.Time{})
	ok = true
	return &BufferedConn{Conn: conn, Reader: reader}, nil
}

// BufferedConn preserves read-ahead bytes across protocol handoffs and forwards
// TCP half-close capability through both HTTP CONNECT and SOCKS5 adapters.
type BufferedConn struct {
	net.Conn
	Reader io.Reader
}

func (c *BufferedConn) Read(b []byte) (int, error) { return c.Reader.Read(b) }
func (c *BufferedConn) CloseWrite() error {
	if h, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return h.CloseWrite()
	}
	return c.Conn.Close()
}
