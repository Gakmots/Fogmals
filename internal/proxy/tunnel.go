package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"dwebproxy/internal/netutil"
)

// dialTunnel establishes HTTP/1.1 CONNECT or SOCKS5 to the next hop. It never
// resolves or dials the requested destination directly, nor inherits env proxies.
func (p *forwardProxy) dialTunnel(parent context.Context, target string, timeout time.Duration) (_ net.Conn, err error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	defer func() {
		// Cancellation can close the socket before its deadline reports a
		// timeout. Retain the cause so CONNECT shares HTTP's error semantics.
		if err != nil && ctx.Err() != nil {
			err = fmt.Errorf("upstream CONNECT: %w", context.Cause(ctx))
		}
	}()
	if p.socks != nil {
		return p.socks.DialContext(ctx, "tcp", target)
	}
	return netutil.HTTPConnect(ctx, p.endpoint, target, p.transport.DialContext, p.transport.TLSClientConfig)
}

type idleConn struct {
	net.Conn
	timeout time.Duration
}

func (c idleConn) Read(b []byte) (int, error) {
	c.SetDeadline(time.Now().Add(c.timeout))
	n, e := c.Conn.Read(b)
	if n > 0 {
		c.SetDeadline(time.Now().Add(c.timeout))
	}
	return n, e
}
func (c idleConn) Write(b []byte) (int, error) {
	c.SetDeadline(time.Now().Add(c.timeout))
	n, e := c.Conn.Write(b)
	if n > 0 {
		c.SetDeadline(time.Now().Add(c.timeout))
	}
	return n, e
}

func relay(client, upstream net.Conn, idle time.Duration) {
	done := make(chan struct{}, 2)
	copyHalf := func(dst, src net.Conn) {
		defer func() { done <- struct{}{} }()
		_, err := io.Copy(idleConn{dst, idle}, idleConn{src, idle})
		if err != nil {
			client.Close()
			upstream.Close()
			return
		}
		if c, ok := dst.(interface{ CloseWrite() error }); ok {
			if c.CloseWrite() == nil {
				return
			}
		}
		client.Close()
		upstream.Close()
	}
	go copyHalf(upstream, client)
	go copyHalf(client, upstream)
	<-done
	<-done
	client.Close()
	upstream.Close()
}
