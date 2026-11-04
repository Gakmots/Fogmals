package proxy

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

// dialTunnel establishes HTTP/1.1 CONNECT to the configured next hop. It never
// resolves or dials the requested destination directly, nor inherits env proxies.
func (p *forwardProxy) dialTunnel(parent context.Context, target string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	port := p.endpoint.Port()
	if port == "" {
		port = "80"
		if p.endpoint.Scheme == "https" {
			port = "443"
		}
	}
	c, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(p.endpoint.Hostname(), port))
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
	}()
	deadline, _ := ctx.Deadline()
	c.SetDeadline(deadline)
	var conn net.Conn = c
	if p.endpoint.Scheme == "https" {
		settings := &tls.Config{MinVersion: tls.VersionTLS12}
		if p.transport.TLSClientConfig != nil {
			settings = p.transport.TLSClientConfig.Clone()
		}
		settings.ServerName = p.endpoint.Hostname()
		settings.NextProtos = []string{"http/1.1"}
		secured := tls.Client(c, settings)
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
		return nil, fmt.Errorf("upstream CONNECT returned %d", resp.StatusCode)
	}
	conn.SetDeadline(time.Time{})
	ok = true
	return &bufferedConn{Conn: conn, reader: reader}, nil
}

// Preserve bytes read ahead with the CONNECT headers (including ClientHello).
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.reader.Read(b) }
func (c *bufferedConn) CloseWrite() error {
	if h, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return h.CloseWrite()
	}
	return c.Conn.Close()
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
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, err := io.Copy(idleConn{upstream, idle}, idleConn{client, idle})
		if err != nil {
			client.Close()
			upstream.Close()
			return
		}
		if c, ok := upstream.(interface{ CloseWrite() error }); ok {
			c.CloseWrite()
		} else {
			upstream.Close()
		}
	}()
	io.Copy(idleConn{client, idle}, idleConn{upstream, idle})
	client.Close()
	upstream.Close()
	<-done
}
