package proxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"dwebproxy/internal/netutil"

	"github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
)

// preserveNames prevents the server library's default system-DNS lookup.
// Web3 names resolve in the existing HTTP handler; ordinary names go upstream.
type preserveNames struct{}

func (preserveNames) Resolve(ctx context.Context, _ string) (context.Context, net.IP, error) {
	return ctx, nil, nil
}

// ServeSOCKS5 accepts TCP CONNECT only. The caller owns the listener; Close
// cancels every admitted session, including clients still negotiating SOCKS.
func (h *Handler) ServeSOCKS5(listener net.Listener) error {
	s := h.connect
	reject := func(_ context.Context, w io.Writer, _ *socks5.Request) error {
		return socks5.SendReply(w, statute.RepCommandNotSupported, nil)
	}
	server := socks5.NewServer(socks5.WithResolver(preserveNames{}), socks5.WithConnectHandle(h.serveSOCKSConnect), socks5.WithBindHandle(reject), socks5.WithAssociateHandle(reject))
	var sessions sync.WaitGroup
	defer sessions.Wait()
	defer s.Close() // Stop sessions before waiting if Accept fails or is closed.
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		select {
		case s.slots <- struct{}{}:
		default:
			conn.Close()
			continue
		}
		if !s.track(conn) {
			<-s.slots
			continue
		}
		sessions.Add(1)
		go func() {
			defer sessions.Done()
			defer func() { <-s.slots }()
			defer s.release(conn)
			conn.SetDeadline(time.Now().Add(time.Duration(s.settings.HandshakeTimeout)))
			if err := server.ServeConn(conn); err != nil && s.root.Err() == nil {
				h.logger.Debug("SOCKS5 session ended", "error", err)
			}
		}()
	}
}

func (h *Handler) serveSOCKSConnect(_ context.Context, w io.Writer, request *socks5.Request) error {
	s := h.connect
	client := w.(net.Conn) // ServeConn passes its net.Conn to the connect handler.
	// Negotiation is complete. Upstream setup owns a separate deadline; keep
	// the reply writable after that deadline so timeouts produce a SOCKS error.
	client.SetDeadline(time.Time{})
	name, port, err := authority(request.RawDestAddr.String(), 0)
	if err != nil || port == 0 {
		return s.replySOCKS(client, statute.RepAddrTypeNotSupported, nil)
	}
	conn := &netutil.BufferedConn{Conn: client, Reader: request.Reader}
	// Port 80 is HTTP, so reuse request routing/forwarding even when the next
	// hop is an HTTP proxy which does not permit CONNECT to an HTTP origin.
	if port == 80 {
		if _, err := classifyName(name); err != nil {
			return s.replySOCKS(client, statute.RepRuleFailure, nil)
		}
		if err := s.replySOCKS(client, statute.RepSuccess, client.LocalAddr()); err != nil {
			return err
		}
		client.SetDeadline(time.Time{})
		s.serveHTTPConnection(conn, boundRequestHandler(name, port, "http", h), nil)
		return nil
	}
	destination, err := h.connectDestination(name, port)
	if err != nil {
		return s.socksFailure(client, err)
	}
	certificate, upstream, err := h.openConnection(destination, port)
	if err != nil {
		return s.socksFailure(client, err)
	}
	if upstream != nil {
		if !s.track(upstream) {
			return net.ErrClosed
		}
		defer s.release(upstream)
	}
	if err := s.replySOCKS(client, statute.RepSuccess, client.LocalAddr()); err != nil {
		return err
	}
	client.SetDeadline(time.Time{})
	s.serveConnection(conn, certificate, upstream, destination.name, h)
	return nil
}

func (s *connectIngress) replySOCKS(conn net.Conn, code uint8, bound net.Addr) error {
	conn.SetWriteDeadline(time.Now().Add(time.Duration(s.settings.HandshakeTimeout)))
	return socks5.SendReply(conn, code, bound)
}

func (s *connectIngress) socksFailure(conn net.Conn, err error) error {
	status, _ := connectionFailure(s.root, err)
	reply := statute.RepHostUnreachable
	switch status {
	case http.StatusBadRequest, http.StatusForbidden, http.StatusNotImplemented:
		reply = statute.RepRuleFailure
	case http.StatusGatewayTimeout:
		reply = statute.RepTTLExpired
	}
	if replyErr := s.replySOCKS(conn, reply, nil); replyErr != nil {
		return replyErr
	}
	return err
}
