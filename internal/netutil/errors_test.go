package netutil

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"testing"
)

func TestProxyErrorClassification(t *testing.T) {
	deadlineCause, cancelDeadline := context.WithCancelCause(context.Background())
	cancelDeadline(fmt.Errorf("idle: %w", context.DeadlineExceeded))
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		name   string
		ctx    context.Context
		err    error
		status int
	}{
		{"deadline", context.Background(), fmt.Errorf("request: %w", context.DeadlineExceeded), 504},
		{"network timeout", context.Background(), &net.OpError{Op: "dial", Net: "tcp", Err: &net.DNSError{IsTimeout: true}}, 504},
		{"idle cancellation", deadlineCause, net.ErrClosed, 504},
		{"ordinary cancellation", cancelled, context.Canceled, 502},
		{"missing host", context.Background(), &net.DNSError{IsNotFound: true}, 502},
		{"connection failure", context.Background(), errors.New("connection refused"), 502},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ProxyErrorStatus(tc.ctx, tc.err); got != tc.status {
				t.Fatalf("got %s, want %s", http.StatusText(got), http.StatusText(tc.status))
			}
		})
	}
}
