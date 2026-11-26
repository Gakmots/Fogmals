package resolve

import (
	"context"
	"net"
	"net/url"
	"testing"

	"dwebproxy/internal/netutil"
	"dwebproxy/internal/testutil"
)

// Exercise the SDK clients against an actual proxy and an offline RPC server.
func proxiedRPC(t *testing.T, scheme, origin string) (netutil.DialContextFunc, *testutil.Proxy) {
	t.Helper()
	u, _ := url.Parse(origin)
	p := testutil.NewProxy(t, scheme, func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, u.Host)
	})
	endpoint, _ := url.Parse(p.URL)
	dial, err := netutil.NewDialer(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	return dial, p
}
