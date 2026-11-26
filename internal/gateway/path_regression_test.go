package gateway

import (
	"net/url"
	"strings"
	"testing"

	"dwebproxy/internal/content"
)

func TestRelativeAndExternalRedirectsKeepContentBoundary(t *testing.T) {
	ipfs, _ := content.Parse(content.IPFS, cidV0)
	ar, _ := content.Parse(content.Arweave, strings.Repeat("A", 43))
	base, _ := url.Parse("http://localhost:8080")
	in, _ := url.Parse("https://alice.eth/docs/page")
	for _, tc := range []struct {
		root           content.Target
		location, want string
		invalid        bool
	}{
		{ipfs, "../login", "https://alice.eth/login", false},
		{ipfs, "./next?x=1", "https://alice.eth/docs/next?x=1", false},
		{ipfs, "../100%25.html", "https://alice.eth/100%25.html", false},
		{ipfs, "../literal%2520name", "https://alice.eth/literal%2520name", false},
		{ipfs, "https://other.example/a/../login?uri=business&x=a;b", "https://other.example/a/../login?uri=business&x=a;b", false},
		{ipfs, "../%252e%252e/escape", "", true},
		{ipfs, "http://localhost:8080/ipfs/" + ipfs.ID + "/../../api/v0/shutdown", "", true},
		{ar, "../login", "https://alice.eth/login", false},
		{ar, "../../api/v0/shutdown", "", true},
		{ar, "/other-root/file", "", true},
	} {
		t.Run(tc.location+string(tc.root.Kind), func(t *testing.T) {
			out := targetURL(base, tc.root, in)
			got, err := rewriteLocation(tc.location, base, out, in, in.Host, tc.root)
			if (err != nil) != tc.invalid || (!tc.invalid && got != tc.want) {
				t.Fatalf("got %q, %v; want %q invalid=%v", got, err, tc.want, tc.invalid)
			}
		})
	}
}

func TestRelaxedPathsStillRejectHiddenTraversal(t *testing.T) {
	for _, path := range []string{"/%252e%252e/x", "/%252fapi", "/literal%25text%252fapi", "/%255capi", "/%2500x", "/%09", "/%7f"} {
		u, err := url.Parse(path)
		if err == nil && ValidatePath(u) == nil {
			t.Errorf("accepted %s", path)
		}
	}
}
