package netutil

import (
	"strings"
	"testing"
)

func TestCanonicalASCIIHostname(t *testing.T) {
	longest := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 57) + ".ton"
	for _, name := range []string{"localhost", "example.eth", "sub.example.sns", "a-b.ton", "0.ton", longest} {
		if !ValidASCIIHostname(name) {
			t.Errorf("rejected %q", name)
		}
	}
	for _, name := range []string{"", ".eth", "a..eth", "example.eth.", "Example.eth", "-a.ton", "a-.ton", "a_b.eth", "*.eth", "é.eth", "a\x00.ton", "a/b.ton", strings.Repeat("a", 64) + ".eth", strings.TrimSuffix(longest, ".ton") + "a.ton"} {
		if ValidASCIIHostname(name) {
			t.Errorf("accepted %q", name)
		}
	}
}
