package content

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multihash"
)

const testCID = "QmRAQB6YaCyidP37UdDnjFY5vQuiBrcqdyoW1CuDgwxkD4"

func TestStorageIdentifiers(t *testing.T) {
	root, err := Parse(IPFS, testCID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(root.ID, "bafy") || len(root.ID) > 63 {
		t.Fatal(root)
	}
	for _, value := range []string{testCID, "ipfs://" + testCID, "/ipfs/" + testCID} {
		got, err := Parse(IPFS, value)
		if err != nil || got != root {
			t.Fatalf("%s: %v %v", value, got, err)
		}
	}
	h, _ := multihash.Sum([]byte("peer"), multihash.SHA2_256, -1)
	peer := cid.NewCidV1(cid.Libp2pKey, h)
	a, err := Parse(IPNS, peer.String())
	if err != nil {
		t.Fatal(err)
	}
	b, err := Parse(IPNS, h.B58String())
	if err != nil || a != b || !strings.HasPrefix(a.ID, "k") {
		t.Fatalf("IPNS conversion: %v %v %v", a, b, err)
	}
	for _, tc := range []struct {
		kind  Kind
		value string
	}{
		{IPFS, testCID + "/index.html"}, {IPFS, testCID + "?uri=bad"}, {IPFS, "https://evil.test"},
		{IPNS, root.ID}, {IPNS, "example.com"}, {Arweave, "abc"}, {Arweave, strings.Repeat("A", 44)},
	} {
		if _, err := Parse(tc.kind, tc.value); err == nil {
			t.Errorf("accepted invalid %s %q", tc.kind, tc.value)
		}
	}
}

func TestContenthashNamespaces(t *testing.T) {
	c, _ := cid.Decode(testCID)
	c = cid.NewCidV1(c.Type(), c.Hash())
	for _, tc := range []struct {
		code    uint64
		payload []byte
		kind    Kind
	}{
		{0xe3, c.Bytes(), IPFS},
		{0xe5, cid.NewCidV1(cid.Libp2pKey, c.Hash()).Bytes(), IPNS},
		{0xb29910, make([]byte, 32), Arweave},
	} {
		raw := binary.AppendUvarint(nil, tc.code)
		got, err := DecodeHash(append(raw, tc.payload...))
		if err != nil || got.Kind != tc.kind {
			t.Fatalf("codec %x: %v %v", tc.code, got, err)
		}
		if tc.kind == Arweave && got.ID != base64.RawURLEncoding.EncodeToString(tc.payload) {
			t.Fatal(got)
		}
	}
	if _, err := DecodeHash(binary.AppendUvarint(nil, 0xe4)); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	for _, raw := range [][]byte{nil, {0x80}, {0xe3, 1, 0}, {0x90, 0xb2, 0xc9, 0x05, 1}} {
		if _, err := DecodeHash(raw); err == nil {
			t.Errorf("accepted %x", raw)
		}
	}
}

func FuzzContenthash(f *testing.F) {
	f.Add([]byte{0xe3, 1, 1, 0x70})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		got, err := DecodeHash(b)
		if err == nil {
			again, err := Parse(got.Kind, got.ID)
			if err != nil || again != got {
				t.Fatalf("noncanonical target %v", got)
			}
		}
	})
}
