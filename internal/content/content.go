// Package content validates storage identifiers independently of names and gateways.
package content

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-multicodec"
	"github.com/multiformats/go-multihash"
)

type Kind string

const (
	IPFS    Kind = "ipfs"
	IPNS    Kind = "ipns"
	Arweave Kind = "arweave"
)

var ErrUnsupported = errors.New("unsupported content protocol")

type Target struct {
	Kind Kind
	ID   string
}

// Parse accepts a bare ID, a matching URI, or a matching namespace path.
// Content roots cannot contain a path, query, or fragment in v1.
func Parse(kind Kind, value string) (Target, error) {
	id := strings.TrimSpace(value)
	scheme := string(kind)
	if kind == Arweave {
		scheme = "ar"
	}
	id = strings.TrimPrefix(id, scheme+"://")
	id = strings.TrimPrefix(id, "/"+scheme+"/")
	if id == "" || strings.ContainsAny(id, "/?#@%\\\x00\r\n\t ") {
		return Target{}, fmt.Errorf("invalid %s content root", kind)
	}
	t := Target{Kind: kind}
	switch kind {
	case IPFS:
		c, err := cid.Decode(id)
		if err != nil {
			return Target{}, fmt.Errorf("invalid IPFS CID: %w", err)
		}
		if c.Version() == 0 {
			c = cid.NewCidV1(c.Type(), c.Hash())
		}
		t.ID, err = c.StringOfBase(multibase.Base32)
		if err != nil {
			return Target{}, err
		}
	case IPNS:
		// IPNS accepts peer IDs, including legacy base58 multihashes.
		c, err := cid.Decode(id)
		if err == nil {
			if c.Version() != 0 && c.Type() != cid.Libp2pKey {
				return Target{}, fmt.Errorf("IPNS CID must use libp2p-key codec")
			}
		} else {
			h, e := multihash.FromB58String(id)
			if e != nil {
				return Target{}, fmt.Errorf("invalid IPNS peer ID")
			}
			c = cid.NewCidV1(cid.Libp2pKey, h)
		}
		c = cid.NewCidV1(cid.Libp2pKey, c.Hash())
		t.ID, err = c.StringOfBase(multibase.Base36)
		if err != nil {
			return Target{}, err
		}
	case Arweave:
		b, err := base64.RawURLEncoding.DecodeString(id)
		if err != nil || len(b) != 32 || base64.RawURLEncoding.EncodeToString(b) != id {
			return Target{}, fmt.Errorf("Arweave ID must be canonical base64url of 32 bytes")
		}
		t.ID = id
	default:
		return Target{}, ErrUnsupported
	}
	if kind != Arweave && len(t.ID) > 63 {
		return Target{}, fmt.Errorf("content ID exceeds subdomain label limit")
	}
	return t, nil
}

func (t Target) String() string {
	s := string(t.Kind)
	if t.Kind == Arweave {
		s = "ar"
	}
	return s + "://" + t.ID
}

// DecodeHash decodes ENSIP-7's unsigned-varint namespace followed by its payload.
// Namespace codes are defined in multiformats/multicodec/table.csv.
func DecodeHash(raw []byte) (Target, error) {
	code, n := binary.Uvarint(raw)
	if n <= 0 {
		return Target{}, fmt.Errorf("invalid contenthash namespace")
	}
	payload := raw[n:]
	switch multicodec.Code(code) {
	case multicodec.Ipfs, multicodec.Ipns:
		c, err := cid.Cast(payload)
		if err != nil {
			return Target{}, fmt.Errorf("invalid contenthash CID: %w", err)
		}
		kind := IPFS
		if multicodec.Code(code) == multicodec.Ipns {
			kind = IPNS
		}
		return Parse(kind, c.String())
	case multicodec.ArweaveNs:
		return Parse(Arweave, base64.RawURLEncoding.EncodeToString(payload))
	default:
		return Target{}, fmt.Errorf("%w: contenthash codec %#x", ErrUnsupported, code)
	}
}
