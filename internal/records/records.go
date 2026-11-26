// Package records defines supported name records and their configured order.
// Config validation and resolver construction share the same record catalog.
package records

import (
	"fmt"

	"dwebproxy/internal/content"
)

type Type string

const (
	ContentHash Type = "ContentHash"
	IPFS        Type = "IPFS"
	IPNS        Type = "IPNS"
	Arweave     Type = "Arweave"
)

type Priority struct {
	ENS []Type `json:"ens"`
	SNS []Type `json:"sns"`
}

func Default() Priority {
	return Priority{ENS: []Type{ContentHash}, SNS: []Type{IPFS, IPNS, Arweave}}
}

// Definition separates a user-facing type from its chain field name and
// content protocol. ENS contenthash selects its protocol from the record value.
type Definition struct {
	Name string
	Kind content.Kind
}

var ensCatalog = map[Type]Definition{ContentHash: {Name: "contenthash"}}
var snsCatalog = map[Type]Definition{
	IPFS:    {Name: "IPFS", Kind: content.IPFS},
	IPNS:    {Name: "IPNS", Kind: content.IPNS},
	Arweave: {Name: "ARWV", Kind: content.Arweave},
}

func ForENS(order []Type) ([]Definition, error) { return ordered("ens", order, ensCatalog) }
func ForSNS(order []Type) ([]Definition, error) { return ordered("sns", order, snsCatalog) }

func (p Priority) Validate() error {
	if _, err := ForENS(p.ENS); err != nil {
		return err
	}
	_, err := ForSNS(p.SNS)
	return err
}

func ordered(chain string, order []Type, catalog map[Type]Definition) ([]Definition, error) {
	if order == nil {
		return nil, fmt.Errorf("record_priority.%s must be an array; use [] to disable", chain)
	}
	definitions := make([]Definition, 0, len(order))
	seen := make(map[Type]bool, len(order))
	for _, typ := range order {
		definition, ok := catalog[typ]
		if !ok {
			return nil, fmt.Errorf("record_priority.%s: unsupported record %q", chain, typ)
		}
		if seen[typ] {
			return nil, fmt.Errorf("record_priority.%s: duplicate record %q", chain, typ)
		}
		seen[typ] = true
		definitions = append(definitions, definition)
	}
	return definitions, nil
}
