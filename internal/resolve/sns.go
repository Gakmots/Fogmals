package resolve

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/http"
	"strings"
	"unicode/utf8"

	"dwebproxy/internal/content"
	solana "github.com/solana-foundation/solana-go/v2"
	"github.com/solana-foundation/solana-go/v2/rpc"
	"github.com/solana-foundation/solana-go/v2/rpc/jsonrpc"
)

// Derivations and layouts follow the official SNS SDK (Records V2 / SNS-IP-3).
var (
	nameProgram      = solana.MustPublicKeyFromBase58("namesLPneVptA9Z5rqUDD9tMTWEJwofgaYwp8cawRkX")
	snsRoot          = solana.MustPublicKeyFromBase58("58PwtjSDuFHuUkYjH9BYnnQKHfwo9reZhC2zMJv9JPkx")
	recordProgram    = solana.MustPublicKeyFromBase58("HP3D4D1ZCmohQGFVms2SS4LCANgJyksBf5s1F77FuFjZ")
	tokenizerProgram = solana.MustPublicKeyFromBase58("nftD3vbNkNqfj2Sd3HZwbpw4BxxKWr4AjGb9X38JeZk")
)

var recordTypes = []struct {
	name string
	kind content.Kind
}{{"IPFS", content.IPFS}, {"IPNS", content.IPNS}, {"ARWV", content.Arweave}}

type SNS struct{ client *rpc.Client }

func NewSNS(endpoint string, client *http.Client) *SNS {
	if endpoint == "" {
		return nil
	}
	return &SNS{rpc.NewWithCustomRPCClient(jsonrpc.NewClientWithOpts(endpoint, &jsonrpc.RPCClientOpts{HTTPClient: client}))}
}

func nameKey(label string, class, parent solana.PublicKey) (solana.PublicKey, error) {
	hash := sha256.Sum256([]byte("SPL Name Service" + label))
	key, _, err := solana.FindProgramAddress([][]byte{hash[:], class[:], parent[:]}, nameProgram)
	return key, err
}

func domainKey(name string) (key, parent solana.PublicKey, err error) {
	if !strings.HasSuffix(name, ".sns") {
		return key, parent, ErrInvalid
	}
	labels := strings.Split(strings.TrimSuffix(name, ".sns"), ".")
	if len(labels) < 1 || len(labels) > 2 {
		return key, parent, ErrInvalid
	}
	parent = snsRoot
	key, err = nameKey(labels[len(labels)-1], solana.PublicKey{}, parent)
	if err == nil && len(labels) == 2 {
		parent = key
		key, err = nameKey("\x00"+labels[0], solana.PublicKey{}, parent)
	}
	return
}

func recordClass() (solana.PublicKey, error) {
	key, _, err := solana.FindProgramAddress([][]byte{recordProgram[:]}, recordProgram)
	return key, err
}

func registry(a *rpc.Account, parent, class solana.PublicKey) ([]byte, error) {
	if a == nil {
		return nil, ErrNotFound
	}
	if a.Owner != nameProgram || a.Executable || a.Data == nil {
		return nil, fmt.Errorf("invalid SNS account owner")
	}
	b := a.Data.GetBinary()
	if len(b) < 96 || !bytes.Equal(b[:32], parent[:]) || !bytes.Equal(b[64:96], class[:]) {
		return nil, fmt.Errorf("invalid SNS registry header")
	}
	return b, nil
}

func (r *SNS) Resolve(ctx context.Context, name string) (content.Target, error) {
	if r == nil {
		return content.Target{}, ErrUnavailable
	}
	key, parent, err := domainKey(name)
	if err != nil {
		return content.Target{}, err
	}
	class, err := recordClass()
	if err != nil {
		return content.Target{}, err
	}
	keys := []solana.PublicKey{key}
	for _, typ := range recordTypes {
		k, err := nameKey("\x02"+typ.name, class, key)
		if err != nil {
			return content.Target{}, err
		}
		keys = append(keys, k)
	}
	mint, _, err := solana.FindProgramAddress([][]byte{[]byte("tokenized_name"), key[:]}, tokenizerProgram)
	if err != nil {
		return content.Target{}, err
	}
	keys = append(keys, mint)
	batch, err := r.client.GetMultipleAccountsWithOpts(ctx, keys, &rpc.GetMultipleAccountsOpts{Encoding: solana.EncodingBase64, Commitment: rpc.CommitmentFinalized})
	if err != nil {
		return content.Target{}, fmt.Errorf("SNS accounts: %w", err)
	}
	if batch == nil || len(batch.Value) != len(keys) {
		return content.Target{}, fmt.Errorf("incomplete SNS RPC response")
	}
	domain, err := registry(batch.Value[0], parent, solana.PublicKey{})
	if err != nil {
		return content.Target{}, err
	}
	owner := solana.PublicKeyFromBytes(domain[32:64])
	owner, err = r.effectiveOwner(ctx, mint, batch.Value[4], owner, batch.Context.Slot)
	if err != nil {
		return content.Target{}, err
	}
	for i, typ := range recordTypes {
		if batch.Value[i+1] == nil {
			continue
		}
		b, err := registry(batch.Value[i+1], key, class)
		if err != nil {
			return content.Target{}, err
		}
		value, err := decodeRecord(b[96:], owner)
		if err != nil {
			return content.Target{}, fmt.Errorf("SNS %s: %w", typ.name, err)
		}
		return content.Parse(typ.kind, value)
	}
	return content.Target{}, ErrNotFound
}

// Tokenized names use the NFT holder as their effective owner. Never hide RPC
// failures by falling back to the custodian recorded in the name account.
func (r *SNS) effectiveOwner(ctx context.Context, mint solana.PublicKey, a *rpc.Account, owner solana.PublicKey, minSlot uint64) (solana.PublicKey, error) {
	if a == nil {
		return owner, nil
	}
	if a.Owner != solana.TokenProgramID || a.Data == nil {
		return owner, fmt.Errorf("invalid SNS NFT mint")
	}
	b := a.Data.GetBinary()
	if len(b) != 82 || b[44] != 0 || b[45] != 1 {
		return owner, fmt.Errorf("invalid SNS NFT mint layout")
	}
	supply := binary.LittleEndian.Uint64(b[36:44])
	if supply == 0 {
		return owner, nil
	}
	if supply != 1 {
		return owner, fmt.Errorf("invalid SNS NFT supply")
	}
	largest, err := r.client.GetTokenLargestAccounts(ctx, mint, rpc.CommitmentFinalized)
	if err != nil {
		return owner, fmt.Errorf("SNS NFT holder: %w", err)
	}
	if largest == nil || len(largest.Value) == 0 || largest.Value[0] == nil || largest.Value[0].Amount != "1" {
		return owner, fmt.Errorf("SNS NFT holder missing")
	}
	info, err := r.client.GetAccountInfoWithOpts(ctx, largest.Value[0].Address, &rpc.GetAccountInfoOpts{Encoding: solana.EncodingBase64, Commitment: rpc.CommitmentFinalized, MinContextSlot: &minSlot})
	if err != nil {
		return owner, fmt.Errorf("SNS NFT holder account: %w", err)
	}
	if info == nil || info.Value == nil || info.Value.Owner != solana.TokenProgramID || info.Value.Data == nil {
		return owner, fmt.Errorf("invalid SNS NFT holder account")
	}
	b = info.Value.Data.GetBinary()
	if len(b) != 165 || !bytes.Equal(b[:32], mint[:]) || binary.LittleEndian.Uint64(b[64:72]) != 1 || b[108] == 0 {
		return owner, fmt.Errorf("invalid SNS NFT holder data")
	}
	return solana.PublicKeyFromBytes(b[32:64]), nil
}

func validationLength(v uint16) (int, error) {
	switch v {
	case 0:
		return 0, nil
	case 1, 3:
		return 32, nil
	case 2:
		return 20, nil
	default:
		return 0, fmt.Errorf("unknown SNS validation mode")
	}
}

func decodeRecord(b []byte, owner solana.PublicKey) (string, error) {
	if len(b) < 8 {
		return "", fmt.Errorf("truncated V2 header")
	}
	stale := binary.LittleEndian.Uint16(b[:2])
	roa := binary.LittleEndian.Uint16(b[2:4])
	n := uint64(binary.LittleEndian.Uint32(b[4:8]))
	s, err := validationLength(stale)
	if err != nil {
		return "", err
	}
	r, err := validationLength(roa)
	if err != nil {
		return "", err
	}
	offset := 8 + s + r
	if len(b) < offset || n == 0 || n > uint64(len(b)-offset) {
		return "", fmt.Errorf("truncated or empty V2 payload")
	}
	if stale != 1 || !bytes.Equal(b[8:8+s], owner[:]) {
		return "", ErrStale
	}
	// IPFS/IPNS/ARWV do not define a right-of-association verifier in SNS.
	payload := b[offset : offset+int(n)]
	if !utf8.Valid(payload) {
		return "", fmt.Errorf("V2 payload is not UTF-8")
	}
	return string(payload), nil
}
