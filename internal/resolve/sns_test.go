package resolve

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"dwebproxy/internal/content"
	"dwebproxy/internal/netutil"
	solana "github.com/solana-foundation/solana-go/v2"
)

const testCID = "QmRAQB6YaCyidP37UdDnjFY5vQuiBrcqdyoW1CuDgwxkD4"

func TestSNSDerivationMatchesOfficialSDK(t *testing.T) {
	b, err := os.ReadFile("testdata/sns-sdk.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Rows []struct {
			Name, Domain string
			Records      []string
		}
	}
	if err := json.Unmarshal(b, &fixture); err != nil {
		t.Fatal(err)
	}
	class, err := recordClass()
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range fixture.Rows {
		key, _, err := domainKey(row.Name)
		if err != nil || key.String() != row.Domain {
			t.Fatalf("domain %s: %s %v", row.Name, key, err)
		}
		for i, typ := range recordTypes {
			got, err := nameKey("\x02"+typ.name, class, key)
			if err != nil || got.String() != row.Records[i] {
				t.Errorf("%s %s: %s %v", row.Name, typ.name, got, err)
			}
		}
	}
	if _, _, err := domainKey("example.sol"); err == nil {
		t.Fatal(".sol compatibility enabled")
	}
}

func v2Payload(value string, owner solana.PublicKey) []byte {
	b := make([]byte, 8+32+len(value))
	binary.LittleEndian.PutUint16(b, 1)
	binary.LittleEndian.PutUint32(b[4:8], uint32(len(value)))
	copy(b[8:40], owner[:])
	copy(b[40:], value)
	return b
}

func accountJSON(owner solana.PublicKey, data []byte) any {
	return map[string]any{"owner": owner.String(), "lamports": 1, "executable": false, "rentEpoch": 0, "data": []string{base64.StdEncoding.EncodeToString(data), "base64"}}
}

func registryBytes(parent, owner, class solana.PublicKey, payload []byte) []byte {
	b := make([]byte, 96)
	copy(b, parent[:])
	copy(b[32:], owner[:])
	copy(b[64:], class[:])
	return append(b, payload...)
}

func TestSNSV2ResolutionAndStaleness(t *testing.T) {
	owner := solana.MustPublicKeyFromBase58("Fxuoy3gFjfJALhwkRcuKjRdechcgffUApeYAfMWck6w8")
	newOwner := solana.MustPublicKeyFromBase58("ExXjtfdQe8JacoqP9Z535WzQKjF4CzW1TTRKRgpxvya3")
	key, parent, _ := domainKey("example.sns")
	class, _ := recordClass()
	for _, tc := range []struct {
		name                                  string
		stale, missing, tokenized, rpcFailure bool
	}{
		{name: "normal"}, {name: "transferred", stale: true}, {name: "missing", missing: true},
		{name: "NFT owner", tokenized: true}, {name: "NFT RPC failure", tokenized: true, rpcFailure: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			current := owner
			if tc.stale {
				current = newOwner
			}
			recordOwner := owner
			if tc.tokenized {
				recordOwner = newOwner
			}
			domain := accountJSON(nameProgram, registryBytes(parent, current, solana.PublicKey{}, nil))
			record := accountJSON(nameProgram, registryBytes(key, class, class, v2Payload(testCID, recordOwner)))
			var mintAccount any
			if tc.tokenized {
				b := make([]byte, 82)
				binary.LittleEndian.PutUint64(b[36:44], 1)
				b[44] = 0
				b[45] = 1
				mintAccount = accountJSON(solana.TokenProgramID, b)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req struct {
					ID     any               `json:"id"`
					Method string            `json:"method"`
					Params []json.RawMessage `json:"params"`
				}
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					t.Error(err)
					return
				}
				var result any
				switch req.Method {
				case "getMultipleAccounts":
					var keys []string
					json.Unmarshal(req.Params[0], &keys)
					if len(keys) != 5 || keys[0] != key.String() {
						t.Error("incorrect account batch")
					}
					var opts map[string]any
					json.Unmarshal(req.Params[1], &opts)
					if opts["commitment"] != "finalized" {
						t.Error("commitment not finalized")
					}
					values := []any{domain, record, nil, nil, mintAccount}
					if tc.missing {
						values[1] = nil
					}
					result = map[string]any{"context": map[string]int{"slot": 100}, "value": values}
				case "getTokenLargestAccounts":
					if tc.rpcFailure {
						json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "error": map[string]any{"code": -32000, "message": "RPC down"}})
						return
					}
					result = map[string]any{"context": map[string]int{"slot": 101}, "value": []any{map[string]any{"address": newOwner.String(), "amount": "1", "decimals": 0, "uiAmount": 1}}}
				case "getAccountInfo":
					mint, _, _ := solana.FindProgramAddress([][]byte{[]byte("tokenized_name"), key[:]}, tokenizerProgram)
					b := make([]byte, 165)
					copy(b, mint[:])
					copy(b[32:], newOwner[:])
					binary.LittleEndian.PutUint64(b[64:72], 1)
					b[108] = 1
					result = map[string]any{"context": map[string]int{"slot": 102}, "value": accountJSON(solana.TokenProgramID, b)}
				default:
					t.Errorf("unexpected RPC %s", req.Method)
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
			}))
			defer server.Close()
			client := netutil.Client(time.Second)
			defer client.CloseIdleConnections()
			got, err := NewSNS(server.URL, client).Resolve(context.Background(), "example.sns")
			switch {
			case tc.rpcFailure:
				if err == nil {
					t.Fatal("NFT RPC failure was ignored")
				}
			case tc.stale:
				if !errors.Is(err, ErrStale) {
					t.Fatal(err)
				}
			case tc.missing:
				if !errors.Is(err, ErrNotFound) {
					t.Fatal(err)
				}
			default:
				if err != nil || got.Kind != content.IPFS {
					t.Fatalf("%v %v", got, err)
				}
			}
		})
	}
}

func TestV2PayloadValidation(t *testing.T) {
	owner := solana.PublicKey{1}
	valid := v2Payload(testCID, owner)
	// Allocation padding must never become part of the storage identifier.
	got, err := decodeRecord(append(valid, 0, 0, 0), owner)
	if err != nil || got != testCID {
		t.Fatalf("padding: %q %v", got, err)
	}
	for _, b := range [][]byte{nil, valid[:7], valid[:39], valid[:len(valid)-1]} {
		if _, err := decodeRecord(b, owner); err == nil {
			t.Error("accepted truncated V2 account")
		}
	}
	unverified := append([]byte(nil), valid...)
	binary.LittleEndian.PutUint16(unverified, 3)
	if _, err := decodeRecord(unverified, owner); !errors.Is(err, ErrStale) {
		t.Fatal(err)
	}
	unknown := append([]byte(nil), valid...)
	binary.LittleEndian.PutUint16(unknown[2:4], 99)
	if _, err := decodeRecord(unknown, owner); err == nil {
		t.Error("unknown validation mode accepted")
	}
}

func FuzzSNSRecord(f *testing.F) {
	f.Add(v2Payload(testCID, solana.PublicKey{1}))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = decodeRecord(b, solana.PublicKey{1}) })
}
