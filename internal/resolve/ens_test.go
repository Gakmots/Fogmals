package resolve

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"dwebproxy/internal/content"
	"dwebproxy/internal/netutil"
	ens "github.com/ensdomains/go-ens/v4"
	resolverContract "github.com/ensdomains/go-ens/v4/contracts/resolver"
	"github.com/ensdomains/go-ens/v4/contracts/universalresolver"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ipfs/go-cid"
)

func TestENSUniversalResolverAndCCIPCallback(t *testing.T) {
	c, _ := cid.Decode(testCID)
	c = cid.NewCidV1(c.Type(), c.Hash())
	hash := append(binary.AppendUvarint(nil, 0xe3), c.Bytes()...)
	resolverABI, _ := resolverContract.ContractMetaData.GetAbi()
	inner, _ := resolverABI.Methods["contenthash"].Outputs.Pack(hash)
	urABI, _ := universalresolver.ContractMetaData.GetAbi()
	output, _ := urABI.Methods["resolve"].Outputs.Pack(inner, common.HexToAddress("0x1234"))
	for _, offchain := range []bool{false, true} {
		t.Run(map[bool]string{false: "onchain", true: "ccip"}[offchain], func(t *testing.T) {
			var gatewayCalls, chainCalls atomic.Int32
			gateway := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gatewayCalls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]string{"data": "0x1234"})
			}))
			defer gateway.Close()
			lookupABI, err := abi.JSON(strings.NewReader(`[{"type":"error","name":"OffchainLookup","inputs":[{"type":"address","name":"sender"},{"type":"string[]","name":"urls"},{"type":"bytes","name":"callData"},{"type":"bytes4","name":"callbackFunction"},{"type":"bytes","name":"extraData"}]}]`))
			if err != nil {
				t.Fatal(err)
			}
			lookup := lookupABI.Errors["OffchainLookup"]
			payload, _ := lookup.Inputs.Pack(common.HexToAddress(ens.UniversalResolverContractAddress), []string{gateway.URL + "/{data}"}, []byte{1}, [4]byte{1, 2, 3, 4}, []byte{})
			revert := append(lookup.ID.Bytes()[:4], payload...)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req struct {
					ID     any               `json:"id"`
					Method string            `json:"method"`
					Params []json.RawMessage `json:"params"`
				}
				json.NewDecoder(r.Body).Decode(&req)
				var result string
				switch req.Method {
				case "eth_chainId":
					result = "0x1"
				case "eth_call":
					n := chainCalls.Add(1)
					var call map[string]string
					json.Unmarshal(req.Params[0], &call)
					if !strings.EqualFold(call["to"], ens.UniversalResolverContractAddress) {
						t.Errorf("did not use Universal Resolver: %v", call)
					}
					if offchain && n == 1 {
						json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "error": map[string]any{"code": 3, "message": "execution reverted", "data": "0x" + hex.EncodeToString(revert)}})
						return
					}
					result = "0x" + hex.EncodeToString(output)
				default:
					t.Errorf("unexpected method %s", req.Method)
				}
				json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
			}))
			defer server.Close()
			client := netutil.Client(time.Second)
			defer client.CloseIdleConnections()
			r, err := NewENS(server.URL, client, gateway.Client())
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			got, err := r.Resolve(context.Background(), "sub.example.eth")
			if err != nil || got.Kind != content.IPFS {
				t.Fatalf("%v %v", got, err)
			}
			want := int32(1)
			if offchain {
				want = 2
			}
			if chainCalls.Load() != want {
				t.Fatalf("chain calls=%d", chainCalls.Load())
			}
			if offchain && gatewayCalls.Load() != 1 {
				t.Fatal("CCIP gateway not used")
			}
		})
	}
}
