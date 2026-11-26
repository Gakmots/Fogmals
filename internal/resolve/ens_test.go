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
	"dwebproxy/internal/records"
	"dwebproxy/internal/testutil"
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
	for _, tc := range []struct {
		offchain bool
		proxy    string
		swarm    bool
		localRPC bool
	}{{}, {offchain: true}, {proxy: "http"}, {proxy: "socks5"}, {swarm: true}, {offchain: true, swarm: true}, {proxy: "http", localRPC: true}, {proxy: "socks5", localRPC: true}} {
		offchain := tc.offchain
		t.Run(map[bool]string{false: "onchain", true: "ccip"}[offchain]+"/proxy="+tc.proxy+map[bool]string{false: "", true: "/swarm"}[tc.swarm]+map[bool]string{false: "", true: "/local"}[tc.localRPC], func(t *testing.T) {
			response := output
			if tc.swarm {
				raw, _ := hex.DecodeString("e40101fa011b20d1de9994b4d039f6548d191eb26786769f580809256b4685ef316805265ea162")
				inner, _ := resolverABI.Methods["contenthash"].Outputs.Pack(raw)
				response, _ = urABI.Methods["resolve"].Outputs.Pack(inner, common.HexToAddress("0x1234"))
			}
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
					result = "0x" + hex.EncodeToString(response)
				default:
					t.Errorf("unexpected method %s", req.Method)
				}
				json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
			}))
			defer server.Close()
			var dial netutil.DialContextFunc
			endpoint := server.URL
			if tc.proxy != "" {
				var p *testutil.Proxy
				dial, p = proxiedRPC(t, tc.proxy, server.URL)
				if !tc.localRPC {
					endpoint = "http://ethereum.invalid/rpc"
				}
				defer func() {
					if tc.localRPC && len(p.Requests) != 0 || !tc.localRPC && len(p.Requests) == 0 {
						t.Errorf("ENS RPC proxy routing: local=%v proxy connections=%d", tc.localRPC, len(p.Requests))
					}
				}()
			}
			client := netutil.Client(time.Second, dial)
			defer client.CloseIdleConnections()
			r, err := NewENS(endpoint, client, gateway.Client(), records.Default().ENS)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			got, err := r.Resolve(context.Background(), "sub.example.eth")
			wantKind := content.IPFS
			if tc.swarm {
				wantKind = content.Swarm
			}
			if err != nil || got.Kind != wantKind {
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
