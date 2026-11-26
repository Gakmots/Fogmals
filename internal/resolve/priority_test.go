package resolve

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"dwebproxy/internal/content"
	"dwebproxy/internal/netutil"
	"dwebproxy/internal/records"
	solana "github.com/solana-foundation/solana-go/v2"
)

func TestSNSConfiguredPriorityAndEnabledRecords(t *testing.T) {
	for _, tc := range []struct {
		name             string
		order            []records.Type
		fields           []string
		missing          []string
		stale, malformed string
		kind             content.Kind
		wantErr          error
		invalid          bool
	}{
		{name: "default", order: []records.Type{records.IPFS, records.IPNS, records.Arweave}, fields: []string{"IPFS", "IPNS", "ARWV"}, kind: content.IPFS},
		{name: "IPFS Arweave IPNS", order: []records.Type{records.IPFS, records.Arweave, records.IPNS}, fields: []string{"IPFS", "ARWV", "IPNS"}, kind: content.IPFS},
		{name: "IPNS IPFS Arweave", order: []records.Type{records.IPNS, records.IPFS, records.Arweave}, fields: []string{"IPNS", "IPFS", "ARWV"}, kind: content.IPNS},
		{name: "IPNS Arweave IPFS", order: []records.Type{records.IPNS, records.Arweave, records.IPFS}, fields: []string{"IPNS", "ARWV", "IPFS"}, kind: content.IPNS},
		{name: "Arweave IPFS IPNS", order: []records.Type{records.Arweave, records.IPFS, records.IPNS}, fields: []string{"ARWV", "IPFS", "IPNS"}, kind: content.Arweave},
		{name: "Arweave IPNS IPFS", order: []records.Type{records.Arweave, records.IPNS, records.IPFS}, fields: []string{"ARWV", "IPNS", "IPFS"}, kind: content.Arweave},
		{name: "IPNS only ignores disabled IPFS", order: []records.Type{records.IPNS}, fields: []string{"IPNS"}, stale: "IPFS", kind: content.IPNS},
		{name: "Arweave only", order: []records.Type{records.Arweave}, fields: []string{"ARWV"}, kind: content.Arweave},
		{name: "IPFS only", order: []records.Type{records.IPFS}, fields: []string{"IPFS"}, kind: content.IPFS},
		{name: "missing first", order: []records.Type{records.Arweave, records.IPNS}, fields: []string{"ARWV", "IPNS"}, missing: []string{"ARWV"}, kind: content.IPNS},
		{name: "no implicit enabled type", order: []records.Type{records.Arweave}, fields: []string{"ARWV"}, missing: []string{"ARWV"}, wantErr: ErrNotFound},
		{name: "all enabled missing", order: []records.Type{records.IPNS, records.IPFS}, fields: []string{"IPNS", "IPFS"}, missing: []string{"IPFS", "IPNS"}, wantErr: ErrNotFound},
		{name: "stale first is an error", order: []records.Type{records.IPFS, records.IPNS}, fields: []string{"IPFS", "IPNS"}, stale: "IPFS", wantErr: ErrStale},
		{name: "malformed first is an error", order: []records.Type{records.IPFS, records.IPNS}, fields: []string{"IPFS", "IPNS"}, malformed: "IPFS", invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			owner := solana.PublicKey{1}
			key, parent, err := domainKey("example.sns")
			if err != nil {
				t.Fatal(err)
			}
			class, err := recordClass()
			if err != nil {
				t.Fatal(err)
			}
			mint, _, err := solana.FindProgramAddress([][]byte{[]byte("tokenized_name"), key[:]}, tokenizerProgram)
			if err != nil {
				t.Fatal(err)
			}
			values := map[string]string{"IPFS": testCID, "IPNS": testCID, "ARWV": strings.Repeat("A", 43)}
			accounts := map[string]any{key.String(): accountJSON(nameProgram, registryBytes(parent, owner, solana.PublicKey{}, nil))}
			expectedKeys := []string{key.String()}
			for _, field := range []string{"IPFS", "IPNS", "ARWV"} {
				k, err := nameKey("\x02"+field, class, key)
				if err != nil {
					t.Fatal(err)
				}
				verifier := owner
				if tc.stale == field {
					verifier = solana.PublicKey{2}
				}
				value := values[field]
				if tc.malformed == field {
					value = "not-a-content-id"
				}
				accounts[k.String()] = accountJSON(nameProgram, registryBytes(key, class, class, v2Payload(value, verifier)))
				for _, missing := range tc.missing {
					if missing == field {
						accounts[k.String()] = nil
					}
				}
			}
			for _, field := range tc.fields {
				k, err := nameKey("\x02"+field, class, key)
				if err != nil {
					t.Fatal(err)
				}
				expectedKeys = append(expectedKeys, k.String())
			}
			expectedKeys = append(expectedKeys, mint.String())
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req struct {
					ID     any               `json:"id"`
					Method string            `json:"method"`
					Params []json.RawMessage `json:"params"`
				}
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					t.Error(err)
					http.Error(w, "bad RPC", 400)
					return
				}
				if req.Method != "getMultipleAccounts" || len(req.Params) < 1 {
					t.Errorf("unexpected RPC %s", req.Method)
					http.Error(w, "bad RPC", 400)
					return
				}
				var keys []string
				if err := json.Unmarshal(req.Params[0], &keys); err != nil {
					t.Error(err)
					http.Error(w, "bad keys", 400)
					return
				}
				if !reflect.DeepEqual(keys, expectedKeys) {
					t.Errorf("requested keys=%v, want=%v", keys, expectedKeys)
				}
				batch := make([]any, len(keys))
				for i, k := range keys {
					batch[i] = accounts[k]
				}
				json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": map[string]any{"context": map[string]int{"slot": 100}, "value": batch}})
			}))
			defer server.Close()
			client := netutil.Client(time.Second, nil)
			defer client.CloseIdleConnections()
			resolver, err := NewSNS(server.URL, client, tc.order)
			if err != nil {
				t.Fatal(err)
			}
			got, err := resolver.Resolve(context.Background(), "example.sns")
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("got=%v, err=%v", got, err)
				}
				return
			}
			if tc.invalid {
				if err == nil {
					t.Fatal("invalid high-priority record fell through")
				}
				return
			}
			if err != nil || got.Kind != tc.kind {
				t.Fatalf("got=%v, err=%v, want kind=%s", got, err, tc.kind)
			}
		})
	}
}

func TestDisabledAndInvalidRecordPoliciesDoNotContactRPC(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); http.Error(w, "must not be called", 500) }))
	defer server.Close()
	client := netutil.Client(time.Second, nil)
	defer client.CloseIdleConnections()
	ens, err := NewENS(server.URL, client, client, []records.Type{})
	if err != nil {
		t.Fatal(err)
	}
	defer ens.Close()
	if _, err := ens.Resolve(context.Background(), "example.eth"); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	sns, err := NewSNS(server.URL, client, []records.Type{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sns.Resolve(context.Background(), "example.sns"); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	if _, err := NewENS(server.URL, client, client, []records.Type{records.IPFS}); err == nil {
		t.Fatal("ENS accepted IPFS as a record type")
	}
	if _, err := NewSNS(server.URL, client, []records.Type{records.ContentHash}); err == nil {
		t.Fatal("SNS accepted ContentHash")
	}
	if calls.Load() != 0 {
		t.Fatalf("disabled/invalid records contacted RPC %d times", calls.Load())
	}
}
