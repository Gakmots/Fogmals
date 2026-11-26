package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"dwebproxy/internal/records"
)

func TestRecordPriorityJSON(t *testing.T) {
	for _, tc := range []struct {
		json     string
		ens, sns []records.Type
		invalid  bool
	}{
		{`{}`, []records.Type{records.ContentHash}, []records.Type{records.IPFS, records.IPNS, records.Arweave}, false},
		{`{"record_priority":{"sns":["Arweave","IPNS"]}}`, []records.Type{records.ContentHash}, []records.Type{records.Arweave, records.IPNS}, false},
		{`{"record_priority":{"ens":[]}}`, []records.Type{}, []records.Type{records.IPFS, records.IPNS, records.Arweave}, false},
		{`{"record_priority":{"ens":[],"sns":[]}}`, []records.Type{}, []records.Type{}, false},
		{`{"record_priority":{"sns":["IPNS"]}}`, []records.Type{records.ContentHash}, []records.Type{records.IPNS}, false},
		{`{"record_priority":{"ens":["IPFS"]}}`, nil, nil, true},
		{`{"record_priority":{"ens":["ContentHash","ContentHash"]}}`, nil, nil, true},
		{`{"record_priority":{"sns":["ContentHash"]}}`, nil, nil, true},
		{`{"record_priority":{"sns":["IPFS","IPFS"]}}`, nil, nil, true},
		{`{"record_priority":{"sns":["ARWV"]}}`, nil, nil, true},
		{`{"record_priority":{"sns":["ipfs"]}}`, nil, nil, true},
		{`{"record_priority":{"sns":[""]}}`, nil, nil, true},
		{`{"record_priority":{"sns":null}}`, nil, nil, true},
		{`{"record_priority":{"ens":null}}`, nil, nil, true},
		{`{"record_priority":{"sns":"IPFS"}}`, nil, nil, true},
		{`{"record_priority":{"sns":[1]}}`, nil, nil, true},
		{`{"record_priority":{"ton":[]}}`, nil, nil, true},
	} {
		t.Run(tc.json, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(tc.json), 0600); err != nil {
				t.Fatal(err)
			}
			c, err := Load(path)
			if tc.invalid {
				if err == nil {
					t.Fatal("accepted invalid record priority")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(c.RecordPriority.ENS, tc.ens) || !reflect.DeepEqual(c.RecordPriority.SNS, tc.sns) {
				t.Fatalf("priority=%+v", c.RecordPriority)
			}
			encoded, err := json.Marshal(c)
			if err != nil {
				t.Fatal(err)
			}
			// Explicit [] must remain an empty array rather than becoming null/default.
			if err = os.WriteFile(path, encoded, 0600); err != nil {
				t.Fatal(err)
			}
			again, err := Load(path)
			if err != nil || !reflect.DeepEqual(c.RecordPriority, again.RecordPriority) {
				t.Fatalf("round trip: %+v %v", again.RecordPriority, err)
			}
		})
	}
}
