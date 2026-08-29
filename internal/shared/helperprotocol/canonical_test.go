package helperprotocol

import (
	"bytes"
	"strings"
	"testing"
)

func TestDecodeRejectsNonCanonicalOrAmbiguousJSON(t *testing.T) {
	valid := `{"protocol_version":1,"message_type":"get_receipt_request","domain":"nurproxy.helper.v1","payload":{"operation_id":"op-1","canonical_request_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}`
	if _, err := Decode[Envelope[GetReceiptRequest]]([]byte(valid)); err != nil {
		t.Fatalf("valid envelope rejected: %v", err)
	}

	tests := map[string]string{
		"duplicate key":     `{"protocol_version":1,"protocol_version":1,"message_type":"get_receipt_request","domain":"nurproxy.helper.v1","payload":{"operation_id":"op-1","canonical_request_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}`,
		"case folded field": `{"Protocol_Version":1,"message_type":"get_receipt_request","domain":"nurproxy.helper.v1","payload":{"operation_id":"op-1","canonical_request_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}`,
		"unknown field":     `{"protocol_version":1,"message_type":"get_receipt_request","domain":"nurproxy.helper.v1","payload":{"operation_id":"op-1","canonical_request_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","path":"/etc/passwd"}}`,
		"float":             `{"protocol_version":1.0,"message_type":"get_receipt_request","domain":"nurproxy.helper.v1","payload":{"operation_id":"op-1","canonical_request_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}`,
		"trailing value":    valid + ` {}`,
		"lone surrogate":    strings.Replace(valid, `"op-1"`, `"\ud800"`, 1),
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode[Envelope[GetReceiptRequest]]([]byte(input)); err == nil {
				t.Fatal("ambiguous JSON accepted")
			}
		})
	}
	invalidUTF8 := append([]byte(valid[:20]), 0xff)
	invalidUTF8 = append(invalidUTF8, []byte(valid[20:])...)
	if _, err := Decode[Envelope[GetReceiptRequest]](invalidUTF8); err == nil {
		t.Fatal("invalid UTF-8 accepted")
	}
}

func TestDecodeEnforcesDepthCollectionStringAndFrameBounds(t *testing.T) {
	deep := strings.Repeat(`[`, MaxNestingDepth+1) + `0` + strings.Repeat(`]`, MaxNestingDepth+1)
	if _, err := Decode[any]([]byte(deep)); err == nil {
		t.Fatal("excessive nesting accepted")
	}
	longString := `"` + strings.Repeat("a", MaxStringBytes+1) + `"`
	if _, err := Decode[string]([]byte(longString)); err == nil {
		t.Fatal("oversized string accepted")
	}
	items := `[` + strings.Repeat(`0,`, MaxArrayElements) + `0]`
	if _, err := Decode[[]int]([]byte(items)); err == nil {
		t.Fatal("oversized array accepted")
	}
	if _, err := ReadFrame(bytes.NewReader([]byte{0, 4, 0, 1})); err == nil {
		t.Fatal("oversized declared frame accepted")
	}
}

func TestCanonicalBytesSortsKeysAndDigestIsRepresentationStable(t *testing.T) {
	left := map[string]any{"z": int64(2), "a": "first"}
	right := map[string]any{"a": "first", "z": int64(2)}
	encoded, err := CanonicalBytes(left)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(encoded), `{"a":"first","z":2}`; got != want {
		t.Fatalf("canonical bytes = %s, want %s", got, want)
	}
	leftDigest, err := Digest(left)
	if err != nil {
		t.Fatal(err)
	}
	rightDigest, err := Digest(right)
	if err != nil {
		t.Fatal(err)
	}
	if leftDigest != rightDigest {
		t.Fatalf("equivalent values have different digests: %s != %s", leftDigest, rightDigest)
	}
}

func TestDecodeAllowsOnlySchemaOptionalPointersToBeNull(t *testing.T) {
	type optional struct {
		Child *struct {
			Name string `json:"name"`
		} `json:"child"`
		Items []string `json:"items"`
	}
	if _, err := Decode[optional]([]byte(`{"child":null,"items":[]}`)); err != nil {
		t.Fatalf("optional pointer null rejected: %v", err)
	}
	if _, err := Decode[optional]([]byte(`{"child":null,"items":null}`)); err == nil {
		t.Fatal("non-optional slice null accepted")
	}
}

func TestDecodeAcceptsCanonicalBase64ForByteSlices(t *testing.T) {
	decoded, err := Decode[struct {
		Data []byte `json:"data"`
	}]([]byte(`{"data":"AQID"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.Data, []byte{1, 2, 3}) {
		t.Fatalf("decoded bytes = %v", decoded.Data)
	}
	if _, err := Decode[struct {
		Data []byte `json:"data"`
	}]([]byte(`{"data":[1,2,3]}`)); err == nil {
		t.Fatal("array representation accepted for protocol byte sequence")
	}
}
