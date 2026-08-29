package helperprotocol

import "testing"

func FuzzStrictDecode(f *testing.F) {
	f.Add([]byte(`{"protocol_version":1,"message_type":"get_receipt_request","domain":"nurproxy.helper.v1","payload":{"operation_id":"op-1","canonical_request_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}`))
	f.Add([]byte(`{"protocol_version":1,"protocol_version":2}`))
	f.Add([]byte{0xff, 0xfe})
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > MaxFrameBytes+1 {
			input = input[:MaxFrameBytes+1]
		}
		_, _ = Decode[Envelope[GetReceiptRequest]](input)
	})
}
