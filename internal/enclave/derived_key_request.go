package enclave

import (
	"encoding/binary"

	"github.com/google/go-sev-guest/client"
)

const derivedKeyGuestFieldSelect = uint64(1 << 5)

func DerivedKeyRequest() *client.SnpDerivedKeyReq {
	return &client.SnpDerivedKeyReq{
		UseVCEK: true,
		GuestFieldSelect: client.GuestFieldSelect{
			TCBVersion: true,
		},
	}
}

func derivedKeyRequestNVData() []byte {
	req := make([]byte, 64)
	binary.LittleEndian.PutUint32(req[0:4], 0)
	binary.LittleEndian.PutUint64(req[8:16], derivedKeyGuestFieldSelect)
	return req
}
