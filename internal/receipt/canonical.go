package receipt

import (
	"encoding/json"

	"github.com/gowebpki/jcs"
)

func Canonicalize(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return jcs.Transform(raw)
}
