package receipt

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

const nonceHexLen = 64

func ValidateChallengeNonce(challengeHex string) error {
	if challengeHex == "" {
		return nil
	}
	if len(challengeHex) != nonceHexLen {
		return fmt.Errorf("challenge_nonce must be a 64-character hex string")
	}
	nonce, err := hex.DecodeString(challengeHex)
	if err != nil || len(nonce) != 32 {
		return fmt.Errorf("challenge_nonce must be a 64-character hex string")
	}
	return nil
}

func resolveNonce(challengeHex string) ([]byte, string, error) {
	if challengeHex == "" {
		nonce := make([]byte, 32)
		if _, err := rand.Read(nonce); err != nil {
			return nil, "", err
		}
		return nonce, hex.EncodeToString(nonce), nil
	}
	if err := ValidateChallengeNonce(challengeHex); err != nil {
		return nil, "", err
	}
	nonce, _ := hex.DecodeString(challengeHex)
	return nonce, challengeHex, nil
}
