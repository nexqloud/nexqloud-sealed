package kdf

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/hkdf"
)

type FederationSaltState struct {
	Epoch int    `json:"epoch"`
	Salt  string `json:"salt"`
}

var saltMu sync.Mutex

func LoadFederationSalt(path string) (FederationSaltState, error) {
	if path == "" {
		return FederationSaltState{}, fmt.Errorf("federation salt path is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return bootstrapFederationSalt(path)
		}
		return FederationSaltState{}, err
	}
	var state FederationSaltState
	if err := json.Unmarshal(data, &state); err != nil {
		return FederationSaltState{}, fmt.Errorf("decode federation salt: %w", err)
	}
	if state.Epoch < 1 || state.Salt == "" {
		return FederationSaltState{}, fmt.Errorf("invalid federation salt state")
	}
	return state, nil
}

func bootstrapFederationSalt(path string) (FederationSaltState, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return FederationSaltState{}, err
	}
	state := FederationSaltState{
		Epoch: 1,
		Salt:  hex.EncodeToString(salt),
	}
	if err := saveFederationSalt(path, state); err != nil {
		return FederationSaltState{}, err
	}
	return state, nil
}

func RotateFederationSalt(path string) (int, []byte, error) {
	saltMu.Lock()
	defer saltMu.Unlock()

	state, err := LoadFederationSalt(path)
	if err != nil {
		return 0, nil, err
	}

	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return 0, nil, err
	}
	state.Epoch++
	state.Salt = hex.EncodeToString(salt)
	if err := saveFederationSalt(path, state); err != nil {
		return 0, nil, err
	}
	return state.Epoch, salt, nil
}

func FederationSaltBytes(path string) ([]byte, int, error) {
	state, err := LoadFederationSalt(path)
	if err != nil {
		return nil, 0, err
	}
	salt, err := hex.DecodeString(state.Salt)
	if err != nil {
		return nil, 0, fmt.Errorf("decode federation salt: %w", err)
	}
	return salt, state.Epoch, nil
}

func saveFederationSalt(path string, state FederationSaltState) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func DeriveDEKWithFederation(seed, chipSecret, claimHash, attestBind []byte, tenantID string, version int, fedSalt []byte, epoch int) ([]byte, error) {
	ikm := append(seed, chipSecret...)
	epochBytes := []byte(fmt.Sprintf("|epoch:%d|", epoch))
	salt := append(append(claimHash, attestBind...), append(fedSalt, epochBytes...)...)
	info := []byte(fmt.Sprintf("sealed-dek/1|%s|v%d", tenantID, version))

	r := hkdf.New(sha256.New, ikm, salt, info)
	dek := make([]byte, dekLength)
	if _, err := io.ReadFull(r, dek); err != nil {
		return nil, err
	}
	return dek, nil
}
