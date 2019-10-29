package cryptoutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
	//"github.com/ethereum/go-ethereum/crypto"
)



func PublicKeyToAddress(pub *ecdsa.PublicKey) (string, error) {
	address := crypto.PubkeyToAddress(*pub).Hex()
	return address, nil
}

func MarshalPubkey(pub *ecdsa.PublicKey) []byte {
	return elliptic.Marshal(elliptic.P256(),pub.X, pub.Y)
}

func UnMarshalPubKey(pub []byte) (*ecdsa.PublicKey, error) {
	x, y := elliptic.Unmarshal(elliptic.P256(), pub)
	if x == nil {
		return nil, errors.New("unmarshal error")
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

