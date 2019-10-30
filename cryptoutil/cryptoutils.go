package cryptoutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
	"math/big"
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

func MarshalPrivateKey(pri *ecdsa.PrivateKey) []byte {
	if pri == nil {
		return nil
	}
	return math.PaddedBigBytes(pri.D, pri.Params().BitSize/8)
}

func UnMarshalPrivateKey(privByte []byte) (*ecdsa.PrivateKey, error) {
	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = elliptic.P256()

	priv.D = new(big.Int).SetBytes(privByte)
	priv.PublicKey.X, priv.PublicKey.Y = priv.PublicKey.Curve.ScalarBaseMult(privByte)
	if priv.PublicKey.X == nil {
		return nil, errors.New("invalid private key")
	}
	return priv, nil
}
