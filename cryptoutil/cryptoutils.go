package cryptoutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
	"math/big"
)

// 将公钥转化为地址
func PublicKeyToAddress(pub *ecdsa.PublicKey) (string, error) {
	address := crypto.PubkeyToAddress(*pub).Hex()
	return address, nil
}

// 将公钥序列化为十六进制字符串
func MarshalPubkey(pub *ecdsa.PublicKey) []byte {
	return elliptic.Marshal(elliptic.P256(),pub.X, pub.Y)
}

// 从十六进制字符串反序列化公钥
func UnMarshalPubKey(pub []byte) (*ecdsa.PublicKey, error) {
	x, y := elliptic.Unmarshal(elliptic.P256(), pub)
	if x == nil {
		return nil, errors.New("unmarshal error")
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

// 将私钥序列化为十六进制字符串
func MarshalPrivateKey(pri *ecdsa.PrivateKey) []byte {
	if pri == nil {
		return nil
	}
	return math.PaddedBigBytes(pri.D, pri.Params().BitSize/8)
}

// 从十六进制字符串反序列化私钥
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
