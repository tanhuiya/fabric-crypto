package cryptoutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"github.com/hyperledger/fabric/bccsp/utils"
	"github.com/pkg/errors"
	"math/big"
)

func Verifier2(msg, signature []byte, pub *ecdsa.PublicKey) (bool, error) {
	hasher := sha256.New()
	hasher.Write(msg)
	digest := hasher.Sum(nil)

	sig := new(ECDSASignature)
	_, err := asn1.Unmarshal(signature, sig)
	// Validate sig
	if sig.R == nil {
		return false, errors.New("invalid signature, R must be different from nil")
	}
	if sig.S == nil {
		return false, errors.New("invalid signature, S must be different from nil")
	}

	if sig.R.Sign() != 1 {
		return false, errors.New("invalid signature, R must be larger than zero")
	}
	if sig.S.Sign() != 1 {
		return false, errors.New("invalid signature, S must be larger than zero")
	}
	lowS, err := IsLowS(pub, sig.S)
	if err != nil {
		return false, err
	}
	if !lowS {
		return false, fmt.Errorf("Invalid S. Must be smaller than half the order [%s][%s].", s, utils.GetCurveHalfOrdersAt(k.Curve))
	}

	return ecdsa.Verify(pub, digest, sig.R, sig.S), nil
}

func SignMsg2(msg []byte, priv *ecdsa.PrivateKey) ([]byte, error) {
	//digest, err := cs.Hash(msg, cryptosuite.GetSHAOpts())
	hasher := sha256.New()
	hasher.Write(msg)
	digest := hasher.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, priv, digest)
	if err != nil {
		return nil, err
	}

	s, _, err = ToLowS(&priv.PublicKey, s)
	if err != nil {
		return nil, err
	}
	signature, err := asn1.Marshal(ECDSASignature{r, s})
	return signature, err
}

type ECDSASignature struct {
	R, S *big.Int
}

func ToLowS(k *ecdsa.PublicKey, s *big.Int) (*big.Int, bool, error) {
	lowS, err := IsLowS(k, s)
	if err != nil {
		return nil, false, err
	}

	if !lowS {
		// Set s to N - s that will be then in the lower part of signature space
		// less or equal to half order
		s.Sub(k.Params().N, s)

		return s, true, nil
	}

	return s, false, nil
}
var (
	curveHalfOrders = map[elliptic.Curve]*big.Int{
		elliptic.P224(): new(big.Int).Rsh(elliptic.P224().Params().N, 1),
		elliptic.P256(): new(big.Int).Rsh(elliptic.P256().Params().N, 1),
		elliptic.P384(): new(big.Int).Rsh(elliptic.P384().Params().N, 1),
		elliptic.P521(): new(big.Int).Rsh(elliptic.P521().Params().N, 1),
	}
)
func IsLowS(k *ecdsa.PublicKey, s *big.Int) (bool, error) {
	halfOrder, ok := curveHalfOrders[k.Curve]
	if !ok {
		return false, fmt.Errorf("curve not recognized [%s]", k.Curve)
	}
	return s.Cmp(halfOrder) != 1, nil
}

func DecodePriKey(priv []byte) (*ecdsa.PrivateKey, error) {
	if len(priv) == 0 {
		return nil, errors.New("Invalid PEM. It must be different from nil.")
	}
	block, _ := pem.Decode(priv)
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		switch key.(type) {
		case *ecdsa.PrivateKey:
			return key.(*ecdsa.PrivateKey), nil
		default:
			return nil, errors.New("Found unknown private key type in PKCS#8 wrapping")
		}
	}
	return nil, errors.New("Found unknown private key type in PKCS")
}
func DecodePubKey(pub []byte) (*ecdsa.PublicKey, error) {
	dcert, _ := pem.Decode(pub)
	if dcert == nil {
		return nil, errors.Errorf("Unable to decode cert bytes [%v]", pub)
	}
	x509Cert, err := x509.ParseCertificate(dcert.Bytes)
	if err != nil {
		return nil, errors.Errorf("Unable to parse cert from decoded bytes: %s", err)
	}
	pk := x509Cert.PublicKey

	switch pk.(type) {
	case *ecdsa.PublicKey:
		return pk.(*ecdsa.PublicKey), nil
	default:
		return nil, errors.New("Certificate's public key type not recognized. Supported keys: [ECDSA, RSA]")
	}
}