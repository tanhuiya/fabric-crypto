package cryptoutil

import (
	"github.com/tanhuiya/fabric-crypto/cryptosuite/core"
	factory "github.com/tanhuiya/fabric-crypto/internal/hyperledger/fabric-ca/sdkpatch/cryptosuitebridge"
	"github.com/tanhuiya/fabric-crypto/internal/hyperledger/fabric-ca/util"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/utils"
	"github.com/pkg/errors"
	//"github.com/ethereum/go-ethereum/crypto"
)

// GetPublicKeyFromCert will return public key the from cert
func GetPublicKeyFromCert(cert []byte, cs core.CryptoSuite) (core.Key, error) {

	dcert, _ := pem.Decode(cert)
	if dcert == nil {
		return nil, errors.Errorf("Unable to decode cert bytes [%v]", cert)
	}

	x509Cert, err := x509.ParseCertificate(dcert.Bytes)
	if err != nil {
		return nil, errors.Errorf("Unable to parse cert from decoded bytes: %s", err)
	}

	// get the public key in the right format
	key, err := cs.KeyImport(x509Cert, factory.GetX509PublicKeyImportOpts(true))
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to import certificate's public key")
	}

	return key, nil
}

func GetPrivKeyFromKey (key []byte, cs core.CryptoSuite) (core.Key, error) {
	privateKey, err := util.ImportBCCSPKeyFromPEMBytes(key, cs, true)
	return privateKey, err
}

func SignMsg(msg []byte, priv core.Key, cs core.CryptoSuite) ([]byte, error) {
	//digest, err := cs.Hash(msg, cryptosuite.GetSHAOpts())
	hasher := sha256.New()
	hasher.Write(msg)
	digest := hasher.Sum(nil)

	signature, err := cs.Sign(priv, digest, nil)
	return signature, err
}

func ValidSignature(msg []byte, pub core.Key, signature []byte, cs core.CryptoSuite) (bool, error) {
	hasher := sha256.New()
	hasher.Write(msg)
	digest := hasher.Sum(nil)
	valid, err := cs.Verify(pub, signature, digest, nil)
	return valid, err
}

func VerifyFromPubString(msg, pubstr, signature []byte) (bool, error) {
	pub, err := x509.ParsePKIXPublicKey(pubstr)
	if err != nil {
		return false, errors.Wrap(err, "get pubkey error")
	}
	marshalPub := pub.(*ecdsa.PublicKey)

	hasher := sha256.New()
	hasher.Write(msg)
	digest := hasher.Sum(nil)

	return verifyECDSA(marshalPub, signature, digest, nil)
}

func verifyECDSA(k *ecdsa.PublicKey, signature, digest []byte, opts bccsp.SignerOpts) (bool, error) {
	r, s, err := utils.UnmarshalECDSASignature(signature)
	if err != nil {
		return false, fmt.Errorf("Failed unmashalling signature [%s]", err)
	}

	lowS, err := utils.IsLowS(k, s)
	if err != nil {
		return false, err
	}

	if !lowS {
		return false, fmt.Errorf("Invalid S. Must be smaller than half the order [%s][%s].", s, utils.GetCurveHalfOrdersAt(k.Curve))
	}

	return ecdsa.Verify(k, digest, r, s), nil
}

func PublicKeyToAddress(pub core.Key) (string, error) {
	pubbyte, err := pub.Bytes()
	if err != nil {
		return "", errors.Wrap(err, "marshal error")
	}
	return EcdsaPubToAddress(pubbyte)
}

func EcdsaPubToAddress(pubByte []byte) (string, error) {
	pubecdsa, err := x509.ParsePKIXPublicKey(pubByte)
	if err != nil {
		return "", errors.Wrap(err, "get pubkey error")
	}
	marshalPub := pubecdsa.(*ecdsa.PublicKey)
	address := crypto.PubkeyToAddress(*marshalPub).Hex()
	return address, nil
}