package cryptosuitebridge

import (
	"github.com/tanhuiya/fabric-crypto/cryptosuite/core"
	"crypto/ecdsa"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/utils"
)

//GetX509PublicKeyImportOpts options for importing public keys from an x509 certificate
func GetX509PublicKeyImportOpts(ephemeral bool) core.KeyImportOpts {
	return &bccsp.X509PublicKeyImportOpts{Temporary: ephemeral}
}

// PEMtoPrivateKey is a bridge for bccsp utils.PEMtoPrivateKey()
func PEMtoPrivateKey(raw []byte, pwd []byte) (interface{}, error) {
	return utils.PEMtoPrivateKey(raw, pwd)
}

// PrivateKeyToDER marshals is bridge for utils.PrivateKeyToDER
func PrivateKeyToDER(privateKey *ecdsa.PrivateKey) ([]byte, error) {
	return utils.PrivateKeyToDER(privateKey)
}


//GetECDSAPrivateKeyImportOpts options for ECDSA secret key importation in DER format
// or PKCS#8 format.
func GetECDSAPrivateKeyImportOpts(ephemeral bool) core.KeyImportOpts {
	return &bccsp.ECDSAPrivateKeyImportOpts{Temporary: ephemeral}
}