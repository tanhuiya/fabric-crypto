package FabricBccsp

import (
	"FabricBccsp/cryptosuite"
	"FabricBccsp/cryptoutil"
	"encoding/hex"
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

var testPrivKey = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgp4qKKB0WCEfx7XiB
5Ul+GpjM1P5rqc6RhjD5OkTgl5OhRANCAATyFT0voXX7cA4PPtNstWleaTpwjvbS
J3+tMGTG67f+TdCfDxWYMpQYxLlE8VkbEzKWDwCYvDZRMKCQfv2ErNvb
-----END PRIVATE KEY-----`


var testCert = `-----BEGIN CERTIFICATE-----
MIICGTCCAcCgAwIBAgIRALR/1GXtEud5GQL2CZykkOkwCgYIKoZIzj0EAwIwczEL
MAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNhbiBG
cmFuY2lzY28xGTAXBgNVBAoTEG9yZzEuZXhhbXBsZS5jb20xHDAaBgNVBAMTE2Nh
Lm9yZzEuZXhhbXBsZS5jb20wHhcNMTcwNzI4MTQyNzIwWhcNMjcwNzI2MTQyNzIw
WjBbMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMN
U2FuIEZyYW5jaXNjbzEfMB0GA1UEAwwWVXNlcjFAb3JnMS5leGFtcGxlLmNvbTBZ
MBMGByqGSM49AgEGCCqGSM49AwEHA0IABPIVPS+hdftwDg8+02y1aV5pOnCO9tIn
f60wZMbrt/5N0J8PFZgylBjEuUTxWRsTMpYPAJi8NlEwoJB+/YSs29ujTTBLMA4G
A1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMCsGA1UdIwQkMCKAIIeR0TY+iVFf
mvoEKwaToscEu43ZXSj5fTVJornjxDUtMAoGCCqGSM49BAMCA0cAMEQCID+dZ7H5
AiaiI2BjxnL3/TetJ8iFJYZyWvK//an13WV/AiARBJd/pI5A7KZgQxJhXmmR8bie
XdsmTcdRvJ3TS/6HCA==
-----END CERTIFICATE-----`


func TestGetPrivKey(t *testing.T)  {
	cs := cryptosuite.GetDefault()
	privKey, err := cryptoutil.GetPrivKeyFromKey([]byte(testPrivKey), cs)
	if err != nil {
		fmt.Println(privKey)
	}
}

func TestGetPubKey(t *testing.T)  {
	cs := cryptosuite.GetDefault()
	pubKey, err := cryptoutil.GetPublicKeyFromCert([]byte(testCert), cs)
	if err != nil {
		fmt.Println(pubKey)
	}
}

func TestPubAndPrivMatch(t *testing.T)  {
	cs := cryptosuite.GetDefault()
	pubKey, err := cryptoutil.GetPublicKeyFromCert([]byte(testCert), cs)
	privKey, err := cryptoutil.GetPrivKeyFromKey([]byte(testPrivKey), cs)
	assert.NoError(t, err, "should not have error")
	pub1, err := privKey.PublicKey()

	b1, _ := pub1.Bytes()
	b2, _ := pubKey.Bytes()
	assert.Equal(t, b1, b2)
}

func TestVerify(t *testing.T) {
	cs := cryptosuite.GetDefault()
	privKey, err := cryptoutil.GetPrivKeyFromKey([]byte(testPrivKey), cs)
	assert.NoError(t, err, "privkey export error")

	pubKey, err := cryptoutil.GetPublicKeyFromCert([]byte(testCert), cs)

	msg := []byte("this is a testmsg")
	signature, err := cryptoutil.SignMsg(msg, privKey, cs)
	assert.NoError(t, err, "signature error")

	valid, err := cryptoutil.ValidSignature(msg, pubKey, signature, cs)
	assert.NoError(t, err, "verify error")
	assert.Equal(t, true, valid, "verify error")
}

func TestPrivToPub(t *testing.T)  {
	cs := cryptosuite.GetDefault()
	privKey, err := cryptoutil.GetPrivKeyFromKey([]byte(testPrivKey), cs)
	assert.NoError(t, err, "privkey export error")

	pubKey, err := privKey.PublicKey()

	msg := []byte("this is a testmsg")
	signature, err := cryptoutil.SignMsg(msg, privKey, cs)
	assert.NoError(t, err, "signature error")

	valid, err := cryptoutil.ValidSignature(msg, pubKey, signature, cs)
	assert.NoError(t, err, "verify error")
	assert.Equal(t, true, valid, "verify error")
}

func TestPubToString(t *testing.T) {
	cs := cryptosuite.GetDefault()
	pubKey, _ := cryptoutil.GetPublicKeyFromCert([]byte(testCert), cs)
	bytes, _ := pubKey.Bytes()
	fmt.Println(hex.EncodeToString(bytes))
}

func TestStringToPub(t *testing.T) {
	msg := []byte("this is a testmsg")
	cs := cryptosuite.GetDefault()
	privKey, err := cryptoutil.GetPrivKeyFromKey([]byte(testPrivKey), cs)
	assert.NoError(t, err, "privkey export error")
	signature, err := cryptoutil.SignMsg(msg, privKey, cs)
	assert.NoError(t, err, "signature error")
	pubS := "3059301306072a8648ce3d020106082a8648ce3d03010703420004f2153d2fa175fb700e0f3ed36cb5695e693a708ef6d2277fad3064c6ebb7fe4dd09f0f1598329418c4b944f1591b1332960f0098bc365130a0907efd84acdbdb"
	pubB, _ := hex.DecodeString(pubS)
	cryptoutil.VerifyFromPubString(msg, pubB, signature)
}

// 根据公钥生成地址
func TestGetAddressByPub(t *testing.T)  {
	cs := cryptosuite.GetDefault()
	pubKey, _ := cryptoutil.GetPublicKeyFromCert([]byte(testCert), cs)

	address, _ := cryptoutil.PublicKeyToAddress(pubKey)
	fmt.Println(address)
}