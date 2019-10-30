package FabricBccsp

import (
	"encoding/hex"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/tanhuiya/fabric-crypto/cryptoutil"
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

var badCert = `-----BEGIN CERTIFICATE-----
MIICGTCCAcCgAwIBAgIRSDF/1GXtEud5GQL2CZykkOkwCgYIKoZIzj0EAwIwczEL
MGwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1T
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

var fakeCert = `-----BEGIN CERTIFICATE-----
MIICKTCCAdCgAwIBAgIQNKdAgE+Ow/dtsJxpWNx7mjAKBggqhkjOPQQDAjBzMQsw
CQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNU2FuIEZy
YW5jaXNjbzEZMBcGA1UEChMQb3JnMS5leGFtcGxlLmNvbTEcMBoGA1UEAxMTY2Eu
b3JnMS5leGFtcGxlLmNvbTAeFw0xOTEwMjUwMjM2MDBaFw0yOTEwMjIwMjM2MDBa
MGwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1T
YW4gRnJhbmNpc2NvMQ8wDQYDVQQLEwZjbGllbnQxHzAdBgNVBAMMFlVzZXIxQG9y
ZzEuZXhhbXBsZS5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATuX8Gl8U0m
d2jw2PYh2nd68Ym7LJ2ZvkKy/JkDmyyRYNn0nyCjw7Gst00BZQ/4ZbVZ73s5bvUo
zCTsuLCgd8mVo00wSzAOBgNVHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADArBgNV
HSMEJDAigCAA59kEw+z+G4zJFZTSEYIvJafr06zEYLRv13OdryzgTzAKBggqhkjO
PQQDAgNHADBEAiBL4mvV0oNzHrkqLB+FZ1leih+22PYgYsPALHLHnTWnpAIgCaX/
XESkmkAPme/JQ403xlbL0Ry8YOOmVmitbZtW5wc=
-----END CERTIFICATE-----`

// 实例化私钥
func TestGetPrivKey(t *testing.T)  {
	priKey, err := cryptoutil.DecodePriv([]byte(testPrivKey))
	assert.NoError(t, err)

	priByte := cryptoutil.MarshalPrivateKey(priKey)
	fmt.Println(hex.EncodeToString(priByte))
	priKey2, err := cryptoutil.UnMarshalPrivateKey(priByte)
	assert.Equal(t, priKey, priKey2)
}

func TestGetPubKey(t *testing.T)  {
	pubKey, err := cryptoutil.DecodePub([]byte(testCert))
	assert.NoError(t, err, "verify error")

	privKey, err := cryptoutil.DecodePriv([]byte(testPrivKey))
	assert.NoError(t, err, "verify error")
	assert.Equal(t, privKey.Public(), pubKey)
}

// 公钥序列化
func TestPubToString(t *testing.T) {
	pubKey, _ := cryptoutil.DecodePub([]byte(testCert))
	bytes := cryptoutil.MarshalPubkey(pubKey)
	fmt.Println(hex.EncodeToString(bytes))
	assert.Equal(t, hex.EncodeToString(bytes), "04f2153d2fa175fb700e0f3ed36cb5695e693a708ef6d2277fad3064c6ebb7fe4dd09f0f1598329418c4b944f1591b1332960f0098bc365130a0907efd84acdbdb")
}

func TestStringToPub(t *testing.T) {
	msg := []byte("this is a testmsg")
	privKey, err := cryptoutil.DecodePriv([]byte(testPrivKey))
	assert.NoError(t, err, "privkey export error")
	signature, err := cryptoutil.SignMsg2(msg, privKey)
	assert.NoError(t, err, "signature error")
	pubS := "04f2153d2fa175fb700e0f3ed36cb5695e693a708ef6d2277fad3064c6ebb7fe4dd09f0f1598329418c4b944f1591b1332960f0098bc365130a0907efd84acdbdb"
	b, _  := hex.DecodeString(pubS)
	pubB, _ := cryptoutil.UnMarshalPubKey(b)
	valid, err := cryptoutil.Verifier2(msg, signature, pubB)
	assert.NoError(t, err)
	assert.True(t, valid, "valid should be true")
}

func TestVerifiers(t *testing.T)  {
	msg := []byte("this is a testmsg")
	privKey2, err := cryptoutil.DecodePriv([]byte(testPrivKey))
	signature2, err := cryptoutil.SignMsg2(msg, privKey2)
	assert.NoError(t, err)

	pubKey, err := cryptoutil.DecodePub([]byte(testCert))
	valid, err := cryptoutil.Verifier2(msg, signature2, pubKey)
	assert.NoError(t, err, "verify error")
	assert.Equal(t, true, valid, "verify error")
}

func TestBadVerifiers(t *testing.T)  {
	msg := []byte("this is a testmsg")
	privKey2, err := cryptoutil.DecodePriv([]byte(testPrivKey))
	signature2, err := cryptoutil.SignMsg2(msg, privKey2)
	assert.NoError(t, err)

	pubKey, err := cryptoutil.DecodePub([]byte(fakeCert))
	valid, err := cryptoutil.Verifier2(msg, signature2, pubKey)
	assert.NoError(t, err, "verify error")
	assert.Equal(t, false, valid, "verify error")
}


// 根据公钥生成地址
func TestGetAddressByPub(t *testing.T)  {
	pubKey, _ := cryptoutil.DecodePub([]byte(testCert))
	address, _ := cryptoutil.PublicKeyToAddress(pubKey)
	assert.Equal(t, "0x204bCC42559Faf6DFE1485208F7951aaD800B313", address)
}

// 调用格式
func TestRPCSignFabricTx(t *testing.T)  {
	priKey, err := cryptoutil.DecodePriv([]byte(testPrivKey))
	assert.NoError(t, err)
	priByte := cryptoutil.MarshalPrivateKey(priKey)

	rawData := map[string]interface{}{
		"from": "0x222222222222",
		"to": 	"0x111111111111",
		"amout": 5,
		"gas": 	1,
		"privateKey": hex.EncodeToString(priByte), // 注意参数格式
		"code": 1, // 代表转账
		"fabric": true, // important
	}
	rpcSignPost(rawData) // 调用接口签名
}

func rpcSignPost(data map[string]interface{})  {
	// do nothing
}

