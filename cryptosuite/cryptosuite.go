package cryptosuite

import (
	"FabricBccsp/cryptosuite/core"
	"github.com/pkg/errors"
	"hash"
	"sync"
	"sync/atomic"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/common/flogging"
	bccspSw "github.com/hyperledger/fabric/bccsp/factory"
)

var logger = flogging.MustGetLogger("cryptosuite")

// CryptoSuite provides a wrapper of BCCSP
type CryptoSuite struct {
	BCCSP bccsp.BCCSP
}


//NewCryptoSuite returns cryptosuite adaptor for given bccsp.BCCSP implementation
func NewCryptoSuite(bccsp bccsp.BCCSP) core.CryptoSuite {
	return &CryptoSuite{
		BCCSP: bccsp,
	}
}

//GetKey returns implementation of of cryptosuite.Key
func GetKey(newkey bccsp.Key) core.Key {
	return &key{newkey}
}


// KeyGen is a wrapper of BCCSP.KeyGen
func (c *CryptoSuite) KeyGen(opts core.KeyGenOpts) (k core.Key, err error) {
	key, err := c.BCCSP.KeyGen(opts)
	return GetKey(key), err
}

// KeyImport is a wrapper of BCCSP.KeyImport
func (c *CryptoSuite) KeyImport(raw interface{}, opts core.KeyImportOpts) (k core.Key, err error) {
	key, err := c.BCCSP.KeyImport(raw, opts)
	return GetKey(key), err
}

// GetKey is a wrapper of BCCSP.GetKey
func (c *CryptoSuite) GetKey(ski []byte) (k core.Key, err error) {
	key, err := c.BCCSP.GetKey(ski)
	return GetKey(key), err
}

// Hash is a wrapper of BCCSP.Hash
func (c *CryptoSuite) Hash(msg []byte, opts core.HashOpts) (hash []byte, err error) {
	return c.BCCSP.Hash(msg, opts)
}

// GetHash is a wrapper of BCCSP.GetHash
func (c *CryptoSuite) GetHash(opts core.HashOpts) (h hash.Hash, err error) {
	return c.BCCSP.GetHash(opts)
}

// Sign is a wrapper of BCCSP.Sign
func (c *CryptoSuite) Sign(k core.Key, digest []byte, opts core.SignerOpts) (signature []byte, err error) {
	return c.BCCSP.Sign(k.(*key).key, digest, opts)
}

// Verify is a wrapper of BCCSP.Verify
func (c *CryptoSuite) Verify(k core.Key, signature, digest []byte, opts core.SignerOpts) (valid bool, err error) {
	return c.BCCSP.Verify(k.(*key).key, signature, digest, opts)
}

// Verify is a wrapper of BCCSP.Verify
func (c *CryptoSuite) Verify2(k core.Key, signature, digest []byte, opts core.SignerOpts) (valid bool, err error) {
	return c.BCCSP.Verify(k.(*key).key, signature, digest, opts)
}


type key struct {
	key bccsp.Key
}

func (k *key) Bytes() ([]byte, error) {
	return k.key.Bytes()
}

func (k *key) SKI() []byte {
	return k.key.SKI()
}

func (k *key) Symmetric() bool {
	return k.key.Symmetric()
}

func (k *key) Private() bool {
	return k.key.Private()
}

func (k *key) PublicKey() (core.Key, error) {
	key, err := k.key.PublicKey()
	return GetKey(key), err
}

var initOnce sync.Once
var defaultCryptoSuite core.CryptoSuite
var initialized int32

func initSuite(defaultSuite core.CryptoSuite) error {
	if defaultSuite == nil {
		return errors.New("attempting to set invalid default suite")
	}
	initOnce.Do(func() {
		defaultCryptoSuite = defaultSuite
		atomic.StoreInt32(&initialized, 1)
	})
	return nil
}


//GetDefault returns default core
func GetDefault() core.CryptoSuite {
	if atomic.LoadInt32(&initialized) > 0 {
		return defaultCryptoSuite
	}
	//Set default suite
	logger.Info("No default cryptosuite found, using default SW implementation")

	// Use SW as the default cryptosuite when not initialized properly - should be for testing only
	s, err := GetSuiteWithDefaultEphemeral()
	if err != nil {
		logger.Panicf("Could not initialize default cryptosuite: %s", err)
	}
	err = initSuite(s)
	if err != nil {
		logger.Panicf("Could not set default cryptosuite: %s", err)
	}

	return defaultCryptoSuite
}


//GetSuiteWithDefaultEphemeral returns cryptosuite adaptor for bccsp with default ephemeral options (intended to aid testing)
func GetSuiteWithDefaultEphemeral() (core.CryptoSuite, error) {
	opts := getEphemeralOpts()

	bccsp, err := getBCCSPFromOpts(opts)
	if err != nil {
		return nil, err
	}
	return NewCryptoSuite(bccsp), nil
}

func getBCCSPFromOpts(config *bccspSw.SwOpts) (bccsp.BCCSP, error) {
	f := &bccspSw.SWFactory{}

	opts := &bccspSw.FactoryOpts{
		SwOpts: config,
	}

	csp, err := f.Get(opts)
	if err != nil {
		return nil, errors.Wrapf(err, "Could not initialize BCCSP %s", f.Name())
	}
	return csp, nil
}


func getEphemeralOpts() *bccspSw.SwOpts {
	opts := &bccspSw.SwOpts{
		HashFamily: "SHA2",
		SecLevel:   256,
		Ephemeral:  false,
	}
	logger.Debug("Initialized ephemeral SW cryptosuite with default opts")

	return opts
}
