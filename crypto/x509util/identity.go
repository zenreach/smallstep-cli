package x509util

import (
	"crypto/x509"
	"io/ioutil"

	"github.com/pkg/errors"
	awskeys "github.com/smallstep/cli/aws/keys"
	"github.com/smallstep/cli/crypto/pemutil"
)

// Identity contains a public/private x509 certificate/key pair.
type Identity struct {
	Crt *x509.Certificate
	Key interface{}
}

// NewIdentity returns a new Identity.
func NewIdentity(c *x509.Certificate, k interface{}) *Identity {
	return &Identity{
		Crt: c,
		Key: k,
	}
}

// LoadIdentityFromDisk load a public certificate and private key (both in PEM
// format) from disk.
func LoadIdentityFromDisk(crtPath, keyPath string, arn string, pemOpts ...pemutil.Options) (*Identity, error) {
	// Read using stepx509 to parse the PublicKey
	crt, err := pemutil.ReadCertificate(crtPath)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var (
		keyBytes []byte
		key      interface{}
	)

	if len(arn) > 0 {
		key, err = awskeys.ReadPrivateKey(arn)
	} else {
		keyBytes, err = ioutil.ReadFile(keyPath)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		pemOpts = append(pemOpts, pemutil.WithFilename(keyPath))
		key, err = pemutil.Parse(keyBytes, pemOpts...)
		if err != nil {
			return nil, errors.WithStack(err)
		}
	}
	return NewIdentity(crt, key), nil
}
