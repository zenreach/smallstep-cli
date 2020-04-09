package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"

	"github.com/pkg/errors"
)

// GenerateRSAKey loads the specified key from AWS kms
// assuming permissions will allow this.
func GenerateRSAKey(arn string) (interface{}, error) {
	return ReadPrivateKey(arn)
}

// GenerateECKey loads the specified key from AWS KMS
// assuming perrmissions will allow this.
func GenerateECKey(crv string) (interface{}, error) {
	var c elliptic.Curve
	switch crv {
	case "P-256":
		c = elliptic.P256()
	case "P-384":
		c = elliptic.P384()
	case "P-521":
		c = elliptic.P521()
	default:
		return nil, errors.Errorf("invalid value for argument crv (crv: '%s')", crv)
	}

	key, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		return nil, errors.Wrap(err, "error generating EC key")
	}

	return key, nil
}

// ReadPublicKey will connect to AWS, extract the type of key
// and seed the public key object.
func ReadPublicKey(arn string) (interface{}, error) {
	return ReadAwsKms(arn, "us-west-2")
}

// ReadPrivateKey will connect to AWS, extract the type of key
// and seed the public key object.
func ReadPrivateKey(arn string) (interface{}, error) {
	return ReadAwsKms(arn, "us-west-2")
}
