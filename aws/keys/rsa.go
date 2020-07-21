package keys

import (
	"crypto"
	"crypto/rsa"
	"io"

	"github.com/aws/aws-sdk-go/service/kms"
)

// AwsRsaPublicKey represents the public part of an RSA key.
type AwsRsaPublicKey struct {
	*rsa.PublicKey          // public part.
	ARN              string // AWS ARN in KMS that represents the RSA Key Pair
	Region           string
	AwsPublicKeyInfo kms.GetPublicKeyOutput
}

// AwsRsaPrivateKey represents an RSA key
type AwsRsaPrivateKey struct {
	AwsRsaPublicKey // public part.
}

// Public returns the public key corresponding to priv.
func (priv AwsRsaPrivateKey) Public() crypto.PublicKey {
	return priv.AwsRsaPublicKey.PublicKey
}

// Sign signs digest with priv, reading randomness from rand. If opts is a
// *PSSOptions then the PSS algorithm will be used, otherwise PKCS#1 v1.5 will
// be used. digest must be the result of hashing the input message using
// opts.HashFunc().
//
// This method implements crypto.Signer, which is an interface to support keys
// where the private part is kept in, for example, a hardware module. Common
// uses should use the Sign* functions in this package directly.
func (priv AwsRsaPrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return SignAwsKms(priv.ARN, "us-west-2", digest, opts, "AWS-KMS-RSA")
}
