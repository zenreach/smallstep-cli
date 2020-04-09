package keys

import (
	"crypto"
	"crypto/ecdsa"
	"io"

	"github.com/aws/aws-sdk-go/service/kms"
)

// AwsEcPublicKey represents the public part of an ECDSA key.
type AwsEcPublicKey struct {
	*ecdsa.PublicKey
	ARN              string
	Region           string
	AwsPublicKeyInfo kms.GetPublicKeyOutput
}

// AwsEcPrivateKey represents an ECC key
type AwsEcPrivateKey struct {
	AwsEcPublicKey // public part.
}

// Public returns the public key corresponding to priv.
func (priv AwsEcPrivateKey) Public() crypto.PublicKey {
	// TODO read the Public Key and set the parms from
	// the arn
	return priv.AwsEcPublicKey.PublicKey
}

// Sign signs digest with priv, reading randomness from rand. If opts is a
// *PSSOptions then the PSS algorithm will be used, otherwise PKCS#1 v1.5 will
// be used. digest must be the result of hashing the input message using
// opts.HashFunc().
//
// This method implements crypto.Signer, which is an interface to support keys
// where the private part is kept in, for example, a hardware module. Common
// uses should use the Sign* functions in this package directly.
func (priv AwsEcPrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return SignAwsKms(priv.ARN, "us-west-2", digest, opts, "AWS-KMS-EC")
}
