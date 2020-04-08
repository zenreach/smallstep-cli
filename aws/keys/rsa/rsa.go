package rsa

import (
	"crypto"
	r "crypto/rsa"
	"io"
)

// AwsRsaPublicKey represents the public part of an RSA key.
type AwsRsaPublicKey struct {
	r.PublicKey // public part.
}

// AwsRsaPrivateKey represents an RSA key
type AwsRsaPrivateKey struct {
	AwsRsaPublicKey        // public part.
	ARN             string // AWS ARN in KMS that represents the RSA Key Pair
}

// Public returns the public key corresponding to priv.
func (priv *AwsRsaPrivateKey) Public() crypto.PublicKey {
	return &priv.PublicKey
}

// Sign signs digest with priv, reading randomness from rand. If opts is a
// *PSSOptions then the PSS algorithm will be used, otherwise PKCS#1 v1.5 will
// be used. digest must be the result of hashing the input message using
// opts.HashFunc().
//
// This method implements crypto.Signer, which is an interface to support keys
// where the private part is kept in, for example, a hardware module. Common
// uses should use the Sign* functions in this package directly.
func (priv *AwsRsaPrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}
