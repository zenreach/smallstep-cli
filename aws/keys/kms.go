package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
)

// ParseDER parses the given DER-encoded bytes and results the public or private
// key encoded.
func parseDER(b []byte) (interface{}, error) {
	key, err := x509.ParsePKIXPublicKey(b)
	if err != nil {
		if key, err = x509.ParsePKCS1PublicKey(b); err != nil {
			return nil, errors.New("error decoding DER; bad format")
		}
	}

	return key, nil
}

func SignAwsKms(arn string, region string, digest []byte, opts crypto.SignerOpts, kty string) ([]byte, error) {
	//
	// Connect to AWS and grab the public key
	//
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(region)})
	if err != nil {
		return nil, err
	}

	// Create KMS service client
	svc := kms.New(sess)

	// Choose the correct algorithm based upon the options
	var signAlg string

	switch kty {
	case "AWS-KMS-RSA":
		switch opts.HashFunc() {
		case crypto.SHA256:
			signAlg = kms.SigningAlgorithmSpecRsassaPkcs1V15Sha256
		case crypto.SHA384:
			signAlg = kms.SigningAlgorithmSpecRsassaPkcs1V15Sha384
		case crypto.SHA512:
			signAlg = kms.SigningAlgorithmSpecRsassaPkcs1V15Sha512
		default:
			return nil, errors.New("unsupported RSA signing algorithm")
		}
	case "AWS-KMS-EC":
		switch opts.HashFunc() {
		case crypto.SHA256:
			signAlg = kms.SigningAlgorithmSpecEcdsaSha256
		case crypto.SHA384:
			signAlg = kms.SigningAlgorithmSpecEcdsaSha384
		case crypto.SHA512:
			signAlg = kms.SigningAlgorithmSpecEcdsaSha512
		default:
			return nil, errors.New("unsupported ECDSA signing algorithm")
		}
	default:
		return nil, errors.New("unknown signing algorithm")
	}

	request := kms.SignInput{
		KeyId:            aws.String(arn),
		MessageType:      aws.String(kms.MessageTypeDigest),
		Message:          digest,
		SigningAlgorithm: aws.String(signAlg),
	}

	result, err := svc.Sign(&request)
	if err != nil {
		return nil, err
	}

	return result.Signature, nil
}

func ReadAwsKms(arn string, region string) (interface{}, error) {
	//
	// Connect to AWS and grab the public key
	//
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(region)})
	if err != nil {
		return nil, err
	}

	// Create KMS service client
	svc := kms.New(sess)

	result, err := svc.GetPublicKey(&kms.GetPublicKeyInput{
		KeyId: aws.String(arn)})
	if result == nil || err != nil {
		return nil, err
	}

	if result.KeyUsage == nil || *result.KeyUsage != "SIGN_VERIFY" {
		return nil, errors.New("AWS KMS Key Usage is not SIGN_VERIFY, cannot use this key")
	}

	if result.SigningAlgorithms == nil {
		return nil, errors.New("no signing algorithms found for this key")
	}

	if result.CustomerMasterKeySpec == nil {
		return nil, errors.New("undefined key AWS key type")
	}

	pub, err := parseDER(result.PublicKey)
	if err != nil {
		return nil, errors.New("failed to parse public key")
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return AwsRsaPrivateKey{
			AwsRsaPublicKey: AwsRsaPublicKey{
				ARN:              *result.KeyId,
				Region:           "us-west-2",
				AwsPublicKeyInfo: *result,
				PublicKey:        pub,
			},
		}, nil
	case *ecdsa.PublicKey:
		return AwsEcPrivateKey{
			AwsEcPublicKey: AwsEcPublicKey{
				ARN:              *result.KeyId,
				Region:           "us-west-2",
				AwsPublicKeyInfo: *result,
				PublicKey:        pub,
			},
		}, nil
	default:
		return nil, fmt.Errorf("unsupported key type %T, currently supports RSA and EC keys", pub)
	}
}
