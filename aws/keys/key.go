package keys

// GenerateRSAKey loads the specified key from AWS kms
// assuming permissions will allow this.
func GenerateRSAKey(arn string) (interface{}, error) {
	return ReadPrivateKey(arn)
}

// GenerateECKey loads the specified key from AWS KMS
// assuming perrmissions will allow this.
func GenerateECKey(arn string) (interface{}, error) {
	return ReadPrivateKey(arn)
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
