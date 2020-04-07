package certificate

import (
	"encoding/pem"
	"fmt"
	"io/ioutil"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/aws"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/crypto/x509util"
	"github.com/smallstep/cli/errs"
	"github.com/urfave/cli"
)

func signCommand() cli.Command {
	return cli.Command{
		Name:   "sign",
		Action: cli.ActionFunc(signAction),
		Usage:  "sign a certificate signing request (CSR)",
		UsageText: `**step certificate sign** <csr_file> <crt_file> <key_file>
[**--bundle**]`,
		Description: `**step certificate sign** generates a signed
certificate from a certificate signing request (CSR).

## POSITIONAL ARGUMENTS

<csr_file>
: The path to a certificate signing request (CSR) to be signed.

<crt_file>
: The path to an issuing certificate.

<key_file>
: The path to a private key for signing the CSR.

## EXIT CODES

This command returns 0 on success and \>0 if any error occurs.

## EXAMPLES

Sign a certificate signing request:
'''
$ step certificate sign ./certificate-signing-request.csr \
./issuer-certificate.crt ./issuer-private-key.priv
'''

Sign a certificate signing request and bundle the new certificate with the issuer:
'''
$ step certificate sign ./certificate-signing-request.csr \
./issuer-certificate.crt ./issuer-private-key.priv --bundle
'''`,
		Flags: []cli.Flag{
			cli.BoolFlag{
				Name:  "bundle",
				Usage: `Bundle the new leaf certificate with the signing certificate.`,
			},
			cli.StringFlag{
				Name: "issuer-password-asm-arn",
				Usage: `Specifies the Amazon Secrets Manager ARN (or alias) that will
decrypt the issuer's private key.
Must also specify --issuer-password-asm-key.`,
			},
			cli.StringFlag{
				Name: "issuer-password-asm-key",
				Usage: `Specify the key value pair to extract from the Amazon Secrets
Manager secret. Must also specify --issuer-password-asm-arn.`,
			},
		},
	}
}

func signAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 3); err != nil {
		return err
	}

	pass := []byte{}
	if ctx.String("issuer-password-asm-arn") != "" && ctx.String("issuer-password-asm-key") != "" {
		password, err := aws.ReadSecretManagerSecret(ctx.String("issuer-password-asm-arn"), ctx.String("issuer-password-asm-key"))
		pass = password
		if err != nil {
			return errs.NewExitError(err, 1)
		}
	}

	csrFile := ctx.Args().Get(0)
	crtFile := ctx.Args().Get(1)
	keyFile := ctx.Args().Get(2)

	csrBytes, err := ioutil.ReadFile(csrFile)
	if err != nil {
		return errors.WithStack(err)
	}
	csr, err := x509util.LoadCSRFromBytes(csrBytes)
	if err != nil {
		return errors.WithStack(err)
	}
	if err = csr.CheckSignature(); err != nil {
		return errors.Wrapf(err, "Certificate Request has invalid signature")
	}

	var issuerIdentity *x509util.Identity
	if len(pass) > 0 {
		issuerIdentity, err = x509util.LoadIdentityFromDisk(crtFile, keyFile,
			pemutil.WithPassword(pass))
	} else {
		issuerIdentity, err = x509util.LoadIdentityFromDisk(crtFile, keyFile)
	}

	if err != nil {
		return errors.WithStack(err)
	}

	leafProfile, err := x509util.NewLeafProfileWithCSR(csr, issuerIdentity.Crt,
		issuerIdentity.Key)
	if err != nil {
		return errors.WithStack(err)
	}

	crtBytes, err := leafProfile.CreateCertificate()
	if err != nil {
		return errors.Wrapf(err, "failure creating new leaf certificate from input csr")
	}
	pubPEMs := []*pem.Block{{
		Type:  "CERTIFICATE",
		Bytes: crtBytes,
	}}
	if ctx.Bool("bundle") {
		pubPEMs = append(pubPEMs, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: issuerIdentity.Crt.Raw,
		})
	}
	pubBytes := []byte{}
	for _, pp := range pubPEMs {
		pubBytes = append(pubBytes, pem.EncodeToMemory(pp)...)
	}
	fmt.Printf("%s", string(pubBytes))

	return nil
}
