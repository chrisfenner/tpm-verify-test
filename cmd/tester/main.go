// Package main contains the entry logic for tester
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/tcp"
)

var (
	cmdAddr  = flag.String("cmd_addr", "localhost:2321", "TCP address:port for command service")
	platAddr = flag.String("plat_addr", "localhost:2322", "TCP address:port for platform service")
)

func main() {
	flag.Parse()
	if err := mainErr(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func connectToTPM() (transport.TPMCloser, error) {
	tpm, err := tcp.Open(tcp.Config{
		CommandAddress:  *cmdAddr,
		PlatformAddress: *platAddr,
	})
	if err != nil {
		return nil, err
	}
	if err := tpm.PowerOn(); err != nil {
		return nil, err
	}
	_, err = tpm2.Startup{
		StartupType: tpm2.TPMSUClear,
	}.Execute(tpm)
	if err != nil && !errors.Is(err, tpm2.TPMRCInitialize) {
		// Ignore RC_INITIALIZE, that just means the TPM didn't need to be started up.
		return nil, err
	}
	return tpm, nil
}

func getPub(pub ecdsa.PublicKey, nameAlg tpm2.TPMIAlgHash, hashAlg tpm2.TPMIAlgHash) tpm2.TPMTPublic {
	if pub.Curve != elliptic.P256() {
		panic("not P256")
	}
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: nameAlg,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt: true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Symmetric: tpm2.TPMTSymDefObject{
				Algorithm: tpm2.TPMAlgNull,
			},
			Scheme: tpm2.TPMTECCScheme{
				Scheme: tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUAsymScheme(
					tpm2.TPMAlgECDSA,
					&tpm2.TPMSSigSchemeECDSA{
						HashAlg: hashAlg,
					},
				),
			},
			CurveID: tpm2.TPMECCNistP256,
			KDF: tpm2.TPMTKDFScheme{
				Scheme: tpm2.TPMAlgNull,
			},
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{
				Buffer: pub.X.Bytes(),
			},
			Y: tpm2.TPM2BECCParameter{
				Buffer: pub.Y.Bytes(),
			},
		}),
	}
}

func mainErr() error {
	tpm, err := connectToTPM()
	if err != nil {
		return fmt.Errorf("could not connect to TPM: %w", err)
	}
	defer tpm.Close()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("could not generate key: %w", err)
	}

	for _, testCase := range []struct {
		nameAlg   tpm2.TPMAlgID
		schemeAlg tpm2.TPMAlgID
	}{
		{
			nameAlg:   tpm2.TPMAlgSHA256,
			schemeAlg: tpm2.TPMAlgSHA256,
		},
		{
			nameAlg:   tpm2.TPMAlgSHA1,
			schemeAlg: tpm2.TPMAlgSHA256,
		},
		{
			nameAlg:   tpm2.TPMAlgSHA256,
			schemeAlg: tpm2.TPMAlgSHA1,
		},
		{
			// Fails because the name algorithm is not valid for signing
			nameAlg:   tpm2.TPMAlgNull,
			schemeAlg: tpm2.TPMAlgSHA256,
		},
		{
			// Fails because the scheme algorithm is not valid for signing
			nameAlg:   tpm2.TPMAlgSHA256,
			schemeAlg: tpm2.TPMAlgNull,
		},
		{
			// Fails because the scheme algorithm is not valid for signing
			nameAlg:   tpm2.TPMAlgNull,
			schemeAlg: tpm2.TPMAlgNull,
		},
	} {
		fmt.Printf("Name alg: %v, scheme alg: %v\n", testCase.nameAlg, testCase.schemeAlg)

		if err := runTest(key, tpm, testCase.nameAlg, testCase.schemeAlg); err != nil {
			fmt.Printf("  Error: %v\n", err)
		} else {
			fmt.Printf("  OK\n")
		}
	}

	return nil
}

func runTest(key *ecdsa.PrivateKey, tpm transport.TPM, nameAlg tpm2.TPMIAlgHash, schemeAlg tpm2.TPMIAlgHash) error {
	keyPub := tpm2.New2B(getPub(key.PublicKey, nameAlg, schemeAlg))

	load := tpm2.LoadExternal{
		InPublic:  keyPub,
		Hierarchy: tpm2.TPMRHOwner,
	}

	loaded, err := load.Execute(tpm)
	if err != nil {
		return fmt.Errorf("could not load: %v", err)
	}
	defer tpm2.FlushContext{
		FlushHandle: loaded.ObjectHandle,
	}.Execute(tpm)

	keyName := loaded.Name.Buffer
	if len(keyName) == 0 {
		// LoadExternal with ALG_NULL gives an empty name. Create the name ourselves.
		keyName = []byte{0x00, 0x10}
	}

	auth, err := tpm2.StartAuthSession{
		NonceCaller: tpm2.TPM2BNonce{
			Buffer: make([]byte, 16),
		},
		SessionType: tpm2.TPMSEPolicy,
		AuthHash:    tpm2.TPMAlgSHA256,
		TPMKey:      tpm2.TPMRHNull,
	}.Execute(tpm)
	if err != nil {
		return fmt.Errorf("could not start policy session: %v", err)
	}
	defer tpm2.FlushContext{
		FlushHandle: auth.SessionHandle,
	}.Execute(tpm)

	// Sign the empty policy (which is the current value of the policy session we just started) and try to use it for PolicyAuthorize
	toBeSigned := make([]byte, 32)
	// Note that we use the name algorithm, and not the scheme algorithm, for the signature.
	ticket, err := signVerify(key, loaded.ObjectHandle, tpm, toBeSigned, nameAlg)
	if err != nil {
		return err
	}
	_, err = tpm2.PolicyAuthorize{
		PolicySession: auth.SessionHandle,
		ApprovedPolicy: tpm2.TPM2BDigest{
			Buffer: make([]byte, 32),
		},
		KeySign:     tpm2.TPM2BName{Buffer: keyName},
		CheckTicket: *ticket,
	}.Execute(tpm)
	if err != nil {
		return fmt.Errorf("failed PolicyAuthorize: %v", err)
	}
	tpm2.FlushContext{
		FlushHandle: auth.SessionHandle,
	}.Execute(tpm)

	return nil
}

func signVerify(key *ecdsa.PrivateKey, verifier tpm2.TPMHandle, tpm transport.TPM, message []byte, hashAlg tpm2.TPMIAlgHash) (*tpm2.TPMTTKVerified, error) {
	alg, err := hashAlg.Hash()
	h := alg.New()
	h.Write(message)
	digest := h.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return nil, fmt.Errorf("could not sign: %v", err)
	}

	verified, err := tpm2.VerifySignature{
		KeyHandle: verifier,
		Digest: tpm2.TPM2BDigest{
			Buffer: digest[:],
		},
		Signature: tpm2.TPMTSignature{
			SigAlg: tpm2.TPMAlgECDSA,
			Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgECDSA, &tpm2.TPMSSignatureECC{
				Hash: hashAlg,
				SignatureR: tpm2.TPM2BECCParameter{
					Buffer: r.Bytes(),
				},
				SignatureS: tpm2.TPM2BECCParameter{
					Buffer: s.Bytes(),
				},
			}),
		},
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("could not verify: %v", err)
	}

	return &verified.Validation, nil
}
