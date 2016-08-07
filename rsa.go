package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"strings"
	"time"
)

const (
	// Encrypt const
	Encrypt = 1
	// Decrypt const
	Decrypt = 2
	// GenerateKey const
	GenerateKey = 3

	// OAEP const
	OAEP = "OAEP"
	// PKCS const
	PKCS = "PKCS"

	// KeyHolder const
	KeyHolder = "rsa_key/"
	// PublicKeyDir const
	PublicKeyDir = KeyHolder + "key.pub"
	// PrivateKeyDir const
	PrivateKeyDir = KeyHolder + "key"
	// SignatureDir const
	SignatureDir = KeyHolder + "rsa.sig"
	// TestFileHolder const
	TestFileHolder = "bm_input/"
	// InFolder const
	InFolder = "in/"
	// OutFolder const
	OutFolder = "out/"
)

// HashingTable xxx
var HashingTable = map[string]crypto.Hash{
	"SHA256":   crypto.SHA256,
	"SHA224":   crypto.SHA224,
	"MD5":      crypto.MD5,
	"MD4":      crypto.MD4,
	"SHA512":   crypto.SHA512,
	"SHA3_512": crypto.SHA3_512,
	"MD5SHA1":  crypto.MD5SHA1,
}

// Command-line flags
var (
	inFile  = flag.String("in", "in.txt", "Path to input file")
	outFile = flag.String("out", "out.txt", "Path to output file")
	label   = flag.String("label", "", "Label to use (filename by default)")
	action  = flag.Int("action", 1, "Encrypt = 1. Decrypt = 2. Generate Key = 3")

	keyLength   = flag.Int("kl", 2048, "Bit size for private key to be generated: 512, 1024, 2048...")
	encryptType = flag.String("et", "OAEP", "Encryption type using Hash or not: PKIP/OAEP")
	hashType    = flag.String("ht", "sha256", "Hash type for OAEP encryption, see https://golang.org/pkg/crypto/#Hash")
)

func main() {
	flag.Parse()

	// Time Start
	startTime := time.Now()
	var data []byte

	switch *action {
	case GenerateKey:
		if *keyLength < 8 {
			log.Fatalf("Sorry, key length should be greater than 8 bit")
		}
		privateKey, err := rsa.GenerateKey(rand.Reader, *keyLength)
		if err != nil {
			log.Fatalf("generate key: %s", err)
		}

		publicKey := &privateKey.PublicKey

		saveKey(privateKey, publicKey)

	case Decrypt:
		segment := getPublicKeyLength() / 8
		hash := HashingTable[strings.ToUpper(*hashType)]
		var start, end int
		// preventing message too long
		if segment < 2*hash.Size()+2 {
			log.Fatalf("your key length is too short, minimum recommend: %d", 2*hash.Size()+2)
		}

		in, privateKey, _ := prepareCrypto(*inFile)
		if *label == "" {
			*label = *outFile
		}

		switch strings.ToUpper(*encryptType) {
		case OAEP:

			for i := range in {
				start = i * segment
				if start+segment < len(in) {
					end = start + segment
				} else {
					end = len(in)
				}
				segmentEncrypt := in[start:end]
				segmentDecrypt, err := rsa.DecryptOAEP(hash.New(), rand.Reader, privateKey, segmentEncrypt, []byte(*label))
				if err != nil {
					log.Fatalf("oaep decrypt: %s, start %d, end %d", err, start, end)
				}
				data = append(data, segmentDecrypt...)

				if end == len(in) {
					break
				}
			}
		case PKCS:

			for i := range in {
				start = i * segment
				if start+segment < len(in) {
					end = start + segment
				} else {
					end = len(in)
				}
				segmentEncrypt := in[start:end]
				segmentDecrypt, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, segmentEncrypt)
				if err != nil {
					log.Fatalf("pkcs decrypt: %s, start %d, end %d", err, start, end)
				}
				data = append(data, segmentDecrypt...)

				if end == len(in) {
					break
				}
			}
		}

		// Write data to output file
		if err := ioutil.WriteFile(*outFile, data, 0644); err != nil {
			log.Fatalf("write output: %s", err)
		}

	case Encrypt:
		segment := getPublicKeyLength() / 8
		hash := HashingTable[strings.ToUpper(*hashType)]
		var start, end int

		// preventing message too long
		if segment < 2*hash.Size()+2 {
			log.Fatalf("your key length is too short, minimum recommend: %d", 2*hash.Size()+2)
		}

		in, _, publicKey := prepareCrypto(*inFile)
		if *label == "" {
			*label = *inFile
		}

		switch strings.ToUpper(*encryptType) {
		case OAEP:

			for i := range in {
				start = i * segment / 2
				if start+segment/2 < len(in) {
					end = start + segment/2
				} else {
					end = len(in)
				}
				byteSequence := in[start:end]

				segmentEncrypt, err := rsa.EncryptOAEP(hash.New(), rand.Reader, publicKey, byteSequence, []byte(*label))
				if err != nil {
					log.Fatalf("oaep encrypt: %s", err)
				}
				data = append(data, segmentEncrypt...)

				if end == len(in) {
					break
				}
			}
		case PKCS:

			for i := range in {
				start = i * segment / 2
				if start+segment/2 < len(in) {
					end = start + segment/2
				} else {
					end = len(in)
				}
				byteSequence := in[start:end]

				segmentEncrypt, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, byteSequence)
				if err != nil {
					log.Fatalf("pkcs encrypt: %s", err)
				}
				data = append(data, segmentEncrypt...)

				if end == len(in) {
					break
				}
			}
		}

		// Write data to input file
		if err := ioutil.WriteFile(*outFile, data, 0644); err != nil {
			log.Fatalf("write inputput: %s", err)
		}
	}

	fmt.Println("finished, elapse: ", time.Since(startTime))
}

func saveKey(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) {
	privBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		},
	)
	ioutil.WriteFile(PrivateKeyDir, privBytes, 0644)

	PubASN1, _ := x509.MarshalPKIXPublicKey(publicKey)
	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: PubASN1,
	})
	ioutil.WriteFile(PublicKeyDir, pubBytes, 0644)
}

func getRSAKey() (*rsa.PrivateKey, *rsa.PublicKey) {

	var block *pem.Block
	pemPrivateData, _ := ioutil.ReadFile(PrivateKeyDir)

	// Extract the PEM-encoded data block
	block, _ = pem.Decode(pemPrivateData)
	if block == nil {
		log.Fatalf("bad key data: %s", "not PEM-encoded")
	}
	if got, want := block.Type, "RSA PRIVATE KEY"; got != want {
		log.Fatalf("unknown key type %q, want %q", got, want)
	}

	// Decode the RSA private key
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("bad private key: %s", err)
	}

	// Public Key can be get from &privKey.PublicKey
	pemPubData, _ := ioutil.ReadFile(PublicKeyDir)

	// Extract the PEM-encoded data block
	block, _ = pem.Decode(pemPubData)
	if block == nil {
		log.Fatalf("bad key data: %s", "not PEM-encoded")
	}
	if got, want := block.Type, "RSA PUBLIC KEY"; got != want {
		log.Fatalf("unknown key type %q, want %q", got, want)
	}

	// Decode the RSA public key
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Fatalf("bad private key: %s", err)
	}

	return privKey, pubKey.(*rsa.PublicKey)
}

func prepareCrypto(filename string) ([]byte, *rsa.PrivateKey, *rsa.PublicKey) {
	// Read the input file
	in, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatalf("input file: %s", err)
	}
	privateKey, publicKey := getRSAKey()

	return in, privateKey, publicKey
}

func getPublicKeyLength() int {
	pemPrivData, _ := ioutil.ReadFile(PrivateKeyDir)
	block, _ := pem.Decode(pemPrivData)

	privKey, _ := x509.ParsePKCS1PrivateKey(block.Bytes)

	return privKey.PublicKey.N.BitLen() + 7
}
