package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	mrand "math/rand"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	// Encrypt const
	Encrypt = 1
	// Decrypt const
	Decrypt = 2

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
	TestFileHolder = "bm_input"
	// InFolder const
	InFolder = "in"
	// OutFolder const
	OutFolder = "out"
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
	inFile      = "in.txt"
	encFile     = "enc.txt"
	decFile     = "out.txt"
	label       = flag.String("label", "", "Label to use (filename by default)")
	fileSize    = flag.Int("size", 10000, "File size to encrypt")
	keyLength   = flag.Int("kl", 4096, "Bit size for private key to be generated: 512, 1024, 2048...")
	loops       = flag.Int("lp", 10, "loops for number of decryption")
	encryptType = flag.String("et", "OAEP", "Encryption type using Hash or not: PKIP/OAEP")
	hashType    = flag.String("ht", "sha256", "Hash type for OAEP encryption, see https://golang.org/pkg/crypto/#Hash")
)

func main() {
	// logfile format: decrypt_keyLength_encryptType_hashType_loops
	// logfile := fmt.Sprintf("./logs/decrypt_%d_%d_%s_%s_%d.txt", *fileSize, *keyLength, *encryptType, *hashType, *loops)
	// f, err := os.OpenFile(logfile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	// if err != nil {
	// 	log.Fatalf("error opening file: %v", err)
	// }
	// defer f.Close()
	// log.SetOutput(f)

	flag.Parse()

	fmt.Println(*fileSize)
	inFile = fmt.Sprintf("%s/file_%d.txt", TestFileHolder, *fileSize)
	encFile = fmt.Sprintf("%s/file_%d_encrypted.txt", InFolder, *fileSize)
	decFile = fmt.Sprintf("%s/file_%d_encrypted.txt", OutFolder, *fileSize)

	// Time Start
	startTime := time.Now()

	executeSGX()
	// generateInputFile()
	// generateKey()
	// encrypt()
	// decrypt()

	log.Println("finished, elapse: ", time.Since(startTime))
}

func executeSGX() {
	cmd := exec.Command("/usr/local/go/bin/go", "test", "crypto/aes", "-bench", ".")
	// cmd.Stdin = strings.NewReader("some input")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("in all caps: %s\n", out.String())
}

func generateInputFile() {
	data := make([]byte, *fileSize)
	mrand.Read(data)
	if err := os.WriteFile(inFile, data, 0644); err != nil {
		log.Fatalf("write inputput: %s", err)
	}
}
func encrypt() {
	log.Println("Encrypting File")
	var data []byte

	segment := getPublicKeyLength() / 8
	hash := HashingTable[strings.ToUpper(*hashType)]
	var start, end int

	// preventing message too long
	if segment < 2*hash.Size()+2 {
		log.Fatalf("your key length is too short, minimum recommend: %d", 2*hash.Size()+2)
	}

	in, _, publicKey := prepareCrypto(inFile)
	if *label == "" {
		*label = inFile
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
			log.Println("start, end", start, end)
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
	if err := os.WriteFile(encFile, data, 0644); err != nil {
		log.Fatalf("write inputput: %s", err)
	}
}

func generateKey() {
	log.Println("Generating Keys...")
	if *keyLength < 8 {
		log.Fatalf("Sorry, key length should be greater than 8 bit")
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, *keyLength)
	if err != nil {
		log.Fatalf("generate key: %s", err)
	}

	publicKey := &privateKey.PublicKey

	saveKey(privateKey, publicKey)
}

func decrypt() {
	log.Println("Decrypting file")
	var data []byte

	segment := getPublicKeyLength() / 8
	log.Println("Segment", segment)
	hash := HashingTable[strings.ToUpper(*hashType)]
	var start, end int
	// preventing message too long
	if segment < 2*hash.Size()+2 {
		log.Fatalf("your key length is too short, minimum recommend: %d", 2*hash.Size()+2)
	}

	in, privateKey, _ := prepareCrypto(encFile)
	if *label == "" {
		*label = decFile
	}
	log.Println("Encrypted File Size:", len(in), "Encrypt:", *encryptType, "Hash:", *hashType, "Key Size:", *keyLength, "Loops:", *loops)

	decryptTime := time.Now()
	switch strings.ToUpper(*encryptType) {
	case OAEP:
		for x := 0; x < *loops; x++ {
			input := make([]byte, len(in))
			copy(input, in)
			loopStartTime := time.Now()
			for i := range input {
				start = i * segment
				if start+segment < len(input) {
					end = start + segment
				} else {
					end = len(input)
				}
				segmentEncrypt := input[start:end]
				segmentDecrypt, err := rsa.DecryptOAEP(hash.New(), rand.Reader, privateKey, segmentEncrypt, []byte(*label))
				if err != nil {
					log.Fatalf("oaep decrypt: %s, start %d, end %d", err, start, end)
				}
				data = append(data, segmentDecrypt...)

				if end == len(input) {
					break
				}
			}
			log.Println("loop", x, ":", time.Since(loopStartTime))
		}
	case PKCS:
		for x := 0; x < *loops; x++ {
			input := make([]byte, len(in))
			copy(input, in)
			loopStartTime := time.Now()
			for i := range input {
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
			log.Println("loop ", x, ": ", time.Since(loopStartTime))
		}
	}
	log.Println("Decryption Time: ", time.Since(decryptTime))

	// Write data to output file
	if err := os.WriteFile(decFile, data, 0644); err != nil {
		log.Fatalf("write output: %s", err)
	}
}

func saveKey(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) {
	privBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		},
	)
	err := os.WriteFile(PrivateKeyDir, privBytes, 0644)
	if err != nil {
		log.Fatalf("write output: %s", err)
	}

	PubASN1, _ := x509.MarshalPKIXPublicKey(publicKey)
	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: PubASN1,
	})
	err = os.WriteFile(PublicKeyDir, pubBytes, 0644)
	if err != nil {
		log.Fatalf("write output: %s", err)
	}
}

func getRSAKey() (*rsa.PrivateKey, *rsa.PublicKey) {
	var block *pem.Block
	pemPrivateData, _ := os.ReadFile(PrivateKeyDir)

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
	pemPubData, _ := os.ReadFile(PublicKeyDir)

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
	in, err := os.ReadFile(filename)
	if err != nil {
		log.Fatalf("input file: %s", err)
	}
	privateKey, publicKey := getRSAKey()

	return in, privateKey, publicKey
}

func getPublicKeyLength() int {
	pemPrivData, _ := os.ReadFile(PrivateKeyDir)
	block, _ := pem.Decode(pemPrivData)

	privKey, _ := x509.ParsePKCS1PrivateKey(block.Bytes)

	return privKey.PublicKey.N.BitLen() + 7
}
