# rsa_sgx_benchmarking

An experiment to benchmark RSA encryption and decryption of 1kb and 10kb ciphertext in SGX/Non-SGX settings using RSA2048, RSA4096, RSA8192, RSA16384 in Gramine libOS.

For argument detail: `rsa_benchmarking --help`

## Benchmarks

Below are the benchmarks on the OVH server using [rsa.go](rsa.go) script.

| File Size | Key Size | Loops | SGX | Non-SGX |
| --------- | -------- | ----- | --- | ------- |
| 1kb | 2048 | 10 | 13.639ms | 13.911046ms |
| 1kb | 4096 | 10 | 39.712ms | 35.782381ms |
| 1kb | 8192 | 10 | 130.994ms | 124.677277ms |
| 1kb | 16384 | 10 | 489.981ms | 478.208616ms |
| 10kb | 2048 | 10 | 157.537ms | 123.963205ms |
| 10kb | 4096 | 10 | 409.373ms | 384.027615ms |
| 10kb | 8192 | 10 | 1.31066s | 1.233469675s |
| 10kb | 16384 | 10 | 4.931584s | 4.776776425s |

## Usage

1. To test the benchmarks in SGX, use `SGX=1` flag during compiling.

	```bash
	make clean && make SGX=1 all
	sudo gramine-sgx ./rsa_benchmarking -size 10000 -et "OAEP" -lp 10 -kl 4096
	```

2. To test directly:

	```bash
	make build
	make oaep
	```

> Note: Gramine SGX manifest mounts `rsa_key`, `in`, `out`, `bm_input` directories to `/rsa_key`, `/in`, `/out`, `/bm_input` respectively. Make sure to modify `rsa.go`'s `TestFileHolder` var.

### Prepare benchmark input

Test file is artifical insert, for 10mb file:

```bash
base64 /dev/urandom | head -c 10000000 > file.txt
```

### Generate Key

You should pay some attention to _kl_ flag which indicate RSA keys' size for generating.

For 512 bit RSA:

```bash
./rsa_benchmarking -kl 512
```

As default, _kl_ is 4096, private and public keys are located in folder _rsa_key_ under PEM encode.

### Encryption Type

OAEP and PKCS are supported. OAEP is default but you can set encryption type via _et_ flag

```bash
./rsa_benchmarking -et "OAEP"
```

### Hashing

Hash is needed when performing encryption/decryption, it is set via _ht_ flag. These types of Hash are supported:

```other
SHA256
SHA224
MD5
MD4
SHA512
SHA3_512
MD5SHA1
```

#### Examples

```bash
./rsa_benchmarking -ht SHA512
```

*Note*: Hash size by default for each type in BYTE

- `SHA256`: 32 bytes
- `SHA224`: 28 bytes
- `MD5`: 16 bytes
- `MD4`: 16 bytes
- `SHA512`: 64 bytes
- `SHA3_512`: 64 bytes
- `MD5SHA1`: 36 bytes

### Loops

Number of times to decrypt the encrypted file using _lp_ flag. Default value is `10`.

```bash
./rsa_benchmarking -lp 10
```

### Size

Size of the ciphertext to be encrypted and decrypted using _size_ flag. Default size is `1000`.

```bash
./rsa_benchmarking -size 10000
```

## Credits

- [rsa_benchmarking](https://github.com/keymastervn/rsa_benchmarking)