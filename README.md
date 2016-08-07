# rsa_benchmarking
A demo project

For argument detail: rsa_benchmarking --help

## Prepare benchmark input

Test file is artifical insert, for 10mb file:
```
$ base64 /dev/urandom | head -c 10000000 > file.txt
```

## Generate Key

You should pay some attention to _kl_ flag which indicate RSA keys' size for generating.
For 512 bit RSA:
```
$ rsa_benchmarking -action 3 -kl 512
```

As default, _kl_ is 2048, private and public keys are located in folder _rsa_key_ under PEM encode.

## Encryption Type

OAEP and PKCS are supported. OAEP is default but you can set encryption type via _et_ flag

## Hashing

Hash is needed when performing encryption/decryption, it is set via _ht_ flag. These types of Hash are supported:
```
SHA256
SHA224
MD5
MD4
SHA512
SHA3_512
MD5SHA1
```

*Note*: Hash size by default for each type in BYTE
SHA256: 32 bytes
SHA224: 28 bytes
MD5: 16 bytes
MD4: 16 bytes
SHA512: 64 bytes
SHA3_512: 64 bytes
MD5SHA1: 36 bytes