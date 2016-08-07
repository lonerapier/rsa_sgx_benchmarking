all: 
	rsa_benchmarking -action 3 -kl 512
	rsa_benchmarking -action 3 -kl 1024
	rsa_benchmarking -action 3 -kl 2048
	rsa_benchmarking -action 3 -kl 4096

pkcs: 
	# 1kb
	rsa_benchmarking -action 1 -in bm_input/file_1kb.txt -out in/file_1kb_encrypted.txt -et "PKCS"
	rsa_benchmarking -action 2 -in in/file_1kb_encrypted.txt -out out/file_1kb_decrypted.txt -et "PKCS"

	# 10kb
	rsa_benchmarking -action 1 -in bm_input/file_10kb.txt -out in/file_10kb_encrypted.txt -et "PKCS"
	rsa_benchmarking -action 2 -in in/file_10kb_encrypted.txt -out out/file_10kb_decrypted.txt -et "PKCS"

	#100kb
	rsa_benchmarking -action 1 -in bm_input/file_100kb.txt -out in/file_100kb_encrypted.txt -et "PKCS"
	rsa_benchmarking -action 2 -in in/file_100kb_encrypted.txt -out out/file_100kb_decrypted.txt -et "PKCS"

	# 1mb
	rsa_benchmarking -action 1 -in bm_input/file_1mb.txt -out in/file_1mb_encrypted.txt -et "PKCS"
	rsa_benchmarking -action 2 -in in/file_1mb_encrypted.txt -out out/file_1mb_decrypted.txt -et "PKCS"

oaep:
	#1kb
	rsa_benchmarking -action 1 -ht "SHA256" -in bm_input/file_1kb.txt -out in/file_1kb_encrypted.txt -label "HCMUS-K25"
	rsa_benchmarking -action 2 -ht "SHA256" -in in/file_1kb_encrypted.txt -out out/file_1kb_decrypted.txt -label "HCMUS-K25"

	#10kb
	rsa_benchmarking -action 1 -ht "SHA256" -in bm_input/file_10kb.txt -out in/file_10kb_encrypted.txt -label "HCMUS-K25"
	rsa_benchmarking -action 2 -ht "SHA256" -in in/file_10kb_encrypted.txt -out out/file_10kb_decrypted.txt -label "HCMUS-K25"

	#100kb
	rsa_benchmarking -action 1 -ht "SHA256" -in bm_input/file_100kb.txt -out in/file_100kb_encrypted.txt -label "HCMUS-K25"
	rsa_benchmarking -action 2 -ht "SHA256" -in in/file_100kb_encrypted.txt -out out/file_100kb_decrypted.txt -label "HCMUS-K25"

	#1mb
	rsa_benchmarking -action 1 -ht "SHA256" -in bm_input/file_1mb.txt -out in/file_1mb_encrypted.txt -label "HCMUS-K25"
	rsa_benchmarking -action 2 -ht "SHA256" -in in/file_1mb_encrypted.txt -out out/file_1mb_decrypted.txt -label "HCMUS-K25"
