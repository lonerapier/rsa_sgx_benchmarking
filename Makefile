all: 
	rsa_benchmarking -action 3 -kl 512
	rsa_benchmarking -action 1 -ht "SHA256" -in bm_input/file_text.txt -out in/file_text_encrypted.txt -label "HCMUS-K25"
	rsa_benchmarking -action 2 -ht "SHA256" -in in/file_text_encrypted.txt -out out/file_text_decrypted.txt -label "HCMUS-K25"

	rsa_benchmarking -action 1 -ht "SHA256" -in bm_input/file_1mb.txt -out in/file_1mb_encrypted.txt -label "HCMUS-K25" -et "PKCS"
	rsa_benchmarking -action 2 -ht "SHA256" -in in/file_1mb_encrypted.txt -out out/file_1mb_decrypted.txt -label "HCMUS-K25" -et "PKCS"