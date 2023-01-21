################################# CONSTANTS ###################################

ENCLAVE_SIZE ?= 8G

LOGS?="logs/*"
KEY_LEN?=4096
ET?="OAEP"
LOOP?=10
HASH?="SHA256"
TXT_FILE?="logs/"
SIZE?=1000

# GORUN = env GO111MODULE=on go run

ifeq ($(DEBUG),1)
GRAMINE_LOG_LEVEL = debug
else
GRAMINE_LOG_LEVEL = error
endif

.PHONY: all
all: build rsa_benchmarking.manifest
ifeq ($(SGX),1)
all: build rsa_benchmarking.manifest.sgx rsa_benchmarking.sig rsa_benchmarking.token
endif

build:
	go build -o rsa_benchmarking rsa.go

################################# RSA MANIFEST ###################################

RA_TYPE ?= none
RA_CLIENT_SPID ?=
RA_CLIENT_LINKABLE ?= 0

rsa_benchmarking.manifest: rsa_benchmarking.manifest.template
	gramine-manifest \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Drsa_bin="./rsa_benchmarking" \
		-Dentrypoint="./rsa_benchmarking" \
		-Dra_type=$(RA_TYPE) \
		-Dra_client_spid=$(RA_CLIENT_SPID) \
		-Dra_client_linkable=$(RA_CLIENT_LINKABLE) \
		-Denclave_size=$(ENCLAVE_SIZE) \
		$< >$@

rsa_benchmarking.manifest.sgx rsa_benchmarking.sig: sgx_sign
	@:

.INTERMEDIATE: sgx_sign
sgx_sign: rsa_benchmarking.manifest
	gramine-sgx-sign \
		--manifest $< \
		--output $<.sgx
rsa_benchmarking.token: rsa_benchmarking.sig
	gramine-sgx-get-token --output $@ --sig $<


################################# RSA BENCHMARK COMMANDS ###################################
pkcs:
	# 1kb
	# ./rsa_benchmarking -size 1000 -et $(ET) -lp $(LOOP) -kl $(KEY_LEN)

	# 10kb
	./rsa_benchmarking -size 10000 -et $(ET) -lp $(LOOP) -kl $(KEY_LEN)

	# 100kb
	# ./rsa_benchmarking -size 100000 -et $(ET) -lp $(LOOP) -kl $(KEY_LEN)

	# 1mb
	# ./rsa_benchmarking -size 1000000 -et $(ET) -lp $(LOOP) -kl $(KEY_LEN)

oaep:
	# #1kb
	# ./rsa_benchmarking -ht $(HASH) -size 1000 -label "HCMUS-K25" -et $(ET) -lp $(LOOP) -kl $(KEY_LEN)

	#10kb
	./rsa_benchmarking -ht $(HASH) -size 10000 -label "HCMUS-K25" -et $(ET) -lp $(LOOP) -kl $(KEY_LEN)

	# #100kb
	# ./rsa_benchmarking -ht $(HASH) -size 100000 -label "HCMUS-K25" -et $(ET) -lp $(LOOP) -kl $(KEY_LEN)

	# #1mb
	# ./rsa_benchmarking -ht $(HASH) -size 1000000 -label "HCMUS-K25" -et $(ET) -lp $(LOOP) -kl $(KEY_LEN)

##################################### CLEANUP ########################################
.PHONY: clean
clean:
	$(RM) *.manifest *.manifest.sgx *.token *.sig *OUTPUT* *.PID TEST_STDOUT TEST_STDERR
.PHONY: distclean
distclean: clean
	$(RM) -rf rsa_benchmarking
