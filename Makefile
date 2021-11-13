# make gen_private_key
gen_private_key:
	openssl genpkey -aes-256-cbc -algorithm RSA -out private-key.pem -pkeyopt rsa_keygen_bits:2048

# make gen_public_key
gen_public_key:
	openssl rsa -in private-key.pem -outform PEM -pubout -out public-key.pem

# make run
run:
	go run .

# make test
test:
	go test ./...

# make bench
bench:
	go test -bench=.