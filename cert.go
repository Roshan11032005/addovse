package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"os"
)

func main() {

	data, err := os.ReadFile("cert.pem")
	if err != nil {
		log.Fatal(err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		log.Fatal("failed to decode PEM block")
	}

	var pubKey *rsa.PublicKey

	// ---- FILTER BY TYPE ----
	if block.Type == "CERTIFICATE" {

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Fatal(err)
		}

		key, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			log.Fatal("certificate does not contain RSA key")
		}

		pubKey = key

	} else if block.Type == "PUBLIC KEY" {

		pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			log.Fatal(err)
		}

		key, ok := pubInterface.(*rsa.PublicKey)
		if !ok {
			log.Fatal("not RSA public key")
		}

		pubKey = key

	} else {
		log.Fatalf("unsupported PEM type: %s", block.Type)
	}

	// Extract modulus and exponent
	modHex := hex.EncodeToString(pubKey.N.Bytes())
	expHex := fmt.Sprintf("%06x", pubKey.E)

	result := map[string]string{
		"ovseMod": modHex,
		"ovseExp": expHex,
	}

	jsonBytes, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(jsonBytes))
}