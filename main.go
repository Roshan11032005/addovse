package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"strings"

	"github.com/xuri/excelize/v2"
)

type OVSE struct {
	OvseId   string `json:"ovseId"`
	OvseName string `json:"ovseName"`
	OvseLogo string `json:"ovseLogo"`
	OvseExp  string `json:"ovseExp"`
	OvseMod  string `json:"ovseMod"`
}

// 🔧 Clean messy PEM input
func sanitizeInput(raw string) string {
	raw = strings.TrimSpace(raw)

	// Remove anything before BEGIN
	if idx := strings.Index(raw, "-----BEGIN"); idx != -1 {
		raw = raw[idx:]
	}

	raw = strings.ReplaceAll(raw, "\r", "")
	raw = strings.ReplaceAll(raw, "\\n", "\n")
	raw = strings.ReplaceAll(raw, "\"", "")

	return raw
}

// 🔧 Extract base64 + detect type
func extractBase64(raw string) (string, string) {
	lines := strings.Split(raw, "\n")

	var b64Lines []string
	pemType := ""

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.Contains(line, "BEGIN CERTIFICATE") {
			pemType = "CERTIFICATE"
			continue
		}
		if strings.Contains(line, "BEGIN PUBLIC KEY") {
			pemType = "PUBLIC KEY"
			continue
		}

		if line == "" ||
			strings.Contains(line, "BEGIN") ||
			strings.Contains(line, "END") {
			continue
		}

		b64Lines = append(b64Lines, line)
	}

	return strings.Join(b64Lines, ""), pemType
}

// 🔥 Extract modulus + exponent
func extractKey(raw string) (string, string, error) {

	raw = sanitizeInput(raw)

	if raw == "" || !strings.Contains(raw, "BEGIN") {
		return "", "", fmt.Errorf("invalid or missing PEM block")
	}

	// detect type
	pemType := "CERTIFICATE"
	if strings.Contains(raw, "PUBLIC KEY") {
		pemType = "PUBLIC KEY"
	}

	// extract base64
	b64, detectedType := extractBase64(raw)
	if detectedType != "" {
		pemType = detectedType
	}

	if b64 == "" {
		b64 = strings.ReplaceAll(raw, "\n", "")
	}

	// validate base64
	if _, err := base64.StdEncoding.DecodeString(b64); err != nil {
		return "", "", fmt.Errorf("invalid base64")
	}

	// rebuild clean PEM
	var cleanPEM strings.Builder
	cleanPEM.WriteString("-----BEGIN " + pemType + "-----\n")

	for i := 0; i < len(b64); i += 64 {
		end := i + 64
		if end > len(b64) {
			end = len(b64)
		}
		cleanPEM.WriteString(b64[i:end] + "\n")
	}

	cleanPEM.WriteString("-----END " + pemType + "-----")

	block, _ := pem.Decode([]byte(cleanPEM.String()))
	if block == nil {
		return "", "", fmt.Errorf("PEM decode failed")
	}

	var pub *rsa.PublicKey

	switch block.Type {

	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return "", "", err
		}

		key, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return "", "", fmt.Errorf("not RSA key")
		}
		pub = key

	case "PUBLIC KEY":
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return "", "", err
		}

		rsaKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return "", "", fmt.Errorf("not RSA key")
		}
		pub = rsaKey

	default:
		return "", "", fmt.Errorf("unsupported type: %s", block.Type)
	}

	mod := hex.EncodeToString(pub.N.Bytes())
	exp := fmt.Sprintf("%06x", pub.E)

	return mod, exp, nil
}

func main() {

	file := "ovse2.xlsx"

	f, err := excelize.OpenFile(file)
	if err != nil {
		log.Fatal(err)
	}

	sheet := f.GetSheetName(0)

	rows, err := f.GetRows(sheet)
	if err != nil {
		log.Fatal(err)
	}

	var result []OVSE

	for i, row := range rows {

		if i == 0 {
			continue // skip header
		}

		// ✅ Safe column check
		if len(row) < 7 {
			fmt.Println("⚠️ Skipping row (not enough columns):", i)
			continue
		}

		// ✅ Correct mapping (FIXED)
		name := strings.TrimSpace(row[1])
		id := strings.TrimSpace(row[2])
		logo := strings.TrimSpace(row[5])
		cert := strings.TrimSpace(row[6])

		// validate required fields
		if id == "" || cert == "" {
			fmt.Println("⚠️ Skipping row (empty id/cert):", i)
			continue
		}

		// skip placeholder / invalid cert text
		if !strings.Contains(cert, "BEGIN") {
			fmt.Printf("⚠️ Row %d skipped: not a valid PEM\n", i)
			continue
		}

		// encode logo (SVG text → base64)
		logoBase64 := base64.StdEncoding.EncodeToString([]byte(logo))

		// extract key
		mod, exp, err := extractKey(cert)
		if err != nil {
			fmt.Printf("❌ Row %d skipped: %v\n", i, err)
			continue
		}

		fmt.Printf("✅ Row %d processed (%s)\n", i, id)

		entry := OVSE{
			OvseId:   strings.ToLower(id),
			OvseName: name,
			OvseLogo: logoBase64,
			OvseExp:  exp,
			OvseMod:  mod,
		}

		result = append(result, entry)
	}

	out, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(out))
}