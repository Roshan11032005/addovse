package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"os"
)

func main() {
	filePath := "/home/roshan/dev/addovse/logo.svg"

	// Read the SVG file
	data, err := os.ReadFile(filePath)
	if err != nil {
		log.Fatalf("Failed to read file: %v", err)
	}

	// Convert to Base64
	encoded := base64.StdEncoding.EncodeToString(data)

	// Print Base64 string
	fmt.Println(encoded)

	// Optional: print as data URI (useful for embedding in HTML)
	fmt.Println("\nData URI:")
	fmt.Println("data:image/svg+xml;base64," + encoded)
}