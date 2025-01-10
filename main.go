package main

import (
	"fmt"
	"log"
	"runtime"
	"time"

	"github.com/nikola43/gocypher/cypher"
)

func main() {
	// Set GOMAXPROCS to the maximum number of CPUs
	maxCPUs := runtime.NumCPU()
	runtime.GOMAXPROCS(maxCPUs)

	// Encrypt and decrypt data
	c := cypher.NewCypher("my-secret-key")

	// Encrypt data
	encrypted, err := c.Encrypt([]byte("your data"))
	if err != nil {
		panic(err)
	}

	// Decrypt data
	decrypted, err := c.Decrypt(encrypted)
	if err != nil {
		panic(err)
	}
	
	if string(decrypted) == "your data" {
		fmt.Println("Success: Encrypted and decrypted data match!")
	} else {
		fmt.Println("Error: Encrypted and decrypted data do not match!")
	}


	inputFile := "./data/file.txt"



	// Get original file hash
	inputHash, err := cypher.MD5HashFromFile(inputFile)
	if err != nil {
		log.Fatalf("Failed to get input file hash: %v", err)
	}
	fmt.Printf("Input file hash: %s\n", inputHash)

	// Encrypt the file
	startTime := time.Now()
	encryptedFilepath, err := c.EncryptFile(inputFile)
	if err != nil {
		log.Fatalf("Encryption failed: %v", err)
	}

	fmt.Printf("Encryption completed in %v\n", time.Since(startTime))

	// Decrypt the file
	startTime = time.Now()
	decryptedFilepath, err := c.DecryptFile(*encryptedFilepath)
	if err != nil {
		log.Fatalf("Decryption failed: %v", err)
	}

	fmt.Printf("Decryption completed in %v\n", time.Since(startTime))

	// Verify the decrypted file matches the original
	decryptedHash, err := cypher.MD5HashFromFile(*decryptedFilepath)
	if err != nil {
		log.Fatalf("Failed to get decrypted file hash: %v", err)
	}
	fmt.Printf("Decrypted file hash: %s\n", decryptedHash)

	if inputHash == decryptedHash {
		fmt.Println("Success: Input and decrypted files match!")
	} else {
		fmt.Println("Error: Input and decrypted files do not match!")
	}
}
