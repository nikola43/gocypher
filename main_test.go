package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

const (
	testDataDir = "data"
)

// TestSetup represents the test files and cleanup function
type TestSetup struct {
	InputFile      string
	EncryptedFile  string
	DecryptedFile  string
	CleanupFn      func()
	Key            []byte
	OriginalHash   string
	OriginalSize   int64
}

// setupTest creates test files and returns cleanup function
func setupTest(t *testing.T, size int) (*TestSetup, error) {
	// Create test directory if it doesn't exist
	if err := os.MkdirAll(testDataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create test directory: %w", err)
	}

	// Create unique test file names
	setup := &TestSetup{
		InputFile:     filepath.Join(testDataDir, fmt.Sprintf("test_input_%d.txt", size)),
		EncryptedFile: filepath.Join(testDataDir, fmt.Sprintf("test_encrypted_%d.bin", size)),
		DecryptedFile: filepath.Join(testDataDir, fmt.Sprintf("test_decrypted_%d.txt", size)),
	}

	// Generate test data
	if err := generateTestFile(setup.InputFile, size); err != nil {
		return nil, fmt.Errorf("failed to generate test file: %w", err)
	}

	// Get file hash and size
	hash, err := MD5Hash(setup.InputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to get input file hash: %w", err)
	}
	setup.OriginalHash = hash

	fileInfo, err := os.Stat(setup.InputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to get file info: %w", err)
	}
	setup.OriginalSize = fileInfo.Size()

	// Generate encryption key
	key, err := GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}
	setup.Key = key

	// Create cleanup function
	setup.CleanupFn = func() {
		os.Remove(setup.InputFile)
		os.Remove(setup.EncryptedFile)
		os.Remove(setup.DecryptedFile)
	}

	return setup, nil
}

// generateTestFile creates a file with random data of specified size
func generateTestFile(filename string, size int) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// Create a buffer with random data
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		return err
	}

	_, err = file.Write(data)
	return err
}

// compareFiles checks if two files have identical content
func compareFiles(file1, file2 string) (bool, error) {
	f1, err := os.Open(file1)
	if err != nil {
		return false, err
	}
	defer f1.Close()

	f2, err := os.Open(file2)
	if err != nil {
		return false, err
	}
	defer f2.Close()

	const chunkSize = 64 * 1024 // 64KB chunks
	buf1 := make([]byte, chunkSize)
	buf2 := make([]byte, chunkSize)

	for {
		n1, err1 := f1.Read(buf1)
		n2, err2 := f2.Read(buf2)

		if err1 != nil && err1 != io.EOF {
			return false, err1
		}
		if err2 != nil && err2 != io.EOF {
			return false, err2
		}

		if n1 != n2 {
			return false, nil
		}

		if !bytes.Equal(buf1[:n1], buf2[:n2]) {
			return false, nil
		}

		if err1 == io.EOF && err2 == io.EOF {
			break
		}
	}

	return true, nil
}

// Test cases

func TestEncryptDecryptSmallFile(t *testing.T) {
	setup, err := setupTest(t, 100) // 100 bytes
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}
	defer setup.CleanupFn()

	// Test encryption
	if err := EncryptFile(setup.InputFile, setup.EncryptedFile, setup.Key); err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Verify encrypted file exists and is different from input
	encryptedHash, err := MD5Hash(setup.EncryptedFile)
	if err != nil {
		t.Fatalf("Failed to get encrypted file hash: %v", err)
	}
	if encryptedHash == setup.OriginalHash {
		t.Error("Encrypted file hash matches input file hash")
	}

	// Test decryption
	if err := DecryptFile(setup.EncryptedFile, setup.DecryptedFile, setup.Key); err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Verify decrypted file matches original
	decryptedHash, err := MD5Hash(setup.DecryptedFile)
	if err != nil {
		t.Fatalf("Failed to get decrypted file hash: %v", err)
	}
	if decryptedHash != setup.OriginalHash {
		t.Error("Decrypted file hash doesn't match input file hash")
	}
}

func TestEncryptDecryptLargeFile(t *testing.T) {
	setup, err := setupTest(t, 5*1024*1024) // 5MB
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}
	defer setup.CleanupFn()

	// Test encryption
	if err := EncryptFile(setup.InputFile, setup.EncryptedFile, setup.Key); err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Test decryption
	if err := DecryptFile(setup.EncryptedFile, setup.DecryptedFile, setup.Key); err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Verify files match
	match, err := compareFiles(setup.InputFile, setup.DecryptedFile)
	if err != nil {
		t.Fatalf("File comparison failed: %v", err)
	}
	if !match {
		t.Error("Decrypted file doesn't match input file")
	}
}

func TestInvalidKey(t *testing.T) {
	setup, err := setupTest(t, 1024) // 1KB
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}
	defer setup.CleanupFn()

	// Test with invalid key size
	invalidKey := make([]byte, 16) // Only 16 bytes instead of required 32
	if err := EncryptFile(setup.InputFile, setup.EncryptedFile, invalidKey); err == nil {
		t.Error("Expected error for invalid key size, got nil")
	}
}

func TestNonExistentInputFile(t *testing.T) {
	key, _ := GenerateKey()
	if err := EncryptFile("nonexistent.txt", "output.bin", key); err == nil {
		t.Error("Expected error for non-existent input file, got nil")
	}
}

func TestEncryptionWithWrongDecryptionKey(t *testing.T) {
	setup, err := setupTest(t, 1024) // 1KB
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}
	defer setup.CleanupFn()

	// Encrypt with original key
	if err := EncryptFile(setup.InputFile, setup.EncryptedFile, setup.Key); err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Try to decrypt with different key
	wrongKey, _ := GenerateKey()
	if err := DecryptFile(setup.EncryptedFile, setup.DecryptedFile, wrongKey); err == nil {
		t.Error("Expected error when decrypting with wrong key, got nil")
	}
}

func TestConcurrentEncryption(t *testing.T) {
	// Test concurrent encryption of multiple files
	const numFiles = 3
	setups := make([]*TestSetup, numFiles)
	errs := make(chan error, numFiles)
	
	for i := 0; i < numFiles; i++ {
		setup, err := setupTest(t, 1024*1024) // 1MB each
		if err != nil {
			t.Fatalf("Setup failed for file %d: %v", i, err)
		}
		setups[i] = setup
		
		go func(s *TestSetup) {
			if err := EncryptFile(s.InputFile, s.EncryptedFile, s.Key); err != nil {
				errs <- fmt.Errorf("encryption failed: %w", err)
				return
			}
			if err := DecryptFile(s.EncryptedFile, s.DecryptedFile, s.Key); err != nil {
				errs <- fmt.Errorf("decryption failed: %w", err)
				return
			}
			errs <- nil
		}(setup)
	}

	// Wait for all operations to complete
	for i := 0; i < numFiles; i++ {
		if err := <-errs; err != nil {
			t.Errorf("Concurrent operation failed: %v", err)
		}
	}

	// Cleanup
	for _, setup := range setups {
		setup.CleanupFn()
	}
}

func TestEmptyFile(t *testing.T) {
	setup, err := setupTest(t, 0) // 0 bytes
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}
	defer setup.CleanupFn()

	// Test encryption of empty file
	if err := EncryptFile(setup.InputFile, setup.EncryptedFile, setup.Key); err != nil {
		t.Fatalf("Encryption of empty file failed: %v", err)
	}

	// Test decryption of empty file
	if err := DecryptFile(setup.EncryptedFile, setup.DecryptedFile, setup.Key); err != nil {
		t.Fatalf("Decryption of empty file failed: %v", err)
	}

	// Verify file size is still 0
	info, err := os.Stat(setup.DecryptedFile)
	if err != nil {
		t.Fatalf("Failed to get decrypted file info: %v", err)
	}
	if info.Size() != 0 {
		t.Errorf("Expected decrypted file size to be 0, got %d", info.Size())
	}
}