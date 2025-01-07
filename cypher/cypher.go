package cypher

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
)

const (
	ChunkSize  = 10 * 1024 * 1024 // 1KB
	NumWorkers = 10               // Number of worker goroutines
)

type DataChunk struct {
	data     []byte
	position int
}

type Cypher struct {
	Key []byte
}

func NewCypher(key string) *Cypher {
	return &Cypher{Key: []byte(MD5HashFromString(key))}
}

func (c Cypher) EncryptFile(inputPath string) (*string, error) {
	outputPath := inputPath + ".encrypted"
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open input file: %w", err)
	}
	defer inputFile.Close()

	outputFile, err := os.Create(outputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create output file: %w", err)
	}
	defer outputFile.Close()

	block, err := aes.NewCipher(c.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create channels
	rawChunks := make(chan DataChunk, NumWorkers)
	encryptedChunks := make(chan DataChunk, NumWorkers)
	errorChan := make(chan error, 1)

	// Start the worker pool
	var wg sync.WaitGroup
	for i := 0; i < NumWorkers; i++ {
		wg.Add(1)
		go encryptWorker(ctx, &wg, gcm, rawChunks, encryptedChunks, errorChan)
	}

	// Start the writer goroutine
	writeComplete := make(chan struct{})
	go writeChunks(outputFile, encryptedChunks, writeComplete, errorChan)

	// Read and send chunks for processing
	position := 0
	buffer := make([]byte, ChunkSize)
	for {
		n, err := inputFile.Read(buffer)
		if err == io.EOF {
			break
		}
		if err != nil {
			cancel()
			return nil, fmt.Errorf("failed to read input file: %w", err)
		}

		chunk := make([]byte, n)
		copy(chunk, buffer[:n])

		select {
		case rawChunks <- DataChunk{data: chunk, position: position}:
			position++
		case err := <-errorChan:
			cancel()
			return nil, err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	// Close the raw chunks channel to signal no more data
	close(rawChunks)

	// Wait for all encryption workers to complete
	wg.Wait()

	// Close encrypted chunks channel
	close(encryptedChunks)

	// Wait for writer to complete
	select {
	case <-writeComplete:
		return &outputPath, nil
	case err := <-errorChan:
		return nil, err
	}
}

func encryptWorker(ctx context.Context, wg *sync.WaitGroup, gcm cipher.AEAD, input <-chan DataChunk, output chan<- DataChunk, errorChan chan<- error) {
	defer wg.Done()

	for {
		select {
		case chunk, ok := <-input:
			if !ok {
				return
			}

			nonce := make([]byte, gcm.NonceSize())
			if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
				select {
				case errorChan <- fmt.Errorf("failed to generate nonce: %w", err):
				default:
				}
				return
			}

			encrypted := gcm.Seal(nil, nonce, chunk.data, nil)
			select {
			case output <- DataChunk{data: append(nonce, encrypted...), position: chunk.position}:
			case <-ctx.Done():
				return
			}

		case <-ctx.Done():
			return
		}
	}
}

func writeChunks(file *os.File, input <-chan DataChunk, complete chan<- struct{}, errorChan chan<- error) {
	pending := make(map[int][]byte)
	nextPosition := 0

	for chunk := range input {
		pending[chunk.position] = chunk.data

		// Write chunks in order
		for data, ok := pending[nextPosition]; ok; data, ok = pending[nextPosition] {
			_, err := file.Write(data)
			if err != nil {
				select {
				case errorChan <- fmt.Errorf("failed to write chunk: %w", err):
				default:
				}
				return
			}
			delete(pending, nextPosition)
			nextPosition++
		}
	}

	// Signal completion
	complete <- struct{}{}
}

func (c Cypher) DecryptFile(inputPath string) (*string, error) {
	outputPath := inputPath + ".decrypted"
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open input file: %w", err)
	}
	defer inputFile.Close()

	outputFile, err := os.Create(outputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create output file: %w", err)
	}
	defer outputFile.Close()

	block, err := aes.NewCipher(c.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Calculate total size for encrypted chunk (including nonce and overhead)
	encryptedChunkSize := ChunkSize + gcm.NonceSize() + gcm.Overhead()

	// Create channels
	encryptedChunks := make(chan DataChunk, NumWorkers)
	decryptedChunks := make(chan DataChunk, NumWorkers)
	errorChan := make(chan error, 1)

	// Start the worker pool
	var wg sync.WaitGroup
	for i := 0; i < NumWorkers; i++ {
		wg.Add(1)
		go decryptWorker(ctx, &wg, gcm, encryptedChunks, decryptedChunks, errorChan)
	}

	// Start the writer goroutine
	writeComplete := make(chan struct{})
	go writeChunks(outputFile, decryptedChunks, writeComplete, errorChan)

	// Read and send chunks for processing
	position := 0
	buffer := make([]byte, encryptedChunkSize)
	for {
		n, err := inputFile.Read(buffer)
		if err == io.EOF {
			break
		}
		if err != nil {
			cancel()
			return nil, fmt.Errorf("failed to read input file: %w", err)
		}

		chunk := make([]byte, n)
		copy(chunk, buffer[:n])

		select {
		case encryptedChunks <- DataChunk{data: chunk, position: position}:
			position++
		case err := <-errorChan:
			cancel()
			return nil, err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	// Close the encrypted chunks channel to signal no more data
	close(encryptedChunks)

	// Wait for all decryption workers to complete
	wg.Wait()

	// Close decrypted chunks channel
	close(decryptedChunks)

	// Wait for writer to complete
	select {
	case <-writeComplete:
		return &outputPath, nil
	case err := <-errorChan:
		return nil, err
	}
}

func decryptWorker(ctx context.Context, wg *sync.WaitGroup, gcm cipher.AEAD, input <-chan DataChunk, output chan<- DataChunk, errorChan chan<- error) {
	defer wg.Done()

	for {
		select {
		case chunk, ok := <-input:
			if !ok {
				return
			}

			nonceSize := gcm.NonceSize()
			if len(chunk.data) < nonceSize {
				select {
				case errorChan <- errors.New("encrypted chunk too small"):
				default:
				}
				return
			}

			nonce := chunk.data[:nonceSize]
			ciphertext := chunk.data[nonceSize:]

			plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
			if err != nil {
				select {
				case errorChan <- fmt.Errorf("failed to decrypt chunk: %w", err):
				default:
				}
				return
			}

			select {
			case output <- DataChunk{data: plaintext, position: chunk.position}:
			case <-ctx.Done():
				return
			}

		case <-ctx.Done():
			return
		}
	}
}

func MD5HashFromFile(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func MD5HashFromString(str string) string {
	hash := md5.New()
	if _, err := io.WriteString(hash, str); err != nil {
		panic(err)
	}
	return hex.EncodeToString(hash.Sum(nil))
}
