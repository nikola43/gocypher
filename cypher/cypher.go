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
	"runtime"
	"sync"
)

type DataChunk struct {
	data     []byte
	position int
}

type Cypher struct {
	key        []byte
	ChunkSize  int
	NumWorkers int
	NumCores   int
}
type Option func(*Cypher)

func NewCypher(key string, opts ...Option) *Cypher {
	maxCPUs := runtime.NumCPU()
	runtime.GOMAXPROCS(maxCPUs)

	// Default values
	cypher := &Cypher{
		ChunkSize:  10 * 1024 * 1024, // 10MB
		NumWorkers: 10,               // 10 workers
		key:        []byte(MD5HashFromString(key)),
		NumCores:   maxCPUs,
	}

	// Apply options
	for _, opt := range opts {
		opt(cypher)
	}

	return cypher
}

func (c *Cypher) WithNumCores(numCores int) *Cypher {
	maxCPUs := runtime.NumCPU()

	if numCores > maxCPUs {
		numCores = maxCPUs
	}

	c.NumCores = numCores
	return c
}

func (c *Cypher) WithChunkSize(chunkSize int) *Cypher {
	c.ChunkSize = chunkSize
	return c
}

func (c *Cypher) WithNumWorkers(numWorkers int) *Cypher {
	c.NumWorkers = numWorkers
	return c
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

	block, err := aes.NewCipher(c.key)
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
	rawChunks := make(chan DataChunk, c.NumWorkers)
	encryptedChunks := make(chan DataChunk, c.NumWorkers)
	errorChan := make(chan error, 1)

	// Start the worker pool
	var wg sync.WaitGroup
	for i := 0; i < c.NumWorkers; i++ {
		wg.Add(1)
		go encryptWorker(ctx, &wg, gcm, rawChunks, encryptedChunks, errorChan)
	}

	// Start the writer goroutine
	writeComplete := make(chan struct{})
	go writeChunks(outputFile, encryptedChunks, writeComplete, errorChan)

	// Read and send chunks for processing
	position := 0
	buffer := make([]byte, c.ChunkSize)
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

	block, err := aes.NewCipher(c.key)
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
	encryptedChunkSize := c.ChunkSize + gcm.NonceSize() + gcm.Overhead()

	// Create channels
	encryptedChunks := make(chan DataChunk, c.NumWorkers)
	decryptedChunks := make(chan DataChunk, c.NumWorkers)
	errorChan := make(chan error, 1)

	// Start the worker pool
	var wg sync.WaitGroup
	for i := 0; i < c.NumWorkers; i++ {
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

func (c Cypher) Encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(c.key)
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
	rawChunks := make(chan DataChunk, c.NumWorkers)
	encryptedChunks := make(chan DataChunk, c.NumWorkers)
	errorChan := make(chan error, 1)

	// Start the worker pool
	var wg sync.WaitGroup
	for i := 0; i < c.NumWorkers; i++ {
		wg.Add(1)
		go encryptWorker(ctx, &wg, gcm, rawChunks, encryptedChunks, errorChan)
	}

	// Start collecting results
	var result []byte
	var pendingChunks sync.Map
	var nextPosition int
	var resultMutex sync.Mutex

	// Start collector goroutine
	collectorDone := make(chan struct{})
	go func() {
		defer close(collectorDone)
		for chunk := range encryptedChunks {
			pendingChunks.Store(chunk.position, chunk.data)

			// Try to append chunks in order
			for {
				if data, ok := pendingChunks.LoadAndDelete(nextPosition); ok {
					resultMutex.Lock()
					result = append(result, data.([]byte)...)
					resultMutex.Unlock()
					nextPosition++
				} else {
					break
				}
			}
		}
	}()

	// Split data into chunks and send for encryption
	for i := 0; i < len(data); i += c.ChunkSize {
		end := i + c.ChunkSize
		if end > len(data) {
			end = len(data)
		}

		chunk := make([]byte, end-i)
		copy(chunk, data[i:end])

		select {
		case rawChunks <- DataChunk{data: chunk, position: i / c.ChunkSize}:
		case err := <-errorChan:
			cancel()
			return nil, err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	// Close input channel and wait for workers
	close(rawChunks)
	wg.Wait()
	close(encryptedChunks)

	// Wait for collector
	<-collectorDone

	// Check for errors
	select {
	case err := <-errorChan:
		return nil, err
	default:
		return result, nil
	}
}

func (c Cypher) Decrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Calculate chunk size for encrypted data
	encryptedChunkSize := c.ChunkSize + gcm.NonceSize() + gcm.Overhead()

	// Create channels
	encryptedChunks := make(chan DataChunk, c.NumWorkers)
	decryptedChunks := make(chan DataChunk, c.NumWorkers)
	errorChan := make(chan error, 1)

	// Start the worker pool
	var wg sync.WaitGroup
	for i := 0; i < c.NumWorkers; i++ {
		wg.Add(1)
		go decryptWorker(ctx, &wg, gcm, encryptedChunks, decryptedChunks, errorChan)
	}

	// Start collecting results
	var result []byte
	var pendingChunks sync.Map
	var nextPosition int
	var resultMutex sync.Mutex

	// Start collector goroutine
	collectorDone := make(chan struct{})
	go func() {
		defer close(collectorDone)
		for chunk := range decryptedChunks {
			pendingChunks.Store(chunk.position, chunk.data)

			// Try to append chunks in order
			for {
				if data, ok := pendingChunks.LoadAndDelete(nextPosition); ok {
					resultMutex.Lock()
					result = append(result, data.([]byte)...)
					resultMutex.Unlock()
					nextPosition++
				} else {
					break
				}
			}
		}
	}()

	// Split data into chunks and send for decryption
	for i := 0; i < len(data); i += encryptedChunkSize {
		end := i + encryptedChunkSize
		if end > len(data) {
			end = len(data)
		}

		chunk := make([]byte, end-i)
		copy(chunk, data[i:end])

		select {
		case encryptedChunks <- DataChunk{data: chunk, position: i / encryptedChunkSize}:
		case err := <-errorChan:
			cancel()
			return nil, err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	// Close input channel and wait for workers
	close(encryptedChunks)
	wg.Wait()
	close(decryptedChunks)

	// Wait for collector
	<-collectorDone

	// Check for errors
	select {
	case err := <-errorChan:
		return nil, err
	default:
		return result, nil
	}
}
