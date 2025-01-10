# 🔐 GOCypher

GOCypher is a robust, high-performance file and data encryption/decryption library written in Go. It utilizes AES-GCM encryption with a multi-threaded design to handle large files efficiently. With support for chunk-based processing, Cypher enables parallel encryption/decryption using a worker pool for optimal performance.

## ✨ Features

- 🔒 File Encryption & Decryption
- 🧠 In-Memory Data Encryption & Decryption
- ⚡ Parallel Processing
- ⚙️ Customizable Parameters

## 🚀 Installation

```bash
go install github.com/nikola43/gocypher/cypher@latest
```

## 🔧 Usage

### Creating a Cypher Instance
Initialize Cypher with a secret key:
```
c := cypher.NewCypher("your-secret-key")
```

### File Encryption & Decryption
Encrypt a File:
```
encryptedPath, err := c.EncryptFile("example.txt")
if err != nil {
    log.Fatalf("Encryption failed: %v", err)
}
fmt.Printf("File encrypted successfully: %s\n", *encryptedPath)
```

Decrypt a File:
```
decryptedPath, err := c.DecryptFile("example.txt.encrypted")
if err != nil {
    log.Fatalf("Decryption failed: %v", err)
}
fmt.Printf("File decrypted successfully: %s\n", *decryptedPath)
```

### In-Memory Data Encryption & Decryption
Encrypt Data:
```
data := []byte("Sensitive information")
encryptedData, err := c.Encrypt(data)
if err != nil {
    log.Fatalf("Data encryption failed: %v", err)
}
fmt.Printf("Data encrypted successfully: %x\n", encryptedData)
```

Decrypt Data:
```
decryptedData, err := c.Decrypt(encryptedData)
if err != nil {
    log.Fatalf("Data decryption failed: %v", err)
}
fmt.Printf("Decrypted data: %s\n", string(decryptedData))
```

## ⚙️ Configuration
### Chunk Size
ChunkSize: Adjust the size of data chunks processed in parallel (default: 10 MB).
```
c := cypher.NewCypher("my-secret-key").WithChunkSize(10 * 1024 * 1024)
```

### Number of workers
Configure chunk size and number of workers:
NumWorkers: Configure the number of worker goroutines (default: 10).
```
c := cypher.NewCypher("my-secret-key").WithNumWorkers(10)
```

### Number of cores
Configure number of used cpu cores (default: all).
```
c := cypher.NewCypher("my-secret-key").WithNumCores(4)
```

## 🛠️ Technical Details

- Written in Go

- AES-GCM: Utilizes the Advanced Encryption Standard (AES) with Galois/Counter Mode (GCM) for encryption and authentication.

- Concurrency: Employs channels, worker pools, and a context for efficient chunk-based encryption/decryption.

- Error Handling: Gracefully handles I/O errors, encryption/decryption failures, and worker synchronization issues.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the GPLV3 License - see the LICENSE file for details.

## ⭐ Star History

If you find this project useful, please consider giving it a star on GitHub! Your support helps us keep maintaining and improving this tool.

## 🐛 Found a Bug?

Please open an issue with:
- Command you were trying to run
- Expected behavior
- Actual behavior
- Steps to reproduce

---
Made with ❤️ for the golang community
