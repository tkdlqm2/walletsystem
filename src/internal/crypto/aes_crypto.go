package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"golang.org/x/crypto/pbkdf2"
)

type EncryptedData struct {
	Algorithm string `json:"algorithm"`
	Salt      string `json:"salt"`
	IV        string `json:"iv"`
	AuthTag   string `json:"authTag"`
	Data      string `json:"data"`
}

type AESCrypto struct {
	passphrase string
}

// NewAESCrypto creates a new AESCrypto instance
func NewAESCrypto() (*AESCrypto, error) {
	// Load .env file
	passphrase := os.Getenv("CRYPTO_PASSPHRASE")
	if passphrase == "" {
		return nil, errors.New("CRYPTO_PASSPHRASE not found in environment variables")
	}

	return &AESCrypto{
		passphrase: passphrase,
	}, nil
}

// generateSalt creates a random 16-byte salt
func (a *AESCrypto) generateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	return salt, err
}

// generateIV creates a random 16-byte IV for AES-CBC
func (a *AESCrypto) generateIV() ([]byte, error) {
	iv := make([]byte, 16)
	_, err := rand.Read(iv)
	return iv, err
}

// deriveKey creates a 32-byte key using PBKDF2
func (a *AESCrypto) deriveKey(salt []byte) []byte {
	return pbkdf2.Key([]byte(a.passphrase), salt, 10000, 32, sha256.New)
}

// pkcs7Padding adds PKCS7 padding to data
func pkcs7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := make([]byte, padding)
	for i := range padtext {
		padtext[i] = byte(padding)
	}
	return append(data, padtext...)
}

// pkcs7Unpadding removes PKCS7 padding from data
func pkcs7Unpadding(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("invalid padding")
	}
	unpadding := int(data[length-1])
	if unpadding > length {
		return nil, errors.New("invalid padding")
	}
	return data[:(length - unpadding)], nil
}

// EncryptPrivateKey encrypts the private key using AES-256-CBC and returns JSON
func (a *AESCrypto) EncryptPrivateKey(privateKey []byte) (string, error) {
	// Generate salt and IV
	salt, err := a.generateSalt()
	if err != nil {
		return "", err
	}

	iv, err := a.generateIV()
	if err != nil {
		return "", err
	}

	// Derive key from passphrase and salt
	key := a.deriveKey(salt)

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Add PKCS7 padding
	paddedData := pkcs7Padding(privateKey, aes.BlockSize)

	// Encrypt using CBC mode
	ciphertext := make([]byte, len(paddedData))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, paddedData)

	// Create result structure
	result := EncryptedData{
		Algorithm: "aes-256-cbc",
		Salt:      hex.EncodeToString(salt),
		IV:        hex.EncodeToString(iv),
		AuthTag:   "", // CBC 모드에서는 AuthTag 사용 안함
		Data:      hex.EncodeToString(ciphertext),
	}

	// Convert to JSON
	jsonBytes, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", err
	}

	return string(jsonBytes), nil
}

// DecryptPrivateKey decrypts the private key from JSON format
func (a *AESCrypto) DecryptPrivateKey(encryptedJSON string) ([]byte, error) {
	var encData EncryptedData
	err := json.Unmarshal([]byte(encryptedJSON), &encData)
	if err != nil {
		return nil, err
	}

	if encData.Algorithm != "aes-256-cbc" {
		return nil, errors.New("unsupported algorithm")
	}

	// Decode hex strings
	salt, err := hex.DecodeString(encData.Salt)
	if err != nil {
		return nil, err
	}

	iv, err := hex.DecodeString(encData.IV)
	if err != nil {
		return nil, err
	}

	ciphertext, err := hex.DecodeString(encData.Data)
	if err != nil {
		return nil, err
	}

	// Derive key
	key := a.deriveKey(salt)

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Decrypt using CBC mode
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	// Remove PKCS7 padding
	result, err := pkcs7Unpadding(plaintext)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// EncryptPrivateKeyToBase64 encrypts the private key and returns base64 encoded JSON
func (a *AESCrypto) EncryptPrivateKeyToBase64(privateKey []byte) (string, error) {
	// 먼저 JSON 형태로 암호화
	encryptedJSON, err := a.EncryptPrivateKey(privateKey)
	if err != nil {
		return "", err
	}

	// JSON을 base64로 인코딩
	encodedData := base64.StdEncoding.EncodeToString([]byte(encryptedJSON))
	return encodedData, nil
}

// DecryptPrivateKeyFromBase64 decodes base64 and decrypts the private key
func (a *AESCrypto) DecryptPrivateKeyFromBase64(encodedData string) ([]byte, error) {
	fmt.Println("DecryptPrivateKeyFromBase64 - encodedData:", encodedData)
	// base64 디코딩
	jsonData, err := base64.StdEncoding.DecodeString(encodedData)
	if err != nil {
		return nil, err
	}

	// JSON에서 복호화
	return a.DecryptPrivateKey(string(jsonData))
}

// EncodeToBase64 encodes string to base64
func (a *AESCrypto) EncodeToBase64(data string) string {
	return base64.StdEncoding.EncodeToString([]byte(data))
}

// DecodeFromBase64 decodes base64 to string
func (a *AESCrypto) DecodeFromBase64(encodedData string) (string, error) {
	decodedBytes, err := base64.StdEncoding.DecodeString(encodedData)
	if err != nil {
		return "", err
	}
	return string(decodedBytes), nil
}
