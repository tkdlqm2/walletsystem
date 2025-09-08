package cloud

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// SecretCache 캐싱 구조체
type SecretCache struct {
	mu         sync.RWMutex
	data       map[string]CacheItem
	defaultTTL time.Duration
}

// CacheItem 캐시 아이템
type CacheItem struct {
	Value     string
	ExpiresAt time.Time
}

// WalletDecryptService 지갑 복호화 서비스
type WalletDecryptService struct {
	secretsClient *secretsmanager.Client
	kmsClient     *kms.Client
	cache         *SecretCache
}

// WalletSecret 지갑 시크릿 구조체
type WalletSecret struct {
	EncryptedPrivateKey string `json:"encrypted_private_key"`
	PublicKey           string `json:"public_key"`
	Address             string `json:"address"`
}

var (
	walletService     *WalletDecryptService
	walletServiceOnce sync.Once
)

// 싱글톤 서비스 반환 함수
func GetWalletDecryptService(ctx context.Context) (*WalletDecryptService, error) {
	var err error
	walletServiceOnce.Do(func() {
		walletService, err = NewWalletDecryptService(ctx)
		if err != nil {
			log.Printf("Failed to initialize WalletDecryptService: %v", err)
		}
	})
	return walletService, err
}

// NewSecretCache 새로운 캐시 생성
func NewSecretCache(defaultTTL time.Duration) *SecretCache {
	return &SecretCache{
		data:       make(map[string]CacheItem),
		defaultTTL: defaultTTL,
	}
}

// Set 캐시에 값 저장
func (c *SecretCache) Set(key, value string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.data[key] = CacheItem{
		Value:     value,
		ExpiresAt: time.Now().Add(c.defaultTTL),
	}
}

// Get 캐시에서 값 조회
func (c *SecretCache) Get(key string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	item, exists := c.data[key]
	if !exists {
		return "", false
	}

	if time.Now().After(item.ExpiresAt) {
		// 만료된 캐시 삭제
		delete(c.data, key)
		return "", false
	}

	return item.Value, true
}

// NewWalletDecryptService 새로운 지갑 복호화 서비스 생성
func NewWalletDecryptService(ctx context.Context) (*WalletDecryptService, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	return &WalletDecryptService{
		secretsClient: secretsmanager.NewFromConfig(cfg),
		kmsClient:     kms.NewFromConfig(cfg),
		cache:         NewSecretCache(15 * time.Minute), // 15분 캐시 TTL
	}, nil
}

// GetSecretFromSecretsManager Secrets Manager에서 시크릿 조회 (캐싱 포함)
func (w *WalletDecryptService) GetSecretFromSecretsManager(ctx context.Context, secretID string) (string, error) {
	// 캐시에서 먼저 확인
	if cachedValue, exists := w.cache.Get(secretID); exists {
		log.Printf("Cache hit for secret: %s", secretID)
		return cachedValue, nil
	}

	log.Printf("Cache miss, fetching from Secrets Manager: %s", secretID)

	// Secrets Manager에서 시크릿 조회
	input := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretID),
	}

	result, err := w.secretsClient.GetSecretValue(ctx, input)
	if err != nil {
		return "", fmt.Errorf("failed to get secret value: %w", err)
	}

	if result.SecretString == nil {
		return "", fmt.Errorf("secret string is nil")
	}

	secretValue := *result.SecretString

	// 캐시에 저장
	w.cache.Set(secretID, secretValue)

	return secretValue, nil
}

// DecryptWithKMS KMS로 암호화된 데이터 복호화
func (w *WalletDecryptService) DecryptWithKMS(ctx context.Context, keyAlias, encryptedData string) (string, error) {
	// Base64 디코딩
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64 data: %w", err)
	}

	// KMS Decrypt 요청
	input := &kms.DecryptInput{
		KeyId:          aws.String(keyAlias),
		CiphertextBlob: ciphertext,
	}

	result, err := w.kmsClient.Decrypt(ctx, input)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt with KMS: %w", err)
	}

	// Plaintext를 문자열로 변환
	decryptedData := string(result.Plaintext)
	return decryptedData, nil
}

// GetAndDecryptWalletSecret 지갑 시크릿 조회 및 복호화
func (w *WalletDecryptService) GetAndDecryptWalletSecret(ctx context.Context, secretID, keyAlias string) (*WalletSecret, string, error) {
	// 1. Secrets Manager에서 암호화된 데이터 조회 (캐싱 포함)
	secretString, err := w.GetSecretFromSecretsManager(ctx, secretID)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get secret: %w", err)
	}

	log.Printf("Raw secret data (first 100 chars): %.100s", secretString)

	// 2. 데이터 형태 확인
	// Secrets Manager에서 반환된 데이터가 JSON인지 Base64인지 확인
	var walletSecret WalletSecret
	var decryptedPrivateKey string

	if len(secretString) > 0 && secretString[0] == '{' {
		// JSON 형태인 경우
		log.Printf("Detected JSON format")
		if err := json.Unmarshal([]byte(secretString), &walletSecret); err != nil {
			return nil, "", fmt.Errorf("failed to unmarshal JSON secret: %w", err)
		}

		// 암호화된 Private Key를 KMS로 복호화
		decryptedPrivateKey, err = w.DecryptWithKMS(ctx, keyAlias, walletSecret.EncryptedPrivateKey)
		if err != nil {
			return nil, "", fmt.Errorf("failed to decrypt private key: %w", err)
		}
	} else {
		// Base64 형태인 경우 (CLI 명령어와 동일한 상황)
		log.Printf("Detected Base64 format, decrypting directly")

		// 전체 secretString이 암호화된 데이터라고 가정하고 KMS로 직접 복호화
		decryptedData, err := w.DecryptWithKMS(ctx, keyAlias, secretString)
		if err != nil {
			return nil, "", fmt.Errorf("failed to decrypt with KMS: %w", err)
		}

		log.Printf("Decrypted data (first 100 chars): %.100s", decryptedData)

		// 복호화된 데이터가 JSON인지 확인
		if len(decryptedData) > 0 && decryptedData[0] == '{' {
			// 복호화된 데이터가 JSON인 경우
			if err := json.Unmarshal([]byte(decryptedData), &walletSecret); err != nil {
				return nil, "", fmt.Errorf("failed to unmarshal decrypted JSON: %w", err)
			}
			// 이 경우 private_key는 이미 복호화된 상태
			decryptedPrivateKey = walletSecret.EncryptedPrivateKey
		} else {
			// 복호화된 데이터가 직접 Private Key인 경우
			decryptedPrivateKey = decryptedData
			walletSecret = WalletSecret{
				EncryptedPrivateKey: "",
				PublicKey:           "N/A",
				Address:             "N/A",
			}
		}
	}

	return &walletSecret, decryptedPrivateKey, nil
}
