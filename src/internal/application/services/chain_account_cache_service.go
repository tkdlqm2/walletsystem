package services

import (
	"context"
	"strings"
	"sync"

	"github.com/acecasino/account_manage/internal/domain/entities"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// ChainAccountCacheService manages caching of chain account data
type ChainAccountCacheService struct {
	db     *gorm.DB
	logger *zap.Logger
	cache  map[string]*entities.ChainAccount
	mutex  sync.RWMutex
}

// NewChainAccountCacheService creates a new chain account cache service
func NewChainAccountCacheService(db *gorm.DB, logger *zap.Logger) *ChainAccountCacheService {
	return &ChainAccountCacheService{
		db:     db,
		logger: logger,
		cache:  make(map[string]*entities.ChainAccount),
	}
}

// InitializeCache loads all chain account data from database into cache
func (c *ChainAccountCacheService) InitializeCache(ctx context.Context) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.logger.Info("Initializing chain account cache")

	var accounts []entities.ChainAccount
	err := c.db.WithContext(ctx).Find(&accounts).Error
	if err != nil {
		c.logger.Error("Failed to load chain accounts from database", zap.Error(err))
		return err
	}

	// Clear existing cache
	c.cache = make(map[string]*entities.ChainAccount)

	// Populate cache (소문자로 정규화하여 저장)
	for i := range accounts {
		account := &accounts[i]
		// 주소를 소문자로 정규화하여 저장
		normalizedAddress := strings.ToLower(account.AccountAddress)
		c.cache[normalizedAddress] = account
	}

	// 디버깅: 캐시된 주소들 로그 출력
	cachedAddresses := make([]string, 0, len(c.cache))
	for addr := range c.cache {
		cachedAddresses = append(cachedAddresses, addr)
	}

	c.logger.Info("Chain account cache initialized",
		zap.Int("cached_accounts", len(c.cache)),
		zap.Strings("cached_addresses", cachedAddresses),
	)

	return nil
}

// GetAccountByAddress retrieves chain account by address from cache
func (c *ChainAccountCacheService) GetAccountByAddress(ctx context.Context, address string) (*entities.ChainAccount, error) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	// Check if cache is empty
	if len(c.cache) == 0 {
		c.mutex.RUnlock()
		// Initialize cache if empty
		if err := c.InitializeCache(ctx); err != nil {
			return nil, err
		}
		c.mutex.RLock()
	}

	// 주소를 소문자로 정규화하여 조회
	normalizedAddress := strings.ToLower(address)
	if account, exists := c.cache[normalizedAddress]; exists {
		return account, nil
	}

	// Account not found in cache
	return nil, nil
}

// GetAccountsByAddresses retrieves multiple chain accounts by addresses from cache
func (c *ChainAccountCacheService) GetAccountsByAddresses(ctx context.Context, addresses []string) (map[string]*entities.ChainAccount, error) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	// Check if cache is empty
	if len(c.cache) == 0 {
		c.mutex.RUnlock()
		// Initialize cache if empty
		if err := c.InitializeCache(ctx); err != nil {
			return nil, err
		}
		c.mutex.RLock()
	}

	result := make(map[string]*entities.ChainAccount)
	for _, address := range addresses {
		// 주소를 소문자로 정규화하여 조회
		normalizedAddress := strings.ToLower(address)
		if account, exists := c.cache[normalizedAddress]; exists {
			result[address] = account // 원본 주소를 키로 사용
			c.logger.Info("Found account in cache",
				zap.String("original_address", address),
				zap.String("normalized_address", normalizedAddress),
				zap.Int("account_id", account.ID),
			)
		} else {
			c.logger.Debug("Account not found in cache",
				zap.String("original_address", address),
				zap.String("normalized_address", normalizedAddress),
			)
		}
	}

	return result, nil
}

// RefreshCache reloads all chain account data from database
func (c *ChainAccountCacheService) RefreshCache(ctx context.Context) error {
	c.logger.Info("Refreshing chain account cache")
	return c.InitializeCache(ctx)
}

// GetCacheSize returns the number of cached accounts
func (c *ChainAccountCacheService) GetCacheSize() int {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return len(c.cache)
}

// ClearCache clears the cache
func (c *ChainAccountCacheService) ClearCache() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.cache = make(map[string]*entities.ChainAccount)
	c.logger.Info("Chain account cache cleared")
}
