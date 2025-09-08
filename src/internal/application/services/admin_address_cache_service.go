package services

import (
	"context"
	"strings"
	"sync"

	"github.com/acecasino/account_manage/internal/domain/entities"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// AdminAddressCacheService manages caching of admin wallet addresses
type AdminAddressCacheService struct {
	db     *gorm.DB
	logger *zap.Logger
	cache  map[string]bool // normalized address -> true
	mutex  sync.RWMutex
}

// NewAdminAddressCacheService creates a new admin address cache service
func NewAdminAddressCacheService(db *gorm.DB, logger *zap.Logger) *AdminAddressCacheService {
	return &AdminAddressCacheService{
		db:     db,
		logger: logger,
		cache:  make(map[string]bool),
	}
}

// InitializeCache loads all admin wallet addresses from blockchain table into cache
func (c *AdminAddressCacheService) InitializeCache(ctx context.Context) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.logger.Info("Initializing admin address cache")

	// blockchain 테이블에서 withdraw_address 컬럼 조회
	var blockchains []entities.Blockchain
	err := c.db.WithContext(ctx).
		Select("withdraw_address").
		Where("withdraw_address IS NOT NULL AND withdraw_address != ''").
		Find(&blockchains).Error

	if err != nil {
		c.logger.Error("Failed to load admin addresses from database", zap.Error(err))
		return err
	}

	// Clear existing cache
	c.cache = make(map[string]bool)

	// Populate cache (소문자로 정규화하여 저장)
	for _, blockchain := range blockchains {
		if blockchain.WithdrawAddress != "" {
			// 주소를 소문자로 정규화하여 저장
			normalizedAddress := strings.ToLower(blockchain.WithdrawAddress)
			c.cache[normalizedAddress] = true
		}
	}

	// 디버깅: 캐시된 주소들 로그 출력
	cachedAddresses := make([]string, 0, len(c.cache))
	for addr := range c.cache {
		cachedAddresses = append(cachedAddresses, addr)
	}

	c.logger.Info("Admin address cache initialized",
		zap.Int("cached_addresses", len(c.cache)),
		zap.Strings("cached_addresses", cachedAddresses),
	)

	return nil
}

// IsAdminAddress checks if the given address is an admin address
func (c *AdminAddressCacheService) IsAdminAddress(ctx context.Context, address string) (bool, error) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	// Check if cache is empty
	if len(c.cache) == 0 {
		c.mutex.RUnlock()
		// Initialize cache if empty
		if err := c.InitializeCache(ctx); err != nil {
			return false, err
		}
		c.mutex.RLock()
	}

	// 주소를 소문자로 정규화하여 조회
	normalizedAddress := strings.ToLower(address)
	return c.cache[normalizedAddress], nil
}

// GetCacheSize returns the number of cached admin addresses
func (c *AdminAddressCacheService) GetCacheSize() int {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return len(c.cache)
}

// RefreshCache refreshes the admin address cache
func (c *AdminAddressCacheService) RefreshCache(ctx context.Context) error {
	return c.InitializeCache(ctx)
}
