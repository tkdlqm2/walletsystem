package repositories

import (
	"context"
	"fmt"

	"github.com/acecasino/account_manage/internal/domain/entities"
	"gorm.io/gorm"
)

type CurrencyRepository struct {
	db *gorm.DB
}

func NewCurrencyRepository(db *gorm.DB) *CurrencyRepository {
	return &CurrencyRepository{db: db}
}

// GetByID retrieves currency by ID
func (r *CurrencyRepository) GetByID(ctx context.Context, id int) (*entities.Currency, error) {
	var currency entities.Currency
	err := r.db.WithContext(ctx).Preload("Blockchain").First(&currency, id).Error
	return &currency, err
}

// GetBySymbol retrieves currency by symbol
func (r *CurrencyRepository) GetBySymbol(ctx context.Context, symbol string) (*entities.Currency, error) {
	var currency entities.Currency
	err := r.db.WithContext(ctx).Preload("Blockchain").Where("symbol = ?", symbol).First(&currency).Error
	return &currency, err
}

// GetBySymbolWithBlockchain retrieves currency by symbol with blockchain information
func (r *CurrencyRepository) GetBySymbolWithBlockchain(ctx context.Context, symbol string) (*entities.Currency, error) {
	var currency entities.Currency
	err := r.db.WithContext(ctx).Preload("Blockchain").Where("symbol = ?", symbol).First(&currency).Error
	return &currency, err
}

// GetAll retrieves all currencies
func (r *CurrencyRepository) GetAll(ctx context.Context) ([]entities.Currency, error) {
	var currencies []entities.Currency
	err := r.db.WithContext(ctx).Preload("Blockchain").Find(&currencies).Error
	return currencies, err
}

// GetActive retrieves all active currencies
func (r *CurrencyRepository) GetActive(ctx context.Context) ([]entities.Currency, error) {
	var currencies []entities.Currency
	err := r.db.WithContext(ctx).Preload("Blockchain").Where("active_watch = ?", true).Find(&currencies).Error
	return currencies, err
}

// GetByChainID retrieves currencies by chain ID
func (r *CurrencyRepository) GetByChainID(ctx context.Context, chainID int) ([]entities.Currency, error) {
	var currencies []entities.Currency
	err := r.db.WithContext(ctx).Preload("Blockchain").Where("chain_id = ?", chainID).Find(&currencies).Error
	return currencies, err
}

// Create creates a new currency
func (r *CurrencyRepository) Create(ctx context.Context, currency *entities.Currency) error {
	return r.db.WithContext(ctx).Create(currency).Error
}

// Update updates a currency
func (r *CurrencyRepository) Update(ctx context.Context, currency *entities.Currency) error {
	return r.db.WithContext(ctx).Save(currency).Error
}

// Delete deletes a currency
func (r *CurrencyRepository) Delete(ctx context.Context, id int) error {
	return r.db.WithContext(ctx).Delete(&entities.Currency{}, id).Error
}

// GetCurrency retrieves currency by token symbol (legacy function)
func (r *CurrencyRepository) GetCurrency(ctx context.Context, token string) (*entities.Currency, error) {
	// 먼저 currency 테이블만 조회해서 chain_id 확인
	var currencyInfo struct {
		ID           int     `gorm:"column:id"`
		Symbol       string  `gorm:"column:symbol"`
		Address      string  `gorm:"column:address"`
		ChainID      int     `gorm:"column:chain_id"`
		Decimal      int     `gorm:"column:decimal"`
		Price        float64 `gorm:"column:price"`
		ActiveWatch  bool    `gorm:"column:active_watch"`
		DefaultValue bool    `gorm:"column:default_value"`
	}

	result := r.db.WithContext(ctx).Table("currency").Where("symbol = ?", token).First(&currencyInfo)
	if result.Error != nil {
		return nil, result.Error
	}

	// blockchain 테이블에서 해당 chain_id의 정보 조회
	var blockchainInfo struct {
		ID               int    `gorm:"column:id"`
		Name             string `gorm:"column:name"`
		RpcURL           string `gorm:"column:rpc_url"`
		WalletType       string `gorm:"column:wallet_type"`
		LastCheckedBlock int    `gorm:"column:last_checked_block"`
		ActiveWatch      bool   `gorm:"column:active_watch"`
	}

	err := r.db.WithContext(ctx).Table("blockchain").Where("id = ?", currencyInfo.ChainID).First(&blockchainInfo).Error
	if err != nil {
		return nil, fmt.Errorf("failed to get blockchain info: %w", err)
	}

	// 결과를 Currency 구조체로 변환
	currency := &entities.Currency{
		ID:           currencyInfo.ID,
		ChainID:      blockchainInfo.ID,
		Symbol:       currencyInfo.Symbol,
		Address:      currencyInfo.Address,
		Decimal:      currencyInfo.Decimal,
		Price:        currencyInfo.Price,
		ActiveWatch:  currencyInfo.ActiveWatch,
		DefaultValue: currencyInfo.DefaultValue,
		Blockchain: entities.Blockchain{
			ID:               blockchainInfo.ID,
			Name:             blockchainInfo.Name,
			RpcURL:           blockchainInfo.RpcURL,
			WalletType:       blockchainInfo.WalletType,
			LastCheckedBlock: blockchainInfo.LastCheckedBlock,
			ActiveWatch:      blockchainInfo.ActiveWatch,
		},
	}

	return currency, nil
}
