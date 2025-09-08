package repositories

import (
	"context"

	"github.com/acecasino/account_manage/internal/domain/entities"
	"gorm.io/gorm"
)

type UserWalletBalanceRepository struct {
	db *gorm.DB
}

func NewUserWalletBalanceRepository(db *gorm.DB) *UserWalletBalanceRepository {
	return &UserWalletBalanceRepository{db: db}
}

// GetByID retrieves user wallet balance by ID
func (r *UserWalletBalanceRepository) GetByID(ctx context.Context, id int) (*entities.UserWalletBalance, error) {
	var balance entities.UserWalletBalance
	err := r.db.WithContext(ctx).Preload("Blockchain").First(&balance, id).Error
	return &balance, err
}

// GetByChainAccountID retrieves user wallet balance by chain account ID
func (r *UserWalletBalanceRepository) GetByChainAccountID(ctx context.Context, chainAccountID int) (*entities.UserWalletBalance, error) {
	var balance entities.UserWalletBalance
	err := r.db.WithContext(ctx).Preload("Blockchain").Where("chain_account_id = ?", chainAccountID).First(&balance).Error
	return &balance, err
}

// GetByUserID retrieves user wallet balances by user ID
func (r *UserWalletBalanceRepository) GetByUserID(ctx context.Context, userID int) ([]entities.UserWalletBalance, error) {
	var balances []entities.UserWalletBalance
	err := r.db.WithContext(ctx).Preload("Blockchain").
		Joins("JOIN chain_accounts ON user_wallet_balance.chain_account_id = chain_accounts.id").
		Where("chain_accounts.user_id = ?", userID).
		Find(&balances).Error
	return balances, err
}

// GetByChainID retrieves user wallet balances by chain ID
func (r *UserWalletBalanceRepository) GetByChainID(ctx context.Context, chainID int) ([]entities.UserWalletBalance, error) {
	var balances []entities.UserWalletBalance
	err := r.db.WithContext(ctx).Preload("Blockchain").Where("chain_id = ?", chainID).Find(&balances).Error
	return balances, err
}

// GetAll retrieves all user wallet balances
func (r *UserWalletBalanceRepository) GetAll(ctx context.Context) ([]entities.UserWalletBalance, error) {
	var balances []entities.UserWalletBalance
	err := r.db.WithContext(ctx).Preload("Blockchain").Find(&balances).Error
	return balances, err
}

// Create creates a new user wallet balance
func (r *UserWalletBalanceRepository) Create(ctx context.Context, balance *entities.UserWalletBalance) error {
	return r.db.WithContext(ctx).Create(balance).Error
}

// Update updates a user wallet balance
func (r *UserWalletBalanceRepository) Update(ctx context.Context, balance *entities.UserWalletBalance) error {
	return r.db.WithContext(ctx).Save(balance).Error
}

// Delete deletes a user wallet balance
func (r *UserWalletBalanceRepository) Delete(ctx context.Context, id int) error {
	return r.db.WithContext(ctx).Delete(&entities.UserWalletBalance{}, id).Error
}

// UpdateBalance updates the balance for a specific chain account
func (r *UserWalletBalanceRepository) UpdateBalance(ctx context.Context, chainAccountID int, balance string) error {
	return r.db.WithContext(ctx).Model(&entities.UserWalletBalance{}).
		Where("chain_account_id = ?", chainAccountID).
		Update("balance", balance).Error
}
