package repositories

import (
	"context"
	"errors"
	"fmt"

	"github.com/acecasino/account_manage/internal/domain/entities"
	"gorm.io/gorm"
)

type ChainAccountRepository struct {
	db *gorm.DB
}

func NewChainAccountRepository(db *gorm.DB) *ChainAccountRepository {
	return &ChainAccountRepository{db: db}
}

// GetByID retrieves chain account by ID
func (r *ChainAccountRepository) GetByID(ctx context.Context, id int) (*entities.ChainAccount, error) {
	var account entities.ChainAccount
	err := r.db.WithContext(ctx).First(&account, id).Error
	return &account, err
}

// GetByUserID retrieves chain accounts by user ID
func (r *ChainAccountRepository) GetByUserID(ctx context.Context, userID int) ([]entities.ChainAccount, error) {
	var accounts []entities.ChainAccount
	err := r.db.WithContext(ctx).Where("user_id = ?", userID).Find(&accounts).Error
	return accounts, err
}

// GetByUserIDAndWalletType retrieves chain account by user ID and wallet type
func (r *ChainAccountRepository) GetByUserIDAndWalletType(ctx context.Context, userID int, walletType string) (*entities.ChainAccount, error) {
	var account entities.ChainAccount
	err := r.db.WithContext(ctx).Where("user_id = ? AND wallet_type = ?", userID, walletType).First(&account).Error
	return &account, err
}

// GetByEmailAndWalletType retrieves chain account by email and wallet type
func (r *ChainAccountRepository) GetByEmailAndWalletType(ctx context.Context, email, walletType string) (*entities.ChainAccount, error) {
	var account entities.ChainAccount
	err := r.db.WithContext(ctx).Joins("JOIN users ON chain_accounts.user_id = users.id").
		Where("users.email = ? AND chain_accounts.wallet_type = ?", email, walletType).
		First(&account).Error
	return &account, err
}

// GetByAddress retrieves chain account by address
func (r *ChainAccountRepository) GetByAddress(ctx context.Context, address string) (*entities.ChainAccount, error) {
	var account entities.ChainAccount
	// Find를 사용하여 record not found 에러 로그 출력 방지
	err := r.db.WithContext(ctx).Where("account_address = ?", address).Find(&account).Error
	if err != nil {
		return nil, err
	}
	// 결과가 없으면 nil 반환 (로그 출력 없음)
	if account.ID == 0 {
		return nil, nil
	}
	return &account, nil
}

// GetAll retrieves all chain accounts
func (r *ChainAccountRepository) GetAll(ctx context.Context) ([]entities.ChainAccount, error) {
	var accounts []entities.ChainAccount
	err := r.db.WithContext(ctx).Find(&accounts).Error
	return accounts, err
}

// Create creates a new chain account
func (r *ChainAccountRepository) Create(ctx context.Context, account *entities.ChainAccount) error {
	return r.db.WithContext(ctx).Create(account).Error
}

// Update updates a chain account
func (r *ChainAccountRepository) Update(ctx context.Context, account *entities.ChainAccount) error {
	return r.db.WithContext(ctx).Save(account).Error
}

// Delete deletes a chain account
func (r *ChainAccountRepository) Delete(ctx context.Context, id int) error {
	return r.db.WithContext(ctx).Delete(&entities.ChainAccount{}, id).Error
}

// GetPrivateKeyUsingEmail retrieves private keys by email
func (r *ChainAccountRepository) GetPrivateKeyUsingEmail(ctx context.Context, email string) (map[string]string, error) {
	var accounts []entities.ChainAccount
	err := r.db.WithContext(ctx).Joins("JOIN users ON chain_accounts.user_id = users.id").
		Where("users.email = ?", email).
		Find(&accounts).Error

	if err != nil {
		return nil, err
	}

	result := make(map[string]string)
	for _, account := range accounts {
		result[account.WalletType] = account.PrivateKey
	}

	return result, nil
}

// GetPrivateKeyUsingEmailAndWalletType retrieves private key by email and wallet type
func (r *ChainAccountRepository) GetPrivateKeyUsingEmailAndWalletType(ctx context.Context, email, walletType string) (string, error) {
	var account entities.ChainAccount
	err := r.db.WithContext(ctx).Joins("JOIN users ON chain_accounts.user_id = users.id").
		Where("users.email = ? AND chain_accounts.wallet_type = ?", email, walletType).
		Select("private_key").
		First(&account).Error

	return account.PrivateKey, err
}

// GetChainAccountByEmailAndWalletType retrieves chain account by email and wallet type (legacy function)
func (r *ChainAccountRepository) GetChainAccountByEmailAndWalletType(ctx context.Context, email, walletType string) (*entities.ChainAccount, error) {
	// 이메일로 사용자 ID 조회
	userRepo := NewUserRepository(r.db)
	userID, err := userRepo.GetUserIDByEmail(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("failed to get user ID: %w", err)
	}

	if userID == 0 {
		return nil, errors.New("user not found")
	}

	// chain_account 테이블에서 user_id와 wallet_type으로 조회
	var chainAccount entities.ChainAccount
	err = r.db.WithContext(ctx).Where("user_id = ? AND wallet_type = ?", userID, walletType).First(&chainAccount).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, errors.New("chain account not found for user and wallet type")
		}
		return nil, fmt.Errorf("failed to query chain account: %w", err)
	}

	return &chainAccount, nil
}

// GetPrivateKeyUsingEmailLegacy retrieves private keys by email (legacy function)
func (r *ChainAccountRepository) GetPrivateKeyUsingEmailLegacy(ctx context.Context, email string) ([]entities.ChainAccount, error) {
	// 이메일로 사용자 ID 조회
	userRepo := NewUserRepository(r.db)
	userID, err := userRepo.GetUserIDByEmail(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("failed to get user ID: %w", err)
	}

	// chain_account 테이블에서 해당 사용자의 모든 지갑 정보 조회
	var chainAccounts []entities.ChainAccount
	err = r.db.WithContext(ctx).Where("user_id = ?", userID).Find(&chainAccounts).Error
	if err != nil {
		return nil, fmt.Errorf("failed to query chain accounts: %w", err)
	}

	return chainAccounts, nil
}
