package repositories

import (
	"context"
	"errors"
	"fmt"

	"github.com/acecasino/account_manage/internal/domain/entities"
	domainRepos "github.com/acecasino/account_manage/internal/domain/repositories"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

// userBalanceRepository implements UserBalanceRepository interface
type userBalanceRepository struct {
	db *gorm.DB
}

// NewUserBalanceRepository creates a new user balance repository
func NewUserBalanceRepository(db *gorm.DB) domainRepos.UserBalanceRepository {
	return &userBalanceRepository{db: db}
}

// GetBalanceByUserIDAndCurrencyID retrieves balance for a specific user and currency
func (r *userBalanceRepository) GetBalanceByUserIDAndCurrencyID(ctx context.Context, userID, currencyID int) (*entities.UserBalance, error) {
	var userBalance entities.UserBalance
	err := r.db.WithContext(ctx).
		Where("user_id = ? AND currency_id = ?", userID, currencyID).
		First(&userBalance).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil // Return nil if no record found
		}
		return nil, err
	}

	return &userBalance, nil
}

// GetBalanceByAccountIDAndCurrencyID retrieves balance for a specific account and currency
func (r *userBalanceRepository) GetBalanceByAccountIDAndCurrencyID(ctx context.Context, accountID, currencyID int) (*entities.UserBalance, error) {
	var userBalance entities.UserBalance
	err := r.db.WithContext(ctx).
		Where("account_id = ? AND currency_id = ?", accountID, currencyID).
		First(&userBalance).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil // Return nil if no record found
		}
		return nil, err
	}

	return &userBalance, nil
}

// Create creates a new user balance record
func (r *userBalanceRepository) Create(ctx context.Context, userBalance *entities.UserBalance) error {
	return r.db.WithContext(ctx).Create(userBalance).Error
}

// Update updates an existing user balance record
func (r *userBalanceRepository) Update(ctx context.Context, userBalance *entities.UserBalance) error {
	return r.db.WithContext(ctx).Save(userBalance).Error
}

// Delete deletes a user balance record
func (r *userBalanceRepository) Delete(ctx context.Context, id uint) error {
	return r.db.WithContext(ctx).Delete(&entities.UserBalance{}, id).Error
}

// 기존 파일에 메서드 추가
func (r *userBalanceRepository) UpsertBalanceBatch(ctx context.Context, updates []domainRepos.BalanceUpdate) error {
	if len(updates) == 0 {
		return nil
	}

	// PostgreSQL UNNEST를 사용한 벌크 UPSERT
	accountIDs := make([]int, len(updates))
	currencyIDs := make([]int, len(updates))
	userIDs := make([]int, len(updates))
	amounts := make([]string, len(updates))

	for i, update := range updates {
		accountIDs[i] = update.AccountID
		currencyIDs[i] = update.CurrencyID
		userIDs[i] = update.UserID
		amounts[i] = fmt.Sprintf("%.18f", update.Balance) // Amount -> Balance로 변경
	}

	query := `
        INSERT INTO user_balance (account_id, currency_id, user_id, balance, last_action)
        SELECT * FROM UNNEST($1::int[], $2::int[], $3::int[], $4::numeric[], $5::text[])
        AS t(account_id, currency_id, user_id, balance, last_action)
        ON CONFLICT (account_id, currency_id)
        DO UPDATE SET
            balance = user_balance.balance + EXCLUDED.balance,
            last_action = EXCLUDED.last_action,
            update_at = CURRENT_TIMESTAMP
    `

	lastActions := make([]string, len(updates))
	for i := range lastActions {
		lastActions[i] = "deposit"
	}

	err := r.db.WithContext(ctx).Exec(query,
		pq.Array(accountIDs),
		pq.Array(currencyIDs),
		pq.Array(userIDs),
		pq.Array(amounts),
		pq.Array(lastActions),
	).Error

	return err
}
