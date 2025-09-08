package repositories

import (
	"context"

	"github.com/acecasino/account_manage/internal/domain/entities"
)

// UserBalanceRepository defines the interface for user balance operations
type UserBalanceRepository interface {
	// GetBalanceByUserIDAndCurrencyID retrieves balance for a specific user and currency
	GetBalanceByUserIDAndCurrencyID(ctx context.Context, userID, currencyID int) (*entities.UserBalance, error)

	// GetBalanceByAccountIDAndCurrencyID retrieves balance for a specific account and currency
	GetBalanceByAccountIDAndCurrencyID(ctx context.Context, accountID, currencyID int) (*entities.UserBalance, error)

	// Create creates a new user balance record
	Create(ctx context.Context, userBalance *entities.UserBalance) error

	// Update updates an existing user balance record
	Update(ctx context.Context, userBalance *entities.UserBalance) error

	// Delete deletes a user balance record
	Delete(ctx context.Context, id uint) error

	// Batch operations
	UpsertBalanceBatch(ctx context.Context, updates []BalanceUpdate) error
}

// BalanceUpdate represents a balance update operation
type BalanceUpdate struct {
	AccountID  int     `json:"account_id"`
	CurrencyID int     `json:"currency_id"`
	UserID     int     `json:"user_id"`
	Balance    float64 `json:"balance"` // amount -> balance로 변경
}
