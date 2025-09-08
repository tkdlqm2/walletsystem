package repositories

import (
	"context"

	"github.com/acecasino/account_manage/internal/domain/entities"
)

// WithdrawHistoryRepository defines the interface for withdraw history operations
type WithdrawHistoryRepository interface {
	// Create operations
	Create(ctx context.Context, withdraw *entities.WithdrawHistory) error
	CreateBatch(ctx context.Context, withdraws []entities.WithdrawHistory) error

	// Read operations
	GetByID(ctx context.Context, id int) (*entities.WithdrawHistory, error)
	GetByTxHash(ctx context.Context, txHash string) (*entities.WithdrawHistory, error)
	GetByUserID(ctx context.Context, userID int, limit, offset int) ([]entities.WithdrawHistory, error)
	GetByCurrencyID(ctx context.Context, currencyID int, limit, offset int) ([]entities.WithdrawHistory, error)

	// Update operations
	Update(ctx context.Context, withdraw *entities.WithdrawHistory) error

	// Delete operations
	Delete(ctx context.Context, id int) error

	// Utility operations
	Count(ctx context.Context) (int64, error)
	ExistsByTxHash(ctx context.Context, txHash string) (bool, error)
	ExistsByTxHashBatch(ctx context.Context, txHashes []string) (map[string]bool, error)
}
