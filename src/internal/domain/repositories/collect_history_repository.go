package repositories

import (
	"context"

	"github.com/acecasino/account_manage/internal/domain/entities"
)

// CollectHistoryRepository defines the interface for collect history operations
type CollectHistoryRepository interface {
	// Create operations
	Create(ctx context.Context, collect *entities.CollectHistory) error
	CreateBatch(ctx context.Context, collects []entities.CollectHistory) error

	// Read operations
	GetByID(ctx context.Context, id int64) (*entities.CollectHistory, error)
	GetByTxHash(ctx context.Context, txHash string) (*entities.CollectHistory, error)
	GetByAddress(ctx context.Context, address string, limit, offset int) ([]entities.CollectHistory, error)
	GetByCurrencyID(ctx context.Context, currencyID int, limit, offset int) ([]entities.CollectHistory, error)

	// Update operations
	Update(ctx context.Context, collect *entities.CollectHistory) error

	// Delete operations
	Delete(ctx context.Context, id int64) error

	// Utility operations
	Count(ctx context.Context) (int64, error)
	ExistsByTxHash(ctx context.Context, txHash string) (bool, error)
	ExistsByTxHashBatch(ctx context.Context, txHashes []string) (map[string]bool, error)
}
