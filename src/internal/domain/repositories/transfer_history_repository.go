package repositories

import (
	"context"

	"github.com/acecasino/account_manage/internal/domain/entities"
)

// TransferHistoryRepository defines the interface for transfer history data operations
type TransferHistoryRepository interface {
	GetByID(ctx context.Context, id int) (*entities.TransferHistory, error)
	GetByTxHash(ctx context.Context, txHash string) ([]entities.TransferHistory, error)
	GetByCurrencyID(ctx context.Context, currencyID int) ([]entities.TransferHistory, error)
	GetByAddress(ctx context.Context, address string) ([]entities.TransferHistory, error)
	GetByBlockNumber(ctx context.Context, blockNumber uint64) ([]entities.TransferHistory, error)
	GetByBlockRange(ctx context.Context, fromBlock, toBlock uint64) ([]entities.TransferHistory, error)
	GetAll(ctx context.Context) ([]entities.TransferHistory, error)
	Create(ctx context.Context, transfer *entities.TransferHistory) error
	CreateBatch(ctx context.Context, transfers []entities.TransferHistory) error
	Update(ctx context.Context, transfer *entities.TransferHistory) error
	Delete(ctx context.Context, id int) error
	DeleteOldEntries(ctx context.Context, keepCount int) error

	// Deposit processing methods
	GetUnprocessedEvents(ctx context.Context, limit int) ([]entities.TransferHistory, error)
	MarkAsProcessed(ctx context.Context, eventIDs []int64) error
	GetUnprocessedCount(ctx context.Context) (int, error)
}
