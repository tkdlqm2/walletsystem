package repositories

import (
	"context"

	"github.com/acecasino/account_manage/internal/domain/entities"
)

// BlockchainRepository defines the interface for blockchain data operations
type BlockchainRepository interface {
	GetByID(ctx context.Context, id int) (*entities.Blockchain, error)
	GetByName(ctx context.Context, name string) (*entities.Blockchain, error)
	GetAll(ctx context.Context) ([]entities.Blockchain, error)
	GetActive(ctx context.Context) ([]entities.Blockchain, error)
	UpdateLastCheckedBlock(ctx context.Context, id int, blockNumber int64) error
	Create(ctx context.Context, blockchain *entities.Blockchain) error
	Update(ctx context.Context, blockchain *entities.Blockchain) error
	Delete(ctx context.Context, id int) error
}
