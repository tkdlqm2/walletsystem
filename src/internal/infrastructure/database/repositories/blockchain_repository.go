package repositories

import (
	"context"

	"github.com/acecasino/account_manage/internal/domain/entities"
	"gorm.io/gorm"
)

type BlockchainRepository struct {
	db *gorm.DB
}

func NewBlockchainRepository(db *gorm.DB) *BlockchainRepository {
	return &BlockchainRepository{db: db}
}

// GetByID retrieves blockchain by ID
func (r *BlockchainRepository) GetByID(ctx context.Context, id int) (*entities.Blockchain, error) {
	var blockchain entities.Blockchain
	err := r.db.WithContext(ctx).First(&blockchain, id).Error
	return &blockchain, err
}

// GetByName retrieves blockchain by name
func (r *BlockchainRepository) GetByName(ctx context.Context, name string) (*entities.Blockchain, error) {
	var blockchain entities.Blockchain
	err := r.db.WithContext(ctx).Where("name = ?", name).First(&blockchain).Error
	return &blockchain, err
}

// GetAll retrieves all blockchains
func (r *BlockchainRepository) GetAll(ctx context.Context) ([]entities.Blockchain, error) {
	var blockchains []entities.Blockchain
	err := r.db.WithContext(ctx).Find(&blockchains).Error
	return blockchains, err
}

// GetActive retrieves all active blockchains
func (r *BlockchainRepository) GetActive(ctx context.Context) ([]entities.Blockchain, error) {
	var blockchains []entities.Blockchain
	err := r.db.WithContext(ctx).Where("active_watch = ?", true).Find(&blockchains).Error
	return blockchains, err
}

// UpdateLastCheckedBlock updates the last checked block number
func (r *BlockchainRepository) UpdateLastCheckedBlock(ctx context.Context, id int, blockNumber int64) error {
	return r.db.WithContext(ctx).Model(&entities.Blockchain{}).Where("id = ?", id).Update("last_checked_block", blockNumber).Error
}

// Create creates a new blockchain
func (r *BlockchainRepository) Create(ctx context.Context, blockchain *entities.Blockchain) error {
	return r.db.WithContext(ctx).Create(blockchain).Error
}

// Update updates a blockchain
func (r *BlockchainRepository) Update(ctx context.Context, blockchain *entities.Blockchain) error {
	return r.db.WithContext(ctx).Save(blockchain).Error
}

// Delete deletes a blockchain
func (r *BlockchainRepository) Delete(ctx context.Context, id int) error {
	return r.db.WithContext(ctx).Delete(&entities.Blockchain{}, id).Error
}
