package repositories

import (
	"context"

	"github.com/acecasino/account_manage/internal/domain/entities"
	domainRepos "github.com/acecasino/account_manage/internal/domain/repositories"
	"gorm.io/gorm"
)

// collectHistoryRepository implements CollectHistoryRepository interface
type collectHistoryRepository struct {
	db *gorm.DB
}

// NewCollectHistoryRepository creates a new collect history repository
func NewCollectHistoryRepository(db *gorm.DB) domainRepos.CollectHistoryRepository {
	return &collectHistoryRepository{
		db: db,
	}
}

// Create creates a new collect history record
func (r *collectHistoryRepository) Create(ctx context.Context, collect *entities.CollectHistory) error {
	return r.db.WithContext(ctx).Create(collect).Error
}

// CreateBatch creates multiple collect history records in batch
func (r *collectHistoryRepository) CreateBatch(ctx context.Context, collects []entities.CollectHistory) error {
	if len(collects) == 0 {
		return nil
	}
	return r.db.WithContext(ctx).CreateInBatches(collects, 100).Error
}

// GetByID retrieves collect history by ID
func (r *collectHistoryRepository) GetByID(ctx context.Context, id int64) (*entities.CollectHistory, error) {
	var collect entities.CollectHistory
	err := r.db.WithContext(ctx).First(&collect, id).Error
	if err != nil {
		return nil, err
	}
	return &collect, nil
}

// GetByTxHash retrieves collect history by transaction hash
func (r *collectHistoryRepository) GetByTxHash(ctx context.Context, txHash string) (*entities.CollectHistory, error) {
	var collect entities.CollectHistory
	err := r.db.WithContext(ctx).Where("tx_hash = ?", txHash).First(&collect).Error
	if err != nil {
		return nil, err
	}
	return &collect, nil
}

// GetByAddress retrieves collect history by address (from_addr or to_addr)
func (r *collectHistoryRepository) GetByAddress(ctx context.Context, address string, limit, offset int) ([]entities.CollectHistory, error) {
	var collects []entities.CollectHistory
	query := r.db.WithContext(ctx).Where("from_addr = ? OR to_addr = ?", address, address)

	if limit > 0 {
		query = query.Limit(limit)
	}
	if offset > 0 {
		query = query.Offset(offset)
	}

	err := query.Order("created DESC").Find(&collects).Error
	return collects, err
}

// GetByCurrencyID retrieves collect history by currency ID
func (r *collectHistoryRepository) GetByCurrencyID(ctx context.Context, currencyID int, limit, offset int) ([]entities.CollectHistory, error) {
	var collects []entities.CollectHistory
	query := r.db.WithContext(ctx).Where("currency_id = ?", currencyID)

	if limit > 0 {
		query = query.Limit(limit)
	}
	if offset > 0 {
		query = query.Offset(offset)
	}

	err := query.Order("created DESC").Find(&collects).Error
	return collects, err
}

// Update updates an existing collect history record
func (r *collectHistoryRepository) Update(ctx context.Context, collect *entities.CollectHistory) error {
	return r.db.WithContext(ctx).Save(collect).Error
}

// Delete deletes a collect history record by ID
func (r *collectHistoryRepository) Delete(ctx context.Context, id int64) error {
	return r.db.WithContext(ctx).Delete(&entities.CollectHistory{}, id).Error
}

// Count returns the total count of collect history records
func (r *collectHistoryRepository) Count(ctx context.Context) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&entities.CollectHistory{}).Count(&count).Error
	return count, err
}

// ExistsByTxHash checks if a collect history record exists by transaction hash
func (r *collectHistoryRepository) ExistsByTxHash(ctx context.Context, txHash string) (bool, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&entities.CollectHistory{}).Where("tx_hash = ?", txHash).Count(&count).Error
	return count > 0, err
}

// ExistsByTxHashBatch checks if collect history records exist by transaction hashes
func (r *collectHistoryRepository) ExistsByTxHashBatch(ctx context.Context, txHashes []string) (map[string]bool, error) {
	if len(txHashes) == 0 {
		return make(map[string]bool), nil
	}

	var results []struct {
		TxHash string `gorm:"column:tx_hash"`
	}

	err := r.db.WithContext(ctx).Model(&entities.CollectHistory{}).
		Select("tx_hash").
		Where("tx_hash IN ?", txHashes).
		Find(&results).Error

	if err != nil {
		return nil, err
	}

	existsMap := make(map[string]bool)
	for _, result := range results {
		existsMap[result.TxHash] = true
	}

	return existsMap, nil
}
