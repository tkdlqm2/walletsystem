package repositories

import (
	"context"

	"github.com/acecasino/account_manage/internal/domain/entities"
	domainRepos "github.com/acecasino/account_manage/internal/domain/repositories"
	"gorm.io/gorm"
)

// withdrawHistoryRepository implements WithdrawHistoryRepository interface
type withdrawHistoryRepository struct {
	db *gorm.DB
}

// NewWithdrawHistoryRepository creates a new withdraw history repository
func NewWithdrawHistoryRepository(db *gorm.DB) domainRepos.WithdrawHistoryRepository {
	return &withdrawHistoryRepository{
		db: db,
	}
}

// Create creates a new withdraw history record
func (r *withdrawHistoryRepository) Create(ctx context.Context, withdraw *entities.WithdrawHistory) error {
	return r.db.WithContext(ctx).Create(withdraw).Error
}

// CreateBatch creates multiple withdraw history records in batch
func (r *withdrawHistoryRepository) CreateBatch(ctx context.Context, withdraws []entities.WithdrawHistory) error {
	if len(withdraws) == 0 {
		return nil
	}
	return r.db.WithContext(ctx).CreateInBatches(withdraws, 100).Error
}

// GetByID retrieves withdraw history by ID
func (r *withdrawHistoryRepository) GetByID(ctx context.Context, id int) (*entities.WithdrawHistory, error) {
	var withdraw entities.WithdrawHistory
	err := r.db.WithContext(ctx).First(&withdraw, id).Error
	if err != nil {
		return nil, err
	}
	return &withdraw, nil
}

// GetByTxHash retrieves withdraw history by transaction hash
func (r *withdrawHistoryRepository) GetByTxHash(ctx context.Context, txHash string) (*entities.WithdrawHistory, error) {
	var withdraw entities.WithdrawHistory
	err := r.db.WithContext(ctx).Where("tx_hash = ?", txHash).First(&withdraw).Error
	if err != nil {
		return nil, err
	}
	return &withdraw, nil
}

// GetByUserID retrieves withdraw history by user ID
func (r *withdrawHistoryRepository) GetByUserID(ctx context.Context, userID int, limit, offset int) ([]entities.WithdrawHistory, error) {
	var withdraws []entities.WithdrawHistory
	query := r.db.WithContext(ctx).Where("user_id = ?", userID)

	if limit > 0 {
		query = query.Limit(limit)
	}
	if offset > 0 {
		query = query.Offset(offset)
	}

	err := query.Order("create_at DESC").Find(&withdraws).Error
	return withdraws, err
}

// GetByCurrencyID retrieves withdraw history by currency ID
func (r *withdrawHistoryRepository) GetByCurrencyID(ctx context.Context, currencyID int, limit, offset int) ([]entities.WithdrawHistory, error) {
	var withdraws []entities.WithdrawHistory
	query := r.db.WithContext(ctx).Where("currency_id = ?", currencyID)

	if limit > 0 {
		query = query.Limit(limit)
	}
	if offset > 0 {
		query = query.Offset(offset)
	}

	err := query.Order("create_at DESC").Find(&withdraws).Error
	return withdraws, err
}

// Update updates an existing withdraw history record
func (r *withdrawHistoryRepository) Update(ctx context.Context, withdraw *entities.WithdrawHistory) error {
	return r.db.WithContext(ctx).Save(withdraw).Error
}

// Delete deletes a withdraw history record by ID
func (r *withdrawHistoryRepository) Delete(ctx context.Context, id int) error {
	return r.db.WithContext(ctx).Delete(&entities.WithdrawHistory{}, id).Error
}

// Count returns the total count of withdraw history records
func (r *withdrawHistoryRepository) Count(ctx context.Context) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&entities.WithdrawHistory{}).Count(&count).Error
	return count, err
}

// ExistsByTxHash checks if a withdraw history record exists by transaction hash
func (r *withdrawHistoryRepository) ExistsByTxHash(ctx context.Context, txHash string) (bool, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&entities.WithdrawHistory{}).Where("tx_hash = ?", txHash).Count(&count).Error
	return count > 0, err
}

// ExistsByTxHashBatch checks if withdraw history records exist by transaction hashes
func (r *withdrawHistoryRepository) ExistsByTxHashBatch(ctx context.Context, txHashes []string) (map[string]bool, error) {
	if len(txHashes) == 0 {
		return make(map[string]bool), nil
	}

	var results []struct {
		TxHash string `gorm:"column:tx_hash"`
	}

	err := r.db.WithContext(ctx).Model(&entities.WithdrawHistory{}).
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
