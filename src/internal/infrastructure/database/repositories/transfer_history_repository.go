package repositories

import (
	"context"

	"github.com/acecasino/account_manage/internal/domain/entities"
	"gorm.io/gorm"
)

type TransferHistoryRepository struct {
	db *gorm.DB
}

func NewTransferHistoryRepository(db *gorm.DB) *TransferHistoryRepository {
	return &TransferHistoryRepository{db: db}
}

// GetByID retrieves transfer history by ID
func (r *TransferHistoryRepository) GetByID(ctx context.Context, id int) (*entities.TransferHistory, error) {
	var transfer entities.TransferHistory
	err := r.db.WithContext(ctx).First(&transfer, id).Error
	return &transfer, err
}

// GetByTxHash retrieves transfer history by transaction hash
func (r *TransferHistoryRepository) GetByTxHash(ctx context.Context, txHash string) ([]entities.TransferHistory, error) {
	var transfers []entities.TransferHistory
	err := r.db.WithContext(ctx).Where("tx_hash = ?", txHash).Find(&transfers).Error
	return transfers, err
}

// GetByCurrencyID retrieves transfer history by currency ID
func (r *TransferHistoryRepository) GetByCurrencyID(ctx context.Context, currencyID int) ([]entities.TransferHistory, error) {
	var transfers []entities.TransferHistory
	err := r.db.WithContext(ctx).Where("currency_id = ?", currencyID).Find(&transfers).Error
	return transfers, err
}

// GetByAddress retrieves transfer history by address (from or to)
func (r *TransferHistoryRepository) GetByAddress(ctx context.Context, address string) ([]entities.TransferHistory, error) {
	var transfers []entities.TransferHistory
	err := r.db.WithContext(ctx).Where("_from = ? OR _to = ?", address, address).Find(&transfers).Error
	return transfers, err
}

// GetByBlockNumber retrieves transfer history by block number
func (r *TransferHistoryRepository) GetByBlockNumber(ctx context.Context, blockNumber uint64) ([]entities.TransferHistory, error) {
	var transfers []entities.TransferHistory
	err := r.db.WithContext(ctx).Where("block_number = ?", blockNumber).Find(&transfers).Error
	return transfers, err
}

// GetByBlockRange retrieves transfer history by block number range
func (r *TransferHistoryRepository) GetByBlockRange(ctx context.Context, fromBlock, toBlock uint64) ([]entities.TransferHistory, error) {
	var transfers []entities.TransferHistory
	err := r.db.WithContext(ctx).Where("block_number BETWEEN ? AND ?", fromBlock, toBlock).Find(&transfers).Error
	return transfers, err
}

// GetAll retrieves all transfer history
func (r *TransferHistoryRepository) GetAll(ctx context.Context) ([]entities.TransferHistory, error) {
	var transfers []entities.TransferHistory
	err := r.db.WithContext(ctx).Find(&transfers).Error
	return transfers, err
}

// Create creates a new transfer history entry
func (r *TransferHistoryRepository) Create(ctx context.Context, transfer *entities.TransferHistory) error {
	return r.db.WithContext(ctx).Create(transfer).Error
}

// CreateBatch creates multiple transfer history entries
func (r *TransferHistoryRepository) CreateBatch(ctx context.Context, transfers []entities.TransferHistory) error {
	return r.db.WithContext(ctx).Create(&transfers).Error
}

// Update updates a transfer history entry
func (r *TransferHistoryRepository) Update(ctx context.Context, transfer *entities.TransferHistory) error {
	return r.db.WithContext(ctx).Save(transfer).Error
}

// Delete deletes a transfer history entry
func (r *TransferHistoryRepository) Delete(ctx context.Context, id int) error {
	return r.db.WithContext(ctx).Delete(&entities.TransferHistory{}, id).Error
}

// DeleteOldEntries deletes old transfer history entries
func (r *TransferHistoryRepository) DeleteOldEntries(ctx context.Context, keepCount int) error {
	return r.db.WithContext(ctx).Exec(`
		DELETE FROM transfer_history
		WHERE id < (SELECT max(id) - ? FROM transfer_history) AND 
		NOT EXISTS (
			SELECT 1 
			FROM deposit_history 
			WHERE deposit_history.tx_ref = transfer_history.id
		)
	`, keepCount).Error
}

// GetUnprocessedEvents retrieves unprocessed transfer events with optimized query
func (r *TransferHistoryRepository) GetUnprocessedEvents(ctx context.Context, limit int) ([]entities.TransferHistory, error) {
	var events []entities.TransferHistory

	// 인덱스 최적화된 쿼리: processed = false인 이벤트만 조회
	err := r.db.WithContext(ctx).
		Where("processed = ?", false).
		Order("create_at ASC").
		Limit(limit).
		Find(&events).Error

	return events, err
}

// MarkAsProcessed marks transfer events as processed
func (r *TransferHistoryRepository) MarkAsProcessed(ctx context.Context, eventIDs []int64) error {
	if len(eventIDs) == 0 {
		return nil
	}

	// 배치로 processed = true로 업데이트
	return r.db.WithContext(ctx).
		Model(&entities.TransferHistory{}).
		Where("id IN ?", eventIDs).
		Update("processed", true).Error
}

// GetUnprocessedCount returns the count of unprocessed transfer events
func (r *TransferHistoryRepository) GetUnprocessedCount(ctx context.Context) (int, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&entities.TransferHistory{}).
		Where("processed = ?", false).
		Count(&count).Error
	return int(count), err
}
