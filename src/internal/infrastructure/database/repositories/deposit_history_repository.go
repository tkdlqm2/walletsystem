package repositories

import (
	"context"
	"time"

	"github.com/acecasino/account_manage/internal/domain/entities"
	domainRepos "github.com/acecasino/account_manage/internal/domain/repositories"
	"gorm.io/gorm"
)

type depositHistoryRepository struct {
	db *gorm.DB
}

func NewDepositHistoryRepository(db *gorm.DB) domainRepos.DepositHistoryRepository {
	return &depositHistoryRepository{db: db}
}

func (r *depositHistoryRepository) InsertBatch(ctx context.Context, deposits []entities.DepositHistory) error {
	if len(deposits) == 0 {
		return nil
	}

	return r.db.WithContext(ctx).CreateInBatches(deposits, 100).Error
}

func (r *depositHistoryRepository) ExistsByTxRef(ctx context.Context, txRef int64) (bool, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&entities.DepositHistory{}).Where("tx_ref = ?", txRef).Count(&count).Error
	return count > 0, err
}

func (r *depositHistoryRepository) ExistsByTxRefBatch(ctx context.Context, txRefs []int64) (map[int64]bool, error) {
	if len(txRefs) == 0 {
		return make(map[int64]bool), nil
	}

	var results []struct {
		TxRef int64 `gorm:"column:tx_ref"`
	}

	err := r.db.WithContext(ctx).Model(&entities.DepositHistory{}).
		Select("tx_ref").
		Where("tx_ref IN ?", txRefs).
		Find(&results).Error

	if err != nil {
		return nil, err
	}

	existsMap := make(map[int64]bool)
	for _, result := range results {
		existsMap[result.TxRef] = true
	}

	// 모든 txRef에 대해 false로 초기화
	for _, txRef := range txRefs {
		if !existsMap[txRef] {
			existsMap[txRef] = false
		}
	}

	return existsMap, nil
}

func (r *depositHistoryRepository) GetByTxRef(ctx context.Context, txRef int64) (*entities.DepositHistory, error) {
	var deposit entities.DepositHistory
	err := r.db.WithContext(ctx).Where("tx_ref = ?", txRef).First(&deposit).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &deposit, nil
}

func (r *depositHistoryRepository) GetByAccountID(ctx context.Context, accountID int, limit, offset int) ([]entities.DepositHistory, error) {
	var deposits []entities.DepositHistory
	query := r.db.WithContext(ctx).Where("account_id = ?", accountID).Order("created DESC")

	if limit > 0 {
		query = query.Limit(limit)
	}
	if offset > 0 {
		query = query.Offset(offset)
	}

	err := query.Find(&deposits).Error
	return deposits, err
}

func (r *depositHistoryRepository) GetDepositStats(ctx context.Context, accountID int, currencyID int, from, to time.Time) (*domainRepos.DepositStats, error) {
	var stats domainRepos.DepositStats

	// 총 입금 개수
	var count int64
	err := r.db.WithContext(ctx).Model(&entities.DepositHistory{}).
		Where("account_id = ? AND currency_id = ? AND created BETWEEN ? AND ?", accountID, currencyID, from, to).
		Count(&count).Error
	if err != nil {
		return nil, err
	}
	stats.TotalDeposits = int(count)

	// 총 입금 금액
	var totalAmount struct {
		Total float64 `gorm:"column:total"`
	}
	err = r.db.WithContext(ctx).Model(&entities.DepositHistory{}).
		Select("COALESCE(SUM(amount), 0) as total").
		Where("account_id = ? AND currency_id = ? AND created BETWEEN ? AND ?", accountID, currencyID, from, to).
		Scan(&totalAmount).Error
	if err != nil {
		return nil, err
	}

	// 첫 번째 입금 시간
	var firstDeposit entities.DepositHistory
	err = r.db.WithContext(ctx).Where("account_id = ? AND currency_id = ? AND created BETWEEN ? AND ?", accountID, currencyID, from, to).
		Order("created ASC").First(&firstDeposit).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, err
	}
	if err == nil {
		stats.FirstDeposit = firstDeposit.Created
	}

	// 마지막 입금 시간
	var lastDeposit entities.DepositHistory
	err = r.db.WithContext(ctx).Where("account_id = ? AND currency_id = ? AND created BETWEEN ? AND ?", accountID, currencyID, from, to).
		Order("created DESC").First(&lastDeposit).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, err
	}
	if err == nil {
		stats.LastDeposit = lastDeposit.Created
	}

	return &stats, nil
}
