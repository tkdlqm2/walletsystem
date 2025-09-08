package repositories

import (
	"context"
	"time"

	"github.com/acecasino/account_manage/internal/domain/entities"
	"github.com/shopspring/decimal"
)

type DepositHistoryRepository interface {
	// 배치 삽입
	InsertBatch(ctx context.Context, deposits []entities.DepositHistory) error

	// 중복 확인
	ExistsByTxRef(ctx context.Context, txRef int64) (bool, error)
	ExistsByTxRefBatch(ctx context.Context, txRefs []int64) (map[int64]bool, error)

	// 조회
	GetByTxRef(ctx context.Context, txRef int64) (*entities.DepositHistory, error)
	GetByAccountID(ctx context.Context, accountID int, limit, offset int) ([]entities.DepositHistory, error)

	// 통계
	GetDepositStats(ctx context.Context, accountID int, currencyID int, from, to time.Time) (*DepositStats, error)
}

type DepositStats struct {
	TotalDeposits int             `json:"total_deposits"`
	TotalAmount   decimal.Decimal `json:"total_amount"`
	FirstDeposit  time.Time       `json:"first_deposit"`
	LastDeposit   time.Time       `json:"last_deposit"`
}

// DepositProcessorService defines the interface for deposit processing operations
type DepositProcessorService interface {
	// 메인 처리 메서드
	ProcessPendingDeposits(ctx context.Context) (*entities.DepositProcessingResult, error)

	// 배치 처리
	ProcessBatch(ctx context.Context, events []entities.TransferHistory) (*entities.DepositProcessingResult, error)

	// 상태 확인
	GetProcessingStatus(ctx context.Context) (*ProcessingStatus, error)

	// 수동 재처리
	ReprocessFailedDeposits(ctx context.Context, eventIDs []int64) (*entities.DepositProcessingResult, error)
}

// ProcessingStatus represents the current processing status
type ProcessingStatus struct {
	IsRunning      bool      `json:"is_running"`
	LastProcessed  time.Time `json:"last_processed"`
	PendingCount   int       `json:"pending_count"`
	ProcessedToday int       `json:"processed_today"`
	FailedToday    int       `json:"failed_today"`
}
