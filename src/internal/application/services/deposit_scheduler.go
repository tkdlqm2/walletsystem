package services

import (
	"context"
	"fmt"
	"time"

	domainRepos "github.com/acecasino/account_manage/internal/domain/repositories"
	"github.com/robfig/cron/v3"
	"go.uber.org/zap"
)

type DepositScheduler struct {
	depositService domainRepos.DepositProcessorService
	cron           *cron.Cron
	logger         *zap.Logger
	isRunning      bool
}

func NewDepositScheduler(depositService domainRepos.DepositProcessorService, logger *zap.Logger) *DepositScheduler {
	return &DepositScheduler{
		depositService: depositService,
		cron:           cron.New(),
		logger:         logger,
	}
}

func (ds *DepositScheduler) Start() error {
	if ds.isRunning {
		return fmt.Errorf("scheduler is already running")
	}

	// 10초마다 입금 처리 실행
	_, err := ds.cron.AddFunc("@every 10s", func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		ds.logger.Debug("Starting scheduled deposit processing")

		result, err := ds.depositService.ProcessPendingDeposits(ctx)
		if err != nil {
			ds.logger.Error("Scheduled deposit processing failed", zap.Error(err))
			return
		}

		if result.TotalProcessed > 0 {
			ds.logger.Info("Scheduled deposit processing completed",
				zap.Int("total_processed", result.TotalProcessed),
				zap.Int("successful", result.Successful),
				zap.Int("duplicates", result.Duplicates),
				zap.Int("failed", len(result.Failed)),
				zap.Duration("duration", result.Duration),
			)
		}

		// 실패한 입금이 있으면 상세 로그 출력
		if len(result.Failed) > 0 {
			ds.logger.Warn("Some deposits failed to process",
				zap.Int("failed_count", len(result.Failed)),
			)
			for _, failed := range result.Failed {
				ds.logger.Debug("Failed deposit detail",
					zap.Int64("event_id", failed.EventID),
					zap.String("reason", failed.Reason),
					zap.String("error", failed.Error),
				)
			}
		}
	})

	if err != nil {
		return fmt.Errorf("failed to add cron job: %w", err)
	}

	ds.cron.Start()
	ds.isRunning = true
	ds.logger.Info("Deposit scheduler started")

	return nil
}

func (ds *DepositScheduler) Stop() {
	if ds.isRunning {
		ds.cron.Stop()
		ds.isRunning = false
		ds.logger.Info("Deposit scheduler stopped")
	}
}

func (ds *DepositScheduler) IsRunning() bool {
	return ds.isRunning
}
