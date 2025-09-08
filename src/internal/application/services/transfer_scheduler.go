package services

import (
	"context"
	"time"

	"github.com/acecasino/account_manage/internal/domain/entities"
	"github.com/robfig/cron/v3"
	"go.uber.org/zap"
)

// TransferScheduler handles scheduling of transfer processing (deposit, collect, withdraw)
type TransferScheduler struct {
	transferProcessor *TransferHistoryProcessor
	logger            *zap.Logger
	cron              *cron.Cron
	isRunning         bool
}

// NewTransferScheduler creates a new transfer scheduler
func NewTransferScheduler(transferProcessor *TransferHistoryProcessor, logger *zap.Logger) *TransferScheduler {
	return &TransferScheduler{
		transferProcessor: transferProcessor,
		logger:            logger,
		cron:              cron.New(cron.WithSeconds()),
		isRunning:         false,
	}
}

// Start starts the transfer scheduler
func (s *TransferScheduler) Start() error {
	if s.isRunning {
		s.logger.Warn("Transfer scheduler is already running")
		return nil
	}

	// 10초마다 실행
	_, err := s.cron.AddFunc("*/10 * * * * *", s.processTransfers)
	if err != nil {
		s.logger.Error("Failed to add cron job", zap.Error(err))
		return err
	}

	s.cron.Start()
	s.isRunning = true

	s.logger.Info("Transfer scheduler started - processing every 10 seconds")
	return nil
}

// Stop stops the transfer scheduler
func (s *TransferScheduler) Stop() {
	if !s.isRunning {
		return
	}

	s.cron.Stop()
	s.isRunning = false
	s.logger.Info("Transfer scheduler stopped")
}

// IsRunning returns whether the scheduler is currently running
func (s *TransferScheduler) IsRunning() bool {
	return s.isRunning
}

// processTransfers processes pending transfers
func (s *TransferScheduler) processTransfers() {
	startTime := time.Now()

	s.logger.Info("Starting scheduled transfer processing")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := s.transferProcessor.ProcessPendingTransfers(ctx)
	if err != nil {
		s.logger.Error("Failed to process transfers", zap.Error(err))
		return
	}

	duration := time.Since(startTime)

	// 로그 출력
	s.logger.Info("Scheduled transfer processing completed",
		zap.Int("total_processed", result.TotalProcessed),
		zap.Int("deposits", result.Deposits),
		zap.Int("collects", result.Collects),
		zap.Int("withdraws", result.Withdraws),
		zap.Int("duplicates", result.Duplicates),
		zap.Int("failed", len(result.Failed)),
		zap.Duration("duration", duration),
	)

	// 실패한 이벤트들 로그 출력
	if len(result.Failed) > 0 {
		s.logger.Warn("Some transfers failed",
			zap.Int("failed_count", len(result.Failed)),
		)
		for _, failed := range result.Failed {
			s.logger.Warn("Failed transfer detail",
				zap.Int64("event_id", failed.EventID),
				zap.String("address", failed.Address),
				zap.String("amount", failed.Amount),
				zap.String("error", failed.Error),
			)
		}
	}
}

// ProcessOnce processes transfers once (for manual execution)
func (s *TransferScheduler) ProcessOnce() (*entities.TransferProcessingResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	return s.transferProcessor.ProcessPendingTransfers(ctx)
}
