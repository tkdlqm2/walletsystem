package services

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/acecasino/account_manage/internal/domain/entities"
	domainRepos "github.com/acecasino/account_manage/internal/domain/repositories"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type depositProcessorService struct {
	db                  *gorm.DB
	transferHistoryRepo domainRepos.TransferHistoryRepository
	depositHistoryRepo  domainRepos.DepositHistoryRepository
	chainAccountRepo    domainRepos.ChainAccountRepository
	currencyRepo        domainRepos.CurrencyRepository
	userBalanceRepo     domainRepos.UserBalanceRepository
	chainAccountCache   *ChainAccountCacheService
	logger              *zap.Logger
	batchSize           int
	isRunning           bool
	lastProcessed       time.Time
}

func NewDepositProcessorService(
	db *gorm.DB,
	transferHistoryRepo domainRepos.TransferHistoryRepository,
	depositHistoryRepo domainRepos.DepositHistoryRepository,
	chainAccountRepo domainRepos.ChainAccountRepository,
	currencyRepo domainRepos.CurrencyRepository,
	userBalanceRepo domainRepos.UserBalanceRepository,
	chainAccountCache *ChainAccountCacheService,
	logger *zap.Logger,
	batchSize int,
) domainRepos.DepositProcessorService {
	return &depositProcessorService{
		db:                  db,
		transferHistoryRepo: transferHistoryRepo,
		depositHistoryRepo:  depositHistoryRepo,
		chainAccountRepo:    chainAccountRepo,
		currencyRepo:        currencyRepo,
		userBalanceRepo:     userBalanceRepo,
		chainAccountCache:   chainAccountCache,
		logger:              logger,
		batchSize:           batchSize,
	}
}

func (s *depositProcessorService) ProcessPendingDeposits(ctx context.Context) (*entities.DepositProcessingResult, error) {
	if s.isRunning {
		return &entities.DepositProcessingResult{
			Duration: 0,
		}, fmt.Errorf("deposit processing is already running")
	}

	s.isRunning = true
	defer func() {
		s.isRunning = false
		s.lastProcessed = time.Now()
	}()

	start := time.Now()

	result := &entities.DepositProcessingResult{
		Failed: make([]entities.FailedDepositDetail, 0),
	}

	// 배치 스케줄링 방식: 한 번의 배치만 처리
	events, err := s.transferHistoryRepo.GetUnprocessedEvents(ctx, s.batchSize)
	if err != nil {
		return nil, fmt.Errorf("failed to get unprocessed events: %w", err)
	}

	if len(events) == 0 {
		s.logger.Info("No unprocessed events found")
		result.Duration = time.Since(start)
		return result, nil
	}

	s.logger.Info("Processing batch", zap.Int("batch_size", len(events)))

	// 배치 처리
	batchResult, err := s.ProcessBatch(ctx, events)
	if err != nil {
		s.logger.Error("Failed to process batch", zap.Error(err))
		return nil, fmt.Errorf("failed to process batch: %w", err)
	}

	// 결과 집계
	result.TotalProcessed = batchResult.TotalProcessed
	result.Successful = batchResult.Successful
	result.Duplicates = batchResult.Duplicates
	result.Failed = batchResult.Failed

	result.Duration = time.Since(start)

	s.logger.Info("Deposit processing completed",
		zap.Int("total_processed", result.TotalProcessed),
		zap.Int("successful", result.Successful),
		zap.Int("duplicates", result.Duplicates),
		zap.Int("failed", len(result.Failed)),
		zap.Duration("duration", result.Duration),
	)

	return result, nil
}

func (s *depositProcessorService) ProcessBatch(ctx context.Context, events []entities.TransferHistory) (*entities.DepositProcessingResult, error) {
	result := &entities.DepositProcessingResult{
		TotalProcessed: len(events),
		Failed:         make([]entities.FailedDepositDetail, 0),
	}

	// 1. 중복 확인 (이미 처리된 이벤트 필터링)
	filteredEvents, duplicateCount := s.filterDuplicates(ctx, events)
	result.Duplicates = duplicateCount

	if len(filteredEvents) == 0 {
		return result, nil
	}

	// 2. 필요한 데이터 배치 조회
	batchData, err := s.prepareBatchData(ctx, filteredEvents)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare batch data: %w", err)
	}

	// 3. 유효한 이벤트들을 deposit_history와 balance_update로 변환
	deposits, balanceUpdates, validEventIDs := s.buildDepositData(filteredEvents, batchData, result)

	// 4. 데이터베이스 트랜잭션으로 일괄 처리 (deposits가 있는 경우만)
	if len(deposits) > 0 {
		s.logger.Info("Executing deposit transaction",
			zap.Int("deposit_count", len(deposits)),
			zap.Int("balance_update_count", len(balanceUpdates)),
		)
		err = s.executeDepositTransaction(ctx, deposits, balanceUpdates)
		if err != nil {
			s.logger.Error("Failed to execute deposit transaction",
				zap.Error(err),
				zap.Int("deposit_count", len(deposits)),
			)
			return nil, fmt.Errorf("failed to execute deposit transaction: %w", err)
		}
		result.Successful = len(deposits)
		s.logger.Info("Deposit transaction completed successfully",
			zap.Int("successful_deposits", len(deposits)),
		)
	} else {
		s.logger.Warn("No deposits to process - all events may have failed validation")
	}

	// 5. 모든 이벤트들 마킹 (deposits가 없어도 validEventIDs는 있을 수 있음)
	if len(validEventIDs) > 0 {
		s.logger.Info("Marking events as processed",
			zap.Int("event_count", len(validEventIDs)),
			zap.Int64s("event_ids", validEventIDs),
		)
		if err := s.transferHistoryRepo.MarkAsProcessed(ctx, validEventIDs); err != nil {
			s.logger.Error("Failed to mark events as processed", zap.Error(err))
		}
	} else {
		s.logger.Warn("No valid event IDs to mark as processed")
	}

	return result, nil
}

// filterDuplicates filters out events that are already processed
// With processed column, this is now simplified as GetUnprocessedEvents already filters processed events
func (s *depositProcessorService) filterDuplicates(ctx context.Context, events []entities.TransferHistory) ([]entities.TransferHistory, int) {
	if len(events) == 0 {
		return events, 0
	}

	// processed 컬럼이 추가되어 GetUnprocessedEvents에서 이미 필터링되므로
	// 추가적인 중복 확인은 deposit_history 테이블에서만 수행
	txRefs := make([]int64, len(events))
	for i, event := range events {
		txRefs[i] = int64(event.ID)
	}

	existsMap, err := s.depositHistoryRepo.ExistsByTxRefBatch(ctx, txRefs)
	if err != nil {
		s.logger.Error("Failed to check duplicates", zap.Error(err))
		return events, 0 // 에러 시 전체 처리 시도
	}

	filtered := make([]entities.TransferHistory, 0)
	duplicateCount := 0

	for _, event := range events {
		if exists, ok := existsMap[int64(event.ID)]; ok && exists {
			duplicateCount++
			continue
		}
		filtered = append(filtered, event)
	}

	return filtered, duplicateCount
}

func (s *depositProcessorService) prepareBatchData(ctx context.Context, events []entities.TransferHistory) (*entities.DepositBatchData, error) {
	// 필요한 주소들과 통화ID들 수집
	addressSet := make(map[string]bool)
	currencySet := make(map[int]bool)

	s.logger.Info("Collecting addresses and currency IDs from events",
		zap.Int("event_count", len(events)),
	)

	for _, event := range events {
		// 주소 수집 (중복 제거) - 소문자로 정규화하여 저장
		if event.To != "" {
			normalizedAddress := strings.ToLower(event.To)
			addressSet[normalizedAddress] = true
		}
		if event.CurrencyID > 0 {
			currencySet[event.CurrencyID] = true
		}
	}

	// 배열로 변환
	addresses := make([]string, 0, len(addressSet))
	for addr := range addressSet {
		addresses = append(addresses, addr)
	}

	currencyIDs := make([]int, 0, len(currencySet))
	for id := range currencySet {
		currencyIDs = append(currencyIDs, id)
	}

	// 캐싱된 계정 데이터 조회
	s.logger.Info("Preparing batch data - looking up accounts from cache",
		zap.Int("address_count", len(addresses)),
		zap.Strings("addresses", addresses),
	)

	// 주소들은 이미 prepareBatchData에서 정규화되었으므로 그대로 사용
	accounts, err := s.chainAccountCache.GetAccountsByAddresses(ctx, addresses)
	if err != nil {
		return nil, fmt.Errorf("failed to get accounts from cache: %w", err)
	}

	// 디버깅: 정규화된 주소들과 캐시 매칭 결과 로그
	logCount := 5
	if len(addresses) < logCount {
		logCount = len(addresses)
	}

	// 찾은 계정들 로그 출력
	for addr, account := range accounts {
		s.logger.Info("Found registered account",
			zap.String("address", addr),
			zap.Int("account_id", account.ID),
			zap.Int("user_id", account.UserID),
			zap.String("wallet_type", account.WalletType),
		)
	}

	// TODO: GetByIDBatch 메서드 구현 필요 - 임시로 개별 조회
	currencies := make(map[int]*entities.Currency)
	for _, id := range currencyIDs {
		currency, err := s.currencyRepo.GetByID(ctx, id)
		if err == nil && currency != nil {
			currencies[id] = currency
		}
	}

	return &entities.DepositBatchData{
		Accounts:   accounts,
		Currencies: currencies,
	}, nil
}

func (s *depositProcessorService) buildDepositData(
	events []entities.TransferHistory,
	batchData *entities.DepositBatchData,
	result *entities.DepositProcessingResult,
) ([]entities.DepositHistory, []domainRepos.BalanceUpdate, []int64) {

	deposits := make([]entities.DepositHistory, 0)
	balanceUpdates := make([]domainRepos.BalanceUpdate, 0)
	validEventIDs := make([]int64, 0)

	for _, event := range events {
		// 1. 보안 검증: 우리 시스템 계정인지 확인 (주소 정규화하여 조회)
		normalizedAddress := strings.ToLower(event.To)
		account := batchData.Accounts[normalizedAddress]
		if account == nil {
			// 미등록 계정은 조용히 패스하지만 processed = true로 마킹하여 중복 조회 방지
			validEventIDs = append(validEventIDs, int64(event.ID))
			continue
		}

		// 등록된 계정 발견 - 디버깅 로그
		s.logger.Info("Processing registered account",
			zap.Int64("event_id", int64(event.ID)),
			zap.String("to_address", event.To),
			zap.Int("account_id", account.ID),
			zap.Int("user_id", account.UserID),
		)

		// 2. 추가 보안 검증: 계정이 활성 상태인지 확인
		if !s.isAccountActive(account) {
			result.Failed = append(result.Failed, entities.FailedDepositDetail{
				EventID: int64(event.ID),
				Reason:  "inactive_account",
				Error:   fmt.Sprintf("account is inactive: %s", event.To),
			})
			// 실패한 이벤트도 processed = true로 마킹하여 중복 조회 방지
			validEventIDs = append(validEventIDs, int64(event.ID))
			continue
		}

		// 2. 통화 확인
		currency := batchData.Currencies[event.CurrencyID]
		if currency == nil {
			s.logger.Error("Currency not found for registered account",
				zap.Int64("event_id", int64(event.ID)),
				zap.Int("currency_id", event.CurrencyID),
				zap.String("to_address", event.To),
			)
			result.Failed = append(result.Failed, entities.FailedDepositDetail{
				EventID: int64(event.ID),
				Reason:  "currency_not_found",
				Error:   fmt.Sprintf("currency not found: %d", event.CurrencyID),
			})
			// 실패한 이벤트도 processed = true로 마킹하여 중복 조회 방지
			validEventIDs = append(validEventIDs, int64(event.ID))
			continue
		}

		// 3. 금액 조정 (decimal 적용)
		amount, err := decimal.NewFromString(event.Amount)
		if err != nil {
			s.logger.Error("Invalid amount format for registered account",
				zap.Int64("event_id", int64(event.ID)),
				zap.String("amount", event.Amount),
				zap.String("to_address", event.To),
				zap.Error(err),
			)
			result.Failed = append(result.Failed, entities.FailedDepositDetail{
				EventID: int64(event.ID),
				Reason:  "invalid_amount",
				Error:   fmt.Sprintf("invalid amount format: %s", event.Amount),
			})
			// 실패한 이벤트도 processed = true로 마킹하여 중복 조회 방지
			validEventIDs = append(validEventIDs, int64(event.ID))
			continue
		}
		adjustedAmount := s.calculateAdjustedAmount(amount, currency.Decimal)

		// 등록된 계정 처리 성공 - 디버깅 로그
		s.logger.Info("Successfully processed registered account",
			zap.Int64("event_id", int64(event.ID)),
			zap.String("to_address", event.To),
			zap.String("amount", event.Amount),
			zap.String("adjusted_amount", adjustedAmount.String()),
			zap.Int("currency_decimal", currency.Decimal),
		)

		// 4. deposit_history 데이터 생성
		deposit := entities.DepositHistory{
			AccountID:   account.ID,
			TxRef:       int64(event.ID),
			CurrencyID:  event.CurrencyID,
			FromAddr:    event.From,
			ToAddr:      event.To,
			TxHash:      event.TxHash,
			BlockNumber: int64(event.BlockNumber),
			Amount:      adjustedAmount,
			Created:     event.CreateAt,
		}
		deposits = append(deposits, deposit)

		// 5. balance_update 데이터 생성
		balanceUpdate := domainRepos.BalanceUpdate{
			AccountID:  account.ID,
			CurrencyID: event.CurrencyID,
			UserID:     account.UserID,
			Balance:    adjustedAmount.InexactFloat64(), // Amount -> Balance로 변경
		}
		balanceUpdates = append(balanceUpdates, balanceUpdate)

		validEventIDs = append(validEventIDs, int64(event.ID))
	}

	return deposits, balanceUpdates, validEventIDs
}

func (s *depositProcessorService) executeDepositTransaction(
	ctx context.Context,
	deposits []entities.DepositHistory,
	balanceUpdates []domainRepos.BalanceUpdate,
) error {
	return s.withTransaction(ctx, func(tx *gorm.DB) error {
		// 1. deposit_history 일괄 삽입
		if err := s.depositHistoryRepo.InsertBatch(ctx, deposits); err != nil {
			return fmt.Errorf("failed to insert deposit histories: %w", err)
		}

		// 2. user_balance 일괄 UPSERT
		if err := s.userBalanceRepo.UpsertBalanceBatch(ctx, balanceUpdates); err != nil {
			return fmt.Errorf("failed to update user balances: %w", err)
		}

		return nil
	})
}

func (s *depositProcessorService) calculateAdjustedAmount(amount decimal.Decimal, currencyDecimal int) decimal.Decimal {
	if currencyDecimal <= 0 {
		return amount
	}

	divisor := decimal.NewFromInt(10).Pow(decimal.NewFromInt(int64(currencyDecimal)))
	return amount.Div(divisor)
}

func (s *depositProcessorService) withTransaction(ctx context.Context, fn func(*gorm.DB) error) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return fn(tx)
	})
}

func (s *depositProcessorService) GetProcessingStatus(ctx context.Context) (*domainRepos.ProcessingStatus, error) {
	pendingCount, err := s.transferHistoryRepo.GetUnprocessedCount(ctx)
	if err != nil {
		return nil, err
	}

	// 오늘 처리된 통계 조회 (간단히 구현)
	processedToday := 0 // TODO: 실제 구현 시 오늘 처리된 개수 조회
	failedToday := 0    // TODO: 실제 구현 시 오늘 실패한 개수 조회

	return &domainRepos.ProcessingStatus{
		IsRunning:      s.isRunning,
		LastProcessed:  s.lastProcessed,
		PendingCount:   pendingCount,
		ProcessedToday: processedToday,
		FailedToday:    failedToday,
	}, nil
}

func (s *depositProcessorService) ReprocessFailedDeposits(ctx context.Context, eventIDs []int64) (*entities.DepositProcessingResult, error) {
	// TODO: 실패한 이벤트들을 다시 처리하는 로직 구현
	return nil, fmt.Errorf("not implemented yet")
}

// isAccountActive checks if the account is active and valid for deposits
func (s *depositProcessorService) isAccountActive(account *entities.ChainAccount) bool {
	// 기본적인 활성 상태 확인
	// 필요에 따라 더 복잡한 비즈니스 로직 추가 가능
	return account != nil && account.ID > 0
}
