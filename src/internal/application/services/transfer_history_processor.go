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

// TransferHistoryProcessor handles all types of transfer processing (deposit, collect, withdraw)
type TransferHistoryProcessor struct {
	db                  *gorm.DB
	transferHistoryRepo domainRepos.TransferHistoryRepository
	depositHistoryRepo  domainRepos.DepositHistoryRepository
	collectHistoryRepo  domainRepos.CollectHistoryRepository
	withdrawHistoryRepo domainRepos.WithdrawHistoryRepository
	chainAccountCache   *ChainAccountCacheService
	adminAddressCache   *AdminAddressCacheService
	currencyRepo        domainRepos.CurrencyRepository
	userBalanceRepo     domainRepos.UserBalanceRepository
	logger              *zap.Logger
	batchSize           int
	isRunning           bool
	lastProcessed       time.Time
}

// NewTransferHistoryProcessor creates a new transfer history processor
func NewTransferHistoryProcessor(
	db *gorm.DB,
	transferHistoryRepo domainRepos.TransferHistoryRepository,
	depositHistoryRepo domainRepos.DepositHistoryRepository,
	collectHistoryRepo domainRepos.CollectHistoryRepository,
	withdrawHistoryRepo domainRepos.WithdrawHistoryRepository,
	chainAccountCache *ChainAccountCacheService,
	adminAddressCache *AdminAddressCacheService,
	currencyRepo domainRepos.CurrencyRepository,
	userBalanceRepo domainRepos.UserBalanceRepository,
	logger *zap.Logger,
	batchSize int,
) *TransferHistoryProcessor {
	return &TransferHistoryProcessor{
		db:                  db,
		transferHistoryRepo: transferHistoryRepo,
		depositHistoryRepo:  depositHistoryRepo,
		collectHistoryRepo:  collectHistoryRepo,
		withdrawHistoryRepo: withdrawHistoryRepo,
		chainAccountCache:   chainAccountCache,
		adminAddressCache:   adminAddressCache,
		currencyRepo:        currencyRepo,
		userBalanceRepo:     userBalanceRepo,
		logger:              logger,
		batchSize:           batchSize,
	}
}

// ProcessPendingTransfers processes a single batch of pending transfers
func (p *TransferHistoryProcessor) ProcessPendingTransfers(ctx context.Context) (*entities.TransferProcessingResult, error) {
	result := &entities.TransferProcessingResult{
		TotalProcessed: 0,
		Deposits:       0,
		Collects:       0,
		Withdraws:      0,
		Duplicates:     0,
		Failed:         make([]entities.FailedTransferDetail, 0),
	}

	// 배치 스케줄링 방식: 한 번의 배치만 처리
	events, err := p.transferHistoryRepo.GetUnprocessedEvents(ctx, p.batchSize)
	if err != nil {
		return result, fmt.Errorf("failed to get unprocessed events: %w", err)
	}

	if len(events) == 0 {
		p.logger.Info("No unprocessed events found")
		return result, nil
	}

	result.TotalProcessed = len(events)

	// 디버깅: 조회된 이벤트들 로그 출력
	p.logger.Info("Retrieved unprocessed events",
		zap.Int("event_count", len(events)),
	)

	for i, event := range events {
		if i < 3 { // 처음 3개 이벤트만 로그 출력
			p.logger.Info("Unprocessed event details",
				zap.Int64("event_id", int64(event.ID)),
				zap.Int("currency_id", event.CurrencyID),
				zap.String("from_addr", event.From),
				zap.String("to_addr", event.To),
				zap.String("tx_hash", event.TxHash),
				zap.Uint64("block_number", event.BlockNumber),
				zap.String("amount", event.Amount),
				zap.Bool("processed", event.Processed),
			)
		}
	}

	// 모든 이벤트 ID를 수집 (조건에 맞든 안맞든 무조건 processed=true로 마킹)
	allEventIDs := make([]int64, 0, len(events))
	for _, event := range events {
		allEventIDs = append(allEventIDs, int64(event.ID))
	}

	// 1. 중복 확인 (이미 처리된 이벤트 필터링)
	filteredEvents, duplicateCount := p.filterDuplicates(ctx, events)
	result.Duplicates = duplicateCount

	// 2. 배치 데이터 준비 (필터링된 이벤트로)
	var batchData *entities.TransferBatchData
	if len(filteredEvents) > 0 {
		var err error
		batchData, err = p.prepareBatchData(ctx, filteredEvents)
		if err != nil {
			p.logger.Error("Failed to prepare batch data", zap.Error(err))
			// 배치 데이터 준비 실패해도 모든 이벤트는 processed=true로 마킹
		}
	}

	// 3. 이벤트 분류 및 처리 (배치 데이터가 준비된 경우에만)
	if batchData != nil {
		depositEvents, collectEvents, withdrawEvents := p.classifyEvents(filteredEvents, batchData)

		// 4. 각 타입별 처리
		// Deposit 처리
		if len(depositEvents) > 0 {
			depositResult, err := p.processDeposits(ctx, depositEvents, batchData)
			if err != nil {
				p.logger.Error("Failed to process deposits", zap.Error(err))
			} else {
				result.Deposits = depositResult.Successful
			}
		}

		// Collect 처리
		if len(collectEvents) > 0 {
			collectResult, err := p.processCollects(ctx, collectEvents, batchData)
			if err != nil {
				p.logger.Error("Failed to process collects", zap.Error(err))
			} else {
				result.Collects = collectResult.Successful
			}
		}

		// Withdraw 처리
		if len(withdrawEvents) > 0 {
			withdrawResult, err := p.processWithdraws(ctx, withdrawEvents, batchData)
			if err != nil {
				p.logger.Error("Failed to process withdraws", zap.Error(err))
			} else {
				result.Withdraws = withdrawResult.Successful
			}
		}
	}

	// 5. 모든 이벤트들 마킹 (조건에 맞든 안맞든 무조건 processed=true로 마킹)
	p.logger.Info("Marking all events as processed",
		zap.Int("event_count", len(allEventIDs)),
		zap.Int64s("event_ids", allEventIDs),
	)
	if err := p.transferHistoryRepo.MarkAsProcessed(ctx, allEventIDs); err != nil {
		p.logger.Error("Failed to mark events as processed", zap.Error(err))
	} else {
		p.logger.Info("Successfully marked all events as processed",
			zap.Int("event_count", len(allEventIDs)),
		)
	}

	return result, nil
}

// classifyEvents classifies events into deposit, collect, and withdraw categories
func (p *TransferHistoryProcessor) classifyEvents(events []entities.TransferHistory, batchData *entities.TransferBatchData) ([]entities.TransferHistory, []entities.TransferHistory, []entities.TransferHistory) {
	depositEvents := make([]entities.TransferHistory, 0)
	collectEvents := make([]entities.TransferHistory, 0)
	withdrawEvents := make([]entities.TransferHistory, 0)

	for _, event := range events {
		normalizedTo := strings.ToLower(event.To)

		// Admin 주소인지 확인
		isToAdmin, _ := p.adminAddressCache.IsAdminAddress(context.Background(), event.To)
		isFromAdmin, _ := p.adminAddressCache.IsAdminAddress(context.Background(), event.From)

		// 분류 로직 (우선순위 순서)
		if isToAdmin {
			// 1순위: toAddr이 Admin 지갑주소면 Collect
			collectEvents = append(collectEvents, event)
		} else if isFromAdmin && batchData.Accounts[normalizedTo] != nil {
			// 2순위: from이 Admin이고 to가 캐싱된 주소면 Deposit + Withdraw 둘 다 처리
			depositEvents = append(depositEvents, event)
			withdrawEvents = append(withdrawEvents, event)
		} else if isFromAdmin {
			// 3순위: fromAddr이 Admin 지갑주소면 Withdraw
			withdrawEvents = append(withdrawEvents, event)
		} else if batchData.Accounts[normalizedTo] != nil {
			// 4순위: toAddr이 캐싱된 주소면 Deposit
			depositEvents = append(depositEvents, event)
		}
	}
	return depositEvents, collectEvents, withdrawEvents
}

// filterDuplicates filters out events that are already processed
func (p *TransferHistoryProcessor) filterDuplicates(ctx context.Context, events []entities.TransferHistory) ([]entities.TransferHistory, int) {
	if len(events) == 0 {
		return events, 0
	}

	// processed 컬럼이 추가되어 GetUnprocessedEvents에서 이미 필터링되므로
	// 추가적인 중복 확인은 deposit_history 테이블에서만 수행
	txRefs := make([]int64, len(events))
	for i, event := range events {
		txRefs[i] = int64(event.ID)
	}

	existsMap, err := p.depositHistoryRepo.ExistsByTxRefBatch(ctx, txRefs)
	if err != nil {
		p.logger.Error("Failed to check duplicates", zap.Error(err))
		return events, 0 // 에러 시 전체 처리 시도
	}

	filtered := make([]entities.TransferHistory, 0)
	duplicateCount := 0

	for _, event := range events {
		if exists, ok := existsMap[int64(event.ID)]; ok && exists {
			duplicateCount++
			p.logger.Warn("Duplicate transfer found - already exists in deposit_history",
				zap.Int64("event_id", int64(event.ID)),
				zap.String("to_address", event.To),
				zap.String("amount", event.Amount),
			)
			continue
		}
		filtered = append(filtered, event)
	}

	return filtered, duplicateCount
}

// prepareBatchData prepares batch data for processing
func (p *TransferHistoryProcessor) prepareBatchData(ctx context.Context, events []entities.TransferHistory) (*entities.TransferBatchData, error) {
	// 필요한 주소들과 통화ID들 수집
	addressSet := make(map[string]bool)
	currencySet := make(map[int]bool)

	for _, event := range events {
		// 주소 수집 (중복 제거) - 소문자로 정규화하여 저장
		if event.To != "" {
			normalizedAddress := strings.ToLower(event.To)
			addressSet[normalizedAddress] = true
		}
		if event.From != "" {
			normalizedAddress := strings.ToLower(event.From)
			addressSet[normalizedAddress] = true
		}
		if event.CurrencyID > 0 {
			currencySet[event.CurrencyID] = true
		}
	}

	// 슬라이스로 변환
	addresses := make([]string, 0, len(addressSet))
	for addr := range addressSet {
		addresses = append(addresses, addr)
	}

	currencyIDs := make([]int, 0, len(currencySet))
	for id := range currencySet {
		currencyIDs = append(currencyIDs, id)
	}

	// 캐싱된 계정 데이터 조회
	accounts, err := p.chainAccountCache.GetAccountsByAddresses(ctx, addresses)
	if err != nil {
		return nil, fmt.Errorf("failed to get accounts from cache: %w", err)
	}

	// 통화 데이터 조회 (개별 조회)
	currencyMap := make(map[int]*entities.Currency)
	for _, currencyID := range currencyIDs {
		currency, err := p.currencyRepo.GetByID(ctx, currencyID)
		if err != nil {
			p.logger.Warn("Failed to get currency", zap.Int("currency_id", currencyID), zap.Error(err))
			continue
		}
		currencyMap[currencyID] = currency
	}

	return &entities.TransferBatchData{
		Accounts:   accounts,
		Currencies: currencyMap,
	}, nil
}

// processDeposits processes deposit events (기존 deposit_processor_service 로직 사용)
func (p *TransferHistoryProcessor) processDeposits(ctx context.Context, events []entities.TransferHistory, batchData *entities.TransferBatchData) (*entities.DepositProcessingResult, error) {
	result := &entities.DepositProcessingResult{
		TotalProcessed: len(events),
		Successful:     0,
		Duplicates:     0,
		Failed:         make([]entities.FailedDepositDetail, 0),
	}

	deposits := make([]entities.DepositHistory, 0)
	balanceUpdates := make([]domainRepos.BalanceUpdate, 0)

	for _, event := range events {
		// 디버깅: 이벤트 데이터 로그 출력
		p.logger.Info("Processing deposit event",
			zap.Int64("event_id", int64(event.ID)),
			zap.Int("currency_id", event.CurrencyID),
			zap.String("from_addr", event.From),
			zap.String("to_addr", event.To),
			zap.String("tx_hash", event.TxHash),
			zap.Uint64("block_number", event.BlockNumber),
			zap.String("amount", event.Amount),
		)

		// 1. 보안 검증: 우리 시스템 계정인지 확인 (주소 정규화하여 조회)
		normalizedAddress := strings.ToLower(event.To)
		account := batchData.Accounts[normalizedAddress]
		if account == nil {
			// 미등록 계정은 조용히 패스 (processed는 상위에서 처리)
			p.logger.Debug("Account not found in cache - skipping deposit processing",
				zap.String("to_address", event.To),
				zap.String("normalized_address", normalizedAddress),
			)
			continue
		}

		// 등록된 계정 발견 - 디버깅 로그
		p.logger.Info("Processing registered account",
			zap.Int64("event_id", int64(event.ID)),
			zap.String("to_address", event.To),
			zap.Int("account_id", account.ID),
			zap.Int("user_id", account.UserID),
		)

		// 2. 추가 보안 검증: 계정이 활성 상태인지 확인
		if !p.isAccountActive(account) {
			result.Failed = append(result.Failed, entities.FailedDepositDetail{
				EventID: int64(event.ID),
				Reason:  "inactive_account",
				Error:   fmt.Sprintf("account is inactive: %s", event.To),
			})
			// 실패한 이벤트는 상위에서 processed 처리
			continue
		}

		// 3. 통화 확인
		currency := batchData.Currencies[event.CurrencyID]
		if currency == nil {
			p.logger.Error("Currency not found for registered account",
				zap.Int64("event_id", int64(event.ID)),
				zap.Int("currency_id", event.CurrencyID),
				zap.String("to_address", event.To),
			)
			result.Failed = append(result.Failed, entities.FailedDepositDetail{
				EventID: int64(event.ID),
				Reason:  "currency_not_found",
				Error:   fmt.Sprintf("currency not found: %d", event.CurrencyID),
			})
			// 실패한 이벤트는 상위에서 processed 처리
			continue
		}

		// 4. 금액 조정 (decimal 적용)
		amount, err := decimal.NewFromString(event.Amount)
		if err != nil {
			p.logger.Error("Invalid amount format for registered account",
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
			// 실패한 이벤트는 상위에서 processed 처리
			continue
		}
		adjustedAmount := p.calculateAdjustedAmount(amount, currency.Decimal)

		// 등록된 계정 처리 성공 - 디버깅 로그
		p.logger.Info("Successfully processed registered account",
			zap.Int64("event_id", int64(event.ID)),
			zap.String("to_address", event.To),
			zap.String("original_amount", event.Amount),
			zap.String("adjusted_amount", adjustedAmount.String()),
			zap.Int("currency_id", event.CurrencyID),
		)

		// 5. DepositHistory 생성
		deposit := entities.DepositHistory{
			AccountID:   account.ID,
			TxRef:       int64(event.ID),
			CurrencyID:  event.CurrencyID,
			FromAddr:    event.From,
			ToAddr:      event.To,
			TxHash:      event.TxHash,
			BlockNumber: int64(event.BlockNumber),
			Amount:      adjustedAmount,
			Created:     time.Now(),
		}

		// 디버깅: 생성된 DepositHistory 로그 출력
		p.logger.Info("Created DepositHistory",
			zap.Int("account_id", deposit.AccountID),
			zap.Int64("tx_ref", deposit.TxRef),
			zap.Int("currency_id", deposit.CurrencyID),
			zap.String("from_addr", deposit.FromAddr),
			zap.String("to_addr", deposit.ToAddr),
			zap.String("tx_hash", deposit.TxHash),
			zap.Int64("block_number", deposit.BlockNumber),
			zap.String("amount", deposit.Amount.String()),
		)

		deposits = append(deposits, deposit)

		// 6. BalanceUpdate 생성
		balanceUpdate := domainRepos.BalanceUpdate{
			AccountID:  account.ID,
			UserID:     account.UserID,
			CurrencyID: event.CurrencyID,
			Balance:    adjustedAmount.InexactFloat64(),
		}
		balanceUpdates = append(balanceUpdates, balanceUpdate)
	}

	// 7. 트랜잭션으로 deposit_history와 user_balance 처리
	if len(deposits) > 0 {
		if err := p.executeDepositTransaction(ctx, deposits, balanceUpdates); err != nil {
			p.logger.Error("Failed to execute deposit transaction", zap.Error(err))
			return result, fmt.Errorf("failed to execute deposit transaction: %w", err)
		}

		result.Successful = len(deposits)
		p.logger.Info("Deposit transaction completed successfully",
			zap.Int("successful_deposits", len(deposits)),
		)
	} else {
		p.logger.Warn("No deposits to process - all events may have failed validation")
	}

	return result, nil
}

// isAccountActive checks if the account is active
func (p *TransferHistoryProcessor) isAccountActive(account *entities.ChainAccount) bool {
	// 여기서는 간단히 true 반환 (실제 구현 시 account 상태 확인)
	return true
}

// calculateAdjustedAmount calculates the adjusted amount based on currency decimal
func (p *TransferHistoryProcessor) calculateAdjustedAmount(amount decimal.Decimal, currencyDecimal int) decimal.Decimal {
	if currencyDecimal <= 0 {
		return amount
	}

	divisor := decimal.NewFromInt(10).Pow(decimal.NewFromInt(int64(currencyDecimal)))
	return amount.Div(divisor)
}

// withTransaction executes a function within a database transaction
func (p *TransferHistoryProcessor) withTransaction(ctx context.Context, fn func(*gorm.DB) error) error {
	return p.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return fn(tx)
	})
}

// executeDepositTransaction executes deposit processing within a transaction
func (p *TransferHistoryProcessor) executeDepositTransaction(
	ctx context.Context,
	deposits []entities.DepositHistory,
	balanceUpdates []domainRepos.BalanceUpdate,
) error {
	return p.withTransaction(ctx, func(tx *gorm.DB) error {
		// 1. deposit_history 일괄 삽입
		if err := p.depositHistoryRepo.InsertBatch(ctx, deposits); err != nil {
			return fmt.Errorf("failed to insert deposit histories: %w", err)
		}

		// 2. user_balance 일괄 UPSERT
		if len(balanceUpdates) > 0 {
			if err := p.userBalanceRepo.UpsertBalanceBatch(ctx, balanceUpdates); err != nil {
				return fmt.Errorf("failed to update user balances: %w", err)
			}
		}

		return nil
	})
}

// executeCollectTransaction executes collect processing within a transaction
func (p *TransferHistoryProcessor) executeCollectTransaction(
	ctx context.Context,
	collects []entities.CollectHistory,
) error {
	return p.withTransaction(ctx, func(tx *gorm.DB) error {
		// collect_history 일괄 삽입
		if err := p.collectHistoryRepo.CreateBatch(ctx, collects); err != nil {
			return fmt.Errorf("failed to insert collect histories: %w", err)
		}

		return nil
	})
}

// processCollects processes collect events
func (p *TransferHistoryProcessor) processCollects(ctx context.Context, events []entities.TransferHistory, batchData *entities.TransferBatchData) (*entities.CollectProcessingResult, error) {
	result := &entities.CollectProcessingResult{
		TotalProcessed: len(events),
		Successful:     0,
		Failed:         make([]entities.FailedCollectDetail, 0),
	}

	collects := make([]entities.CollectHistory, 0)

	for _, event := range events {
		// 1. 통화 검증
		_, exists := batchData.Currencies[event.CurrencyID]
		if !exists {
			result.Failed = append(result.Failed, entities.FailedCollectDetail{
				EventID: int64(event.ID),
				Address: event.To,
				Amount:  event.Amount,
				Error:   fmt.Sprintf("currency not found: %d", event.CurrencyID),
			})
			continue
		}

		// 2. 금액 검증
		amount, err := decimal.NewFromString(event.Amount)
		if err != nil {
			result.Failed = append(result.Failed, entities.FailedCollectDetail{
				EventID: int64(event.ID),
				Address: event.To,
				Amount:  event.Amount,
				Error:   fmt.Sprintf("invalid amount format: %s", event.Amount),
			})
			continue
		}

		// 3. CollectHistory 생성
		collect := entities.CollectHistory{
			CurrencyID:  event.CurrencyID,
			FromAddr:    event.From,
			ToAddr:      event.To,
			TxHash:      event.TxHash,
			BlockNumber: int64(event.BlockNumber),
			Amount:      amount.InexactFloat64(),
			Created:     time.Now(),
		}

		collects = append(collects, collect)

		p.logger.Info("Processing collect event",
			zap.Int64("event_id", int64(event.ID)),
			zap.String("from_addr", event.From),
			zap.String("to_addr", event.To),
			zap.String("amount", event.Amount),
			zap.Int("currency_id", event.CurrencyID),
		)
	}

	// 4. 트랜잭션으로 collect_history 처리
	if len(collects) > 0 {
		if err := p.executeCollectTransaction(ctx, collects); err != nil {
			p.logger.Error("Failed to execute collect transaction", zap.Error(err))
			return result, fmt.Errorf("failed to execute collect transaction: %w", err)
		}

		result.Successful = len(collects)
		p.logger.Info("Collect transaction completed successfully",
			zap.Int("successful_collects", len(collects)),
		)
	} else {
		p.logger.Warn("No collects to process - all events may have failed validation")
	}

	return result, nil
}

// processWithdraws processes withdraw events
func (p *TransferHistoryProcessor) processWithdraws(ctx context.Context, events []entities.TransferHistory, batchData *entities.TransferBatchData) (*entities.WithdrawProcessingResult, error) {
	result := &entities.WithdrawProcessingResult{
		TotalProcessed: len(events),
		Successful:     0,
		Failed:         make([]entities.FailedWithdrawDetail, 0),
	}

	withdraws := make([]entities.WithdrawHistory, 0)

	for _, event := range events {
		// 디버깅: 이벤트 데이터 로그 출력
		p.logger.Info("Processing withdraw event",
			zap.Int64("event_id", int64(event.ID)),
			zap.Int("currency_id", event.CurrencyID),
			zap.String("from_addr", event.From),
			zap.String("to_addr", event.To),
			zap.String("tx_hash", event.TxHash),
			zap.Uint64("block_number", event.BlockNumber),
			zap.String("amount", event.Amount),
		)

		// 1. 통화 검증
		currency, exists := batchData.Currencies[event.CurrencyID]
		if !exists {
			result.Failed = append(result.Failed, entities.FailedWithdrawDetail{
				EventID: int64(event.ID),
				Address: event.To,
				Amount:  event.Amount,
				Error:   fmt.Sprintf("currency not found: %d", event.CurrencyID),
			})
			continue
		}

		// 2. 금액 검증
		amount, err := decimal.NewFromString(event.Amount)
		if err != nil {
			result.Failed = append(result.Failed, entities.FailedWithdrawDetail{
				EventID: int64(event.ID),
				Address: event.To,
				Amount:  event.Amount,
				Error:   fmt.Sprintf("invalid amount format: %s", event.Amount),
			})
			continue
		}
		adjustedAmount := p.calculateAdjustedAmount(amount, currency.Decimal)

		// 3. 사용자 ID 찾기 (to 주소가 캐싱된 주소인 경우)
		normalizedTo := strings.ToLower(event.To)
		account := batchData.Accounts[normalizedTo]
		var userID int
		if account != nil {
			userID = account.UserID
		} else {
			// Admin에서 출금하는 경우 userID는 0으로 설정 (시스템 출금)
			userID = 0
		}

		// 4. WithdrawHistory 생성
		withdraw := entities.WithdrawHistory{
			UserID:     userID,
			CurrencyID: event.CurrencyID,
			ToAddress:  event.To,
			Amount:     adjustedAmount,
			CreateAt:   time.Now(),
			Process:    "completed", // 출금 완료 상태
			TxRef:      int(event.ID),
			TxHash:     event.TxHash,
		}

		withdraws = append(withdraws, withdraw)

		p.logger.Info("Processing withdraw event",
			zap.Int64("event_id", int64(event.ID)),
			zap.String("from_addr", event.From),
			zap.String("to_addr", event.To),
			zap.String("amount", event.Amount),
			zap.Int("currency_id", event.CurrencyID),
			zap.Int("user_id", userID),
		)
	}

	// 5. 트랜잭션으로 withdraw_history 처리
	if len(withdraws) > 0 {
		if err := p.executeWithdrawTransaction(ctx, withdraws); err != nil {
			p.logger.Error("Failed to execute withdraw transaction", zap.Error(err))
			return result, fmt.Errorf("failed to execute withdraw transaction: %w", err)
		}

		result.Successful = len(withdraws)
		p.logger.Info("Withdraw transaction completed successfully",
			zap.Int("successful_withdraws", len(withdraws)),
		)
	} else {
		p.logger.Warn("No withdraws to process - all events may have failed validation")
	}

	return result, nil
}

// executeWithdrawTransaction executes withdraw processing within a transaction
func (p *TransferHistoryProcessor) executeWithdrawTransaction(
	ctx context.Context,
	withdraws []entities.WithdrawHistory,
) error {
	return p.withTransaction(ctx, func(tx *gorm.DB) error {
		// withdraw_history 일괄 삽입
		if err := p.withdrawHistoryRepo.CreateBatch(ctx, withdraws); err != nil {
			return fmt.Errorf("failed to insert withdraw histories: %w", err)
		}

		return nil
	})
}
