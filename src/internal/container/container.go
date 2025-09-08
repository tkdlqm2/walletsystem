package container

import (
	"github.com/acecasino/account_manage/internal/application/services"
	"github.com/acecasino/account_manage/internal/config"
	domainRepos "github.com/acecasino/account_manage/internal/domain/repositories"
	"github.com/acecasino/account_manage/internal/infrastructure/database/repositories"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// Container holds all application dependencies
type Container struct {
	Config *config.Config
	DB     *gorm.DB

	// Repositories
	UserRepo            domainRepos.UserRepository
	ChainAccountRepo    domainRepos.ChainAccountRepository
	CurrencyRepo        domainRepos.CurrencyRepository
	UserBalanceRepo     domainRepos.UserBalanceRepository
	WithdrawHistoryRepo domainRepos.WithdrawHistoryRepository
	TransferHistoryRepo domainRepos.TransferHistoryRepository
	BlockchainRepo      domainRepos.BlockchainRepository
	ErrorLogsRepo       domainRepos.ErrorLogsRepository

	// Deposit related services
	DepositHistoryRepo  domainRepos.DepositHistoryRepository
	DepositProcessorSvc domainRepos.DepositProcessorService
	DepositScheduler    *services.DepositScheduler

	// Collect related services
	CollectHistoryRepo domainRepos.CollectHistoryRepository

	// Cache services
	ChainAccountCacheSvc *services.ChainAccountCacheService
	AdminAddressCacheSvc *services.AdminAddressCacheService

	// Transfer processing services
	TransferHistoryProcessor *services.TransferHistoryProcessor
	TransferScheduler        *services.TransferScheduler
}

// NewContainer creates a new container with all dependencies
func NewContainer() (*Container, error) {
	// Load configuration
	cfg := config.LoadConfig()

	// Initialize database
	db, err := config.NewDatabase(cfg.Database)
	if err != nil {
		return nil, err
	}

	// Initialize repositories
	userRepo := repositories.NewUserRepository(db)
	chainAccountRepo := repositories.NewChainAccountRepository(db)
	currencyRepo := repositories.NewCurrencyRepository(db)
	userBalanceRepo := repositories.NewUserBalanceRepository(db)
	withdrawHistoryRepo := repositories.NewWithdrawHistoryRepository(db)
	transferHistoryRepo := repositories.NewTransferHistoryRepository(db)
	blockchainRepo := repositories.NewBlockchainRepository(db)
	errorLogsRepo := repositories.NewErrorLogsRepository(db)
	depositHistoryRepo := repositories.NewDepositHistoryRepository(db)
	collectHistoryRepo := repositories.NewCollectHistoryRepository(db)

	return &Container{
		Config: cfg,
		DB:     db,

		// Repositories
		UserRepo:            userRepo,
		ChainAccountRepo:    chainAccountRepo,
		CurrencyRepo:        currencyRepo,
		UserBalanceRepo:     userBalanceRepo,
		WithdrawHistoryRepo: withdrawHistoryRepo,
		TransferHistoryRepo: transferHistoryRepo,
		BlockchainRepo:      blockchainRepo,
		ErrorLogsRepo:       errorLogsRepo,
		DepositHistoryRepo:  depositHistoryRepo,
		CollectHistoryRepo:  collectHistoryRepo,
	}, nil
}

// InitializeTransferServices initializes transfer-related services (deposit, collect, withdraw)
func (c *Container) InitializeTransferServices(logger *zap.Logger) error {
	// Initialize ChainAccountCacheService
	chainAccountCacheSvc := services.NewChainAccountCacheService(c.DB, logger)
	c.ChainAccountCacheSvc = chainAccountCacheSvc

	// Initialize AdminAddressCacheService
	adminAddressCacheSvc := services.NewAdminAddressCacheService(c.DB, logger)
	c.AdminAddressCacheSvc = adminAddressCacheSvc

	// Initialize TransferHistoryProcessor
	transferHistoryProcessor := services.NewTransferHistoryProcessor(
		c.DB,
		c.TransferHistoryRepo,
		c.DepositHistoryRepo,
		c.CollectHistoryRepo,
		c.WithdrawHistoryRepo,
		chainAccountCacheSvc,
		adminAddressCacheSvc,
		c.CurrencyRepo,
		c.UserBalanceRepo,
		logger,
		500, // batch size
	)
	c.TransferHistoryProcessor = transferHistoryProcessor

	// Initialize DepositProcessorService (기존 호환성을 위해 유지)
	depositProcessorSvc := services.NewDepositProcessorService(
		c.DB,
		c.TransferHistoryRepo,
		c.DepositHistoryRepo,
		c.ChainAccountRepo,
		c.CurrencyRepo,
		c.UserBalanceRepo,
		chainAccountCacheSvc,
		logger,
		500, // batch size - 성능 최적화를 위해 500개로 증가
	)
	c.DepositProcessorSvc = depositProcessorSvc

	// Initialize TransferScheduler (새로운 통합 스케줄러)
	transferScheduler := services.NewTransferScheduler(transferHistoryProcessor, logger)
	c.TransferScheduler = transferScheduler

	// Initialize DepositScheduler (기존 호환성을 위해 유지)
	depositScheduler := services.NewDepositScheduler(depositProcessorSvc, logger)
	c.DepositScheduler = depositScheduler

	return nil
}
