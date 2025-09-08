package main

import (
	"fmt"

	"github.com/acecasino/account_manage/internal/config"
	"github.com/acecasino/account_manage/internal/container"
	"github.com/acecasino/account_manage/internal/notification"
	"github.com/acecasino/account_manage/pkg/logger"
	"github.com/acecasino/account_manage/pkg/utils"
	"github.com/joho/godotenv"
	"github.com/robfig/cron/v3"
	"go.uber.org/zap"
)

func init() {
	err := godotenv.Load()
	if err != nil {
		fmt.Println("Error loading .env file")
		panic(err)
	}
	// am.Migrate()
}

func main() {
	logger.InitGlobalLogger()
	notification.SendTelMsg("Account Manage Server Start")

	// Initialize container with all dependencies
	container, err := container.NewContainer()
	if err != nil {
		fmt.Println("Failed to initialize container:", err)
		panic(err)
	}

	// Log configuration information
	logConfigInfo(container.Config)

	utils.InitData(container.DB)

	// Initialize deposit services
	zapLogger, _ := zap.NewProduction()
	if err := container.InitializeTransferServices(zapLogger); err != nil {
		fmt.Println("Failed to initialize deposit services:", err)
		panic(err)
	}

	// Start transfer scheduler (deposit, collect, withdraw 통합 처리)
	if err := container.TransferScheduler.Start(); err != nil {
		fmt.Println("Failed to start transfer scheduler:", err)
		panic(err)
	}
	logger.GetLogger().Info("Transfer scheduler started successfully")

	c := cron.New(cron.WithSeconds())
	_, err = c.AddFunc("*/10 * * * * *", func() { utils.TraceBlockchainWithContainer(container) })
	if err != nil {
		fmt.Println("AddFunc TraceBlockchain", err)
		panic(err)
	}
	_, err = c.AddFunc("*/10 * * * * *", func() { utils.CheckLastWithdrawWithContainer(container) })
	if err != nil {
		fmt.Println("AddFunc CheckLastWithdraw", err)
		panic(err)
	}
	c.Start()

	// Graceful shutdown handling
	defer func() {
		container.DepositScheduler.Stop()
		logger.GetLogger().Info("Deposit scheduler stopped")
	}()

	select {}
}

// logConfigInfo logs configuration information at startup
func logConfigInfo(config *config.Config) {
	log := logger.GetLogger()

	log.Info("=== Server Configuration ===")
	log.Infof("Server Host: %s", config.Server.Host)
	log.Infof("Server Port: %s", config.Server.Port)
	log.Info("=== Configuration Loaded Successfully ===")
}
