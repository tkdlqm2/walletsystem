package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/acecasino/account_manage/internal/config"
	"github.com/acecasino/account_manage/internal/domain/entities"
	"github.com/acecasino/account_manage/internal/infrastructure/crypto"
	"github.com/acecasino/account_manage/internal/infrastructure/database/repositories"
	"github.com/acecasino/account_manage/internal/infrastructure/external/notification"
	"github.com/acecasino/account_manage/pkg/logger"
	"github.com/labstack/echo"
	"gorm.io/gorm"
)

// 싱글톤 로거 import
// 반드시 logger.go가 같은 패키지(account_manage)에 있어야 합니다.
// import "github.com/sirupsen/logrus"는 logger.go에서만 필요

func RestAPI() {
	cfg := config.LoadConfig()
	db, err := config.NewDatabase(cfg.Database)
	if err != nil {
		logger.GetLogger().WithError(err).Error("RestAPI DB error")
		panic(err)
	}

	e := echo.New()
	e.Use(logger.LoggingMiddleware)
	e.GET("/ether-address", EtherAddress(db))
	e.GET("/tron-address", TronAddress(db))
	e.GET("/address", GetAllAddress(db))
	e.GET("/balance", Balance(db))
	e.POST("/collect", Collect(db))
	e.POST("/send", Send(db))
	e.POST("/do_withdraw", DoWithdraw(db))
	e.POST("/manual_request", ManualRequest(db))
	e.GET("/heartbeat", HeartBeat)

	// 새로운 암호화/복호화 API 엔드포인트
	e.GET("/encrypt-all-private-keys", EncryptAllPrivateKeys(db))
	e.GET("/encrypt-private-key-by-email", EncryptPrivateKeyByEmail(db))
	e.GET("/decrypt-private-key-by-email", DecryptPrivateKeyByEmail(db))

	port := os.Getenv("SERVER_PORT")
	e.Logger.Fatal(e.Start(":" + port))
}

func GetAllAddress(db *gorm.DB) func(c echo.Context) error {
	return func(c echo.Context) error {
		key := c.QueryParam("key")
		log := logger.GetLogger().WithField("key", key)

		if key == "" {
			log.Error("Key parameter is required")
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "key parameter is required"})
		}

		// 1. email를 통해 user의 address 여부 확인 (한번의 쿼리로 모든 정보 조회)
		type UserAddressResult struct {
			UserID          int    `gorm:"column:user_id"`
			Email           string `gorm:"column:email"`
			EthereumAddress string `gorm:"column:ethereum_address"`
			TronAddress     string `gorm:"column:tron_address"`
		}

		var result UserAddressResult
		sqlStatement := `
		SELECT 
			u.id as user_id,
			u.email,
			eth_ca.account_address as ethereum_address,
			tron_ca.account_address as tron_address
		FROM users u
		LEFT JOIN chain_accounts eth_ca ON u.id = eth_ca.user_id AND eth_ca.wallet_type = 'ETHEREUM'
		LEFT JOIN chain_accounts tron_ca ON u.id = tron_ca.user_id AND tron_ca.wallet_type = 'TRON'
		WHERE u.email = $1`

		err := db.Raw(sqlStatement, key).Scan(&result).Error
		if err != nil {
			log.WithError(err).Error("Database query failed")
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "database query failed"})
		}

		if result.UserID == 0 {
			log.Error("User not found")
			return c.JSON(http.StatusNotFound, map[string]string{"error": "user not found"})
		}

		m := map[string]string{}

		// Private key는 필요한 경우에만 한 번 생성
		var pk string

		// Ethereum 주소 처리
		if result.EthereumAddress != "empty_address" {
			m["ether"] = result.EthereumAddress
			log.WithField("ether_address", result.EthereumAddress).Info("Existing Ethereum address found")
		} else {
			if pk == "" {
				pk, err = crypto.GeneratePrivateKey(key)
				if err != nil {
					log.WithError(err).Error("Failed to generate private key")
					return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to generate private key"})
				}
			}
			addr, err := GetEtherAddress(key, pk, db)
			if err != nil {
				log.WithError(err).Error("Failed to get Ethereum address")
				return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to generate ethereum address"})
			}
			m["ether"] = addr
			log.WithField("ether_address", addr).Info("New Ethereum address generated")
		}

		// Tron 주소 처리
		if result.TronAddress != "empty_address" {
			m["tron"] = result.TronAddress
			log.WithField("tron_address", result.TronAddress).Info("Existing Tron address found")
		} else {
			if pk == "" {
				pk, err = crypto.GeneratePrivateKey(key)
				if err != nil {
					log.WithError(err).Error("Failed to generate private key")
					return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to generate private key"})
				}
			}
			tronAddr, err := GetTronAddress(key, pk, db)
			if err != nil {
				log.WithError(err).Error("Failed to get Tron address")
				return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to generate tron address"})
			}
			m["tron"] = tronAddr
			log.WithField("tron_address", tronAddr).Info("New Tron address generated")
		}

		log.WithFields(map[string]interface{}{
			"ether_address": m["ether"],
			"tron_address":  m["tron"],
		}).Info("Address response prepared")

		return c.JSON(http.StatusOK, m)
	}
}

func HeartBeat(c echo.Context) error {
	return c.String(http.StatusOK, "ok")
}

func Send(db *gorm.DB) func(c echo.Context) error {
	return func(c echo.Context) error {
		// defer 함수 정의 - withdrawInfo.Process가 "completed"일 때 user_balance 업데이트
		var withdrawInfo *entities.WithdrawInfo
		senderToken := c.Request().Header.Get("TOKEN")
		checkSenderToken := os.Getenv("SEND_TOKEN")
		if senderToken != checkSenderToken {
			return c.JSON(http.StatusUnauthorized, "unauthorized")
		}

		token := c.FormValue("token")
		cc, err := GetCurrency(db, token)
		if err != nil {
			fmt.Println(err.Error())
			return err
		}
		userEmail := c.FormValue("user")
		amountStr := c.FormValue("amount")
		toAddr := c.FormValue("toAddr")
		memo := c.FormValue("memo")

		// 이메일로 사용자 ID 조회
		userRepo := repositories.NewUserRepository(db)
		userID, err := userRepo.GetUserIDByEmail(context.Background(), userEmail)
		if err != nil {
			logger.GetLogger().WithError(err).WithField("email", userEmail).Error("Failed to get user ID by email")
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "User not found"})
		}

		// withdraw_history에 전송 요청 기록 추가
		withdrawInfo = &entities.WithdrawInfo{
			UserID:     userID, // 사용자 ID 설정
			CurrencyID: cc.ID,  // Currency의 ID를 CurrencyID로 설정
			ToAddress:  toAddr, // 사용자의 지갑 주소
			Amount:     amountStr,
			Process:    "request",
			CreateAt:   time.Now(),
		}

		// withdraw_history 테이블에 저장
		err = db.Table("withdraw_history").Create(withdrawInfo).Error
		if err != nil {
			logger.GetLogger().WithError(err).Error("Failed to create withdraw_history record")
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to create withdraw history"})
		}

		logger.GetLogger().WithFields(map[string]interface{}{
			"withdraw_id": withdrawInfo.ID,
			"token":       token,
			"to_address":  toAddr,
			"amount":      amountStr,
			"memo":        memo,
		}).Info("Withdraw history record created")

		switch cc.Blockchain.WalletType {
		case "ETHEREUM":
			res, err := EtherSend(db, token, toAddr, amountStr, memo)
			if err != nil {
				// 에러 발생 시 withdraw_history 상태 업데이트
				withdrawInfo.Process = "error"
				withdrawInfo.TxHash = err.Error()
				db.Table("withdraw_history").Save(withdrawInfo)

				logger.GetLogger().WithError(err).Error("EtherSend failed")
				return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
			}

			// 성공 시 withdraw_history 상태 업데이트
			withdrawInfo.Process = "completed"
			withdrawInfo.TxHash = res["hash"]
			db.Table("withdraw_history").Save(withdrawInfo)

			logger.GetLogger().WithFields(map[string]interface{}{
				"withdraw_id": withdrawInfo.ID,
				"tx_hash":     res["hash"],
				"amount":      res["amount"],
			}).Info("EtherSend completed successfully")

			return c.JSON(http.StatusOK, res)
		case "TRON":
			res, err := TronSend(db, token, toAddr, amountStr, memo)
			if err != nil {
				// 에러 발생 시 withdraw_history 상태 업데이트
				withdrawInfo.Process = "error"
				withdrawInfo.TxHash = err.Error()
				db.Table("withdraw_history").Save(withdrawInfo)

				logger.GetLogger().WithError(err).Error("TronSend failed")
				return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
			}

			// 성공 시 withdraw_history 상태 업데이트
			withdrawInfo.Process = "completed"
			withdrawInfo.TxHash = res["hash"]
			db.Table("withdraw_history").Save(withdrawInfo)

			logger.GetLogger().WithFields(map[string]interface{}{
				"withdraw_id": withdrawInfo.ID,
				"tx_hash":     res["hash"],
				"amount":      res["amount"],
			}).Info("TronSend completed successfully")

			return c.JSON(http.StatusOK, res)
		}
		return c.JSON(http.StatusBadRequest, "invalid token")
	}
}

func GetCurrency(db *gorm.DB, token string) (*entities.Currency, error) {
	// 먼저 currency 테이블만 조회해서 chain_id 확인
	var currencyInfo struct {
		ID      int    `db:"id"`
		ChainID int    `db:"chain_id"`
		Symbol  string `db:"symbol"`
	}

	err := db.Raw(`SELECT id, chain_id, symbol FROM currency WHERE symbol = ?`, token).Scan(&currencyInfo).Error
	if err != nil {
		return nil, err
	}

	// blockchain 테이블에서 해당 chain_id의 데이터 조회
	var blockchainInfo struct {
		ID               int    `db:"id"`
		Name             string `db:"name"`
		RpcURL           string `db:"rpc_url"`
		WalletType       string `db:"wallet_type"`
		LastCheckedBlock int    `db:"last_checked_block"`
		ActiveWatch      bool   `db:"active_watch"`
	}

	// 먼저 chain_id로 조회 시도
	err = db.Raw(`SELECT id, name, rpc_url, wallet_type, last_checked_block, active_watch FROM blockchain WHERE id = ?`, currencyInfo.ChainID).Scan(&blockchainInfo).Error
	if err != nil {
		return nil, err
	}

	// 만약 blockchain 정보가 비어있거나 잘못된 경우, 심볼 기반으로 올바른 blockchain 찾기
	if blockchainInfo.ID == 0 || blockchainInfo.Name == "" {
		fmt.Println("DEBUG - Invalid blockchain found, searching by symbol pattern...")

		// USDC(Ethereum) -> ETHEREUM, USDC(TRON) -> TRON 등으로 매핑
		var targetWalletType string
		if strings.Contains(currencyInfo.Symbol, "Ethereum") {
			targetWalletType = "ETHEREUM"
		} else if strings.Contains(currencyInfo.Symbol, "TRON") {
			targetWalletType = "TRON"
		} else if strings.Contains(currencyInfo.Symbol, "BSC") {
			targetWalletType = "BSC"
		}

		if targetWalletType != "" {
			// 해당 wallet_type을 가진 blockchain 찾기
			err = db.Raw(`SELECT id, name, rpc_url, wallet_type, last_checked_block, active_watch FROM blockchain WHERE wallet_type = ? ORDER BY id LIMIT 1`, targetWalletType).Scan(&blockchainInfo).Error
			if err != nil {
				fmt.Println("DEBUG - Failed to find blockchain by wallet_type:", err)
			} else {
				fmt.Println("DEBUG - Found blockchain by wallet_type:", blockchainInfo)
				// currency의 chain_id도 업데이트
				currencyInfo.ChainID = blockchainInfo.ID
			}
		}
	}

	// blockchain 테이블의 전체 데이터 확인
	var allBlockchains []struct {
		ID   int    `db:"id"`
		Name string `db:"name"`
	}
	err = db.Raw(`SELECT id, name FROM blockchain ORDER BY id`).Scan(&allBlockchains).Error

	// Raw SQL로 조인해서 데이터 가져오기
	sqlQuery := `
		SELECT 
			c.id, c.chain_id, c.name, c.symbol, c.address, c.price, c.decimal, c.active_watch, c.default_value,
			b.id as blockchain_id, b.name as blockchain_name, b.rpc_url, b.wallet_type, b.last_checked_block, b.active_watch as blockchain_active
		FROM currency c
		LEFT JOIN blockchain b ON c.chain_id = b.id
		WHERE c.symbol = ?
	`

	var result struct {
		ID               int     `db:"id"`
		ChainID          int     `db:"chain_id"`
		Name             string  `db:"name"`
		Symbol           string  `db:"symbol"`
		Address          string  `db:"address"`
		Price            float64 `db:"price"`
		Decimal          int     `db:"decimal"`
		ActiveWatch      bool    `db:"active_watch"`
		DefaultValue     bool    `db:"default_value"`
		BlockchainID     int     `db:"blockchain_id"`
		BlockchainName   string  `db:"blockchain_name"`
		RpcURL           string  `db:"rpc_url"`
		WalletType       string  `db:"wallet_type"`
		LastCheckedBlock int     `db:"last_checked_block"`
		BlockchainActive bool    `db:"blockchain_active"`
	}

	err = db.Raw(sqlQuery, token).Scan(&result).Error
	if err != nil {
		return nil, err
	}

	// 결과를 Currency 구조체로 변환
	// blockchainInfo에서 찾은 올바른 정보를 사용
	currency := &entities.Currency{
		ID:           result.ID,
		ChainID:      blockchainInfo.ID, // blockchainInfo.ID를 사용 (올바른 chain_id)
		Name:         result.Name,
		Symbol:       result.Symbol,
		Address:      result.Address,
		Price:        result.Price,
		Decimal:      result.Decimal,
		ActiveWatch:  result.ActiveWatch,
		DefaultValue: result.DefaultValue,
		Blockchain: entities.Blockchain{
			ID:               blockchainInfo.ID,
			Name:             blockchainInfo.Name,
			RpcURL:           blockchainInfo.RpcURL,
			WalletType:       blockchainInfo.WalletType,
			LastCheckedBlock: blockchainInfo.LastCheckedBlock,
			ActiveWatch:      blockchainInfo.ActiveWatch,
		},
	}
	return currency, nil
}

func Balance(db *gorm.DB) func(c echo.Context) error {
	return func(c echo.Context) error {
		token := c.FormValue("token")
		key := c.FormValue("key")
		log := logger.GetLogger().WithFields(map[string]interface{}{
			"token": token,
			"key":   key,
			"path":  c.Path(),
		})
		cc, err := GetCurrency(db, token)

		if err != nil {
			log.WithError(err).Warn("Invalid token")
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}

		switch cc.Blockchain.WalletType {
		case "ETHEREUM":
			balance, err := EtherBalance(db, key, token)
			if err != nil {
				log.WithError(err).Error("EtherBalance error")
				return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
			}
			log.WithField("balance", balance).Info("ETH balance response")
			return c.String(http.StatusOK, balance)
		case "TRON":
			balance, err := TronBalance(db, key)
			if err != nil {
				log.WithError(err).Error("TronBalance error")
				return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
			}
			log.WithField("balance", balance).Info("TRON balance response")
			return c.String(http.StatusOK, balance)
		default:
			log.Warn("Invalid token type")
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid token"})
		}
	}
}

func Collect(db *gorm.DB) func(c echo.Context) error {
	return func(c echo.Context) error {
		token := c.FormValue("token")
		cc, err := GetCurrency(db, token)
		if err != nil {
			return err
		}

		key := c.FormValue("key")
		switch cc.Blockchain.WalletType {
		case "ETHEREUM":
			res, err := EtherCollect(db, key, token)
			if err != nil {
				return err
			}
			return c.String(http.StatusOK, res)
		case "TRON":
			res, err := TronCollect(db, key)
			if err != nil {
				return err
			}
			return c.String(http.StatusOK, res)
		}
		return c.JSON(http.StatusBadRequest, "invalid token")
	}
}

func Collect_(db *gorm.DB, key, token string) (string, error) {
	cc, err := GetCurrency(db, token)
	if err != nil {
		fmt.Println(err.Error())
		return "nil", err
	}
	switch cc.Blockchain.WalletType {
	case "ETHEREUM":
		res, err := EtherCollect(db, key, token)
		if err != nil {
			fmt.Println(err.Error())
			return "", err
		}
		return res, nil
	case "TRON":
		res, err := TronCollect(db, key)
		if err != nil {
			fmt.Println(err.Error())
			return "", err
		}
		return res, nil
	}
	return "", errors.New("invalid token")
}

func ManualRequest(db *gorm.DB) func(c echo.Context) error {
	return func(c echo.Context) error {
		senderToken := c.Request().Header.Get("TOKEN")
		checkSenderToken := os.Getenv("SEND_TOKEN")
		if senderToken != checkSenderToken {
			return c.JSON(http.StatusUnauthorized, "unauthorized")
		}
		withdraw := &entities.WithdrawInfo{}
		id := c.FormValue("id")
		err := db.Table("withdraw_history").Where("id = ? and process = ?", id, "manual_request").First(&withdraw).Error
		if err != nil {
			return c.String(http.StatusBadRequest, fmt.Errorf("error : %s", err).Error())
		}
		if withdraw.Process != "manual_request" {
			return c.String(http.StatusBadRequest, "invalid process")
		}
		err = processWithdraw(db, withdraw, "manual request")
		if err != nil {
			return c.String(http.StatusBadRequest, fmt.Errorf("error : %s", err).Error())
		}
		return nil
	}
}

func DoWithdraw(db *gorm.DB) func(c echo.Context) error {
	return func(c echo.Context) error {
		senderToken := c.Request().Header.Get("TOKEN")
		checkSenderToken := os.Getenv("SEND_TOKEN")
		if senderToken != checkSenderToken {
			return c.JSON(http.StatusUnauthorized, "unauthorized")
		}
		withdraws := []*entities.WithdrawInfo{}
		err := db.Table("withdraw_history").Where("process = ?", "request").Find(&withdraws).Error
		if err != nil {
			return err
		}

		for _, w := range withdraws {
			processWithdraw(db, w, "manual process")
		}
		return nil
	}
}

var processLock = sync.Mutex{}

func processWithdraw(db *gorm.DB, w *entities.WithdrawInfo, memo string) (err error) {
	processLock.Lock()
	defer processLock.Unlock()

	w.Process = "processing"
	err = db.Table("withdraw_history").Save(w).Error
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			notification.SendTelMsg(fmt.Sprintf("Withdraw Error, id : %d", w.ID))
			w.Process = "error"
			_err := db.Save(w).Error
			if _err != nil {
				notification.SendTelMsg(fmt.Sprintf("Withdraw Error save error, id : %d", w.ID))
			}
		}

		if r := recover(); r != nil {
			notification.SendTelMsg(fmt.Sprintf("panic Withdraw Error, id : %d", w.ID))
			w.Process = "error"
			_err := db.Save(w).Error
			if _err != nil {
				notification.SendTelMsg(fmt.Sprintf("panic Withdraw Error save error, id : %d", w.ID))
			}
		}
	}()

	var cc *entities.Currency
	cc, err = getCurrencyByID(db, w.CurrencyID)

	if err != nil {
		return err
	}

	var data map[string]string
	switch cc.Blockchain.WalletType {
	case "ETHEREUM":
		data, err = EtherWithdraw(db, cc, w, memo)
	case "TRON":
		data, err = TronWithdraw(db, cc, w, memo)
	default:
		err = errors.New("invalid blockchain")
		return
	}
	if err == nil {
		w.Process = "processed"
		w.TxHash = data["hash"]
		err = db.Table("withdraw_history").Save(w).Error
	}

	return err
}

func getCurrencyByID(db *gorm.DB, id int) (*entities.Currency, error) {
	cc := &entities.Currency{}
	err := db.Model(&entities.Currency{}).Where("id = ?", id).First(&cc).Error
	if err != nil {
		return nil, err
	}
	db.Model(&entities.Blockchain{}).Where("id = ?", cc.ChainID).Scan(&cc.Blockchain)
	return cc, nil
}
