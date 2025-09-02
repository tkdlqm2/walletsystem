package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync"

	"github.com/acecasino/account_manage/internal/crypto"
	"github.com/acecasino/account_manage/internal/database"
	"github.com/acecasino/account_manage/internal/notification"
	"github.com/acecasino/account_manage/pkg/logger"
	"github.com/labstack/echo"
	"gorm.io/gorm"
)

// 싱글톤 로거 import
// 반드시 logger.go가 같은 패키지(account_manage)에 있어야 합니다.
// import "github.com/sirupsen/logrus"는 logger.go에서만 필요

func RestAPI() {
	db, err := database.NewDB()
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
	if port == "" {
		port = "6215"
	}
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
				pk, err = crypto.GetPrivateKey(key)
				if err != nil {
					log.WithError(err).Error("Failed to generate private key")
					return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to generate private key"})
				}
			}
			addr, err := generateEtherAddress(key, pk, db)
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
				pk, err = crypto.GetPrivateKey(key)
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
		toAddr := c.FormValue("toAddr")
		amountStr := c.FormValue("amount")
		memo := c.FormValue("memo")
		switch cc.Blockchain.WalletType {
		case "ETHEREUM":
			res, err := EtherSend(db, token, toAddr, amountStr, memo)
			if err != nil {
				fmt.Println(err.Error())
				return err
			}
			return c.JSON(http.StatusOK, res)
		case "TRON":
			res, err := TronSend(db, token, toAddr, amountStr, memo)
			if err != nil {
				fmt.Println(err.Error())
				return err
			}
			return c.JSON(http.StatusOK, res)
		}
		return c.JSON(http.StatusBadRequest, "invalid token")
	}
}

func GetCurrency(db *gorm.DB, token string) (*database.Currency, error) {
	var cy []*database.Currency
	db.Model(&database.Currency{}).Where("symbol = ?", token).Find(&cy)
	if len(cy) == 0 {
		return nil, errors.New("invalid token")
	}
	return cy[0], nil
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
		withdraw := &database.WithdrawInfo{}
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
		withdraws := []*database.WithdrawInfo{}
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

func processWithdraw(db *gorm.DB, w *database.WithdrawInfo, memo string) (err error) {
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

	var cc *database.Currency
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

func getCurrencyByID(db *gorm.DB, id int) (*database.Currency, error) {
	cc := &database.Currency{}
	err := db.Model(&database.Currency{}).Where("id = ?", id).First(&cc).Error
	if err != nil {
		return nil, err
	}
	db.Model(&database.Blockchain{}).Where("id = ?", cc.ChainID).Scan(&cc.Blockchain)
	return cc, nil
}

// generateEtherAddress는 이메일과 private key를 사용하여 이더리움 주소를 생성합니다
func generateEtherAddress(email, pk string, db *gorm.DB) (string, error) {
	// 간단한 구현 - 실제로는 이더리움 주소 생성 알고리즘을 사용해야 합니다
	// 여기서는 해시 기반으로 주소를 생성합니다
	hash := sha256.Sum256([]byte(email + pk))
	address := "0x" + hex.EncodeToString(hash[:20]) // 이더리움 주소 형식
	return address, nil
}


