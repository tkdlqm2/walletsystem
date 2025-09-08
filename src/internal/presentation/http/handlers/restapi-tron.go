package handlers

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"crypto/sha256"
	"encoding/hex"
	"math"

	"github.com/acecasino/account_manage/internal/domain/entities"
	"github.com/acecasino/account_manage/internal/infrastructure/crypto"
	"github.com/acecasino/account_manage/internal/infrastructure/database/repositories"
	"github.com/acecasino/account_manage/internal/infrastructure/external/notification"
	"github.com/acecasino/account_manage/pkg/logger"
	"github.com/labstack/echo"
	"gorm.io/gorm"
)

var _TronCollectLock = sync.Mutex{}

func TronAddress(db *gorm.DB) func(c echo.Context) error {
	return func(c echo.Context) error {
		key := c.QueryParam("key")
		log := logger.GetLogger().WithFields(map[string]interface{}{
			"key":  key,
			"path": "/tron-address",
		})
		pk, err := crypto.GeneratePrivateKey(key)
		if err != nil {
			log.WithError(err).Error("Failed to get private key")
			return err
		}
		addr, err := GetTronAddress(key, pk, db)
		if err != nil {
			log.WithError(err).Error("Failed to get Tron address")
			return err
		}
		log.WithField("address", addr).Info("Tron address fetched")
		return c.String(http.StatusOK, addr)
	}
}

func TronSend(db *gorm.DB, token, toAddr, amountStr, memo string) (map[string]string, error) {
	_TronCollectLock.Lock()
	defer _TronCollectLock.Unlock()
	log := logger.GetLogger().WithFields(map[string]interface{}{
		"token":     token,
		"toAddr":    toAddr,
		"amountStr": amountStr,
		"memo":      memo,
	})
	ustdContractAddr := os.Getenv("TRON_USDT_ADDR")
	ctx := context.Background()
	adminPk, err := crypto.GetAdminPrivateKey(ctx)
	if err != nil {
		log.WithError(err).Error("Failed to get admin private key")
		return nil, err
	}

	manager, err := NewTRC20Manager("", adminPk, ustdContractAddr)
	if err != nil {
		log.WithError(err).Error("Failed to create TRC20Manager")
		return nil, err
	}

	bi, err := ConvertTokenToBigInt(amountStr, 6)
	if err != nil {
		log.WithError(err).Error("ConvertTokenToBigInt failed")
		return nil, fmt.Errorf("invalid err %v amount %v", err, amountStr)
	}
	txhash, err := manager.Send(manager.adminAddr, toAddr, adminPk, bi)
	if err != nil {
		log.WithError(err).Error("TRC20 Send failed")
		return nil, err
	}

	log.WithFields(map[string]interface{}{
		"txhash": txhash,
		"amount": bi.String(),
	}).Info("TronSend succeeded")

	return map[string]string{
		"to":     toAddr,
		"amount": bi.String(),
		"hash":   txhash,
	}, nil
}

func TronBalance(db *gorm.DB, email string) (string, error) {
	log := logger.GetLogger().WithField("email", email)
	ustdContractAddr := os.Getenv("TRON_USDT_ADDR")
	ctx := context.Background()
	adminPk, err := crypto.GetAdminPrivateKey(ctx)
	if err != nil {
		log.WithError(err).Error("Failed to get admin private key")
		return "", err
	}

	manager, err := NewTRC20Manager("", adminPk, ustdContractAddr)
	if err != nil {
		log.WithError(err).Error("Failed to create TRC20Manager")
		return "", err
	}

	// getPrivateKeyUsingEmail을 사용하여 TRON 지갑의 private key 조회
	chainAccountRepo := repositories.NewChainAccountRepository(db)
	privateKeys, err := chainAccountRepo.GetPrivateKeyUsingEmailLegacy(context.Background(), email)
	if err != nil {
		log.WithError(err).Error("Failed to get deposit private keys")
		return "", err
	}

	// TRON 지갑의 private key 추출
	var encryptedPk string
	for _, account := range privateKeys {
		if account.WalletType == "TRON" {
			encryptedPk = account.PrivateKey
			break
		}
	}
	if encryptedPk == "" {
		log.Error("TRON wallet not found for user")
		return "", errors.New("TRON wallet not found")
	}

	// 복호화 하기
	aesCrypto, err := crypto.NewAESCrypto()
	if err != nil {
		log.WithError(err).Error("Failed to create AESCrypto instance")
		return "", err
	}

	decryptedPk, err := aesCrypto.DecryptPrivateKeyFromBase64(encryptedPk)
	if err != nil {
		log.WithError(err).Error("Failed to decrypt private key")
		return "", err
	}

	// []byte를 string으로 변환
	depositPk := string(decryptedPk)

	depositAddr, err := TronMakeAddress(depositPk)
	if err != nil {
		log.WithError(err).Error("TronMakeAddress failed")
		return "", err
	}
	trxbi := manager.Balance(depositAddr)
	log.WithField("balance", trxbi.String()).Info("TronBalance succeeded")
	return trxbi.String(), nil
}

func TronCollect(db *gorm.DB, email string) (string, error) {
	_TronCollectLock.Lock()
	defer _TronCollectLock.Unlock()
	log := logger.GetLogger().WithField("email", email)

	log.Info("=== TronCollect 시작 ===")

	ustdContractAddr := os.Getenv("TRON_USDT_ADDR")
	log.WithField("ustdContractAddr", ustdContractAddr).Info("TRON USDT 컨트랙트 주소 확인")

	ctx := context.Background()
	adminPk, err := crypto.GetAdminPrivateKey(ctx)
	if err != nil {
		log.WithError(err).Error("Failed to get admin private key")
		return "", err
	}
	log.Info("Admin private key 획득 성공")

	manager, err := NewTRC20Manager("", adminPk, ustdContractAddr)
	if err != nil {
		log.WithError(err).Error("Failed to create TRC20Manager")
		return "", err
	}
	log.Info("TRC20Manager 생성 성공")

	// getPrivateKeyUsingEmail을 사용하여 TRON 지갑의 private key 조회
	log.Info("데이터베이스에서 private key 조회 시작")
	chainAccountRepo := repositories.NewChainAccountRepository(db)
	privateKeys, err := chainAccountRepo.GetPrivateKeyUsingEmailLegacy(context.Background(), email)
	if err != nil {
		log.WithError(err).Error("Failed to get deposit private keys")
		return "", err
	}
	log.WithField("privateKeys_count", len(privateKeys)).Info("Private keys 조회 성공")

	// TRON 지갑의 private key 추출
	var encryptedPk string
	for _, account := range privateKeys {
		if account.WalletType == "TRON" {
			encryptedPk = account.PrivateKey
			break
		}
	}
	if encryptedPk == "" {
		log.Error("TRON wallet not found for user")
		return "", errors.New("TRON wallet not found")
	}
	log.Info("TRON private key 추출 성공")

	// 복호화 하기
	log.Info("AES 암호화 인스턴스 생성 시작")
	aesCrypto, err := crypto.NewAESCrypto()
	if err != nil {
		log.WithError(err).Error("Failed to create AESCrypto instance")
		return "", err
	}
	log.Info("AES 암호화 인스턴스 생성 성공")

	log.Info("Private key 복호화 시작")
	decryptedPk, err := aesCrypto.DecryptPrivateKeyFromBase64(encryptedPk)
	if err != nil {
		log.WithError(err).Error("Failed to decrypt private key")
		return "", err
	}
	log.Info("Private key 복호화 성공")

	// []byte를 string으로 변환
	depositPk := string(decryptedPk)
	log.Info("TRON 주소 생성 시작")
	depositAddr, err := TronMakeAddress(depositPk)
	if err != nil {
		log.WithError(err).Error("TronMakeAddress failed")
		return "", err
	}
	log.WithField("depositAddr", depositAddr).Info("TRON 주소 생성 성공")

	log.Info("잔액 및 승인량 조회 시작")
	allow := manager.Allowance(depositAddr)
	trxbi := manager.Balance(depositAddr)
	bi := manager.TRC20Balance(depositAddr)

	log.WithFields(map[string]interface{}{
		"allowance":    allow.String(),
		"trxBalance":   trxbi.String(),
		"tokenBalance": bi.String(),
	}).Info("잔액 및 승인량 조회 완료")

	if bi.Cmp(big.NewInt(1000000)) < 0 {
		log.WithField("balance", bi.String()).Warn("잔액이 1 USDT 미만입니다")
		return "", errors.New("not sended balance less then 1(" + bi.String() + ")")
	}

	if allow.Cmp(bi) < 0 {
		log.Warn("승인량이 잔액보다 적어서 승인 프로세스 시작")
		approveFee := big.NewInt(21261000)
		if approveFee.Cmp(trxbi) > 0 {
			log.Warn("TRX 잔액 부족으로 승인 수수료 전송 시작")
			_, err := manager.SendTRX(depositAddr, approveFee)
			if err != nil {
				log.WithError(err).Error("SendTRX failed")
				return "", err
			}
			log.Info("승인 수수료 전송 성공")
		}
		log.Info("토큰 승인 시작")
		_, err := manager.Approve(depositAddr, depositPk, big.NewInt(1000000000000000))
		if err != nil {
			log.WithError(err).Error("Approve failed")
			return "", err
		}
		log.Info("토큰 승인 성공")
	}

	log.Info("TRC20 토큰 전송 시작")
	if _, err := manager.TRC20TransferFrom(depositAddr, bi); err != nil {
		log.WithError(err).Error("TRC20TransferFrom failed")
		return "", err
	}
	log.WithField("amount", bi.String()).Info("=== TronCollect 완료 ===")
	return bi.String(), nil
}

func GetTronAddress(email, pk string, db *gorm.DB) (string, error) {
	log := logger.GetLogger().WithField("email", email)
	addr, err := TronMakeAddress(pk)
	if err != nil {
		log.WithError(err).Error("TronMakeAddress failed")
		return "", err
	}

	// 1. 암호화 후 base64 인코딩
	aesCrypto, err := crypto.NewAESCrypto()
	if err != nil {
		log.WithError(err).Error("Failed to create AESCrypto instance")
		return "", err
	}

	// private key를 byte 배열로 변환
	pkBytes := []byte(pk)
	encryptedBase64, err := aesCrypto.EncryptPrivateKeyToBase64(pkBytes)
	if err != nil {
		log.WithError(err).Error("Failed to encrypt private key")
		return "", err
	}

	// 먼저 이메일로 사용자 ID 조회
	userRepo := repositories.NewUserRepository(db)
	userID, err := userRepo.GetUserIDByEmail(context.Background(), email)
	if err != nil {
		log.WithError(err).Error("Failed to get user ID by email")
		return "", err
	}

	if userID == 0 {
		log.Error("User not found")
		return "", errors.New("user not found")
	}

	// 암호화된 private key를 데이터베이스에 저장 (INSERT 또는 UPDATE)
	// 먼저 레코드가 존재하는지 확인
	var existingRecord entities.ChainAccount
	err = db.Where("user_id = ? AND wallet_type = ?", userID, "TRON").First(&existingRecord).Error

	if err != nil && err.Error() == "record not found" {
		// 레코드가 없으면 INSERT
		newRecord := entities.ChainAccount{
			UserID:         userID,
			WalletType:     "TRON",
			AccountAddress: addr,
			PrivateKey:     encryptedBase64,
		}
		err = db.Create(&newRecord).Error
		if err != nil {
			log.WithError(err).Error("INSERT failed")
			return "", err
		}
	} else if err != nil {
		// 다른 에러 발생
		log.WithError(err).Error("Database query failed")
		return "", err
	} else {
		// 레코드가 있으면 UPDATE
		err = db.Model(&existingRecord).Updates(map[string]interface{}{
			"account_address": addr,
			"private_key":     encryptedBase64,
		}).Error
		if err != nil {
			log.WithError(err).Error("UPDATE failed")
			return "", err
		}
	}
	log.WithField("address", addr).Info("Tron address updated in DB")
	return addr, nil

}

func TronWithdraw(db *gorm.DB, cc *entities.Currency, w *entities.WithdrawInfo, memo string) (map[string]string, error) {
	log := logger.GetLogger().WithFields(map[string]interface{}{
		"symbol":    cc.Symbol,
		"toAddress": w.ToAddress,
		"amount":    w.Amount,
		"memo":      memo,
	})
	requestAm, err := strconv.ParseFloat(w.Amount, 64)
	if err != nil {
		log.WithError(err).Error("ParseFloat failed")
		return nil, err
	}
	w.Fee = 3
	w.Take = requestAm - w.Fee
	err = db.Table("withdraw_history").Save(w).Error
	if err != nil {
		log.WithError(err).Error("withdraw_history Save failed")
		notification.SendTelMsg(fmt.Sprintln("TronWithdraw ", err.Error()))
	}

	am := strconv.FormatFloat(w.Take, 'f', -1, 64)
	if w.Take < 0 {
		log.Warn("Invalid amount for withdraw")
		return nil, fmt.Errorf("invalid amount %v", w.Take)
	}
	data, err := TronSend(db, cc.Symbol, w.ToAddress, am, memo)
	if err != nil {
		log.WithError(err).Error("TronSend failed")
		errorLogsRepo := repositories.NewErrorLogsRepository(db)
		errorLogsRepo.SendErrMsg(context.Background(), "TronWithdraw", err)
		w.Process = "error"
		err = db.Table("withdraw_history").Save(w).Error
		if err != nil {
			log.WithError(err).Error("withdraw_history Save failed after error")
			notification.SendTelMsg(fmt.Sprintln("TronWithdraw ", err.Error()))
		}
	}
	log.WithField("withdraw_data", data).Info("TronWithdraw succeeded")
	return data, err
}

// EncryptAllPrivateKeys - chain_accounts 테이블의 모든 private_key를 암호화
func EncryptAllPrivateKeys(db *gorm.DB) func(c echo.Context) error {
	return func(c echo.Context) error {
		log := logger.GetLogger().WithField("path", "/encrypt-all-private-keys")

		// AES 암호화 인스턴스 생성
		aesCrypto, err := crypto.NewAESCrypto()
		if err != nil {
			log.WithError(err).Error("Failed to create AESCrypto instance")
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to create crypto instance"})
		}

		// chain_accounts 테이블의 모든 데이터 조회
		var chainAccounts []entities.ChainAccount
		err = db.Find(&chainAccounts).Error
		if err != nil {
			log.WithError(err).Error("Failed to fetch chain_accounts")
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to fetch data"})
		}

		encryptedCount := 0
		alreadyEncryptedCount := 0

		for _, account := range chainAccounts {
			// private_key가 "=="로 끝나는지 확인 (이미 암호화된 경우)
			if len(account.PrivateKey) >= 250 && account.PrivateKey[len(account.PrivateKey)-2:] == "==" {
				alreadyEncryptedCount++
				continue
			}

			// private_key를 byte 배열로 변환하여 암호화
			pkBytes := []byte(account.PrivateKey)
			encryptedBase64, err := aesCrypto.EncryptPrivateKeyToBase64(pkBytes)
			if err != nil {
				log.WithError(err).WithField("account_id", account.ID).Error("Failed to encrypt private key")
				continue
			}

			// 암호화된 private_key로 업데이트
			err = db.Model(&entities.ChainAccount{}).Where("id = ?", account.ID).Update("private_key", encryptedBase64).Error
			if err != nil {
				log.WithError(err).WithField("account_id", account.ID).Error("Failed to update encrypted private key")
				continue
			}

			encryptedCount++
		}

		log.WithFields(map[string]interface{}{
			"total_accounts":    len(chainAccounts),
			"encrypted_count":   encryptedCount,
			"already_encrypted": alreadyEncryptedCount,
		}).Info("Encryption process completed")

		return c.JSON(http.StatusOK, map[string]interface{}{
			"message":           "Encryption process completed",
			"total_accounts":    len(chainAccounts),
			"encrypted_count":   encryptedCount,
			"already_encrypted": alreadyEncryptedCount,
		})
	}
}

// EncryptPrivateKeyByEmail - 특정 이메일의 private_key를 암호화
func EncryptPrivateKeyByEmail(db *gorm.DB) func(c echo.Context) error {
	return func(c echo.Context) error {
		email := c.QueryParam("email")
		if email == "" {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "email parameter is required"})
		}

		log := logger.GetLogger().WithFields(map[string]interface{}{
			"email": email,
			"path":  "/encrypt-private-key-by-email",
		})

		// AES 암호화 인스턴스 생성
		aesCrypto, err := crypto.NewAESCrypto()
		if err != nil {
			log.WithError(err).Error("Failed to create AESCrypto instance")
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to create crypto instance"})
		}

		// 이메일로 사용자 ID 조회
		userRepo := repositories.NewUserRepository(db)
		userID, err := userRepo.GetUserIDByEmail(context.Background(), email)
		if err != nil {
			log.WithError(err).Error("Failed to get user ID by email")
			return c.JSON(http.StatusNotFound, map[string]string{"error": "user not found"})
		}

		// 해당 사용자의 모든 chain_accounts 조회
		var chainAccounts []entities.ChainAccount
		err = db.Where("user_id = ?", userID).Find(&chainAccounts).Error
		if err != nil {
			log.WithError(err).Error("Failed to fetch chain_accounts for user")
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to fetch data"})
		}

		if len(chainAccounts) == 0 {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "no chain accounts found for user"})
		}

		encryptedCount := 0
		alreadyEncryptedCount := 0

		for _, account := range chainAccounts {
			// private_key가 "=="로 끝나는지 확인 (이미 암호화된 경우)
			if len(account.PrivateKey) >= 2 && account.PrivateKey[len(account.PrivateKey)-2:] == "==" {
				alreadyEncryptedCount++
				continue
			}

			// private_key를 byte 배열로 변환하여 암호화
			pkBytes := []byte(account.PrivateKey)
			encryptedBase64, err := aesCrypto.EncryptPrivateKeyToBase64(pkBytes)
			if err != nil {
				log.WithError(err).WithField("account_id", account.ID).Error("Failed to encrypt private key")
				continue
			}

			// 암호화된 private_key로 업데이트
			err = db.Model(&entities.ChainAccount{}).Where("id = ?", account.ID).Update("private_key", encryptedBase64).Error
			if err != nil {
				log.WithError(err).WithField("account_id", account.ID).Error("Failed to update encrypted private key")
				continue
			}

			encryptedCount++
		}

		log.WithFields(map[string]interface{}{
			"email":             email,
			"total_accounts":    len(chainAccounts),
			"encrypted_count":   encryptedCount,
			"already_encrypted": alreadyEncryptedCount,
		}).Info("Email-specific encryption completed")

		return c.JSON(http.StatusOK, map[string]interface{}{
			"message":           "Email-specific encryption completed",
			"email":             email,
			"total_accounts":    len(chainAccounts),
			"encrypted_count":   encryptedCount,
			"already_encrypted": alreadyEncryptedCount,
		})
	}
}

// DecryptPrivateKeyByEmail - 특정 이메일의 private_key를 복호화
func DecryptPrivateKeyByEmail(db *gorm.DB) func(c echo.Context) error {
	return func(c echo.Context) error {
		email := c.QueryParam("email")
		if email == "" {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "email parameter is required"})
		}

		log := logger.GetLogger().WithFields(map[string]interface{}{
			"email": email,
			"path":  "/decrypt-private-key-by-email",
		})

		// AES 암호화 인스턴스 생성
		aesCrypto, err := crypto.NewAESCrypto()
		if err != nil {
			log.WithError(err).Error("Failed to create AESCrypto instance")
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to create crypto instance"})
		}

		// 이메일로 사용자 ID 조회
		userRepo := repositories.NewUserRepository(db)
		userID, err := userRepo.GetUserIDByEmail(context.Background(), email)
		if err != nil {
			log.WithError(err).Error("Failed to get user ID by email")
			return c.JSON(http.StatusNotFound, map[string]string{"error": "user not found"})
		}
		fmt.Println("userID:", userID)

		// 해당 사용자의 모든 chain_accounts 조회
		var chainAccounts []entities.ChainAccount
		err = db.Where("user_id = ?", userID).Find(&chainAccounts).Error
		if err != nil {
			log.WithError(err).Error("Failed to fetch chain_accounts for user")
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to fetch data"})
		}

		if len(chainAccounts) == 0 {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "no chain accounts found for user"})
		}

		decryptedKeys := make(map[string]string)
		decryptedCount := 0
		notEncryptedCount := 0

		for _, account := range chainAccounts {
			// private_key가 "=="로 끝나는지 확인 (암호화된 경우)
			if len(account.PrivateKey) >= 2 && account.PrivateKey[len(account.PrivateKey)-2:] == "==" {
				// 암호화된 경우 복호화 시도
				decryptedPk, err := aesCrypto.DecryptPrivateKeyFromBase64(account.PrivateKey)
				if err != nil {
					log.WithError(err).WithField("account_id", account.ID).Error("Failed to decrypt private key")
					continue
				}
				decryptedKeys[account.WalletType] = string(decryptedPk)
				decryptedCount++
			} else {
				// 이미 복호화된 경우
				decryptedKeys[account.WalletType] = account.PrivateKey
				notEncryptedCount++
			}
		}

		log.WithFields(map[string]interface{}{
			"email":               email,
			"total_accounts":      len(chainAccounts),
			"decrypted_count":     decryptedCount,
			"not_encrypted_count": notEncryptedCount,
		}).Info("Email-specific decryption completed")

		return c.JSON(http.StatusOK, map[string]interface{}{
			"message":             "Email-specific decryption completed",
			"email":               email,
			"total_accounts":      len(chainAccounts),
			"decrypted_count":     decryptedCount,
			"not_encrypted_count": notEncryptedCount,
			"decrypted_keys":      decryptedKeys,
		})
	}
}

// NewTRC20Manager는 TRC20 토큰 관리를 위한 매니저를 생성합니다
func NewTRC20Manager(rpcURL, adminPk, contractAddr string) (*TRC20Manager, error) {
	// 간단한 구현 - 실제로는 TRON 네트워크 연결이 필요합니다
	return &TRC20Manager{
		rpcURL:       rpcURL,
		adminPk:      adminPk,
		contractAddr: contractAddr,
		adminAddr:    "TAdminAddress", // 실제로는 private key에서 생성해야 함
	}, nil
}

// TRC20Manager는 TRC20 토큰 관리를 담당합니다
type TRC20Manager struct {
	rpcURL       string
	adminPk      string
	contractAddr string
	adminAddr    string
}

// Send는 TRC20 토큰을 전송합니다
func (m *TRC20Manager) Send(fromAddr, toAddr, pk string, amount *big.Int) (string, error) {
	// 간단한 구현 - 실제로는 TRON 네트워크에 트랜잭션을 보내야 합니다
	return "txhash_" + fmt.Sprintf("%d", time.Now().Unix()), nil
}

// Balance는 TRX 잔액을 조회합니다
func (m *TRC20Manager) Balance(addr string) *big.Int {
	// 간단한 구현 - 실제로는 TRON 네트워크에서 잔액을 조회해야 합니다
	return big.NewInt(1000000000) // 1 TRX
}

// TRC20Balance는 TRC20 토큰 잔액을 조회합니다
func (m *TRC20Manager) TRC20Balance(addr string) *big.Int {
	// 간단한 구현 - 실제로는 TRON 네트워크에서 토큰 잔액을 조회해야 합니다
	return big.NewInt(1000000) // 1 USDT
}

// Allowance는 토큰 승인량을 조회합니다
func (m *TRC20Manager) Allowance(addr string) *big.Int {
	// 간단한 구현 - 실제로는 TRON 네트워크에서 승인량을 조회해야 합니다
	return big.NewInt(0)
}

// Approve는 토큰 사용을 승인합니다
func (m *TRC20Manager) Approve(addr, pk string, amount *big.Int) (string, error) {
	// 간단한 구현 - 실제로는 TRON 네트워크에 승인 트랜잭션을 보내야 합니다
	return "approve_txhash_" + fmt.Sprintf("%d", time.Now().Unix()), nil
}

// TRC20TransferFrom은 승인된 토큰을 전송합니다
func (m *TRC20Manager) TRC20TransferFrom(fromAddr string, amount *big.Int) (string, error) {
	// 간단한 구현 - 실제로는 TRON 네트워크에 전송 트랜잭션을 보내야 합니다
	return "transfer_txhash_" + fmt.Sprintf("%d", time.Now().Unix()), nil
}

// SendTRX는 TRX를 전송합니다
func (m *TRC20Manager) SendTRX(toAddr string, amount *big.Int) (string, error) {
	// 간단한 구현 - 실제로는 TRON 네트워크에 TRX 전송 트랜잭션을 보내야 합니다
	return "trx_txhash_" + fmt.Sprintf("%d", time.Now().Unix()), nil
}

// ConvertTokenToBigInt는 토큰 문자열을 BigInt로 변환합니다
func ConvertTokenToBigInt(amountStr string, decimals int) (*big.Int, error) {
	amount, err := strconv.ParseFloat(amountStr, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid amount: %v", err)
	}

	// 소수점 자릿수를 고려하여 정수로 변환
	multiplier := math.Pow(10, float64(decimals))
	amountInt := int64(amount * multiplier)

	return big.NewInt(amountInt), nil
}

// TronMakeAddress는 private key로부터 TRON 주소를 생성합니다
func TronMakeAddress(pk string) (string, error) {
	// 간단한 구현 - 실제로는 TRON 주소 생성 알고리즘을 사용해야 합니다
	// 여기서는 해시 기반으로 주소를 생성합니다
	hash := sha256.Sum256([]byte(pk))
	address := "T" + hex.EncodeToString(hash[:20]) // TRON 주소 형식
	return address, nil
}

// GetLogger는 로거를 반환합니다
func GetLogger() interface{} {
	return logger.GetLogger()
}
