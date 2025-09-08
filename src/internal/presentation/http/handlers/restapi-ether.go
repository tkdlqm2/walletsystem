package handlers

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/acecasino/account_manage/internal/domain/entities"
	"github.com/acecasino/account_manage/internal/infrastructure/crypto"
	"github.com/acecasino/account_manage/internal/infrastructure/database/repositories"
	"github.com/acecasino/account_manage/internal/infrastructure/external/blockchain/ethereum"
	"github.com/acecasino/account_manage/internal/infrastructure/external/notification"
	"github.com/acecasino/account_manage/pkg/logger"
	"github.com/ethereum/go-ethereum/common"

	"github.com/labstack/echo"
	"gorm.io/gorm"
)

var _EtherCollectLock = sync.Mutex{}

func EtherAddress(db *gorm.DB) func(c echo.Context) error {
	return func(c echo.Context) error {
		key := c.QueryParam("key")
		log := logger.GetLogger().WithFields(map[string]interface{}{
			"key":  key,
			"path": "/ether-address",
		})
		pk, err := crypto.GeneratePrivateKey(key)
		if err != nil {
			log.WithError(err).Error("Failed to get private key using email")
			return err
		}
		addr, err := GetEtherAddress(key, pk, db)
		if err != nil {
			log.WithError(err).Error("Failed to get Ether address")
			return err
		}
		log.WithField("address", addr).Info("Ether address fetched")
		return c.String(http.StatusOK, addr)
	}
}

func EtherSend(db *gorm.DB, token, toAddr, amountStr, memo string) (map[string]string, error) {
	_EtherCollectLock.Lock()
	defer _EtherCollectLock.Unlock()
	log := logger.GetLogger().WithFields(map[string]interface{}{
		"func":      "EtherSend",
		"token":     token,
		"toAddr":    toAddr,
		"amountStr": amountStr,
		"memo":      memo,
	})

	cc, err := GetCurrency(db, token)
	if err != nil {
		log.WithError(err).Error("Failed to get currency")
		return nil, err
	}

	ctx := context.Background()
	adminPk, err := crypto.GetAdminPrivateKey(ctx)
	if err != nil {
		log.WithError(err).Error("Failed to get admin private key")
		return nil, err
	}

	manager, err := ethereum.NewERC20Manager(cc, adminPk)
	if err != nil {
		log.WithError(err).Error("Failed to create ERC20Manager")
		return nil, err
	}
	addr := common.HexToAddress(toAddr)
	txhash, amt, err := manager.AdminERC20Transfer(addr, amountStr)
	if err != nil {
		log.WithError(err).Error("AdminERC20Transfer failed")
		return nil, err
	}

	log.WithFields(map[string]interface{}{
		"txhash": txhash,
		"amount": amt.String(),
	}).Info("EtherSend succeeded")

	//TODO save history send token : insert with memo
	return map[string]string{
		"to":     toAddr,
		"amount": amt.String(),
		"hash":   txhash,
	}, nil
}

func EtherBalance(db *gorm.DB, email string, token string) (string, error) {
	log := logger.GetLogger()
	cc, err := GetCurrency(db, token)
	if err != nil {
		log.WithError(err).Error("Failed to get currency")
		return "", err
	}

	ctx := context.Background()
	adminPk, err := crypto.GetAdminPrivateKey(ctx)
	if err != nil {
		log.WithError(err).Error("Failed to get admin private key")
		return "", err
	}

	manager, err := ethereum.NewERC20Manager(cc, adminPk)
	if err != nil {
		log.WithError(err).Error("Failed to create ERC20Manager")
		return "", err
	}

	// 새로운 함수를 사용하여 chain_account 정보 조회
	chainAccountRepo := repositories.NewChainAccountRepository(db)
	chainAccount, err := chainAccountRepo.GetChainAccountByEmailAndWalletType(context.Background(), email, "ETHEREUM")
	if err != nil {
		log.WithError(err).WithField("email", email).Error("Failed to get chain account")
		return "", err
	}

	trxbi, _, err := manager.ERC20BalanceOf(chainAccount.AccountAddress)
	if err != nil {
		log.WithError(err).Error("ERC20BalanceOf failed")
		return "", err
	}
	log.WithField("balance", trxbi).Info("EtherBalance succeeded")
	return trxbi, nil
}

func EtherCollect(db *gorm.DB, email string, token string) (string, error) {
	_EtherCollectLock.Lock()
	defer _EtherCollectLock.Unlock()
	log := logger.GetLogger().WithFields(map[string]interface{}{
		"email": email,
		"token": token,
	})
	cc, err := GetCurrency(db, token)
	if err != nil {
		log.WithError(err).Error("Failed to get currency")
		return "", err
	}
	ctx := context.Background()
	adminPk, err := crypto.GetAdminPrivateKey(ctx)
	if err != nil {
		log.WithError(err).Error("Failed to get admin private key")
		return "", err
	}

	manager, err := ethereum.NewERC20Manager(cc, adminPk)
	if err != nil {
		log.WithError(err).Error("Failed to create ERC20Manager")
		return "", err
	}

	// chain account 조회
	chainAccountRepo := repositories.NewChainAccountRepository(db)
	chainAccount, err := chainAccountRepo.GetChainAccountByEmailAndWalletType(context.Background(), email, "ETHEREUM")
	if err != nil {
		log.WithError(err).Error("Failed to get chain account")
		return "", err
	}

	// 암호화된 private key를 복호화
	aesCrypto, err := crypto.NewAESCrypto()
	if err != nil {
		log.WithError(err).Error("Failed to create AESCrypto instance")
		return "", err
	}

	decryptedPkBytes, err := aesCrypto.DecryptPrivateKeyFromBase64(chainAccount.PrivateKey)
	if err != nil {
		log.WithError(err).Error("Failed to decrypt private key")
		return "", err
	}

	depositPk := string(decryptedPkBytes)

	allowance, err := manager.ERC20Allowance(chainAccount.AccountAddress)
	if err != nil {
		log.WithError(err).Error("ERC20Allowance failed")
		return "", err
	}
	etherBal, err := manager.EtherBalanceOf(chainAccount.AccountAddress)
	if err != nil {
		log.WithError(err).Error("EtherBalanceOf failed")
		return "", err
	}
	log.WithField("etherBal", etherBal)

	_, erc20Balance, err := manager.ERC20BalanceOf(chainAccount.AccountAddress)
	if err != nil {
		log.WithError(err).Error("ERC20BalanceOf failed")
		return "", err
	}
	log.WithField("erc20Balance", erc20Balance)

	// allowFlag should be 1 token unit (e.g., 1000000 for USDT with 6 decimals)
	allowFlag, _ := big.NewInt(0).SetString("1"+strings.Repeat("0", manager.Decimal()), 10)
	if erc20Balance.Cmp(allowFlag) < 0 {
		log.Warn("not sended balance less than 1", erc20Balance.String())
		return "", errors.New("not sended balance less then 1(" + erc20Balance.String() + ")")
	}

	gasPrice, err := manager.Client().SuggestGasPrice(context.Background())
	gasPrice = big.NewInt(0).Mul(gasPrice, big.NewInt(15))
	gasPrice = big.NewInt(0).Div(gasPrice, big.NewInt(10))
	if allowance.Cmp(erc20Balance) < 0 {
		if err != nil {
			log.WithError(err).Error("SuggestGasPrice failed")
			return "", err
		}

		gas, err := manager.EstimagteERC20Approve(depositPk, allowFlag)
		if err != nil {
			log.WithError(err).Error("EstimagteERC20Approve failed")
			return "", err
		}
		gas += (gas / 10) * 2
		approveFee := big.NewInt(0).Mul(gasPrice, big.NewInt(0).SetUint64(gas))
		if approveFee.Cmp(etherBal) > 0 {
			_, err := manager.SendEther(depositPk, approveFee, gasPrice, 0)
			if err != nil {
				log.WithError(err).Error("SendEther for approveFee failed")
				return "", err
			}
			time.Sleep(time.Second * 1)
			for {
				etherBal2, err := manager.EtherBalanceOf(chainAccount.AccountAddress)
				if err != nil {
					log.WithError(err).Error("EtherBalanceOf failed in approveFee loop")
					return "", err
				}
				if approveFee.Cmp(etherBal2) <= 0 {
					break
				}
				time.Sleep(time.Second * 5)
			}
		}
		// Set allowance to current balance + some buffer (e.g., 10% more)
		buffer := big.NewInt(0).Div(erc20Balance, big.NewInt(10)) // 10% buffer
		allowFlag := big.NewInt(0).Add(erc20Balance, buffer)
		_, err = manager.ERC20Approve(depositPk, allowFlag, gas, gasPrice)
		if err != nil {
			log.WithError(err).Error("ERC20Approve failed")
			return "", err
		}
		time.Sleep(time.Second * 1)
		for {
			allow, err := manager.ERC20Allowance(chainAccount.AccountAddress)
			if err != nil {
				log.WithError(err).Error("ERC20Allowance failed in approve loop")
				return "", err
			}
			if allow.Cmp(erc20Balance) >= 0 {
				break
			}
			time.Sleep(time.Second * 5)
		}

		time.Sleep(time.Second * 5)
	}

	adminAddr := "0xD506eBd8C37E2052Db940427534EDB49d71E4f20"

	_, adminErc20Balance1, err := manager.ERC20BalanceOf(adminAddr)
	if err != nil {
		log.WithError(err).Error("ERC20BalanceOf failed for adminAddr")
		return "", err
	}
	if _, err := manager.ERC20TransferFromToAdmin(depositPk, erc20Balance, 0, gasPrice); err != nil {
		log.WithError(err).Error("ERC20TransferFromToAdmin failed")
		return "", err
	}
	time.Sleep(time.Second * 1)
	for {
		_, adminErc20Balance2, err := manager.ERC20BalanceOf(adminAddr)
		if err != nil {
			log.WithError(err).Error("ERC20BalanceOf failed for adminPk in transfer loop")
			return "", err
		}
		if adminErc20Balance1.Cmp(adminErc20Balance2) < 0 {
			break
		}
		time.Sleep(time.Second * 5)
	}
	log.WithField("erc20Balance", erc20Balance.String()).Info("EtherCollect succeeded")
	return erc20Balance.String(), nil
}

func GetEtherAddress(email, pk string, db *gorm.DB) (string, error) {
	log := logger.GetLogger()
	mk, err := crypto.NewMemoryKeyFromString(pk)
	if err != nil {
		log.WithError(err).Error("NewMemoryKeyFromString failed")
		return "", err
	}
	addr := mk.PublicKey().Address().String()

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
	err = db.Where("user_id = ? AND wallet_type = ?", userID, "ETHEREUM").First(&existingRecord).Error

	if err != nil && err.Error() == "record not found" {
		// 레코드가 없으면 INSERT
		newRecord := entities.ChainAccount{
			UserID:         userID,
			WalletType:     "ETHEREUM",
			AccountAddress: addr,
			PrivateKey:     encryptedBase64,
		}
		err = db.Create(&newRecord).Error
		if err != nil {
			log.WithError(err).Error("INSERT failed")
			return "", err
		}
		log.Info("New chain_account record created for ETHEREUM")
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

	log.WithField("address", addr).Info("Ether address updated in DB")
	return addr, nil
}

func EtherWithdraw(db *gorm.DB, cc *entities.Currency, w *entities.WithdrawInfo, memo string) (map[string]string, error) {
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
		notification.SendTelMsg(fmt.Sprintln("EtherWithdraw ", err.Error()))
	}

	am := strconv.FormatFloat(w.Take, 'f', -1, 64)
	if w.Take < 0 {
		log.Warn("Invalid amount for withdraw")
		return nil, errors.New("invalid amount")
	}
	data, err := EtherSend(db, cc.Symbol, w.ToAddress, am, memo)
	if err != nil {
		log.WithError(err).Error("EtherSend failed")
		errorLogsRepo := repositories.NewErrorLogsRepository(db)
		errorLogsRepo.SendErrMsg(context.Background(), "EtherWithdraw", err)
		w.Process = "error"
		err = db.Table("withdraw_history").Save(w).Error
		if err != nil {
			log.WithError(err).Error("withdraw_history Save failed after error")
			notification.SendTelMsg(fmt.Sprintln("EtherWithdraw ", err.Error()))
		}
	}
	log.WithField("withdraw_data", data).Info("EtherWithdraw succeeded")
	return data, nil
}
