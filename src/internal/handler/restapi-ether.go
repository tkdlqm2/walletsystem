package handler

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/acecasino/account_manage/internal/blockchain/ethereum"
	"github.com/acecasino/account_manage/internal/cloud"
	"github.com/acecasino/account_manage/internal/crypto"
	"github.com/acecasino/account_manage/internal/database"
	"github.com/acecasino/account_manage/internal/notification"
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
		pk, err := crypto.GetPrivateKey(key)
		if err != nil {
			log.WithError(err).Error("Failed to get private key using email")
			return err
		}
		addr, err := getEtherAddress(key, pk, db)
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

	cc, err := database.GetCurrency(db, token)
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
	log.Info("memo", memo)

	return map[string]string{
		"to":     toAddr,
		"amount": amt.String(),
		"hash":   txhash,
	}, nil
}

func EtherBalance(db *gorm.DB, email string, token string) (string, error) {
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
	fmt.Println("adminPk:", adminPk)
	if err != nil {
		log.WithError(err).Error("Failed to get admin private key")
		return "", err
	}

	manager, err := ethereum.NewERC20Manager(cc, adminPk)
	if err != nil {
		log.WithError(err).Error("Failed to create ERC20Manager")
		return "", err
	}

	depositPk, err := crypto.GetPrivateKey(email)
	if err != nil {
		log.WithError(err).Error("Failed to get deposit private key")
		return "", err
	}

	trxbi, _, err := manager.ERC20BalanceOf(depositPk)
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
	cc, err := database.GetCurrency(db, token)
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

	depositPk, err := crypto.GetPrivateKey(email)
	if err != nil {
		log.WithError(err).Error("Failed to get deposit private key")
		return "", err
	}

	allowance, err := manager.ERC20Allowance(depositPk)
	if err != nil {
		log.WithError(err).Error("ERC20Allowance failed")
		return "", err
	}
	etherBal, err := manager.EtherBalanceOf(depositPk)
	if err != nil {
		log.WithError(err).Error("EtherBalanceOf failed")
		return "", err
	}
	_, erc20Balance, err := manager.ERC20BalanceOf(depositPk)
	if err != nil {
		log.WithError(err).Error("ERC20BalanceOf failed")
		return "", err
	}

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
				etherBal2, err := manager.EtherBalanceOf(depositPk)
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
		allowFlag, _ := big.NewInt(0).SetString("1000000000"+strings.Repeat("0", manager.Decimal()), 10)
		_, err = manager.ERC20Approve(depositPk, allowFlag, gas, gasPrice)
		if err != nil {
			log.WithError(err).Error("ERC20Approve failed")
			return "", err
		}
		time.Sleep(time.Second * 1)
		for {
			allow, err := manager.ERC20Allowance(depositPk)
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

	_, adminErc20Balance1, err := manager.ERC20BalanceOf(adminPk)
	if err != nil {
		log.WithError(err).Error("ERC20BalanceOf failed for adminPk")
		return "", err
	}
	if _, err := manager.ERC20TransferFromToAdmin(depositPk, erc20Balance, 0, gasPrice); err != nil {
		log.WithError(err).Error("ERC20TransferFromToAdmin failed")
		return "", err
	}
	time.Sleep(time.Second * 1)
	for {
		_, adminErc20Balance2, err := manager.ERC20BalanceOf(adminPk)
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

func getEtherAddress(email, pk string, db *gorm.DB) (string, error) {
	log := logger.GetLogger().WithFields(map[string]interface{}{
		"email": email,
	})
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
	userID, err := database.GetUserIDByEmail(db, email)
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
	var existingRecord database.ChainAccount
	err = db.Where("user_id = ? AND wallet_type = ?", userID, "ETHEREUM").First(&existingRecord).Error

	if err != nil && err.Error() == "record not found" {
		// 레코드가 없으면 INSERT
		newRecord := database.ChainAccount{
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
		log.Info("Existing chain_account record updated for ETHEREUM")
	}

	log.WithField("address", addr).Info("Ether address updated in DB")
	return addr, nil
}

func EtherWithdraw(db *gorm.DB, cc *database.Currency, w *database.WithdrawInfo, memo string) (map[string]string, error) {
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
		database.SendErrMsg(db, "EtherWithdraw", err)
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

func GetAdminPrivateKey(ctx context.Context) (string, error) {
	log := logger.GetLogger().WithField("func", "GetAdminPrivateKey")
	service, err := cloud.GetWalletDecryptService(ctx)
	if err != nil {
		log.WithError(err).Error("GetWalletDecryptService failed")
		return "", err
	}
	secretID := os.Getenv("SECRETID")
	keyAlias := os.Getenv("KEYALIAS")
	_, adminPk, err := service.GetAndDecryptWalletSecret(ctx, secretID, keyAlias)
	if err != nil {
		log.WithError(err).Error("GetAndDecryptWalletSecret failed")
		return "", err
	}
	log.Info("Admin private key decrypted")
	return adminPk, nil
}
