package utils

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"sync"

	"github.com/acecasino/account_manage/internal/blockchain/ethereum"
	"github.com/acecasino/account_manage/internal/blockchain/tron"
	"github.com/acecasino/account_manage/internal/config"
	"github.com/acecasino/account_manage/internal/container"
	"github.com/acecasino/account_manage/internal/handler"
	"github.com/acecasino/account_manage/internal/infrastructure/database/repositories"
	"github.com/acecasino/account_manage/internal/notification"
	"github.com/acecasino/account_manage/pkg/logger"
	"github.com/pkg/errors"
	"gorm.io/gorm"

	"github.com/ethereum/go-ethereum/common"
)

// WithdrawInfo represents withdrawal information
type WithdrawInfo struct {
	ID         int
	UserID     int
	CurrencyID int
	ToAddress  string
	Amount     string
	Process    string
}

// User represents user information
type User struct {
	ID       int
	Email    string
	Username string
}

type currencyInfo struct {
	chainId          int
	currencyId       int
	name             string
	symbol           string
	address          string
	lastCheckedBlock *big.Int
}

var runOneTime = false

func TraceBlockchain() {
	if runOneTime {
		return
	}
	runOneTime = true

	cfg := config.LoadConfig()
	db, err := config.NewDatabase(cfg.Database)
	if err != nil {
		fmt.Println("TraceBlockchain error", err)
		panic(err)
	}
	// defer db.Close()
	if err := doTraceBlockchain(db); err != nil {
		errorLogsRepo := repositories.NewErrorLogsRepository(db)
		errorLogsRepo.SendErrMsg(context.Background(), "100", err)
	}
	runOneTime = false
}

// TraceBlockchainWithContainer uses dependency injection
func TraceBlockchainWithContainer(container *container.Container) {
	if runOneTime {
		return
	}
	runOneTime = true

	if err := doTraceBlockchain(container.DB); err != nil {
		container.ErrorLogsRepo.SendErrMsg(context.Background(), "100", err)
	}
	runOneTime = false
}

func doTraceBlockchain(db *gorm.DB) error {

	// SQL UPDATE 문 실행
	sqlStatement := `SELECT c.chain_id, c.id as currency_id, b."name", b.rpc_url, b.last_checked_block, c.symbol, c.address
		FROM blockchain b
		left join currency c on b.id = c.chain_id
		WHERE b.active_watch = true and c.active_watch = true`

	tx := db.Raw(sqlStatement)
	err := tx.Error
	// 결과 출력
	if err != nil {
		return errors.WithStack(err)
	}
	res, err := tx.Rows()
	if err != nil {
		return errors.WithStack(err)
	}

	currencyMap := map[string][]*currencyInfo{}
	for res.Next() {
		var chainId int
		var currencyId int
		var name string
		var rpcURL string
		var symbol string
		var address string
		var lastCheckedBlock int64
		err = res.Scan(&chainId, &currencyId, &name, &rpcURL, &lastCheckedBlock, &symbol, &address)
		if err != nil {
			return errors.WithStack(err)
		}
		if currencyMap[rpcURL] == nil {
			currencyMap[rpcURL] = []*currencyInfo{}
		}
		currencyMap[rpcURL] = append(currencyMap[rpcURL], &currencyInfo{
			chainId:          chainId,
			currencyId:       currencyId,
			name:             name,
			symbol:           symbol,
			address:          address,
			lastCheckedBlock: big.NewInt(lastCheckedBlock),
		})
	}

	for rpcURL, curr := range currencyMap {
		go func(rpcURL string, curr []*currencyInfo) {
			err := trace(db, rpcURL, curr)
			if err != nil {
				chainId := 0
				if len(curr) > 0 {
					chainId = curr[0].chainId
				}
				fmt.Println("trace", chainId, "err", err)
			}
		}(rpcURL, curr)
	}
	return nil
}

func countDepositList(db *gorm.DB) (count int, err error) {
	// SQL UPDATE 문 실행
	sqlStatement := `SELECT count(*) as dcount FROM deposit_history d`
	err = db.Raw(sqlStatement).Find(&count).Error
	return
}

func getDepositList(db *gorm.DB, limit int) ([]map[string]interface{}, error) {
	// SQL UPDATE 문 실행
	list := []map[string]interface{}{}
	sqlStatement := `select dh.id, u.email , c.symbol , th.amount / 10 ^ c."decimal"  as amount
	from deposit_history dh 
	left join transfer_history th on dh.tx_ref  = th.id
	left join currency c on th.currency_id = c.id
	left join chain_accounts ca on dh.account_id  = ca.id 
	left join users u on ca.user_id = u.id
	order by dh.id desc
	limit $1`
	err := db.Raw(sqlStatement, limit).Scan(&list).Error
	if err != nil {
		return nil, err
	}
	return list, nil
}

var lastWithdraw *WithdrawInfo

func InitData(db *gorm.DB) {
	ls, err := getLastWithdraw(db, -1)
	if err != nil {
		fmt.Println("InitData error", err)
		panic(err)
	}
	if len(ls) == 0 {
		lastWithdraw = &WithdrawInfo{ID: 0}
	} else {
		lastWithdraw = ls[0]
	}
}

var runOneTime2 = false

func CheckLastWithdraw() {
	if runOneTime2 {
		return
	}
	runOneTime2 = true

	cfg := config.LoadConfig()
	db, err := config.NewDatabase(cfg.Database)
	if err != nil {
		fmt.Println("CheckLastWithdraw new db error", err)
		panic(err)
	}

	is, err := getLastWithdraw(db, lastWithdraw.ID)
	if err != nil {
		fmt.Println("CheckLastWithdraw getLastWithdraw error", err)
		panic(err)
	}
	for _, id := range is {
		u := &User{}
		err := db.Raw(fmt.Sprintf("SELECT id, email, username from users where id = %v", id.UserID)).Find(&u).Error
		if err != nil {
			notification.SendTelMsg(fmt.Sprintf("withdraw request id: %v \nemail: %v \nusername: %v \ncurrency: %v \naddr: %v\namount: %v", id.ID, u.Email, u.Username, id.CurrencyID, id.ToAddress, id.Amount))
		} else {
			notification.SendTelMsg(fmt.Sprintf("withdraw request id: %v \ncurrency: %v \naddr: %v\namount: %v", id.ID, id.CurrencyID, id.ToAddress, id.Amount))
		}
	}

	withdraws := []*WithdrawInfo{}
	err = db.Table("withdraw_history").Where("process = ?", "request").Find(&withdraws).Error
	if err != nil {
		notification.SendTelMsg("withdraw_history error " + err.Error())
	} else {
		for _, w := range withdraws {
			processWithdraw(db, w, "auto")
		}
	}

	if len(is) > 0 {
		lastWithdraw = is[0]
	}
	runOneTime2 = false
}

// CheckLastWithdrawWithContainer uses dependency injection
func CheckLastWithdrawWithContainer(container *container.Container) {
	if runOneTime2 {
		return
	}
	runOneTime2 = true

	withdraws, err := getLastWithdraw(container.DB, lastWithdraw.ID)
	if err != nil {
		fmt.Println("CheckLastWithdraw getLastWithdraw error", err)
		panic(err)
	}
	for _, withdraw := range withdraws {
		u := &User{}
		err := container.DB.Table("users").Where("id = ?", withdraw.UserID).First(u).Error
		if err != nil {
			fmt.Println("CheckLastWithdraw get user error", err)
			continue
		}
		notification.SendTelMsg(fmt.Sprintf("withdraw id: %v \nemail: %v \nprocess: %v", withdraw.ID, u.Email, withdraw.Process))
	}
	runOneTime2 = false
}

var runOnce = map[string]bool{}
var waitLock sync.Mutex

func trace(db *gorm.DB, rpcURL string, currInfo []*currencyInfo) error {
	waitLock.Lock()
	if runOnce[rpcURL] {
		waitLock.Unlock()
		return nil
	}
	runOnce[rpcURL] = true
	waitLock.Unlock()
	defer func() {
		waitLock.Lock()
		runOnce[rpcURL] = false
		waitLock.Unlock()
	}()

	tokenAddresses := []string{}
	var lastCheckedBlock *big.Int
	var chainId int
	var chainName string
	cmap := map[string]int{}
	for _, info := range currInfo {
		lastCheckedBlock = info.lastCheckedBlock
		chainId = info.chainId
		chainName = info.name
		if info.address != "" {
			cmap[strings.ToLower(info.address)] = info.currencyId
			tokenAddresses = append(tokenAddresses, info.address)
		} else {
			// 주소가 없는 경우 (네이티브 토큰) 0x0 주소 사용
			cmap[common.HexToAddress("0x0").String()] = info.currencyId
			tokenAddresses = append(tokenAddresses, common.HexToAddress("0x0").String())
		}
	}
	countBefore, err := countDepositList(db)
	if err != nil {
		notification.SendTelMsg("countDepositList countBefore error " + err.Error())
	}
	defer func() {
		countAfter, err := countDepositList(db)
		if err != nil {
			notification.SendTelMsg("countDepositList countAfter error " + err.Error())
		} else if countBefore > 0 {
			if countAfter-countBefore > 0 {
				if list, err := getDepositList(db, countAfter-countBefore); err == nil {
					for _, v := range list {
						notification.SendTelMsg(fmt.Sprintf("deposit id: %v \nemail: %v \ncurrency: %v \namount: %v", v["id"], v["email"], v["symbol"], v["amount"]))
						email := v["email"].(string)
						token := v["symbol"].(string)
						currencyRepo := repositories.NewCurrencyRepository(db)
						cc, err := currencyRepo.GetCurrency(context.Background(), token)
						if err != nil {
							notification.SendTelMsg(fmt.Sprintf("getCurrency error %v", err))
							continue
						}
						switch cc.Blockchain.WalletType {
						case "ETHEREUM":
							go handler.EtherCollect(db, email, token)
						case "TRON":
							go handler.TronCollect(db, email)
						}
					}
				} else {
					notification.SendTelMsg(fmt.Sprintf("detected deposit %d", countAfter-countBefore))
				}
			}
		}
	}()

	// 트랜잭션 추적
	switch chainName {
	case "TRON", "TRON2":
		return tron.TronTrack(rpcURL, lastCheckedBlock, tokenAddresses, db, chainId, cmap)
	default:
		return ethereum.EtherTrack(rpcURL, lastCheckedBlock, tokenAddresses, db, chainId, cmap)
	}
}

/*

DB에서 출금처리를 위한 trace function

*/

// processWithdraw는 출금 요청을 처리합니다
func processWithdraw(db *gorm.DB, withdraw *WithdrawInfo, processType string) error {
	log := logger.GetLogger().WithFields(map[string]interface{}{
		"withdraw_id": withdraw.ID,
		"user_id":     withdraw.UserID,
		"amount":      withdraw.Amount,
		"process":     processType,
	})

	// 출금 상태를 업데이트
	sqlStatement := `UPDATE withdraw_history SET process = $1 WHERE id = $2`
	tx := db.Exec(sqlStatement, processType, withdraw.ID)
	if tx.Error != nil {
		log.WithError(tx.Error).Error("Failed to update withdraw status")
		return tx.Error
	}

	log.Info("Withdraw processed successfully")
	return nil
}

func getLastWithdraw(db *gorm.DB, lastID int) ([]*WithdrawInfo, error) {
	// SQL UPDATE 문 실행
	limit := ""
	where := ""
	if lastID == -1 {
		limit = "limit 1"
	} else {
		where = "where d.id > " + fmt.Sprintf("%d", lastID)
	}
	sqlStatement := `SELECT d.id, d.user_id, d.currency_id, d.to_address, d.amount FROM withdraw_history d ` + where + ` order by d.id desc ` + limit
	withdraws := []*WithdrawInfo{}
	err := db.Raw(sqlStatement).Find(&withdraws).Error
	if err != nil {
		return nil, err
	}
	return withdraws, nil
}
