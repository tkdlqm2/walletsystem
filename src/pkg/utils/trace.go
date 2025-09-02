package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/acecasino/account_manage/internal/blockchain/ethereum"
	"github.com/acecasino/account_manage/internal/blockchain/tron"
	"github.com/acecasino/account_manage/internal/crypto"
	"github.com/acecasino/account_manage/internal/database"
	"github.com/acecasino/account_manage/internal/notification"
	"github.com/acecasino/account_manage/pkg/logger"
	"github.com/pkg/errors"
	"gorm.io/gorm"

	geth "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
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

// transferEvent represents a blockchain transfer event
type transferEvent struct {
	Token       string
	BlockNumber uint64
	EventIndex  uint
	TxHash      string
	From        string
	To          string
	Amount      *big.Int
	CreateAt    time.Time
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

	db, err := NewDB()
	if err != nil {
		fmt.Println("TraceBlockchain error", err)
		panic(err)
	}
	// defer db.Close()
	if err := doTraceBlockchain(db); err != nil {
		SendErrMsg(db, "100", err)
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

	db, err := NewDB()
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
		err := db.Raw(fmt.Sprintf("SELECT id, email, username from user where id = %v", id.UserID)).Find(&u).Error
		if err != nil {
			SendTelMsg(fmt.Sprintf("withdraw request id: %v \nemail: %v \nusername: %v \ncurrency: %v \naddr: %v\namount: %v", id.ID, u.Email, u.Username, id.CurrencyID, id.ToAddress, id.Amount))
		} else {
			SendTelMsg(fmt.Sprintf("withdraw request id: %v \ncurrency: %v \naddr: %v\namount: %v", id.ID, id.CurrencyID, id.ToAddress, id.Amount))
		}
	}

	withdraws := []*WithdrawInfo{}
	err = db.Table("withdraw_history").Where("process = ?", "request").Find(&withdraws).Error
	if err != nil {
		SendTelMsg("withdraw_history error " + err.Error())
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
			cmap[common.HexToAddress("0x0").String()] = info.currencyId
		}
	}
	countBefore, err := countDepositList(db)
	if err != nil {
		SendTelMsg("countDepositList countBefore error " + err.Error())
	}
	defer func() {
		countAfter, err := countDepositList(db)
		if err != nil {
			SendTelMsg("countDepositList countAfter error " + err.Error())
		} else if countBefore > 0 {
			if countAfter-countBefore > 0 {
				if list, err := getDepositList(db, countAfter-countBefore); err == nil {
					for _, v := range list {
						SendTelMsg(fmt.Sprintf("deposit id: %v \nemail: %v \ncurrency: %v \namount: %v", v["id"], v["email"], v["symbol"], v["amount"]))
						email := v["email"].(string)
						token := v["symbol"].(string)
						cc, err := getCurrency(db, token)
						if err != nil {
							fmt.Println("getCurrency error", err)
							SendTelMsg(fmt.Sprintf("getCurrency error %v", err))
							continue
						}
						switch cc.Blockchain.WalletType {
						case "ETHEREUM":
							go EtherCollect(db, email, token)
						case "TRON":
							go TronCollect(db, email)
						}
					}
				} else {
					SendTelMsg(fmt.Sprintf("detected deposit %d", countAfter-countBefore))
				}
			}
		}
	}()

	// 트랜잭션 추적
	switch chainName {
	case "TRON", "TRON2":
		return tronTrack(rpcURL, lastCheckedBlock, tokenAddresses, db, chainId, cmap)
	default:
		return etherTrack(rpcURL, lastCheckedBlock, tokenAddresses, db, chainId, cmap)
	}
}

func updateLastBlockNumber(db *gorm.DB, blocknumber int64, chainId int) error {
	sqlStatement := `UPDATE public.blockchain
	SET last_checked_block=$1
	WHERE id=$2`
	tx := db.Exec(sqlStatement, blocknumber, chainId)
	if tx.Error != nil {
		return errors.WithStack(tx.Error)
	}
	return nil
}

// 데이터베이스에 이벤트 배열 삽입
func insertTransferEvents(db *gorm.DB, chain_id int, cmap map[string]int, ens []*transferEvent) error {
	if len(ens) == 0 {
		return nil
	}

	length := len(ens)
	unit := 1000
	for i := 0; i < length; i += unit {
		next := i + unit
		if next > length {
			next = length
		}
		subens := ens[i:next]
		valueStrings := []string{}
		valueArgs := []interface{}{}

		count := 0
		paramIndex := func() int {
			count++
			return count
		}

		// 각 이벤트에 대한 값 문자열과 인자 생성
		for _, en := range subens {
			valueStrings = append(valueStrings, fmt.Sprintf("($%v, $%v, $%v, $%v, $%v, $%v, $%v, $%v, $%v)", paramIndex(), paramIndex(), paramIndex(), paramIndex(), paramIndex(), paramIndex(), paramIndex(), paramIndex(), paramIndex()))
			currId := cmap[strings.ToLower(en.Token)]
			valueArgs = append(valueArgs, chain_id, currId, en.BlockNumber, en.TxHash, en.EventIndex, en.From, en.To, en.Amount.String(), en.CreateAt)
		}

		// 쿼리 문자열 생성
		stmt := fmt.Sprintf(`INSERT INTO transfer_history (chain_id, currency_id, block_number, tx_hash, event_index, _from, _to, amount, create_at) 
				VALUES 
				%s 
				ON CONFLICT (currency_id, tx_hash, _from, _to, amount) DO NOTHING`,
			strings.Join(valueStrings, ","))
		// 쿼리 실행
		tx := db.Exec(stmt, valueArgs...)
		if tx.Error != nil {
			for _, valueString := range valueStrings {
				fmt.Println(valueString)
			}
			for _, valueString := range valueArgs {
				fmt.Println(valueString)
			}
			return errors.WithStack(tx.Error)
		}

		db.Exec(`delete from transfer_history
		where id < (select max(id)-1000000 from transfer_history) and 
		NOT EXISTS (
			SELECT 1 
			FROM deposit_history 
			WHERE deposit_history.tx_ref = transfer_history.id
		);`)
	}
	return nil
}

// NewDB는 데이터베이스 연결을 생성합니다
func NewDB() (*gorm.DB, error) {
	return database.NewDB()
}

// SendTelMsg는 텔레그램 메시지를 전송합니다
func SendTelMsg(msg string) {
	notification.SendTelMsg(msg)
}

// SendErrMsg는 에러 메시지를 데이터베이스에 저장합니다
func SendErrMsg(db *gorm.DB, code string, err error) {
	database.SendErrMsg(db, code, err)
}

// getCurrency는 토큰 심볼을 사용하여 통화 정보를 가져옵니다
func getCurrency(db *gorm.DB, token string) (*database.Currency, error) {
	var currency database.Currency
	err := db.Where("symbol = ?", token).First(&currency).Error
	if err != nil {
		return nil, err
	}
	return &currency, nil
}

// EtherCollect는 이더리움 입금을 수집합니다
func EtherCollect(db *gorm.DB, email string, token string) (string, error) {
	log := logger.GetLogger().WithFields(map[string]interface{}{
		"email": email,
		"token": token,
	})

	log.Info("EtherCollect started")

	// 사용자 정보 조회
	var user database.User
	err := db.Where("email = ?", email).First(&user).Error
	if err != nil {
		log.WithError(err).Error("Failed to get user")
		return "", err
	}

	// 통화 정보 조회
	cc, err := getCurrency(db, token)
	if err != nil {
		log.WithError(err).Error("Failed to get currency")
		return "", err
	}

	// 사용자 체인 계정 조회
	var chainAccount database.ChainAccount
	err = db.Where("user_id = ? AND chain_id = ?", user.ID, cc.ChainID).First(&chainAccount).Error
	if err != nil {
		log.WithError(err).Error("Failed to get chain account")
		return "", err
	}

	// 관리자 개인키 가져오기
	adminPk, err := crypto.GetAdminPrivateKey(context.Background())
	if err != nil {
		log.WithError(err).Error("Failed to get admin private key")
		return "", err
	}

	// ERC20 매니저 생성
	manager, err := ethereum.NewERC20Manager(cc, adminPk)
	if err != nil {
		log.WithError(err).Error("Failed to create ERC20Manager")
		return "", err
	}

	// 사용자 지갑 잔액 확인
	_, balanceBigInt, err := manager.ERC20BalanceOf(chainAccount.PrivateKey)
	if err != nil {
		log.WithError(err).Error("Failed to get balance")
		return "", err
	}

	if balanceBigInt.Cmp(big.NewInt(0)) <= 0 {
		log.Info("No balance to collect")
		return "no balance", nil
	}

	// 수집 실행 (사용자 지갑에서 관리자 지갑으로 전송)
	txHash, _, err := manager.AdminERC20Transfer(common.HexToAddress(chainAccount.AccountAddress), balanceBigInt.String())
	if err != nil {
		log.WithError(err).Error("Failed to collect tokens")
		return "", err
	}

	log.WithFields(map[string]interface{}{
		"txHash": txHash,
		"amount": balanceBigInt.String(),
		"from":   chainAccount.AccountAddress,
	}).Info("EtherCollect completed successfully")

	return txHash, nil
}

// TronCollect는 TRON 입금을 수집합니다
func TronCollect(db *gorm.DB, email string) (string, error) {
	log := logger.GetLogger().WithFields(map[string]interface{}{
		"email": email,
	})

	log.Info("TronCollect started")

	// 사용자 정보 조회
	var user database.User
	err := db.Where("email = ?", email).First(&user).Error
	if err != nil {
		log.WithError(err).Error("Failed to get user")
		return "", err
	}

	// TRON 체인 계정 조회
	var chainAccount database.ChainAccount
	err = db.Where("user_id = ? AND wallet_type = ?", user.ID, "TRON").First(&chainAccount).Error
	if err != nil {
		log.WithError(err).Error("Failed to get TRON chain account")
		return "", err
	}

	// 관리자 개인키 가져오기
	adminPk, err := crypto.GetAdminPrivateKey(context.Background())
	if err != nil {
		log.WithError(err).Error("Failed to get admin private key")
		return "", err
	}

	// TRC20 매니저 생성 (기본 TRON RPC URL 사용)
	tronRPC := "grpc.trongrid.io:50051"
	manager, err := tron.NewTRC20Manager(tronRPC, adminPk, "")
	if err != nil {
		log.WithError(err).Error("Failed to create TRC20Manager")
		return "", err
	}

	// 사용자 지갑 잔액 확인
	balance := manager.TRC20Balance(chainAccount.AccountAddress)

	if balance.Cmp(big.NewInt(0)) <= 0 {
		log.Info("No TRC20 balance to collect")
		return "no balance", nil
	}

	// 수집 실행 (사용자 지갑에서 관리자 지갑으로 전송)
	// TODO: adminAddr 필드에 대한 적절한 접근 방법 필요
	txHash, err := manager.Send(chainAccount.AccountAddress, "", chainAccount.PrivateKey, balance)
	if err != nil {
		log.WithError(err).Error("Failed to collect TRC20 tokens")
		return "", err
	}

	log.WithFields(map[string]interface{}{
		"txHash": txHash,
		"amount": balance.String(),
		"from":   chainAccount.AccountAddress,
	}).Info("TronCollect completed successfully")

	return txHash, nil
}

// processWithdraw는 출금 요청을 처리합니다
func processWithdraw(db *gorm.DB, withdraw *WithdrawInfo, processType string) error {
	log := logger.GetLogger().WithFields(map[string]interface{}{
		"withdraw_id": withdraw.ID,
		"user_id":     withdraw.UserID,
		"amount":      withdraw.Amount,
		"process":     processType,
	})

	// 출금 상태를 업데이트
	sqlStatement := `UPDATE withdraw_history SET process = $1, updated_at = NOW() WHERE id = $2`
	tx := db.Exec(sqlStatement, processType, withdraw.ID)
	if tx.Error != nil {
		log.WithError(tx.Error).Error("Failed to update withdraw status")
		return tx.Error
	}

	log.Info("Withdraw processed successfully")
	return nil
}

// tronTrack는 TRON 체인의 트랜잭션을 추적합니다
func tronTrack(rpcURL string, lastCheckedBlock *big.Int, tokenAddresses []string, db *gorm.DB, chainId int, cmap map[string]int) error {
	log := logger.GetLogger().WithFields(map[string]interface{}{
		"rpcURL":           rpcURL,
		"lastCheckedBlock": lastCheckedBlock,
		"chainId":          chainId,
	})

	log.Info("TRON chain tracking started")

	// TRON 체인 추적 로직 구현
	// 블록 스캔
	currentBlock, err := getCurrentTronBlock(rpcURL)
	if err != nil {
		log.WithError(err).Error("Failed to get current TRON block")
		return err
	}

	// 마지막 체크된 블록부터 현재 블록까지 스캔
	fromBlock := lastCheckedBlock.Uint64()
	toBlock := currentBlock.Uint64()

	if fromBlock >= toBlock {
		log.Info("No new blocks to scan")
		return nil
	}

	// 블록 범위를 적절한 크기로 나누어 스캔
	blockStep := uint64(1000)
	for block := fromBlock; block <= toBlock; block += blockStep {
		endBlock := block + blockStep - 1
		if endBlock > toBlock {
			endBlock = toBlock
		}

		// 블록 범위 스캔
		events, err := scanTronBlockRange(rpcURL, block, endBlock, tokenAddresses)
		if err != nil {
			log.WithError(err).WithField("blockRange", fmt.Sprintf("%d-%d", block, endBlock)).Error("Failed to scan block range")
			continue
		}

		// 이벤트 처리
		if len(events) > 0 {
			err = insertTransferEvents(db, chainId, cmap, events)
			if err != nil {
				log.WithError(err).Error("Failed to insert transfer events")
				continue
			}
		}

		// 마지막 체크된 블록 업데이트
		err = updateLastBlockNumber(db, int64(endBlock), chainId)
		if err != nil {
			log.WithError(err).Error("Failed to update last block number")
		}
	}

	log.Info("TRON chain tracking completed")
	return nil
}

// etherTrack는 이더리움 체인의 트랜잭션을 추적합니다
func etherTrack(rpcURL string, lastCheckedBlock *big.Int, tokenAddresses []string, db *gorm.DB, chainId int, cmap map[string]int) error {
	log := logger.GetLogger().WithFields(map[string]interface{}{
		"rpcURL":           rpcURL,
		"lastCheckedBlock": lastCheckedBlock,
		"chainId":          chainId,
	})

	log.Info("Ethereum chain tracking started")

	// 이더리움 체인 추적 로직 구현
	// 블록 스캔
	currentBlock, err := getCurrentEthereumBlock(rpcURL)
	if err != nil {
		log.WithError(err).Error("Failed to get current Ethereum block")
		return err
	}

	// 마지막 체크된 블록부터 현재 블록까지 스캔
	fromBlock := lastCheckedBlock.Uint64()
	toBlock := currentBlock.Uint64()

	if fromBlock >= toBlock {
		log.Info("No new blocks to scan")
		return nil
	}

	// 블록 범위를 적절한 크기로 나누어 스캔
	blockStep := uint64(1000)
	for block := fromBlock; block <= toBlock; block += blockStep {
		endBlock := block + blockStep - 1
		if endBlock > toBlock {
			endBlock = toBlock
		}

		// 블록 범위 스캔
		events, err := scanEthereumBlockRange(rpcURL, block, endBlock, tokenAddresses)
		if err != nil {
			log.WithError(err).WithField("blockRange", fmt.Sprintf("%d-%d", block, endBlock)).Error("Failed to scan block range")
			continue
		}

		// 이벤트 처리
		if len(events) > 0 {
			err = insertTransferEvents(db, chainId, cmap, events)
			if err != nil {
				log.WithError(err).Error("Failed to insert transfer events")
				continue
			}
		}

		// 마지막 체크된 블록 업데이트
		err = updateLastBlockNumber(db, int64(endBlock), chainId)
		if err != nil {
			log.WithError(err).Error("Failed to update last block number")
		}
	}

	log.Info("Ethereum chain tracking completed")
	return nil
}

// getCurrentTronBlock는 현재 TRON 블록 번호를 가져옵니다
func getCurrentTronBlock(rpcURL string) (*big.Int, error) {
	// TRON API를 통해 현재 블록 번호 조회
	url := fmt.Sprintf("%s/v1/blocks/latest", rpcURL)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		BlockHeader struct {
			RawData struct {
				Number int64 `json:"number"`
			} `json:"raw_data"`
		} `json:"block_header"`
	}

	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return nil, err
	}

	return big.NewInt(result.BlockHeader.RawData.Number), nil
}

// getCurrentEthereumBlock는 현재 이더리움 블록 번호를 가져옵니다
func getCurrentEthereumBlock(rpcURL string) (*big.Int, error) {
	// 이더리움 RPC를 통해 현재 블록 번호 조회
	client, err := ethclient.Dial(rpcURL)
	if err != nil {
		return nil, err
	}

	blockNumber, err := client.BlockNumber(context.Background())
	if err != nil {
		return nil, err
	}

	return big.NewInt(int64(blockNumber)), nil
}

// scanTronBlockRange는 TRON 블록 범위를 스캔합니다
func scanTronBlockRange(rpcURL string, fromBlock, toBlock uint64, tokenAddresses []string) ([]*transferEvent, error) {
	var events []*transferEvent

	for _, tokenAddress := range tokenAddresses {
		// TRON API를 통해 Transfer 이벤트 조회
		url := fmt.Sprintf("%s/v1/contracts/%s/events?event_name=Transfer&min_block_timestamp=%d&max_block_timestamp=%d",
			rpcURL, tokenAddress, fromBlock, toBlock)

		resp, err := http.Get(url)
		if err != nil {
			continue
		}

		var result struct {
			Data []struct {
				BlockNumber   int64  `json:"block_number"`
				EventIndex    int    `json:"event_index"`
				TransactionID string `json:"transaction_id"`
				Result        struct {
					From  string `json:"from"`
					To    string `json:"to"`
					Value string `json:"value"`
				} `json:"result"`
			} `json:"data"`
		}

		err = json.NewDecoder(resp.Body).Decode(&result)
		resp.Body.Close()
		if err != nil {
			continue
		}

		// 이벤트 변환
		for _, data := range result.Data {
			amount := new(big.Int)
			amount.SetString(data.Result.Value, 10)

			event := &transferEvent{
				Token:       tokenAddress,
				BlockNumber: uint64(data.BlockNumber),
				EventIndex:  uint(data.EventIndex),
				TxHash:      data.TransactionID,
				From:        data.Result.From,
				To:          data.Result.To,
				Amount:      amount,
				CreateAt:    time.Now(),
			}
			events = append(events, event)
		}
	}

	return events, nil
}

// scanEthereumBlockRange는 이더리움 블록 범위를 스캔합니다
func scanEthereumBlockRange(rpcURL string, fromBlock, toBlock uint64, tokenAddresses []string) ([]*transferEvent, error) {
	var events []*transferEvent

	client, err := ethclient.Dial(rpcURL)
	if err != nil {
		return nil, err
	}

	for _, tokenAddress := range tokenAddresses {
		// ERC20 Transfer 이벤트 시그니처
		transferEventSignature := []byte("Transfer(address,address,uint256)")
		transferEventID := ethcrypto.Keccak256(transferEventSignature)[:4]

		// 이벤트 필터 생성
		query := geth.FilterQuery{
			FromBlock: big.NewInt(int64(fromBlock)),
			ToBlock:   big.NewInt(int64(toBlock)),
			Addresses: []common.Address{common.HexToAddress(tokenAddress)},
			Topics:    [][]common.Hash{{common.BytesToHash(transferEventID)}},
		}

		// 로그 조회
		logs, err := client.FilterLogs(context.Background(), query)
		if err != nil {
			continue
		}

		// 로그를 이벤트로 변환
		for _, log := range logs {
			if len(log.Topics) >= 3 {
				from := common.BytesToAddress(log.Topics[1].Bytes())
				to := common.BytesToAddress(log.Topics[2].Bytes())
				amount := new(big.Int).SetBytes(log.Data)

				event := &transferEvent{
					Token:       tokenAddress,
					BlockNumber: log.BlockNumber,
					EventIndex:  uint(log.Index),
					TxHash:      log.TxHash.Hex(),
					From:        from.Hex(),
					To:          to.Hex(),
					Amount:      amount,
					CreateAt:    time.Now(),
				}
				events = append(events, event)
			}
		}
	}

	return events, nil
}
