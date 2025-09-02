package tron

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"errors"

	"github.com/acecasino/account_manage/pkg/logger"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/fbsobreira/gotron-sdk/pkg/address"
	"github.com/mr-tron/base58"
	"gorm.io/gorm"
)

// transferEvent는 TRON 전송 이벤트를 나타냅니다
type transferEvent struct {
	Token       string   `json:"token"`
	BlockNumber uint64   `json:"block_number"`
	EventIndex  int      `json:"event_index"`
	TxHash      string   `json:"tx_hash"`
	From        string   `json:"from"`
	To          string   `json:"to"`
	Amount      *big.Int `json:"amount"`
	CreateAt    int64    `json:"create_at"`
}

func TronMakeAddress(pk string) (string, error) {
	log := logger.GetLogger()
	privateKey, err := crypto.HexToECDSA(pk)
	if err != nil {
		log.WithError(err).Error("Error converting private key")
		return "", err
	}

	publicKey := privateKey.PublicKey
	trxAddress := address.PubkeyToAddress(publicKey)
	if err != nil {
		log.WithError(err).Error("Error generating TRON address")
		return "", err
	}

	log.WithField("address", trxAddress.String()).Info("TRON address generated")
	return trxAddress.String(), nil
}

type ApiData struct {
	Data []struct {
		BlockNumber           int64  `json:"block_number"`
		BlockTimestamp        int64  `json:"block_timestamp"`
		CallerContractAddress string `json:"caller_contract_address"`
		ContractAddress       string `json:"contract_address"`
		EventIndex            int    `json:"event_index"`
		EventName             string `json:"event_name"`
		Result                struct {
			From  string `json:"from"`
			To    string `json:"to"`
			Value string `json:"value"`
		} `json:"result"`
		ResultType struct {
			From  string `json:"from"`
			To    string `json:"to"`
			Value string `json:"value"`
		} `json:"result_type"`
		Event         string `json:"event"`
		TransactionID string `json:"transaction_id"`
	} `json:"data"`
	Meta struct {
		At          int64  `json:"at"`
		Fingerprint string `json:"fingerprint"`
		Links       struct {
			Next string `json:"next"`
		} `json:"links"`
		PageSize int `json:"page_size"`
	} `json:"meta"`
}

func lastEvent(tronGridAPI, usdtContractAddress string) (*transferEvent, error) {
	log := logger.GetLogger().WithFields(map[string]interface{}{
		"tronGridAPI":         tronGridAPI,
		"usdtContractAddress": usdtContractAddress,
	})
	url := fmt.Sprintf("%s/v1/contracts/%s/events?event_name=Transfer&limit=1", tronGridAPI, usdtContractAddress)
	apiData, err := getTronEventData(url)
	if err != nil {
		log.WithError(err).Error("getTronEventData failed")
		return nil, err
	}
	tes, err := extractTrasferEvent(apiData)
	if err != nil {
		log.WithError(err).Error("extractTrasferEvent failed")
		return nil, err
	}
	if len(tes) == 0 {
		log.Warn("no events found")
		return nil, errors.New("no events found")
	}
	log.Info("lastEvent succeeded")
	return tes[0], nil
}

func traceTronTransactionsByTimestamp(tronGridAPI, usdtContractAddress string, blockNumber, toBlockNumber uint64, ch chan []*transferEvent) error {
	log := logger.GetLogger().WithFields(map[string]interface{}{
		"tronGridAPI":         tronGridAPI,
		"usdtContractAddress": usdtContractAddress,
		"blockNumber":         blockNumber,
		"toBlockNumber":       toBlockNumber,
	})
	defer close(ch)

	var ad *ApiData
	var err error
	for blockNumber < toBlockNumber {
		firstUrl := fmt.Sprintf("%s/v1/contracts/%s/events?only_confirmed=true&event_name=Transfer&limit=1&block_number=%d", tronGridAPI, usdtContractAddress, blockNumber)
		ad, err = getTronEventData(firstUrl)
		if err != nil {
			log.WithError(err).Error("getTronEventData failed in traceTronTransactionsByTimestamp")
			return err
		}
		if len(ad.Data) == 0 {
			blockNumber++
			continue
		}
		break
	}
	if ad == nil || len(ad.Data) == 0 {
		log.Warn("no event data found")
		return nil
	}

	startTimestamp := ad.Data[0].BlockTimestamp
	order := "block_timestamp%2Casc"
	url := fmt.Sprintf("%s/v1/contracts/%s/events?only_confirmed=true&event_name=Transfer&min_block_timestamp=%d&order_by=%s&limit=200", tronGridAPI, usdtContractAddress, startTimestamp, order)
	for url != "" {
		ad, err = getTronEventData(url)
		if err != nil {
			log.WithError(err).Error("getTronEventData failed in event loop")
			return err
		}
		if len(ad.Data) == 0 {
			log.Warn("no event data found in event loop")
			return nil
		}
		_tes, err := extractTrasferEvent(ad)
		if err != nil {
			log.WithError(err).Error("extractTrasferEvent failed in event loop")
			return err
		}
		ch <- _tes
		for _, te := range _tes {
			if te.BlockNumber > toBlockNumber {
				return nil
			}
		}
		url = ad.Meta.Links.Next
		time.Sleep(10 * time.Millisecond)
	}
	log.Info("traceTronTransactionsByTimestamp succeeded")
	return nil
}

func traceTronTransactions(tronGridAPI, usdtContractAddress string, blockNumber, toBlockNumber uint64) ([]*transferEvent, error) {
	log := logger.GetLogger().WithFields(map[string]interface{}{
		"tronGridAPI":         tronGridAPI,
		"usdtContractAddress": usdtContractAddress,
		"blockNumber":         blockNumber,
		"toBlockNumber":       toBlockNumber,
	})
	if blockNumber == 0 {
		blockNumber = toBlockNumber - 1
	}
	limit := 200
	tes := []*transferEvent{}
	for toBlockNumber > blockNumber {
		order := "block_timestamp%2Casc"
		url := fmt.Sprintf("%s/v1/contracts/%s/events?only_confirmed=true&event_name=Transfer&order_by=%s&limit=%d&block_number=%d", tronGridAPI, usdtContractAddress, order, limit, blockNumber)
		apiData, err := getTronEventData(url)
		if err != nil {
			log.WithError(err).Error("getTronEventData failed in traceTronTransactions")
			return nil, err
		}
		_tes, err := extractTrasferEvent(apiData)
		if err != nil {
			log.WithError(err).Error("extractTrasferEvent failed in traceTronTransactions")
			return nil, err
		}
		if len(_tes) == 0 {
			log.Warn("no transfer events found")
			blockNumber++
			continue
		}
		blockNumber = _tes[len(_tes)-1].BlockNumber + 1
		if len(_tes) > 0 {
			tes = append(tes, _tes...)
		}
	}
	log.WithField("eventCount", len(tes)).Info("traceTronTransactions succeeded")
	return tes, nil
}

func getTronEventData(url string) (ad *ApiData, err error) {
	log := logger.GetLogger().WithField("url", url)
	ad, err = _getTronEventData(url)
	if err != nil {
		log.WithError(err).Error("_getTronEventData failed (1st try)")
		return
	}
	if len(ad.Data) > 0 {
		return
	}
	time.Sleep(500 * time.Millisecond)
	ad, err = _getTronEventData(url)
	if len(ad.Data) > 0 {
		return
	}
	time.Sleep(500 * time.Millisecond)
	ad, err = _getTronEventData(url)
	if err != nil {
		log.WithError(err).Error("_getTronEventData failed (3rd try)")
	}
	return
}

func _getTronEventData(url string) (*ApiData, error) {
	log := logger.GetLogger().WithField("url", url)
	resp, err := http.Get(url)
	if err != nil {
		log.WithError(err).Error("Failed to fetch transactions")
		return nil, err
	}
	defer resp.Body.Close()

	jsonData, err := io.ReadAll(resp.Body)
	if err != nil {
		log.WithError(err).Error("Failed to read response body")
		return nil, err
	}

	apiData := &ApiData{}
	err = json.Unmarshal(jsonData, &apiData)
	if err != nil {
		log.WithError(err).Error("Failed to unmarshal JSON")
		panic(err)
	}

	log.Info("_getTronEventData succeeded")
	return apiData, nil
}

func extractTrasferEvent(apiData *ApiData) ([]*transferEvent, error) {
	log := logger.GetLogger()
	tes := []*transferEvent{}
	for _, tx := range apiData.Data {
		val, ok := big.NewInt(0).SetString(tx.Result.Value, 10)
		if !ok {
			log.WithField("value", tx.Result.Value).Error("failed to convert value to big.Int")
			return nil, fmt.Errorf("failed to convert value to big.Int")
		}
		te := &transferEvent{
			BlockNumber: uint64(tx.BlockNumber),
			TxHash:      tx.TransactionID,
			EventIndex:  tx.EventIndex,
			Token:       convertEthereumAddressToTron(tx.ContractAddress),
			From:        convertEthereumAddressToTron(tx.Result.From),
			To:          convertEthereumAddressToTron(tx.Result.To),
			Amount:      val,
			CreateAt:    time.Unix(tx.BlockTimestamp/1000, 0).Unix(),
		}
		tes = append(tes, te)
	}
	log.WithField("eventCount", len(tes)).Info("extractTrasferEvent succeeded")
	return tes, nil
}

func convertEthereumAddressToTron(ethAddress string) string {
	log := logger.GetLogger().WithField("ethAddress", ethAddress)
	if len(ethAddress) >= 42 {
		ethAddress = "41" + ethAddress[2:]
		addb, _ := hex.DecodeString(ethAddress)
		hash1 := s256(s256(addb))
		secret := hash1[:4]
		for _, v := range secret {
			addb = append(addb, v)
		}
		tronAddress := base58.Encode(addb)
		log.WithField("tronAddress", tronAddress).Info("Converted Ethereum address to Tron")
		return tronAddress
	}
	return ethAddress
}

func s256(s []byte) []byte {
	h := sha256.New()
	h.Write(s)
	bs := h.Sum(nil)
	return bs
}

func min(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

func tronTrack(rpcURL string, lastCheckedBlock *big.Int, tokenAddresses []string, db *gorm.DB, chainId int, cmap map[string]int) error {
	log := logger.GetLogger().WithFields(map[string]interface{}{
		"rpcURL":           rpcURL,
		"chainId":          chainId,
		"lastCheckedBlock": lastCheckedBlock,
		"tokenAddresses":   tokenAddresses,
	})
	t := time.Now()
	log.Info("tronTrack start")
	defer func() {
		log.WithField("duration", time.Since(t).String()).Info("tronTrack end")
	}()

	saveEvent := func(addr string, fromBlockNumber, toBlockNumber uint64) (uint64, error) {
		log := logger.GetLogger().WithFields(map[string]interface{}{
			"addr":            addr,
			"fromBlockNumber": fromBlockNumber,
			"toBlockNumber":   toBlockNumber,
		})
		t := time.Now()
		log.Info("saveEvent start")
		defer func() {
			log.WithField("duration", time.Since(t).String()).Info("saveEvent end")
		}()
		chte := make(chan []*transferEvent, 1)
		go func() {
			t := time.Now()
			log.Info("traceTronTransactionsByTimestamp start")
			defer func() {
				log.WithField("duration", time.Since(t).String()).Info("traceTronTransactionsByTimestamp end")
			}()
			err := traceTronTransactionsByTimestamp(rpcURL, addr, fromBlockNumber, toBlockNumber, chte)
			if err != nil {
				log.WithError(err).Error("traceTronTransactionsByTimestamp failed")
			}
		}()
		var err error
		for tes := range chte {
			if err := insertTransferEvents(db, chainId, cmap, tes); err != nil {
				log.WithError(err).Error("insertTransferEvents failed")
				return 0, err
			}
			_toBlockNumber := tes[len(tes)-1].BlockNumber - 1
			err = updateLastBlockNumber(db, int64(min(_toBlockNumber, toBlockNumber)), chainId)
			if err != nil {
				log.WithError(err).Error("updateLastBlockNumber failed")
				return 0, err
			}
		}
		return toBlockNumber, nil
	}
	for _, addr := range tokenAddresses {
		te, err := lastEvent(rpcURL, addr)
		if err != nil {
			log.WithError(err).Error("lastEvent failed")
			return err
		}
		lastBlockNumber := te.BlockNumber
		fromBlockNumber := lastCheckedBlock.Uint64()

		var intervalUnit uint64 = 10000

		if lastBlockNumber-fromBlockNumber > intervalUnit {
			toBlockNumber := fromBlockNumber
			for toBlockNumber != lastBlockNumber {
				toBlockNumber = fromBlockNumber + intervalUnit
				if toBlockNumber > lastBlockNumber {
					toBlockNumber = lastBlockNumber
				}
				_toBlockNumber, err := saveEvent(addr, fromBlockNumber, toBlockNumber)
				if err != nil {
					log.WithError(err).Error("saveEvent failed in interval loop")
					return err
				}

				if _toBlockNumber < fromBlockNumber+intervalUnit {
					fromBlockNumber = _toBlockNumber
				} else {
					fromBlockNumber += intervalUnit
				}
				if toBlockNumber != lastBlockNumber {
					time.Sleep(500 * time.Millisecond)
				}
			}
		} else {
			_, err = saveEvent(addr, fromBlockNumber, lastBlockNumber)
			if err != nil {
				log.WithError(err).Error("saveEvent failed in else branch")
				return err
			}
		}
	}
	log.Info("tronTrack completed")
	return nil
}

// insertTransferEvents는 데이터베이스에 이벤트 배열을 삽입합니다
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
		for _, en := range subens {
			valueStrings = append(valueStrings, fmt.Sprintf("($%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d)",
				count*9+1, count*9+2, count*9+3, count*9+4, count*9+5, count*9+6, count*9+7, count*9+8, count*9+9))
			valueArgs = append(valueArgs, en.Token, en.BlockNumber, en.EventIndex, en.TxHash, en.From, en.To, en.Amount.String(), en.CreateAt, chain_id)
			count++
		}

		sqlStatement := fmt.Sprintf("INSERT INTO public.transfer_events (token, block_number, event_index, tx_hash, from_address, to_address, amount, created_at, chain_id) VALUES %s", strings.Join(valueStrings, ","))
		tx := db.Exec(sqlStatement, valueArgs...)
		if tx.Error != nil {
			return fmt.Errorf("insertTransferEvents error: %w", tx.Error)
		}
	}
	return nil
}

// updateLastBlockNumber는 마지막 체크된 블록 번호를 업데이트합니다
func updateLastBlockNumber(db *gorm.DB, blocknumber int64, chainId int) error {
	sqlStatement := `UPDATE public.blockchain
	SET last_checked_block=$1
	WHERE id=$2`
	tx := db.Exec(sqlStatement, blocknumber, chainId)
	if tx.Error != nil {
		return fmt.Errorf("updateLastBlockNumber error: %w", tx.Error)
	}
	return nil
}
