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
	privateKey, err := crypto.HexToECDSA(pk)
	if err != nil {
		return "", err
	}

	publicKey := privateKey.PublicKey
	trxAddress := address.PubkeyToAddress(publicKey)
	if err != nil {
		return "", err
	}

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
	url := fmt.Sprintf("%s/v1/contracts/%s/events?event_name=Transfer&limit=1", tronGridAPI, usdtContractAddress)
	apiData, err := getTronEventData(url)
	if err != nil {
		return nil, err
	}
	tes, err := extractTrasferEvent(apiData)
	if err != nil {
		return nil, err
	}
	if len(tes) == 0 {
		return nil, errors.New("no events found")
	}
	return tes[0], nil
}

func traceTronTransactionsByTimestamp(tronGridAPI, usdtContractAddress string, blockNumber, toBlockNumber uint64, ch chan []*transferEvent) error {
	defer close(ch)

	var ad *ApiData
	var err error
	for blockNumber < toBlockNumber {
		firstUrl := fmt.Sprintf("%s/v1/contracts/%s/events?only_confirmed=true&event_name=Transfer&limit=1&block_number=%d", tronGridAPI, usdtContractAddress, blockNumber)
		ad, err = getTronEventData(firstUrl)
		if err != nil {
			return err
		}
		if len(ad.Data) == 0 {
			blockNumber++
			continue
		}
		break
	}
	if ad == nil || len(ad.Data) == 0 {
		return nil
	}

	startTimestamp := ad.Data[0].BlockTimestamp
	order := "block_timestamp%2Casc"
	url := fmt.Sprintf("%s/v1/contracts/%s/events?only_confirmed=true&event_name=Transfer&min_block_timestamp=%d&order_by=%s&limit=200", tronGridAPI, usdtContractAddress, startTimestamp, order)
	for url != "" {
		ad, err = getTronEventData(url)
		if err != nil {
			return err
		}
		if len(ad.Data) == 0 {
			return nil
		}
		_tes, err := extractTrasferEvent(ad)
		if err != nil {
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
	return nil
}

func traceTronTransactions(tronGridAPI, usdtContractAddress string, blockNumber, toBlockNumber uint64) ([]*transferEvent, error) {
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
			return nil, err
		}
		_tes, err := extractTrasferEvent(apiData)
		if err != nil {
			return nil, err
		}
		if len(_tes) == 0 {
			blockNumber++
			continue
		}
		blockNumber = _tes[len(_tes)-1].BlockNumber + 1
		if len(_tes) > 0 {
			tes = append(tes, _tes...)
		}
	}
	return tes, nil
}

func getTronEventData(url string) (ad *ApiData, err error) {
	ad, err = _getTronEventData(url)
	if err != nil {
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
	return
}

func _getTronEventData(url string) (*ApiData, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	jsonData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	apiData := &ApiData{}
	err = json.Unmarshal(jsonData, &apiData)
	if err != nil {
		panic(err)
	}

	return apiData, nil
}

func extractTrasferEvent(apiData *ApiData) ([]*transferEvent, error) {
	tes := []*transferEvent{}
	for _, tx := range apiData.Data {
		val, ok := big.NewInt(0).SetString(tx.Result.Value, 10)
		if !ok {
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
	return tes, nil
}

func convertEthereumAddressToTron(ethAddress string) string {
	if len(ethAddress) >= 42 {
		ethAddress = "41" + ethAddress[2:]
		addb, _ := hex.DecodeString(ethAddress)
		hash1 := s256(s256(addb))
		secret := hash1[:4]
		for _, v := range secret {
			addb = append(addb, v)
		}
		tronAddress := base58.Encode(addb)
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

func TronTrack(rpcURL string, lastCheckedBlock *big.Int, tokenAddresses []string, db *gorm.DB, chainId int, cmap map[string]int) error {

	saveEvent := func(addr string, fromBlockNumber, toBlockNumber uint64) (uint64, error) {

		chte := make(chan []*transferEvent, 1)
		go func() {
			err := traceTronTransactionsByTimestamp(rpcURL, addr, fromBlockNumber, toBlockNumber, chte)
			if err != nil {
				// 에러 처리
			}
		}()

		var err error
		for tes := range chte {
			if err := insertTransferEvents(db, chainId, cmap, tes); err != nil {
				return 0, err
			}

			_toBlockNumber := tes[len(tes)-1].BlockNumber - 1
			err = updateLastBlockNumber(db, int64(min(_toBlockNumber, toBlockNumber)), chainId)
			if err != nil {
				return 0, err
			}
		}
		return toBlockNumber, nil
	}

	for _, addr := range tokenAddresses {
		te, err := lastEvent(rpcURL, addr)
		if err != nil {
			return err
		}
		lastBlockNumber := te.BlockNumber
		fromBlockNumber := lastCheckedBlock.Uint64()

		var intervalUnit uint64 = 10000
		blockRange := lastBlockNumber - fromBlockNumber

		if blockRange > intervalUnit {
			toBlockNumber := fromBlockNumber

			for toBlockNumber != lastBlockNumber {
				toBlockNumber = fromBlockNumber + intervalUnit
				if toBlockNumber > lastBlockNumber {
					toBlockNumber = lastBlockNumber
				}

				_toBlockNumber, err := saveEvent(addr, fromBlockNumber, toBlockNumber)
				if err != nil {
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
				return err
			}
		}

		// 각 토큰 주소 처리 완료 후 마지막 블록 번호 업데이트
		err = updateLastBlockNumber(db, int64(lastBlockNumber), chainId)
		if err != nil {
			return err
		}
	}
	return nil
}

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
			valueStrings = append(valueStrings, fmt.Sprintf("($%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d)",
				count*8+1, count*8+2, count*8+3, count*8+4, count*8+5, count*8+6, count*8+7, count*8+8))
			currId := cmap[strings.ToLower(en.Token)]
			valueArgs = append(valueArgs, currId, en.BlockNumber, en.TxHash, en.EventIndex, en.From, en.To, en.Amount.String(), time.Unix(en.CreateAt, 0))
			count++
		}

		sqlStatement := fmt.Sprintf(`INSERT INTO public.transfer_history (currency_id, block_number, tx_hash, event_index, _from, _to, amount, create_at) 
			VALUES %s 
			ON CONFLICT (currency_id, tx_hash, _from, _to, amount) DO NOTHING`, strings.Join(valueStrings, ","))
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
