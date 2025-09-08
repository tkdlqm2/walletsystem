package ethereum

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/acecasino/account_manage/pkg/logger"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/pkg/errors"
	"gorm.io/gorm"
)

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

func EtherTrack(rpcURL string, lastCheckedBlock *big.Int, tokenAddressesStr []string, db *gorm.DB, chainId int, cmap map[string]int) error {
	log := logger.GetLogger()
	client, err := ethclient.Dial(rpcURL)
	if err != nil {
		log.WithError(err).Error("Failed to connect to the Ethereum client")
		return errors.WithStack(fmt.Errorf("failed to connect to the Ethereum client: %v", err))
	}

	tokenAddresses := []common.Address{}
	for _, v := range tokenAddressesStr {
		tokenAddresses = append(tokenAddresses, common.HexToAddress(v))
	}
	header, err := client.HeaderByNumber(context.Background(), nil)
	if err != nil {
		log.WithError(err).Error("HeaderByNumber failed")
		return errors.WithStack(err)
	}
	lastBlockNumber := new(big.Int).Sub(header.Number, big.NewInt(6))
	if lastCheckedBlock == nil || lastCheckedBlock.Int64() == 0 {
		lastCheckedBlock = lastBlockNumber
	}
	toBlock := lastBlockNumber
	_toBlock := lastBlockNumber.Uint64()
	_lastCheckedBlock := lastCheckedBlock.Uint64()
	intervalUnit := uint64(100)
	if _toBlock > _lastCheckedBlock+intervalUnit {
		toBlock = new(big.Int).SetUint64(_lastCheckedBlock + intervalUnit)
	}

	if toBlock.Cmp(lastCheckedBlock) > 0 {
		transferEventSignature := []byte("Transfer(address,address,uint256)")
		transferEventHash := crypto.Keccak256Hash(transferEventSignature)

		if len(tokenAddresses) > 0 {
			ToTes, err := TraceMultyToken(client, lastCheckedBlock, toBlock, tokenAddresses, transferEventHash)
			if err != nil {
				log.WithError(err).Error("TraceMultyToken failed")
				return err
			}
			if err := insertTransferEvents(db, chainId, cmap, ToTes); err != nil {
				log.WithError(err).Error("insertTransferEvents failed for tokens")
				return err
			}
		}

		if _, has := cmap[common.HexToAddress("0x0").String()]; has {
			EtTes, err := TraceEther(client, lastCheckedBlock, toBlock)
			if err != nil {
				log.WithError(err).Error("TraceEther failed")
				return err
			}
			if err := insertTransferEvents(db, chainId, cmap, EtTes); err != nil {
				log.WithError(err).Error("insertTransferEvents failed for ether")
				return err
			}
		}
	}

	return updateLastBlockNumber(db, toBlock.Int64(), chainId)
}

func TraceMultyToken(client *ethclient.Client, lastCheckedBlock *big.Int, ToBlock *big.Int, tokenAddresses []common.Address, transferEventHash common.Hash) ([]*transferEvent, error) {
	log := logger.GetLogger().WithFields(map[string]interface{}{
		"fromBlock":      lastCheckedBlock,
		"toBlock":        ToBlock,
		"tokenAddresses": tokenAddresses,
	})
	query := ethereum.FilterQuery{
		FromBlock: lastCheckedBlock,
		ToBlock:   ToBlock,
		Addresses: tokenAddresses,
		Topics:    [][]common.Hash{{transferEventHash}},
	}

	logs, err := client.FilterLogs(context.Background(), query)
	if err != nil {
		log.WithError(err).Error("FilterLogs failed")
		return nil, errors.WithStack(err)
	}

	tes := []*transferEvent{}
	for _, vLog := range logs {
		te := &transferEvent{
			BlockNumber: vLog.BlockNumber,
			TxHash:      vLog.TxHash.Hex(),
			EventIndex:  vLog.Index,
			Token:       vLog.Address.String(),
			From:        common.HexToAddress(vLog.Topics[1].Hex()).String(),
			To:          common.HexToAddress(vLog.Topics[2].Hex()).String(),
			Amount:      big.NewInt(0).SetBytes(vLog.Data),
			CreateAt:    time.Now(),
		}
		tes = append(tes, te)
	}
	return tes, nil
}

func TraceEther(client *ethclient.Client, lastCheckedBlock *big.Int, ToBlock *big.Int) ([]*transferEvent, error) {
	log := logger.GetLogger().WithFields(map[string]interface{}{
		"fromBlock": lastCheckedBlock,
		"toBlock":   ToBlock,
	})
	tes := []*transferEvent{}
	for blockNumber := new(big.Int).Add(lastCheckedBlock, big.NewInt(1)); blockNumber.Cmp(ToBlock) <= 0; blockNumber.Add(blockNumber, big.NewInt(1)) {
		block, err := client.BlockByNumber(context.Background(), blockNumber)
		if err != nil {
			log.WithError(err).Error("BlockByNumber failed")
			return nil, errors.WithStack(err)
		}

		for _, tx := range block.Transactions() {
			from, err := types.Sender(types.NewCancunSigner(tx.ChainId()), tx)
			if err != nil {
				log.WithError(err).Error("Sender failed")
				return nil, errors.WithStack(err)
			}
			value := tx.Value().String()
			if value != "0" {
				to := tx.To()
				if to == nil {
					to = &common.Address{}
				}
				te := &transferEvent{
					BlockNumber: block.Number().Uint64(),
					TxHash:      tx.Hash().Hex(),
					Token:       common.HexToAddress("0x0").String(),
					From:        from.String(),
					To:          to.String(),
					Amount:      tx.Value(),
					CreateAt:    time.Unix(0, int64(block.Time())),
				}
				tes = append(tes, te)
			}
		}
	}
	log.WithField("eventCount", len(tes)).Info("TraceEther completed")
	return tes, nil
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
		for _, en := range subens {
			valueStrings = append(valueStrings, fmt.Sprintf("($%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d)",
				count*8+1, count*8+2, count*8+3, count*8+4, count*8+5, count*8+6, count*8+7, count*8+8))
			currId := cmap[strings.ToLower(en.Token)]
			valueArgs = append(valueArgs, currId, en.BlockNumber, en.TxHash, en.EventIndex, en.From, en.To, en.Amount.String(), en.CreateAt)
			count++
		}

		sqlStatement := fmt.Sprintf(`INSERT INTO public.transfer_history (currency_id, block_number, tx_hash, event_index, _from, _to, amount, create_at) 
			VALUES %s 
			ON CONFLICT (currency_id, tx_hash, _from, _to, amount) DO NOTHING`, strings.Join(valueStrings, ","))
		tx := db.Exec(sqlStatement, valueArgs...)
		if tx.Error != nil {
			return errors.WithStack(tx.Error)
		}
	}
	return nil
}

// 마지막 체크된 블록 번호 업데이트
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
