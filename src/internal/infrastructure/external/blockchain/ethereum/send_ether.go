package ethereum

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/acecasino/account_manage/internal/domain/entities"
	"github.com/acecasino/account_manage/internal/notification"
	"github.com/acecasino/account_manage/pkg/logger"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

type ERC20Manager struct {
	cc         *entities.Currency
	rpc        string
	chainID    *big.Int
	client     *ethclient.Client
	privateKey *ecdsa.PrivateKey
	adminAddr  common.Address
	parsedABI  abi.ABI
}

type ERC20Type string

const (
	ERC20_TransferFrom ERC20Type = "transferFrom"
	ERC20_Transfer     ERC20Type = "transfer"
	ERC20_Approve      ERC20Type = "approve"
	ERC20_Name         ERC20Type = "name"
	ERC20_Symbol       ERC20Type = "symbol"
	ERC20_TotalSupply  ERC20Type = "totalSupply"
	ERC20_BalanceOf    ERC20Type = "balanceOf"
	ERC20_Decimals     ERC20Type = "decimals"
	ERC20_Allowance    ERC20Type = "allowance"
)

func (e ERC20Type) String() string {
	return string(e)
}

func NewERC20Manager(cc *entities.Currency, privateKeyHex string) (*ERC20Manager, error) {
	log := logger.GetLogger()

	client, err := ethclient.Dial(cc.Blockchain.RpcURL)
	if err != nil {
		log.WithError(err).Error("Failed to connect to Ethereum RPC")
		return nil, err
	}

	contract, err := abi.JSON(strings.NewReader(ERC20Abi))
	if err != nil {
		log.WithError(err).Error("Failed to read contract ABI")
		panic(err)
	}

	privateKey, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		log.WithError(err).Error("Invalid private key1")
		return nil, err
	}
	addr := crypto.PubkeyToAddress(privateKey.PublicKey)
	ci := big.NewInt(int64(cc.ChainID))

	return &ERC20Manager{
		cc:         cc,
		client:     client,
		chainID:    ci,
		privateKey: privateKey,
		adminAddr:  addr,
		parsedABI:  contract,
	}, nil
}

func (e *ERC20Manager) Client() *ethclient.Client {
	return e.client
}

// Decimal returns the decimal places of the token
func (e *ERC20Manager) Decimal() int {
	return e.cc.Decimal
}

func (em *ERC20Manager) SendEther(pk string, am *big.Int, gasPrice *big.Int, nonce uint64) (common.Hash, error) {
	log := logger.GetLogger().WithFields(map[string]interface{}{
		"admin_addr": em.adminAddr.Hex(),
		"amount":     am.String(),
		"gasPrice":   gasPrice.String(),
		"nonce":      nonce,
	})
	privateKey, err := crypto.HexToECDSA(pk)
	if err != nil {
		log.WithError(err).Error("Invalid private key2")
		return common.Hash{}, err
	}
	addr := crypto.PubkeyToAddress(privateKey.PublicKey)
	log = log.WithField("to", addr.Hex())
	txHash, err := em.sendTransaction(em.privateKey, addr, am, []byte{}, 0, gasPrice, nonce)
	if err != nil {
		log.WithError(err).Error("SendEther failed")
		return txHash, err
	}
	log.WithField("txHash", txHash.Hex()).Info("SendEther succeeded")
	return txHash, nil
}

func (em *ERC20Manager) sendTxWithMethod(pk *ecdsa.PrivateKey, to common.Address, funcName ERC20Type, gasLimit uint64, gasPrice *big.Int, nonce uint64, am *big.Int, ins ...interface{}) (common.Hash, error) {
	log := logger.GetLogger().WithFields(map[string]interface{}{
		"to":       to.Hex(),
		"funcName": funcName.String(),
		"gasLimit": gasLimit,
		"gasPrice": func() string {
			if gasPrice != nil {
				return gasPrice.String()
			} else {
				return ""
			}
		}(),
		"nonce": nonce,
		"amount": func() string {
			if am != nil {
				return am.String()
			} else {
				return ""
			}
		}(),
		"params": ins,
	})
	data, err := em._abidata(funcName, ins...)
	if err != nil {
		log.WithError(err).Error("Failed to create ABI data")
		return common.Hash{}, err
	}
	log.WithField("abi_data", fmt.Sprintf("%x", data)).Debug("ABI data created")
	txHash, err := em.sendTransaction(pk, to, am, data, gasLimit, gasPrice, nonce)
	if err != nil {
		log.WithError(err).Error("sendTxWithMethod failed")
		return txHash, err
	}
	// Get sender address for logging
	publicKey := pk.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Error("Failed to cast public key to ECDSA for logging")
	} else {
		fromAddr := crypto.PubkeyToAddress(*publicKeyECDSA)
		log.WithFields(map[string]interface{}{
			"fromAddr": fromAddr.Hex(),
			"toAddr":   to.Hex(),
			"txHash":   txHash.Hex(),
		}).Info("sendTxWithMethod succeeded")
	}
	return txHash, nil
}

func (em *ERC20Manager) _abidata(funcName ERC20Type, ins ...interface{}) ([]byte, error) {
	log := logger.GetLogger().WithFields(map[string]interface{}{
		"funcName": funcName.String(),
		"params":   ins,
	})
	method, ok := em.parsedABI.Methods[funcName.String()]
	if !ok {
		log.Error("Function not found in ABI")
		return nil, fmt.Errorf("function %s not found in ABI", funcName)
	}

	data, err := method.Inputs.Pack(ins...)
	if err != nil {
		log.WithError(err).Error("ABI Pack error")
		return nil, err
	}
	data = append(method.ID, data...)
	log.WithField("packed_data", fmt.Sprintf("%x", data)).Debug("ABI data packed")
	return data, nil
}

func (em *ERC20Manager) sendTransaction(pk *ecdsa.PrivateKey, toAddr common.Address, toValue *big.Int, data []byte, gasLimit uint64, gasPrice *big.Int, nonce uint64) (common.Hash, error) {
	log := logger.GetLogger().WithFields(map[string]interface{}{
		"to":      toAddr.Hex(),
		"value":   toValue.String(),
		"chainID": em.chainID.String(),
	})
	if toValue == nil {
		toValue = big.NewInt(0)
	}
	publicKey := pk.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Error("Failed to cast public key to ECDSA")
		return common.Hash{}, errors.New("failed to cast public key to ECDSA")
	}

	var err error
	addr := crypto.PubkeyToAddress(*publicKeyECDSA)
	if nonce == 0 {
		nonce, err = em.client.PendingNonceAt(context.Background(), addr)
		if err != nil {
			log.WithError(err).Error("Failed to get nonce")
			return common.Hash{}, err
		}
	}

	if gasPrice == nil {
		gasPrice, err = em.client.SuggestGasPrice(context.Background())
		if err != nil {
			log.WithError(err).Error("Failed to suggest gas price")
			return common.Hash{}, err
		}
	}

	if gasLimit == 0 {
		gasLimit, err = em.client.EstimateGas(context.Background(), ethereum.CallMsg{
			From: addr,
			To:   &toAddr,
			Data: data,
		})
		if err != nil {
			log.WithError(err).Error("Failed to estimate gas")
			return common.Hash{}, err
		}
	}

	log.WithFields(map[string]interface{}{
		"nonce":    nonce,
		"fromAddr": addr.Hex(),
		"toAddr":   toAddr.Hex(),
		"toValue":  toValue.String(),
		"gasLimit": gasLimit,
		"gasPrice": gasPrice.String(),
		"data":     fmt.Sprintf("%x", data),
	}).Info("Sending transaction")

	tx := types.NewTransaction(nonce, toAddr, toValue, gasLimit, gasPrice, data)
	signer := types.LatestSignerForChainID(big.NewInt(em.chainID.Int64()))
	signedTx, err := types.SignTx(tx, signer, pk)
	if err != nil {
		log.WithError(err).Error("Failed to sign transaction")
		return signedTx.Hash(), err
	}

	result, err := signer.Sender(signedTx)
	if err != nil {
		log.WithError(err).Error("Failed to get sender from signedTx")
		return signedTx.Hash(), err
	}

	log.WithFields(map[string]interface{}{
		"signer":   result.Hex(),
		"fromAddr": addr.Hex(),
		"to":       signedTx.To().Hex(),
		"txHash":   signedTx.Hash().Hex(),
	}).Info("Transaction signed")

	err = em.client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		log.WithError(err).Error("Failed to send transaction")
		return signedTx.Hash(), err
	}
	_, isPending, _ := em.client.TransactionByHash(context.Background(), signedTx.Hash())
	count := 1

	for isPending {
		time.Sleep(time.Second * 1)
		_, isPending, _ = em.client.TransactionByHash(context.Background(), signedTx.Hash())
		if count > 30 {
			log.Warn("tx is pending more than 30 seconds")
			notification.SendTelMsg("tx is pending more than 10 times" + signedTx.Hash().String())
		}
		count++
	}

	log.WithFields(map[string]interface{}{
		"fromAddr": addr.Hex(),
		"toAddr":   signedTx.To().Hex(),
		"txHash":   signedTx.Hash().Hex(),
	}).Info("Transaction confirmed")
	return signedTx.Hash(), nil
}

func (em *ERC20Manager) call(toAddr common.Address, data []byte) ([]byte, error) {
	return em.client.CallContract(context.Background(), ethereum.CallMsg{
		To:   &toAddr,
		Data: data,
	}, nil)
}

func (em *ERC20Manager) ERC20TransferFromToAdmin(pk string, amount *big.Int, gasLimit uint64, gasPrice *big.Int) (string, error) {
	log := logger.GetLogger().WithFields(map[string]interface{}{
		"contract": em.cc.Address,
		"amount":   amount.String(),
		"gasLimit": gasLimit,
		"gasPrice": gasPrice,
	})
	cont := common.HexToAddress(em.cc.Address)
	privateKey, err := crypto.HexToECDSA(pk)
	if err != nil {
		log.WithError(err).Error("Invalid private key3")
		return "", err
	}
	from := crypto.PubkeyToAddress(privateKey.PublicKey)

	hs, err := em.sendTxWithMethod(em.privateKey, cont, ERC20_TransferFrom, gasLimit, gasPrice, 0, big.NewInt(0), from, em.adminAddr, amount)
	if err != nil {
		log.WithError(err).Error("ERC20TransferFromToAdmin failed")
		return "", err
	}
	log.WithField("txHash", hs.String()).Info("ERC20TransferFromToAdmin succeeded")
	return hs.String(), err
}

func (em *ERC20Manager) AdminERC20Transfer(to common.Address, amountStr string) (string, *big.Int, error) {
	log := logger.GetLogger().WithFields(map[string]interface{}{
		"contract":  em.cc.Address,
		"to":        to.Hex(),
		"amountStr": amountStr,
	})
	amt, err := ConvertTokenToBigInt(amountStr, em.cc.Decimal)
	if err != nil {
		log.WithError(err).Error("ConvertTokenToBigInt failed")
		return "", nil, err
	}

	cont := common.HexToAddress(em.cc.Address)
	hs, err := em.sendTxWithMethod(em.privateKey, cont, ERC20_Transfer, 0, nil, 0, big.NewInt(0), to, amt)
	if err != nil {
		log.WithError(err).Error("AdminERC20Transfer failed")
		return "", nil, err
	}
	log.WithField("txHash", hs.String()).Info("AdminERC20Transfer succeeded")
	return hs.String(), amt, err
}

func (em *ERC20Manager) EtherBalanceOf(address string) (*big.Int, error) {
	addr := common.HexToAddress(address)
	return em.client.BalanceAt(context.Background(), addr, nil)
}

func (em *ERC20Manager) ERC20BalanceOf(address string) (string, *big.Int, error) {
	log := logger.GetLogger().WithFields(map[string]interface{}{
		"contract": em.cc.Address,
		"address":  address,
	})

	cont := common.HexToAddress(em.cc.Address)
	addr := common.HexToAddress(address)

	abidata, err := em._abidata(ERC20_BalanceOf, addr)
	if err != nil {
		log.WithError(err).Error("Failed to create ABI data")
		return "", nil, err
	}

	bs, err := em.call(cont, abidata)
	if err != nil {
		log.WithError(err).Error("Contract call failed")
		return "", nil, err
	}
	log.WithField("call_result", fmt.Sprintf("%x", bs)).Debug("Contract call result")

	method, ok := em.parsedABI.Methods[ERC20_BalanceOf.String()]
	if !ok {
		log.Error("ABI method not found: balanceOf")
		return "", nil, fmt.Errorf("function %s not found in ABI", ERC20_BalanceOf.String())
	}
	data, err := method.Outputs.Unpack(bs)
	if err != nil {
		log.WithError(err).Error("ABI unpack error")
		return "", nil, err
	}
	bi, ok := data[0].(*big.Int)
	if !ok {
		log.Error("Failed to convert unpacked data to big.Int")
		return "", nil, errors.New("failed to convert data to big.Int")
	}
	amtStr := ConvertBigIntToToken(bi, em.cc.Decimal)
	log.WithFields(map[string]interface{}{
		"address": address,
		"balance": bi.String(),
		"decimal": em.cc.Decimal,
		"amtStr":  amtStr,
	}).Info("ERC20 balance fetched")

	return amtStr, bi, err
}

func (em *ERC20Manager) ERC20Approve(pk string, amt *big.Int, gasLimit uint64, gasPrice *big.Int) (string, error) {
	log := logger.GetLogger().WithFields(map[string]interface{}{
		"contract": em.cc.Address,
		"amt":      amt.String(),
		"gasLimit": gasLimit,
		"gasPrice": gasPrice,
	})
	cont := common.HexToAddress(em.cc.Address)
	privateKey, err := crypto.HexToECDSA(pk)
	if err != nil {
		log.WithError(err).Error("Invalid private key5")
		return "", err
	}

	hs, err := em.sendTxWithMethod(privateKey, cont, ERC20_Approve, gasLimit, gasPrice, 0, big.NewInt(0), em.adminAddr, amt)
	if err != nil {
		log.WithError(err).Error("ERC20Approve failed")
		return "", err
	}
	log.WithField("txHash", hs.String()).Info("ERC20Approve succeeded")
	return hs.String(), err
}

func (em *ERC20Manager) EstimagteERC20Approve(pk string, amt *big.Int) (uint64, error) {
	log := logger.GetLogger().WithFields(map[string]interface{}{
		"contract": em.cc.Address,
		"amt":      amt.String(),
	})
	cont := common.HexToAddress(em.cc.Address)
	privateKey, err := crypto.HexToECDSA(pk)
	if err != nil {
		log.WithError(err).Error("Invalid private key6")
		return 0, err
	}
	data, err := em._abidata(ERC20_Approve, em.adminAddr, amt)
	if err != nil {
		log.WithError(err).Error("Failed to create ABI data for approve")
		return 0, err
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Error("Failed to cast public key to ECDSA")
		return 0, errors.New("failed to cast public key to ECDSA")
	}

	addr := crypto.PubkeyToAddress(*publicKeyECDSA)

	gasLimit, err := em.client.EstimateGas(context.Background(), ethereum.CallMsg{
		From: addr,
		To:   &cont,
		Data: data,
	})
	if err != nil {
		log.WithError(err).Error("EstimateGas failed for approve")
		return 0, err
	}

	log.WithField("gasLimit", gasLimit).Info("Estimated gas for ERC20Approve")
	return gasLimit, nil
}

func (em *ERC20Manager) ERC20Allowance(address string) (*big.Int, error) {
	log := logger.GetLogger().WithFields(map[string]interface{}{
		"contract": em.cc.Address,
	})
	cont := common.HexToAddress(em.cc.Address)
	addr := common.HexToAddress(address)

	abidata, err := em._abidata(ERC20_Allowance, addr, em.adminAddr)
	if err != nil {
		log.WithError(err).Error("Failed to create ABI data for allowance")
		return nil, err
	}

	bs, err := em.call(cont, abidata)
	if err != nil {
		log.WithError(err).Error("Contract call failed for allowance")
		return nil, err
	}

	method, ok := em.parsedABI.Methods[ERC20_BalanceOf.String()]
	if !ok {
		log.Error("ABI method not found: balanceOf (for allowance)")
		return nil, fmt.Errorf("function %s not found in ABI", ERC20_BalanceOf.String())
	}

	data, err := method.Outputs.Unpack(bs)
	if err != nil {
		log.WithError(err).Error("ABI unpack error for allowance")
		return nil, err
	}
	bi, ok := data[0].(*big.Int)
	if !ok {
		log.Error("Failed to convert unpacked data to big.Int (allowance)")
		return nil, errors.New("failed to convert data to big.Int")
	}
	log.WithField("allowance", bi.String()).Info("ERC20 allowance fetched")
	return bi, err
}

// convertTokenToBigInt converts a token value with given decimals to big.Int
func ConvertTokenToBigInt(tokenValue string, decimals int) (*big.Int, error) {
	// Split the token value into integer and fractional parts
	parts := strings.Split(tokenValue, ".")
	if len(parts) == 1 {
		parts = append(parts, "0")
	}
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid token format")
	}

	intPart := parts[0]
	fracPart := parts[1]

	// Pad or truncate the fractional part to match the required decimals
	if len(fracPart) < decimals {
		fracPart += strings.Repeat("0", decimals-len(fracPart))
	} else if len(fracPart) > decimals {
		fracPart = fracPart[:decimals]
	}

	// Combine the integer part and the fractional part
	fullNumberStr := intPart + fracPart

	// Convert the combined string to big.Int
	tokenBigInt := new(big.Int)
	tokenBigInt, success := tokenBigInt.SetString(fullNumberStr, 10)
	if !success {
		return nil, fmt.Errorf("failed to convert token to big.Int")
	}

	return tokenBigInt, nil
}

// convertBigIntToToken converts a big.Int value to a string with the given decimals
func ConvertBigIntToToken(value *big.Int, decimals int) string {
	// Convert the big.Int value to a string
	valueStr := value.String()

	// Pad with leading zeros if necessary
	if len(valueStr) <= decimals {
		valueStr = strings.Repeat("0", decimals-len(valueStr)+1) + valueStr
	}

	// Insert the decimal point
	intPart := valueStr[:len(valueStr)-decimals]
	fracPart := valueStr[len(valueStr)-decimals:]

	// Trim leading zeros in the integer part
	intPart = strings.TrimLeft(intPart, "0")
	if intPart == "" {
		intPart = "0"
	}

	// Trim trailing zeros in the fractional part
	fracPart = strings.TrimRight(fracPart, "0")

	// If the fractional part is empty after trimming, we don't need to add it
	if fracPart == "" {
		return intPart
	}

	// Combine the integer part and the fractional part
	return intPart + "." + fracPart
}
