package tron

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"

	"github.com/acecasino/account_manage/internal/blockchain/ethereum"
	"github.com/acecasino/account_manage/pkg/logger"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/fbsobreira/gotron-sdk/pkg/address"
	"github.com/fbsobreira/gotron-sdk/pkg/client"
	"github.com/fbsobreira/gotron-sdk/pkg/client/transaction"
	"github.com/fbsobreira/gotron-sdk/pkg/common"
	"github.com/fbsobreira/gotron-sdk/pkg/keystore"
	"github.com/fbsobreira/gotron-sdk/pkg/proto/api"
	"google.golang.org/grpc"
)

const feeLimit = 30000000
const passphrase = "1231"

type TRC20Manager struct {
	rpc             string
	client          *client.GrpcClient
	adminAddr       string
	adminPKHex      string
	adminPK         *ecdsa.PrivateKey
	contractAddress string
	parsedABI       abi.ABI
}

func NewTRC20Manager(rpc, privateKeyHex, contractAddress string) (*TRC20Manager, error) {
	log := logger.GetLogger()
	tclient := client.NewGrpcClient(rpc)
	APIKey := os.Getenv("TRONGRID_API_KEY")
	err := tclient.SetAPIKey(APIKey)
	if err != nil {
		log.WithError(err).Error("SetAPIKey failed")
		panic(err)
	}
	opts := make([]grpc.DialOption, 0)
	opts = append(opts, grpc.WithInsecure())
	err = tclient.Start(opts...)
	if err != nil {
		log.WithError(err).Error("GrpcClient Start failed")
		panic(err)
	}

	contract, err := abi.JSON(strings.NewReader(ethereum.ERC20Abi))
	if err != nil {
		log.WithError(err).Error("Failed to read contract ABI")
		panic(err)
	}
	ks, acc, err := getKsAcc(privateKeyHex)
	if err != nil {
		log.WithError(err).Error("getKsAcc failed")
		panic(err)
	}
	defer ks.Delete(acc, passphrase)

	privateKey, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		log.WithError(err).Error("Invalid private key")
		return nil, err
	}

	log.WithField("adminAddr", acc.Address.String()).Info("TRC20Manager initialized")
	return &TRC20Manager{
		rpc:             rpc,
		client:          tclient,
		adminAddr:       acc.Address.String(),
		adminPKHex:      privateKeyHex,
		adminPK:         privateKey,
		contractAddress: contractAddress,
		parsedABI:       contract,
	}, nil

}

func (e *TRC20Manager) Balance(addr string) *big.Int {
	log := logger.GetLogger()
	bal := getBalance(addr)
	log.WithField("balance", bal.String()).Info("TRX balance fetched")
	return bal
}
func getBalance(addr string) *big.Int {
	log := logger.GetLogger().WithField("addr", addr)
	url := "https://api.trongrid.io/jsonrpc"

	taddr, err := address.Base58ToAddress(addr)
	if err != nil {
		log.WithError(err).Error("Base58ToAddress failed")
		return nil
	}

	// 요청할 JSON 데이터 생성
	requestData := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "eth_getBalance",
		"params": []interface{}{
			taddr.Hex(),
			"latest",
		},
		"id": 64,
	}

	// JSON 데이터를 바이트 슬라이스로 변환
	jsonData, err := json.Marshal(requestData)
	if err != nil {
		fmt.Println("JSON marshaling error:", err)
		return nil
	}

	// HTTP POST 요청 생성
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Println("HTTP request error:", err)
		return nil
	}
	req.Header.Set("Content-Type", "application/json")

	// HTTP 클라이언트 생성 및 요청 보내기
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("HTTP request error:", err)
		return nil
	}
	defer resp.Body.Close()

	// 응답 읽기
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("HTTP response reading error:", err)
		return nil
	}

	m := map[string]interface{}{}
	err = json.Unmarshal(body, &m)
	if err != nil {
		fmt.Println("HTTP response reading error:", err)
		return nil
	}

	if resul, ok := m["result"].(string); ok {
		if bi, ok := big.NewInt(0).SetString(strings.Replace(resul, "0x", "", -1), 16); ok {
			return bi
		}
		return nil
	}

	return nil
}

func (e *TRC20Manager) TRC20Balance(addr string) *big.Int {
	log := logger.GetLogger()
	bi, err := e.client.TRC20ContractBalance(addr, e.contractAddress)
	if err != nil {
		log.WithError(err).Error("TRC20Balance failed")
		panic(err)
	}
	log.WithField("balance", bi.String()).Info("TRC20 token balance fetched")
	return bi
}

func (e *TRC20Manager) Allowance(owner string) *big.Int {
	log := logger.GetLogger()
	addrA, err := address.Base58ToAddress(owner)
	if err != nil {
		log.WithError(err).Error("Base58ToAddress failed for owner")
		panic(err)
	}
	addrB, err := address.Base58ToAddress(e.adminAddr)
	if err != nil {
		log.WithError(err).Error("Base58ToAddress failed for adminAddr")
		panic(err)
	}
	req := "0xdd62ed3e" + "0000000000000000000000000000000000000000000000000000000000000000"[len(addrA.Hex())-4:] + addrA.Hex()[4:]
	req += "0000000000000000000000000000000000000000000000000000000000000000"[len(addrB.Hex())-4:] + addrB.Hex()[4:]
	result, err := e.client.TRC20Call("", e.contractAddress, req, true, 0)
	if err != nil {
		log.WithError(err).Error("TRC20Allowance, TRC20Call failed")
		panic(err)
	}
	data := common.BytesToHexString(result.GetConstantResult()[0])
	r, err := e.client.ParseTRC20NumericProperty(data)
	if err != nil {
		log.WithError(err).Error("TRC20Allowance, ParseTRC20NumericProperty failed", "contractAddress", e.contractAddress, "data", data)
		panic(err)
	}
	if r == nil {
		log.Error("TRC20Allowance, invalid balance")
		panic(fmt.Errorf("contract address %s: invalid balance of %s", e.contractAddress, addrA))
	}
	return r
}

func (e *TRC20Manager) Approve(from string, pk string, amount *big.Int) (string, error) {
	log := logger.GetLogger().WithFields(map[string]interface{}{
		"from":            from,
		"adminAddr":       e.adminAddr,
		"contractAddress": e.contractAddress,
		"amount":          amount.String(),
	})
	ks, acc, err := getKsAcc(pk)
	if err != nil {
		log.WithError(err).Error("getKsAcc failed")
		return "", err
	}
	defer ks.Delete(acc, passphrase)

	tx, err := e.client.TRC20Approve(
		from,
		e.adminAddr,
		e.contractAddress,
		amount,
		feeLimit,
	)
	if err != nil {
		log.WithError(err).Error("TRC20Approve failed")
		return "", err
	}
	addrResult, err := e.sendTx(ks, acc, tx)
	if err != nil {
		log.WithError(err).Error("sendTx failed")
		return "", err
	}
	log.WithField("txHash", addrResult).Info("TRC20Approve succeeded")
	return addrResult, nil

}

func (e *TRC20Manager) SendTRX(to string, amount *big.Int) (string, error) {
	log := logger.GetLogger().WithFields(map[string]interface{}{
		"from":   e.adminAddr,
		"to":     to,
		"amount": amount.String(),
	})
	ks, acc, err := getKsAcc(e.adminPKHex)
	if err != nil {
		log.WithError(err).Error("getKsAcc failed")
		return "", err
	}
	defer ks.Delete(acc, passphrase)

	tx, err := e.client.Transfer(acc.Address.String(), to, amount.Int64())
	if err != nil {
		log.WithError(err).Error("Transfer failed")
		return "", err
	}

	addrResult, err := e.sendTx(ks, acc, tx)
	if err != nil {
		log.WithError(err).Error("sendTx failed")
		return "", err
	}
	log.WithField("txHash", addrResult).Info("SendTRX succeeded")
	return addrResult, nil
}

func (e *TRC20Manager) Send(from, to string, pk string, amount *big.Int) (string, error) {
	log := logger.GetLogger().WithFields(map[string]interface{}{
		"from":            from,
		"to":              to,
		"contractAddress": e.contractAddress,
		"amount":          amount.String(),
	})
	tx, err := e.client.TRC20Send(
		from,
		to,
		e.contractAddress,
		amount,
		feeLimit,
	)
	if err != nil {
		log.WithError(err).Error("TRC20Send failed")
		return "", err
	}

	ks, acc, err := getKsAcc(pk)
	if err != nil {
		log.WithError(err).Error("getKsAcc failed")
		return "", err
	}
	defer ks.Delete(acc, passphrase)

	addrResult, err := e.sendTx(ks, acc, tx)
	if err != nil {
		log.WithError(err).Error("sendTx failed")
		return "", err
	}
	log.WithField("txHash", addrResult).Info("TRC20Send succeeded")
	return addrResult, nil
}

func (e *TRC20Manager) sendTx(ks *keystore.KeyStore, acc keystore.Account, tx *api.TransactionExtention) (string, error) {
	log := logger.GetLogger().WithFields(map[string]interface{}{
		"from": acc.Address.String(),
	})
	ctrlr := transaction.NewController(e.client, ks, &acc, tx.Transaction)
	if err := ctrlr.ExecuteTransaction(); err != nil {
		log.WithError(err).Error("ExecuteTransaction failed")
		return "", err
	}
	txHash, nil := ctrlr.TransactionHash()
	log.WithField("txHash", txHash).Info("Transaction executed")
	return txHash, nil

}

func getKsAcc(pk string) (*keystore.KeyStore, keystore.Account, error) {
	log := logger.GetLogger()
	ks := keystore.NewKeyStore("./keystore", keystore.StandardScryptN, keystore.StandardScryptP)
	privateKey, err := crypto.HexToECDSA(pk)
	if err != nil {
		log.WithError(err).Error("HexToECDSA failed")
		return nil, keystore.Account{}, err
	}
	acc, err := ks.ImportECDSA(privateKey, passphrase)
	if err != nil && err != keystore.ErrAccountAlreadyExists {
		log.WithError(err).Error("ImportECDSA failed")
		return nil, keystore.Account{}, err
	}
	err = ks.Unlock(acc, passphrase)
	if err != nil {
		log.WithError(err).Error("Unlock failed")
		return nil, keystore.Account{}, err
	}
	log.WithField("address", acc.Address.String()).Info("Account unlocked")
	return ks, acc, nil
}

func (e *TRC20Manager) TRC20TransferFrom(from string, amount *big.Int) (string, error) {
	log := logger.GetLogger().WithFields(map[string]interface{}{
		"from":            from,
		"adminAddr":       e.adminAddr,
		"contractAddress": e.contractAddress,
		"amount":          amount.String(),
	})
	addrA, err := address.Base58ToAddress(from)
	if err != nil {
		log.WithError(err).Error("Base58ToAddress failed for from")
		return "", err
	}
	addrB, err := address.Base58ToAddress(e.adminAddr)
	if err != nil {
		log.WithError(err).Error("Base58ToAddress failed for adminAddr")
		return "", err
	}
	ab := common.LeftPadBytes(amount.Bytes(), 32)
	req := "0x23b872dd" +
		"0000000000000000000000000000000000000000000000000000000000000000"[len(addrA.Hex())-2:] + addrA.Hex()[2:] +
		"0000000000000000000000000000000000000000000000000000000000000000"[len(addrB.Hex())-2:] + addrB.Hex()[2:]
	req += common.Bytes2Hex(ab)

	ks, acc, err := getKsAcc(e.adminPKHex)
	if err != nil {
		log.WithError(err).Error("getKsAcc failed")
		return "", err
	}
	defer ks.Delete(acc, passphrase)

	tx, err := e.client.TRC20Call(acc.Address.String(), e.contractAddress, req, false, 34000000)
	if err != nil {
		log.WithError(err).Error("TRC20Call failed")
		return "", err
	}
	addrResult, err := e.sendTx(ks, acc, tx)
	if err != nil {
		log.WithError(err).Error("sendTx failed")
		return "", err
	}
	log.WithField("txHash", addrResult).Info("TRC20TransferFrom succeeded")
	return addrResult, nil
}
