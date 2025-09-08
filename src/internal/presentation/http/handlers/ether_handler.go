package handlers

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/acecasino/account_manage/internal/container"
	"github.com/acecasino/account_manage/internal/domain/entities"
	"github.com/acecasino/account_manage/internal/infrastructure/crypto"
	"github.com/acecasino/account_manage/pkg/logger"
	"github.com/labstack/echo"
)

// EtherHandler handles Ethereum-related requests
type EtherHandler struct {
	container *container.Container
}

// NewEtherHandler creates a new EtherHandler
func NewEtherHandler(container *container.Container) *EtherHandler {
	return &EtherHandler{
		container: container,
	}
}

// EtherAddress handles Ethereum address generation
func (h *EtherHandler) EtherAddress() func(c echo.Context) error {
	return func(c echo.Context) error {
		email := c.FormValue("email")
		if email == "" {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "email is required"})
		}

		// Generate new Ethereum address
		address, err := h.generateEtherAddress(email)
		if err != nil {
			logger.GetLogger().WithError(err).WithField("email", email).Error("Failed to generate Ethereum address")
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to generate address"})
		}

		return c.JSON(http.StatusOK, map[string]string{"address": address})
	}
}

// EtherWithdraw handles Ethereum withdrawals
func (h *EtherHandler) EtherWithdraw() func(c echo.Context) error {
	return func(c echo.Context) error {
		email := c.FormValue("email")
		token := c.FormValue("token")
		toAddr := c.FormValue("toAddr")
		amountStr := c.FormValue("amount")
		memo := c.FormValue("memo")

		// Parse amount
		_, err := strconv.ParseFloat(amountStr, 64)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid amount"})
		}

		// Get currency info
		cc, err := h.container.CurrencyRepo.GetCurrency(context.Background(), token)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid token"})
		}

		// Create withdraw history record
		withdrawInfo := &entities.WithdrawInfo{
			UserID:     0, // Will be set after getting user ID
			CurrencyID: cc.ID,
			ToAddress:  toAddr,
			Amount:     amountStr,
			Process:    "request",
			CreateAt:   time.Now(),
		}

		// Get user ID
		userID, err := h.container.UserRepo.GetUserIDByEmail(context.Background(), email)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "User not found"})
		}
		withdrawInfo.UserID = userID

		// Save withdraw history
		err = h.container.DB.Table("withdraw_history").Create(withdrawInfo).Error
		if err != nil {
			logger.GetLogger().WithError(err).Error("Failed to create withdraw history")
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to create withdraw history"})
		}

		// Process withdrawal
		result, err := h.EtherSend(token, toAddr, amountStr, memo)
		if err != nil {
			// Update status to error
			h.container.DB.Table("withdraw_history").Where("id = ?", withdrawInfo.ID).Update("process", "error")
			h.container.ErrorLogsRepo.SendErrMsg(context.Background(), "EtherWithdraw", err)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Withdrawal failed"})
		}

		// Update status to success
		h.container.DB.Table("withdraw_history").Where("id = ?", withdrawInfo.ID).Update("process", "success")

		return c.JSON(http.StatusOK, map[string]string{"result": result})
	}
}

// generateEtherAddress generates a new Ethereum address for the user
func (h *EtherHandler) generateEtherAddress(email string) (string, error) {
	// Get user ID
	userID, err := h.container.UserRepo.GetUserIDByEmail(context.Background(), email)
	if err != nil {
		return "", fmt.Errorf("failed to get user ID: %w", err)
	}

	// Generate new private key
	privateKeyHex, err := crypto.GeneratePrivateKey(email)
	if err != nil {
		return "", fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create crypto instance
	aesCrypto, err := crypto.NewAESCrypto()
	if err != nil {
		return "", fmt.Errorf("failed to create crypto instance: %w", err)
	}

	// Convert hex string to bytes
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return "", fmt.Errorf("failed to decode private key: %w", err)
	}

	// Encrypt private key
	encryptedPk, err := aesCrypto.EncryptPrivateKey(privateKeyBytes)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt private key: %w", err)
	}

	// Generate address from private key
	memoryKey, err := crypto.NewMemoryKeyFromString(privateKeyHex)
	if err != nil {
		return "", fmt.Errorf("failed to create memory key: %w", err)
	}
	address := memoryKey.PublicKey().Address().String()

	// Save to database
	chainAccount := &entities.ChainAccount{
		UserID:         userID,
		WalletType:     "ETHEREUM",
		AccountAddress: address,
		PrivateKey:     encryptedPk,
	}

	err = h.container.ChainAccountRepo.Create(context.Background(), chainAccount)
	if err != nil {
		return "", fmt.Errorf("failed to save chain account: %w", err)
	}

	return address, nil
}

// EtherSend handles Ethereum transaction sending
func (h *EtherHandler) EtherSend(token, toAddr, amountStr, memo string) (string, error) {
	// Get currency info
	_, err := h.container.CurrencyRepo.GetCurrency(context.Background(), token)
	if err != nil {
		return "", err
	}

	// Get chain account
	chainAccount, err := h.container.ChainAccountRepo.GetChainAccountByEmailAndWalletType(context.Background(), "", "ETHEREUM")
	if err != nil {
		return "", err
	}

	// Create crypto instance
	aesCrypto, err := crypto.NewAESCrypto()
	if err != nil {
		return "", fmt.Errorf("failed to create crypto instance: %w", err)
	}

	// Decrypt private key
	_, err = aesCrypto.DecryptPrivateKey(chainAccount.PrivateKey)
	if err != nil {
		return "", err
	}

	// Send transaction (placeholder - need to implement proper transaction sending)
	result := fmt.Sprintf("Ethereum transaction sent: %s to %s, amount: %s", token, toAddr, amountStr)

	return result, nil
}
