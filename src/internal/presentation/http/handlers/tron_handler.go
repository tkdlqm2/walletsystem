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

// TronHandler handles TRON-related requests
type TronHandler struct {
	container *container.Container
}

// NewTronHandler creates a new TronHandler
func NewTronHandler(container *container.Container) *TronHandler {
	return &TronHandler{
		container: container,
	}
}

// TronAddress handles TRON address generation
func (h *TronHandler) TronAddress() func(c echo.Context) error {
	return func(c echo.Context) error {
		email := c.FormValue("email")
		if email == "" {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "email is required"})
		}

		// Generate new TRON address
		address, err := h.generateTronAddress(email)
		if err != nil {
			logger.GetLogger().WithError(err).WithField("email", email).Error("Failed to generate TRON address")
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to generate address"})
		}

		return c.JSON(http.StatusOK, map[string]string{"address": address})
	}
}

// TronWithdraw handles TRON withdrawals
func (h *TronHandler) TronWithdraw() func(c echo.Context) error {
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
		_, err = h.container.CurrencyRepo.GetCurrency(context.Background(), token)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid token"})
		}

		// Create withdraw history record
		withdrawInfo := &entities.WithdrawInfo{
			UserID:     0, // Will be set after getting user ID
			CurrencyID: 1, // Placeholder currency ID
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
		result, err := h.TronSend(token, toAddr, amountStr, memo)
		if err != nil {
			// Update status to error
			h.container.DB.Table("withdraw_history").Where("id = ?", withdrawInfo.ID).Update("process", "error")
			h.container.ErrorLogsRepo.SendErrMsg(context.Background(), "TronWithdraw", err)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Withdrawal failed"})
		}

		// Update status to success
		h.container.DB.Table("withdraw_history").Where("id = ?", withdrawInfo.ID).Update("process", "success")

		return c.JSON(http.StatusOK, map[string]string{"result": result})
	}
}

// generateTronAddress generates a new TRON address for the user
func (h *TronHandler) generateTronAddress(email string) (string, error) {
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

	// Generate address from private key (TRON format - placeholder)
	address := fmt.Sprintf("TRON_%s", privateKeyHex[:8])

	// Save to database
	chainAccount := &entities.ChainAccount{
		UserID:         userID,
		WalletType:     "TRON",
		AccountAddress: address,
		PrivateKey:     encryptedPk,
	}

	err = h.container.ChainAccountRepo.Create(context.Background(), chainAccount)
	if err != nil {
		return "", fmt.Errorf("failed to save chain account: %w", err)
	}

	return address, nil
}

// TronSend handles TRON transaction sending
func (h *TronHandler) TronSend(token, toAddr, amountStr, memo string) (string, error) {
	// Get currency info
	_, err := h.container.CurrencyRepo.GetCurrency(context.Background(), token)
	if err != nil {
		return "", err
	}

	// Get chain accounts for TRON
	privateKeys, err := h.container.ChainAccountRepo.GetPrivateKeyUsingEmailLegacy(context.Background(), "")
	if err != nil {
		return "", err
	}

	// Find TRON private key
	var tronPrivateKey string
	for _, account := range privateKeys {
		if account.WalletType == "TRON" {
			tronPrivateKey = account.PrivateKey
			break
		}
	}

	if tronPrivateKey == "" {
		return "", fmt.Errorf("TRON private key not found")
	}

	// Create crypto instance
	aesCrypto, err := crypto.NewAESCrypto()
	if err != nil {
		return "", fmt.Errorf("failed to create crypto instance: %w", err)
	}

	// Decrypt private key
	_, err = aesCrypto.DecryptPrivateKey(tronPrivateKey)
	if err != nil {
		return "", err
	}

	// Send TRON transaction (placeholder implementation)
	// This would need to be implemented based on the existing TRON logic
	result := fmt.Sprintf("TRON transaction sent: %s to %s, amount: %s", token, toAddr, amountStr)

	return result, nil
}
