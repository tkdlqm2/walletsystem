package handlers

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/acecasino/account_manage/internal/container"
	"github.com/acecasino/account_manage/internal/domain/entities"
	"github.com/acecasino/account_manage/pkg/logger"
	"github.com/labstack/echo"
)

// RestAPIHandler handles REST API requests
type RestAPIHandler struct {
	container *container.Container
}

// NewRestAPIHandler creates a new RestAPIHandler
func NewRestAPIHandler(container *container.Container) *RestAPIHandler {
	return &RestAPIHandler{
		container: container,
	}
}

// RestAPI handles the main REST API endpoint
func (h *RestAPIHandler) RestAPI() func(c echo.Context) error {
	return func(c echo.Context) error {
		token := c.FormValue("token")
		cc, err := h.GetCurrency(token)
		if err != nil {
			fmt.Println(err.Error())
			return err
		}
		userEmail := c.FormValue("user")
		amountStr := c.FormValue("amount")
		toAddr := c.FormValue("toAddr")
		memo := c.FormValue("memo")

		// 이메일로 사용자 ID 조회
		userID, err := h.container.UserRepo.GetUserIDByEmail(context.Background(), userEmail)
		if err != nil {
			logger.GetLogger().WithError(err).WithField("email", userEmail).Error("Failed to get user ID by email")
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "User not found"})
		}

		// 사용자 잔액 조회 및 음수 체크
		amount, err := strconv.ParseFloat(amountStr, 64)
		if err != nil {
			logger.GetLogger().WithError(err).WithField("amount", amountStr).Error("Failed to parse amount")
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid amount format"})
		}

		// user_balance 테이블에서 잔액 조회 (repository 패턴 사용)
		userBalance, err := h.container.UserBalanceRepo.GetBalanceByUserIDAndCurrencyID(context.Background(), userID, cc.ID)
		if err != nil {
			logger.GetLogger().WithError(err).WithFields(map[string]interface{}{
				"user_id":     userID,
				"currency_id": cc.ID,
			}).Error("Failed to get user balance")
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to retrieve user balance"})
		}

		// 잔액 레코드가 없는 경우
		if userBalance == nil {
			logger.GetLogger().WithFields(map[string]interface{}{
				"user_id":     userID,
				"currency_id": cc.ID,
			}).Warn("User balance record not found")
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "User balance not found"})
		}

		// 잔액 부족 체크
		if userBalance.Balance < amount {
			logger.GetLogger().WithFields(map[string]interface{}{
				"user_id":     userID,
				"currency_id": cc.ID,
				"requested":   amount,
				"available":   userBalance.Balance,
			}).Warn("Insufficient balance")
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Insufficient balance"})
		}

		// withdraw_history에 전송 요청 기록 추가
		withdrawInfo := &entities.WithdrawInfo{
			UserID:     userID, // 사용자 ID 설정
			CurrencyID: cc.ID,  // Currency의 ID를 CurrencyID로 설정
			ToAddress:  toAddr, // 사용자의 지갑 주소
			Amount:     amountStr,
			Process:    "request",
			CreateAt:   time.Now(),
		}

		// withdraw_history 테이블에 저장
		err = h.container.DB.Table("withdraw_history").Create(withdrawInfo).Error
		if err != nil {
			logger.GetLogger().WithError(err).Error("Failed to create withdraw_history record")
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to create withdraw history"})
		}

		logger.GetLogger().WithFields(map[string]interface{}{
			"withdraw_id": withdrawInfo.ID,
			"token":       token,
			"to_address":  toAddr,
			"amount":      amountStr,
			"memo":        memo,
		}).Info("Withdraw history record created")

		switch cc.Blockchain.WalletType {
		case "ETHEREUM":
			res, err := h.EtherSend(token, toAddr, amountStr, memo)
			if err != nil {
				// 에러 발생 시 withdraw_history 상태 업데이트
				h.container.DB.Table("withdraw_history").Where("id = ?", withdrawInfo.ID).Update("process", "error")
				logger.GetLogger().WithError(err).Error("EtherSend failed")
				return c.JSON(http.StatusInternalServerError, map[string]string{"error": "EtherSend failed"})
			}
			return c.JSON(http.StatusOK, map[string]string{"result": res})
		case "TRON":
			res, err := h.TronSend(token, toAddr, amountStr, memo)
			if err != nil {
				// 에러 발생 시 withdraw_history 상태 업데이트
				h.container.DB.Table("withdraw_history").Where("id = ?", withdrawInfo.ID).Update("process", "error")
				logger.GetLogger().WithError(err).Error("TronSend failed")
				return c.JSON(http.StatusInternalServerError, map[string]string{"error": "TronSend failed"})
			}
			return c.JSON(http.StatusOK, map[string]string{"result": res})
		default:
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Unsupported blockchain type"})
		}
	}
}

// GetCurrency retrieves currency by token symbol
func (h *RestAPIHandler) GetCurrency(token string) (*entities.Currency, error) {
	return h.container.CurrencyRepo.GetCurrency(context.Background(), token)
}

// EtherSend handles Ethereum transactions
func (h *RestAPIHandler) EtherSend(token, toAddr, amountStr, memo string) (string, error) {
	// This would need to be implemented based on the existing EtherSend logic
	// For now, returning a placeholder
	return "EtherSend placeholder", nil
}

// TronSend handles TRON transactions
func (h *RestAPIHandler) TronSend(token, toAddr, amountStr, memo string) (string, error) {
	// This would need to be implemented based on the existing TronSend logic
	// For now, returning a placeholder
	return "TronSend placeholder", nil
}
