package entities

import (
	"time"
)

// WithdrawInfo represents withdraw information for API responses
type WithdrawInfo struct {
	ID         int        `json:"id"`
	UserID     int        `json:"user_id"`
	CurrencyID int        `json:"currency_id"`
	ToAddress  string     `json:"to_address"`
	Amount     string     `json:"amount"`
	CreateAt   time.Time  `json:"create_at"`
	Process    string     `json:"process"`
	TxRef      int        `json:"tx_ref"`
	Fee        float64    `json:"fee"`
	Take       float64    `json:"take"`
	TxHash     string     `json:"tx_hash"`
	Editor     string     `json:"editor"`
	UpdateAt   *time.Time `json:"update_at"`
	IP         string     `json:"ip"`
}
