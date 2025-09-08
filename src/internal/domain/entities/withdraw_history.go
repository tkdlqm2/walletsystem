package entities

import (
	"time"

	"github.com/shopspring/decimal"
)

// WithdrawHistory represents the withdraw_history table
type WithdrawHistory struct {
	ID         int             `gorm:"primaryKey;autoIncrement;column:id" json:"id"`
	UserID     int             `gorm:"not null;column:user_id" json:"user_id"`
	CurrencyID int             `gorm:"not null;column:currency_id" json:"currency_id"`
	ToAddress  string          `gorm:"type:text;not null;column:to_address" json:"to_address"`
	Amount     decimal.Decimal `gorm:"type:decimal(38,18);not null;column:amount" json:"amount"`
	CreateAt   time.Time       `gorm:"column:create_at;default:now();not null" json:"create_at"`
	Process    string          `gorm:"size:255;column:process" json:"process"`
	TxRef      int             `gorm:"column:tx_ref" json:"tx_ref"`
	Fee        decimal.Decimal `gorm:"type:decimal(38,18);column:fee" json:"fee"`
	Take       decimal.Decimal `gorm:"type:decimal(38,18);column:take" json:"take"`
	TxHash     string          `gorm:"size:120;column:tx_hash" json:"tx_hash"`
	Editor     string          `gorm:"size:200;column:editor" json:"editor"`
	UpdateAt   *time.Time      `gorm:"column:update_at" json:"update_at"`
	IP         string          `gorm:"size:20;column:ip" json:"ip"`
}

// TableName returns the table name for WithdrawHistory
func (WithdrawHistory) TableName() string {
	return "withdraw_history"
}
