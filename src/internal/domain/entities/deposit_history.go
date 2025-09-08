package entities

import (
	"time"

	"github.com/shopspring/decimal"
)

type DepositHistory struct {
	ID          int             `gorm:"primaryKey;autoIncrement;column:id" json:"id"`
	AccountID   int             `gorm:"column:account_id" json:"account_id"`
	TxRef       int64           `gorm:"column:tx_ref" json:"tx_ref"`
	CurrencyID  int             `gorm:"column:currency_id" json:"currency_id"`
	FromAddr    string          `gorm:"size:255;column:from_addr" json:"from_addr"`
	ToAddr      string          `gorm:"size:255;column:to_addr" json:"to_addr"`
	TxHash      string          `gorm:"size:66;column:tx_hash" json:"tx_hash"`
	BlockNumber int64           `gorm:"column:block_number" json:"block_number"`
	Amount      decimal.Decimal `gorm:"type:decimal(38,18);column:amount" json:"amount"`
	Created     time.Time       `gorm:"column:created;default:CURRENT_TIMESTAMP" json:"created"`
}

func (DepositHistory) TableName() string {
	return "deposit_history"
}

type DepositProcessingResult struct {
	TotalProcessed int                   `json:"total_processed"`
	Successful     int                   `json:"successful"`
	Duplicates     int                   `json:"duplicates"`
	Failed         []FailedDepositDetail `json:"failed"`
	Duration       time.Duration         `json:"duration"`
}

type FailedDepositDetail struct {
	EventID int64  `json:"event_id"`
	Reason  string `json:"reason"`
	Error   string `json:"error"`
}

type DepositBatchData struct {
	Accounts   map[string]*ChainAccount `json:"accounts"`
	Currencies map[int]*Currency        `json:"currencies"`
}
