package entities

import (
	"time"
)

// CollectHistory represents the collect_history table
type CollectHistory struct {
	ID          int64     `gorm:"primaryKey;autoIncrement;column:id" json:"id"`
	CurrencyID  int       `gorm:"column:currency_id" json:"currency_id"`
	FromAddr    string    `gorm:"size:255;column:from_addr" json:"from_addr"`
	ToAddr      string    `gorm:"size:255;column:to_addr" json:"to_addr"`
	TxHash      string    `gorm:"size:66;column:tx_hash" json:"tx_hash"`
	BlockNumber int64     `gorm:"column:block_number" json:"block_number"`
	Amount      float64   `gorm:"type:decimal(38,18);column:amount" json:"amount"`
	Created     time.Time `gorm:"column:created;default:CURRENT_TIMESTAMP" json:"created"`
}

// TableName returns the table name for CollectHistory
func (CollectHistory) TableName() string {
	return "collect_history"
}
