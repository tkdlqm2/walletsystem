package entities

import "time"

// TransferHistory represents transfer history information
type TransferHistory struct {
	ID          int       `gorm:"primaryKey;autoIncrement;column:id"`
	CurrencyID  int       `gorm:"column:currency_id"`
	BlockNumber uint64    `gorm:"column:block_number"`
	TxHash      string    `gorm:"column:tx_hash"`
	EventIndex  int       `gorm:"column:event_index"`
	From        string    `gorm:"column:_from"`
	To          string    `gorm:"column:_to"`
	Amount      string    `gorm:"column:amount"`
	CreateAt    time.Time `gorm:"column:create_at"`
	Processed   bool      `gorm:"column:processed;default:false;index:idx_transfer_history_processed_createat"`
}

func (TransferHistory) TableName() string {
	return "transfer_history"
}
