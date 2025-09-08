package entities

import (
	"time"
)

// UserBalance represents the user_balance table
type UserBalance struct {
	ID         uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	AccountID  int       `gorm:"column:account_id;not null" json:"account_id"`
	CurrencyID int       `gorm:"column:currency_id;not null" json:"currency_id"`
	Balance    float64   `gorm:"column:balance;type:decimal(38,18);default:0;not null" json:"balance"`
	Bonus      float64   `gorm:"column:bonus;type:decimal(38,18);default:0;not null" json:"bonus"`
	UpdateAt   time.Time `gorm:"column:update_at;default:CURRENT_TIMESTAMP" json:"update_at"`
	LastAction string    `gorm:"column:last_action" json:"last_action"`
	UserID     int       `gorm:"column:user_id;not null" json:"user_id"`

	// Foreign key relationships
	Account  ChainAccount `gorm:"foreignKey:AccountID;references:ID;constraint:OnDelete:CASCADE,OnUpdate:CASCADE" json:"account,omitempty"`
	Currency Currency     `gorm:"foreignKey:CurrencyID;references:ID" json:"currency,omitempty"`
	User     User         `gorm:"foreignKey:UserID;references:ID" json:"user,omitempty"`
}

// TableName returns the table name for UserBalance
func (UserBalance) TableName() string {
	return "user_balance"
}
