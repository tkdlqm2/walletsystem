package entities

// UserWalletBalance represents user wallet balance information
type UserWalletBalance struct {
	ID             int        `gorm:"primaryKey;autoIncrement;column:id"`
	ChainID        int        `gorm:"column:chain_id"`
	Blockchain     Blockchain `gorm:"foreignKey:ChainID;references:ID"`
	ChainAccountID int        `gorm:"column:chain_account_id"`
	Balance        string     `gorm:"type:numeric(38,18);column:balance"`
}

func (UserWalletBalance) TableName() string {
	return "user_wallet_balance"
}
