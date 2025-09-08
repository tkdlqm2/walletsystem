package entities

// ChainAccount represents chain account information
type ChainAccount struct {
	ID             int    `gorm:"primaryKey;autoIncrement;column:id"`
	UserID         int    `gorm:"column:user_id"`
	WalletType     string `gorm:"column:wallet_type"`
	AccountAddress string `gorm:"column:account_address"`
	PrivateKey     string `gorm:"column:private_key"`
}

func (ChainAccount) TableName() string {
	return "chain_accounts"
}
