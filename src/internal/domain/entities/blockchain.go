package entities

// Blockchain represents blockchain information
type Blockchain struct {
	ID               int    `gorm:"primaryKey;autoIncrement;column:id"`
	Name             string `gorm:"size:50;not null;column:name"`
	RpcURL           string `gorm:"type:text;column:rpc_url"`
	TraceInterval    int    `gorm:"column:trace_interval"`
	WalletType       string `gorm:"size:20;column:wallet_type"`
	LastCheckedBlock int    `gorm:"column:last_checked_block"`
	ActiveWatch      bool   `gorm:"default:false;not null;column:active_watch"`
	FinalityBlock    int    `gorm:"default:0;column:finality_block"`
	ScanURL          string `gorm:"column:scan_url"`
	ChainID          int    `gorm:"column:chain_id"`
	WithdrawAddress  string `gorm:"size:100;column:withdraw_address"` // Admin 지갑주소
}

func (Blockchain) TableName() string {
	return "blockchain"
}
