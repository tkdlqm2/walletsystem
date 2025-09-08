package entities

// Currency represents currency information
type Currency struct {
	ID           int        `gorm:"primaryKey;autoIncrement;column:id"`
	ChainID      int        `gorm:"column:chain_id"`
	Blockchain   Blockchain `gorm:"foreignKey:ChainID;references:ID"`
	Name         string     `gorm:"size:50;not null;column:name"`
	Symbol       string     `gorm:"size:20;not null;uniqueIndex:currency_symbol_idx;column:symbol"`
	Address      string     `gorm:"size:200;not null;column:address"`
	Price        float64    `gorm:"type:numeric(38,18);column:price"`
	Decimal      int        `gorm:"type:numeric;column:decimal"`
	ActiveWatch  bool       `gorm:"default:false;not null;column:active_watch"`
	DefaultValue bool       `gorm:"column:default_value"`
}

func (Currency) TableName() string {
	return "currency"
}
