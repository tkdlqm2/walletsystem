package entities

import "time"

// User represents user information
type User struct {
	ID         int       `gorm:"primaryKey;autoIncrement;column:id"`
	Username   string    `gorm:"size:50;not null;column:username"`
	Email      string    `gorm:"size:255;not null;uniqueIndex:users_email_idx;column:email"`
	Lang       string    `gorm:"size:4;column:lang"`
	BirthDay   time.Time `gorm:"column:birth_day;default:1900-01-01"`
	Marketing  bool      `gorm:"column:marketing;default:true"`
	CreateAt   time.Time `gorm:"column:create_at;default:CURRENT_TIMESTAMP;not null"`
	Addrbook   string    `gorm:"column:addrbook"`
	RedeemCode string    `gorm:"size:100;column:redeem_code"`
	RedeemIP   int64     `gorm:"type:numeric(10);uniqueIndex:users_redeem_ip_idx;column:redeem_ip"`
	Block      bool      `gorm:"column:block"`
}

func (User) TableName() string {
	return "users"
}
