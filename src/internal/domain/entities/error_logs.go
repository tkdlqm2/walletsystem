package entities

import "gorm.io/gorm"

// ErrorLogs represents error logs in the database
type ErrorLogs struct {
	gorm.Model
	Code string `gorm:"column:code"`
	Msg  string `gorm:"column:msg"`
}

func (ErrorLogs) TableName() string {
	return "error_logs"
}
