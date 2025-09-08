package repositories

import (
	"context"

	"github.com/acecasino/account_manage/internal/domain/entities"
)

// ErrorLogsRepository defines the interface for error logs data operations
type ErrorLogsRepository interface {
	GetByID(ctx context.Context, id int) (*entities.ErrorLogs, error)
	GetAll(ctx context.Context) ([]entities.ErrorLogs, error)
	Create(ctx context.Context, errorLog *entities.ErrorLogs) error
	Update(ctx context.Context, errorLog *entities.ErrorLogs) error
	Delete(ctx context.Context, id int) error
	// Legacy functions for backward compatibility
	SendErrMsg(ctx context.Context, code string, err error) error
}
