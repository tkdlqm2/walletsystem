package repositories

import (
	"context"
	"errors"

	"github.com/acecasino/account_manage/internal/domain/entities"
	"github.com/acecasino/account_manage/internal/domain/repositories"
	"gorm.io/gorm"
)

// errorLogsRepository implements ErrorLogsRepository interface
type errorLogsRepository struct {
	db *gorm.DB
}

// NewErrorLogsRepository creates a new error logs repository
func NewErrorLogsRepository(db *gorm.DB) repositories.ErrorLogsRepository {
	return &errorLogsRepository{db: db}
}

// GetByID retrieves error log by ID
func (r *errorLogsRepository) GetByID(ctx context.Context, id int) (*entities.ErrorLogs, error) {
	var errorLog entities.ErrorLogs
	err := r.db.WithContext(ctx).First(&errorLog, id).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &errorLog, nil
}

// GetAll retrieves all error logs
func (r *errorLogsRepository) GetAll(ctx context.Context) ([]entities.ErrorLogs, error) {
	var errorLogs []entities.ErrorLogs
	err := r.db.WithContext(ctx).Find(&errorLogs).Error
	return errorLogs, err
}

// Create creates a new error log
func (r *errorLogsRepository) Create(ctx context.Context, errorLog *entities.ErrorLogs) error {
	return r.db.WithContext(ctx).Create(errorLog).Error
}

// Update updates an existing error log
func (r *errorLogsRepository) Update(ctx context.Context, errorLog *entities.ErrorLogs) error {
	return r.db.WithContext(ctx).Save(errorLog).Error
}

// Delete deletes an error log
func (r *errorLogsRepository) Delete(ctx context.Context, id int) error {
	return r.db.WithContext(ctx).Delete(&entities.ErrorLogs{}, id).Error
}

// SendErrMsg sends error message to error_logs table (legacy function)
func (r *errorLogsRepository) SendErrMsg(ctx context.Context, code string, err error) error {
	errorLog := entities.ErrorLogs{
		Code: code,
		Msg:  err.Error(),
	}
	return r.Create(ctx, &errorLog)
}
