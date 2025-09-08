package repositories

import (
	"context"

	"github.com/acecasino/account_manage/internal/domain/entities"
)

// CurrencyRepository defines the interface for currency data operations
type CurrencyRepository interface {
	GetByID(ctx context.Context, id int) (*entities.Currency, error)
	GetBySymbol(ctx context.Context, symbol string) (*entities.Currency, error)
	GetBySymbolWithBlockchain(ctx context.Context, symbol string) (*entities.Currency, error)
	GetAll(ctx context.Context) ([]entities.Currency, error)
	GetActive(ctx context.Context) ([]entities.Currency, error)
	GetByChainID(ctx context.Context, chainID int) ([]entities.Currency, error)
	Create(ctx context.Context, currency *entities.Currency) error
	Update(ctx context.Context, currency *entities.Currency) error
	Delete(ctx context.Context, id int) error
	// Legacy functions for backward compatibility
	GetCurrency(ctx context.Context, token string) (*entities.Currency, error)
}
