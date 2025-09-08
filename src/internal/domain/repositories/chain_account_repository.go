package repositories

import (
	"context"

	"github.com/acecasino/account_manage/internal/domain/entities"
)

// ChainAccountRepository defines the interface for chain account data operations
type ChainAccountRepository interface {
	GetByID(ctx context.Context, id int) (*entities.ChainAccount, error)
	GetByUserID(ctx context.Context, userID int) ([]entities.ChainAccount, error)
	GetByUserIDAndWalletType(ctx context.Context, userID int, walletType string) (*entities.ChainAccount, error)
	GetByEmailAndWalletType(ctx context.Context, email, walletType string) (*entities.ChainAccount, error)
	GetByAddress(ctx context.Context, address string) (*entities.ChainAccount, error)
	GetAll(ctx context.Context) ([]entities.ChainAccount, error)
	Create(ctx context.Context, account *entities.ChainAccount) error
	Update(ctx context.Context, account *entities.ChainAccount) error
	Delete(ctx context.Context, id int) error
	GetPrivateKeyUsingEmail(ctx context.Context, email string) (map[string]string, error)
	GetPrivateKeyUsingEmailAndWalletType(ctx context.Context, email, walletType string) (string, error)
	// Legacy functions for backward compatibility
	GetChainAccountByEmailAndWalletType(ctx context.Context, email, walletType string) (*entities.ChainAccount, error)
	GetPrivateKeyUsingEmailLegacy(ctx context.Context, email string) ([]entities.ChainAccount, error)
}
