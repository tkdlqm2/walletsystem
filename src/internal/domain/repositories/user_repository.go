package repositories

import (
	"context"

	"github.com/acecasino/account_manage/internal/domain/entities"
)

// UserRepository defines the interface for user data operations
type UserRepository interface {
	GetByID(ctx context.Context, id int) (*entities.User, error)
	GetByEmail(ctx context.Context, email string) (*entities.User, error)
	GetByUsername(ctx context.Context, username string) (*entities.User, error)
	GetByRedeemCode(ctx context.Context, redeemCode string) (*entities.User, error)
	GetAll(ctx context.Context) ([]entities.User, error)
	GetBlocked(ctx context.Context) ([]entities.User, error)
	Create(ctx context.Context, user *entities.User) error
	Update(ctx context.Context, user *entities.User) error
	Delete(ctx context.Context, id int) error
	Block(ctx context.Context, id int) error
	Unblock(ctx context.Context, id int) error
	// Legacy functions for backward compatibility
	GetUserIDByEmail(ctx context.Context, email string) (int, error)
}
