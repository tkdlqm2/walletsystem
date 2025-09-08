package repositories

import (
	"context"
	"errors"

	"github.com/acecasino/account_manage/internal/domain/entities"
	"gorm.io/gorm"
)

type UserRepository struct {
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) *UserRepository {
	return &UserRepository{db: db}
}

// GetByID retrieves user by ID
func (r *UserRepository) GetByID(ctx context.Context, id int) (*entities.User, error) {
	var user entities.User
	err := r.db.WithContext(ctx).First(&user, id).Error
	return &user, err
}

// GetByEmail retrieves user by email
func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*entities.User, error) {
	var user entities.User
	err := r.db.WithContext(ctx).Where("email = ?", email).First(&user).Error
	return &user, err
}

// GetByUsername retrieves user by username
func (r *UserRepository) GetByUsername(ctx context.Context, username string) (*entities.User, error) {
	var user entities.User
	err := r.db.WithContext(ctx).Where("username = ?", username).First(&user).Error
	return &user, err
}

// GetByRedeemCode retrieves user by redeem code
func (r *UserRepository) GetByRedeemCode(ctx context.Context, redeemCode string) (*entities.User, error) {
	var user entities.User
	err := r.db.WithContext(ctx).Where("redeem_code = ?", redeemCode).First(&user).Error
	return &user, err
}

// GetAll retrieves all users
func (r *UserRepository) GetAll(ctx context.Context) ([]entities.User, error) {
	var users []entities.User
	err := r.db.WithContext(ctx).Find(&users).Error
	return users, err
}

// GetBlocked retrieves all blocked users
func (r *UserRepository) GetBlocked(ctx context.Context) ([]entities.User, error) {
	var users []entities.User
	err := r.db.WithContext(ctx).Where("block = ?", true).Find(&users).Error
	return users, err
}

// Create creates a new user
func (r *UserRepository) Create(ctx context.Context, user *entities.User) error {
	return r.db.WithContext(ctx).Create(user).Error
}

// Update updates a user
func (r *UserRepository) Update(ctx context.Context, user *entities.User) error {
	return r.db.WithContext(ctx).Save(user).Error
}

// Delete deletes a user
func (r *UserRepository) Delete(ctx context.Context, id int) error {
	return r.db.WithContext(ctx).Delete(&entities.User{}, id).Error
}

// Block blocks a user
func (r *UserRepository) Block(ctx context.Context, id int) error {
	return r.db.WithContext(ctx).Model(&entities.User{}).Where("id = ?", id).Update("block", true).Error
}

// Unblock unblocks a user
func (r *UserRepository) Unblock(ctx context.Context, id int) error {
	return r.db.WithContext(ctx).Model(&entities.User{}).Where("id = ?", id).Update("block", false).Error
}

// GetUserIDByEmail retrieves user ID by email (legacy function)
func (r *UserRepository) GetUserIDByEmail(ctx context.Context, email string) (int, error) {
	var user entities.User
	err := r.db.WithContext(ctx).Where("email = ?", email).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return 0, errors.New("user not found")
		}
		return 0, err
	}
	return int(user.ID), nil
}
