package services

import (
	"context"
	"errors"

	"github.com/acecasino/account_manage/internal/domain/entities"
	"github.com/acecasino/account_manage/internal/domain/repositories"
)

// UserService defines the interface for user business logic
type UserService interface {
	GetUserByID(ctx context.Context, id int) (*entities.User, error)
	GetUserByEmail(ctx context.Context, email string) (*entities.User, error)
	CreateUser(ctx context.Context, user *entities.User) error
	UpdateUser(ctx context.Context, user *entities.User) error
	DeleteUser(ctx context.Context, id int) error
	BlockUser(ctx context.Context, id int) error
	UnblockUser(ctx context.Context, id int) error
}

// userService implements UserService interface
type userService struct {
	userRepo repositories.UserRepository
}

// NewUserService creates a new user service
func NewUserService(userRepo repositories.UserRepository) UserService {
	return &userService{
		userRepo: userRepo,
	}
}

// GetUserByID retrieves a user by ID
func (s *userService) GetUserByID(ctx context.Context, id int) (*entities.User, error) {
	if id <= 0 {
		return nil, errors.New("invalid user ID")
	}

	return s.userRepo.GetByID(ctx, id)
}

// GetUserByEmail retrieves a user by email
func (s *userService) GetUserByEmail(ctx context.Context, email string) (*entities.User, error) {
	if email == "" {
		return nil, errors.New("email cannot be empty")
	}

	return s.userRepo.GetByEmail(ctx, email)
}

// CreateUser creates a new user
func (s *userService) CreateUser(ctx context.Context, user *entities.User) error {
	if user == nil {
		return errors.New("user cannot be nil")
	}

	if user.Email == "" {
		return errors.New("email is required")
	}

	if user.Username == "" {
		return errors.New("username is required")
	}

	return s.userRepo.Create(ctx, user)
}

// UpdateUser updates an existing user
func (s *userService) UpdateUser(ctx context.Context, user *entities.User) error {
	if user == nil {
		return errors.New("user cannot be nil")
	}

	if user.ID <= 0 {
		return errors.New("invalid user ID")
	}

	return s.userRepo.Update(ctx, user)
}

// DeleteUser deletes a user
func (s *userService) DeleteUser(ctx context.Context, id int) error {
	if id <= 0 {
		return errors.New("invalid user ID")
	}

	return s.userRepo.Delete(ctx, id)
}

// BlockUser blocks a user
func (s *userService) BlockUser(ctx context.Context, id int) error {
	if id <= 0 {
		return errors.New("invalid user ID")
	}

	return s.userRepo.Block(ctx, id)
}

// UnblockUser unblocks a user
func (s *userService) UnblockUser(ctx context.Context, id int) error {
	if id <= 0 {
		return errors.New("invalid user ID")
	}

	return s.userRepo.Unblock(ctx, id)
}
