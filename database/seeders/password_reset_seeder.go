package seeders

import (
	"goravel/app/models"
	"time"

	"github.com/goravel/framework/facades"
)

type PasswordResetSeeder struct {
}

// Signature The name and signature of the seeder.
func (s *PasswordResetSeeder) Signature() string {
	return "PasswordResetSeeder"
}

// Run executes the seeder logic.
func (s *PasswordResetSeeder) Run() error {
	// Get a test user to associate with password reset tokens
	var user models.User
	err := facades.Orm().Query().First(&user)
	if err != nil {
		facades.Log().Info("No users found, skipping PasswordResetSeeder")
		return nil
	}

	// Create sample password reset tokens for testing
	now := time.Now()

	tokens := []models.PasswordResetToken{
		{
			Email:     user.Email,
			Token:     "test-reset-token-1",
			CreatedAt: now,
		},
		{
			Email:     user.Email,
			Token:     "test-reset-token-2",
			CreatedAt: now.Add(-30 * time.Minute), // Created 30 minutes ago
		},
		{
			Email:     "test@example.com",
			Token:     "test-reset-token-3",
			CreatedAt: now.Add(-2 * time.Hour), // Created 2 hours ago
		},
	}

	// Create tokens in database
	for _, token := range tokens {
		err := facades.Orm().Query().Create(&token)
		if err != nil {
			facades.Log().Error("Failed to create password reset token: " + err.Error())
			return err
		}
	}

	facades.Log().Info("Password reset tokens seeded successfully")
	return nil
}
