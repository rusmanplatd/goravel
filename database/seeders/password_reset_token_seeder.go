package seeders

import (
	"fmt"
	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type PasswordResetTokenSeeder struct {
}

// Signature The name and signature of the seeder.
func (s *PasswordResetTokenSeeder) Signature() string {
	return "PasswordResetTokenSeeder"
}

// Run executes the seeder logic.
func (s *PasswordResetTokenSeeder) Run() error {
	facades.Log().Info(fmt.Sprintf("%s started", s.Signature()))
	defer facades.Log().Info(fmt.Sprintf("%s completed", s.Signature()))
	// Get users to associate with password reset tokens
	var users []models.User
	err := facades.Orm().Query().Limit(5).Find(&users)
	if err != nil {
		facades.Log().Info("No users found, skipping PasswordResetTokenSeeder")
		return nil
	}

	if len(users) == 0 {
		facades.Log().Info("No users found, skipping PasswordResetTokenSeeder")
		return nil
	}

	// Create password reset tokens
	passwordResetTokens := []models.PasswordResetToken{
		{
			Email: users[0].Email,
			Token: "valid-token-1",
		},
		{
			Email: users[0].Email,
			Token: "expired-token-1",
		},
		{
			Email: users[0].Email,
			Token: "valid-token-2",
		},
	}

	// Add password reset tokens for other users
	if len(users) > 1 {
		passwordResetTokens = append(passwordResetTokens, models.PasswordResetToken{
			Email: users[1].Email,
			Token: "valid-token-user2",
		})
	}

	if len(users) > 2 {
		passwordResetTokens = append(passwordResetTokens, models.PasswordResetToken{
			Email: users[2].Email,
			Token: "expired-token-user3",
		})
	}

	// Create password reset tokens in database
	for _, token := range passwordResetTokens {
		// Check if password reset token already exists
		var existingToken models.PasswordResetToken
		err := facades.Orm().Query().Where("email = ? AND token = ?", token.Email, token.Token).First(&existingToken)
		if err == nil {
			facades.Log().Info("Password reset token already exists for: " + token.Email)
			continue
		}

		err = facades.Orm().Query().Create(&token)
		if err != nil {
			facades.Log().Error("Failed to create password reset token: " + err.Error())
			return err
		}

		facades.Log().Info("Created password reset token for: " + token.Email)
	}

	// Create additional password reset tokens for testing edge cases
	edgeCaseTokens := []models.PasswordResetToken{
		{
			Email: "nonexistent@example.com",
			Token: "token-for-nonexistent-user",
		},
		{
			Email: users[0].Email,
			Token: "almost-expired-token",
		},
	}

	// Create edge case tokens in database
	for _, token := range edgeCaseTokens {
		// Check if password reset token already exists
		var existingToken models.PasswordResetToken
		err := facades.Orm().Query().Where("email = ? AND token = ?", token.Email, token.Token).First(&existingToken)
		if err == nil {
			facades.Log().Info("Password reset token already exists for: " + token.Email)
			continue
		}

		err = facades.Orm().Query().Create(&token)
		if err != nil {
			facades.Log().Error("Failed to create edge case password reset token: " + err.Error())
			return err
		}

		facades.Log().Info("Created edge case password reset token for: " + token.Email)
	}

	facades.Log().Info("Password reset tokens seeded successfully")
	return nil
}
