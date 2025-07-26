package migrations

import (
	"github.com/goravel/framework/facades"
)

type M20250115000074MigrateGoogleOauthToIdp struct{}

// Signature returns the unique identifier for this migration
func (r *M20250115000074MigrateGoogleOauthToIdp) Signature() string {
	return "20250115000074_migrate_google_oauth_to_idp"
}

// Up runs the migration
func (r *M20250115000074MigrateGoogleOauthToIdp) Up() error {
	// This migration will be handled by a custom data migration
	// We'll create the logic to migrate existing Google OAuth users
	// to the new OAuth Identity Provider structure

	// Get all users with google_id
	type User struct {
		ID       string  `gorm:"column:id"`
		Email    string  `gorm:"column:email"`
		Name     string  `gorm:"column:name"`
		Avatar   string  `gorm:"column:avatar"`
		GoogleID *string `gorm:"column:google_id"`
	}

	var users []User
	err := facades.Orm().Query().Table("users").Where("google_id IS NOT NULL AND google_id != ''").Find(&users)
	if err != nil {
		facades.Log().Error("Failed to get users with Google ID", map[string]interface{}{
			"error": err.Error(),
		})
		return nil // Continue migration even if this fails
	}

	// Get the Google provider ID
	type Provider struct {
		ID uint `gorm:"column:id"`
	}

	var provider Provider
	err = facades.Orm().Query().Table("oauth_identity_providers").Where("name", "google").First(&provider)
	if err != nil {
		facades.Log().Warning("Google OAuth provider not found, skipping user migration", map[string]interface{}{
			"error": err.Error(),
		})
		return nil // Continue migration
	}

	// Migrate each user
	for _, user := range users {
		if user.GoogleID == nil || *user.GoogleID == "" {
			continue
		}

		// Check if identity already exists
		existingCount, err := facades.Orm().Query().Table("oauth_user_identities").
			Where("user_id", user.ID).
			Where("provider_id", provider.ID).
			Count()
		if err != nil {
			facades.Log().Error("Failed to check existing identity", map[string]interface{}{
				"user_id": user.ID,
				"error":   err.Error(),
			})
			continue
		}

		if existingCount > 0 {
			continue // Identity already exists
		}

		// Create new OAuth user identity
		identity := map[string]interface{}{
			"user_id":          user.ID,
			"provider_id":      provider.ID,
			"provider_user_id": *user.GoogleID,
			"provider_email":   user.Email,
			"provider_name":    user.Name,
			"provider_avatar":  user.Avatar,
			"created_at":       "NOW()",
			"updated_at":       "NOW()",
		}

		err = facades.Orm().Query().Table("oauth_user_identities").Create(&identity)
		if err != nil {
			facades.Log().Error("Failed to create OAuth identity for user", map[string]interface{}{
				"user_id":   user.ID,
				"google_id": *user.GoogleID,
				"error":     err.Error(),
			})
		} else {
			facades.Log().Info("Migrated Google OAuth user", map[string]interface{}{
				"user_id":   user.ID,
				"google_id": *user.GoogleID,
			})
		}
	}

	facades.Log().Info("Google OAuth migration completed", map[string]interface{}{
		"migrated_users": len(users),
	})

	return nil
}

// Down reverses the migration
func (r *M20250115000074MigrateGoogleOauthToIdp) Down() error {
	// Remove OAuth identities for Google provider
	var provider struct {
		ID uint `gorm:"column:id"`
	}

	err := facades.Orm().Query().Table("oauth_identity_providers").Where("name", "google").First(&provider)
	if err != nil {
		return nil // Provider not found, nothing to clean up
	}

	_, err = facades.Orm().Query().Table("oauth_user_identities").Where("provider_id", provider.ID).Delete()
	return err
}
