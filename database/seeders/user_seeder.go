package seeders

import (
	"fmt"
	"goravel/app/models"

	"github.com/goravel/framework/facades"
	"golang.org/x/crypto/bcrypt"
)

type UserSeeder struct {
}

// Signature The name and signature of the seeder.
func (s *UserSeeder) Signature() string {
	return "UserSeeder"
}

// Run executes the seeder logic.
func (s *UserSeeder) Run() error {
	facades.Log().Info(fmt.Sprintf("%s started", s.Signature()))
	defer facades.Log().Info(fmt.Sprintf("%s completed", s.Signature()))

	// Ensure system user for seeding exists
	var systemUser models.User
	err := facades.Orm().Query().Where("id = ?", models.USER_SEEDER_ULID).First(&systemUser)
	if err != nil || systemUser.ID == "" {
		systemUser = models.User{
			BaseModel: models.BaseModel{ID: models.USER_SEEDER_ULID},
			Name:      "System Seeder",
			Email:     "system-seeder@goravel.com",
			Password:  "", // No password needed
			IsActive:  false,
		}
		err = facades.Orm().Query().Create(&systemUser)
		if err != nil {
			return err
		}
		facades.Log().Info("Created system seeder user with ULID: " + models.USER_SEEDER_ULID)
	}

	// Create default users
	users := []map[string]interface{}{
		{
			"name":       "Seed User",
			"email":      "seed@goravel.com",
			"password":   "password123",
			"role":       "super-admin",
			"isActive":   false,
			"created_by": models.USER_SEEDER_ULID,
			"updated_by": models.USER_SEEDER_ULID,
		},
		{
			"name":       "Super Administrator",
			"email":      "superadmin@goravel.com",
			"password":   "password123",
			"role":       "super-admin",
			"isActive":   true,
			"created_by": models.USER_SEEDER_ULID, // System-created
			"updated_by": models.USER_SEEDER_ULID, // System-created
		},
		{
			"name":       "Admin User",
			"email":      "admin@goravel.com",
			"password":   "password123",
			"role":       "admin",
			"isActive":   true,
			"created_by": models.USER_SEEDER_ULID, // System-created
			"updated_by": models.USER_SEEDER_ULID, // System-created
		},
		{
			"name":       "Manager User",
			"email":      "manager@goravel.com",
			"password":   "password123",
			"role":       "manager",
			"isActive":   true,
			"created_by": models.USER_SEEDER_ULID, // System-created
			"updated_by": models.USER_SEEDER_ULID, // System-created
		},
		{
			"name":       "Regular User",
			"email":      "user@goravel.com",
			"password":   "password123",
			"role":       "user",
			"isActive":   true,
			"created_by": models.USER_SEEDER_ULID, // System-created
			"updated_by": models.USER_SEEDER_ULID, // System-created
		},
		{
			"name":       "Test User",
			"email":      "test@goravel.com",
			"password":   "password123",
			"role":       "user",
			"isActive":   true,
			"created_by": models.USER_SEEDER_ULID, // System-created
			"updated_by": models.USER_SEEDER_ULID, // System-created
		},
		{
			"name":       "Guest User",
			"email":      "guest@goravel.com",
			"password":   "password123",
			"role":       "guest",
			"isActive":   true,
			"created_by": models.USER_SEEDER_ULID, // System-created
			"updated_by": models.USER_SEEDER_ULID, // System-created
		},
	}

	for _, userData := range users {
		var existingUser models.User
		err := facades.Orm().Query().Where("email = ?", userData["email"]).First(&existingUser)
		if err != nil || existingUser.ID == "" {
			// Hash password
			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(userData["password"].(string)), bcrypt.DefaultCost)
			if err != nil {
				return err
			}

			// Create user
			user := models.User{
				Name:     userData["name"].(string),
				Email:    userData["email"].(string),
				Password: string(hashedPassword),
				IsActive: userData["isActive"].(bool),
			}

			err = facades.Orm().Query().Create(&user)
			if err != nil {
				return err
			}

			// Assign role to user
			roleName := userData["role"].(string)
			var role models.Role
			err = facades.Orm().Query().Where("name = ?", roleName).First(&role)
			if err == nil && role.ID != "" {
				userRole := models.UserRole{
					UserID: user.ID,
					RoleID: role.ID,
				}
				err = facades.Orm().Query().Create(&userRole)
				if err != nil {
					return err
				}
			}

			facades.Log().Info("Created user: " + user.Email)
		} else {
			facades.Log().Info("User already exists: " + existingUser.Email)
		}
	}

	return nil
}
