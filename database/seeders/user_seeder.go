package seeders

import (
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
	// Create default users
	users := []map[string]interface{}{
		{
			"name":     "Super Administrator",
			"email":    "superadmin@goravel.com",
			"password": "password123",
			"role":     "super-admin",
			"isActive": true,
		},
		{
			"name":     "Admin User",
			"email":    "admin@goravel.com",
			"password": "password123",
			"role":     "admin",
			"isActive": true,
		},
		{
			"name":     "Manager User",
			"email":    "manager@goravel.com",
			"password": "password123",
			"role":     "manager",
			"isActive": true,
		},
		{
			"name":     "Regular User",
			"email":    "user@goravel.com",
			"password": "password123",
			"role":     "user",
			"isActive": true,
		},
		{
			"name":     "Test User",
			"email":    "test@goravel.com",
			"password": "password123",
			"role":     "user",
			"isActive": true,
		},
		{
			"name":     "Guest User",
			"email":    "guest@goravel.com",
			"password": "password123",
			"role":     "guest",
			"isActive": true,
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
