package seeders

import (
	"fmt"
	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type UserRoleSeeder struct {
}

// Signature The name and signature of the seeder.
func (s *UserRoleSeeder) Signature() string {
	return "UserRoleSeeder"
}

// Run executes the seeder logic.
func (s *UserRoleSeeder) Run() error {
	facades.Log().Info(fmt.Sprintf("%s started", s.Signature()))
	defer facades.Log().Info(fmt.Sprintf("%s completed", s.Signature()))
	// Get all users
	var users []models.User
	err := facades.Orm().Query().Find(&users)
	if err != nil {
		facades.Log().Info("No users found, skipping UserRoleSeeder")
		return nil
	}

	// Get all roles
	var roles []models.Role
	err = facades.Orm().Query().Find(&roles)
	if err != nil {
		facades.Log().Info("No roles found, skipping UserRoleSeeder")
		return nil
	}

	// Get all tenants
	var tenants []models.Tenant
	err = facades.Orm().Query().Find(&tenants)
	if err != nil {
		facades.Log().Info("No tenants found, skipping UserRoleSeeder")
		return nil
	}

	// Create user-role assignments
	userRoleAssignments := []struct {
		userEmail   string
		roleName    string
		tenantName  string
		description string
	}{
		{
			userEmail:   "superadmin@goravel.com",
			roleName:    "super-admin",
			tenantName:  "",
			description: "Super admin with global access",
		},
		{
			userEmail:   "admin@goravel.com",
			roleName:    "admin",
			tenantName:  "Default Company",
			description: "Admin for default tenant",
		},
		{
			userEmail:   "manager@goravel.com",
			roleName:    "manager",
			tenantName:  "Default Company",
			description: "Manager for default tenant",
		},
		{
			userEmail:   "user@goravel.com",
			roleName:    "user",
			tenantName:  "Default Company",
			description: "Regular user for default tenant",
		},
		{
			userEmail:   "test@goravel.com",
			roleName:    "user",
			tenantName:  "Default Company",
			description: "Test user for default tenant",
		},
		{
			userEmail:   "guest@goravel.com",
			roleName:    "guest",
			tenantName:  "Default Company",
			description: "Guest user for default tenant",
		},
		{
			userEmail:   "admin@example.com",
			roleName:    "admin",
			tenantName:  "Test Company 1",
			description: "Admin for test company 1",
		},
		{
			userEmail:   "test1@example.com",
			roleName:    "user",
			tenantName:  "Test Company 1",
			description: "User for test company 1",
		},
		{
			userEmail:   "test2@example.com",
			roleName:    "manager",
			tenantName:  "Test Company 2",
			description: "Manager for test company 2",
		},
	}

	// Process each assignment
	for _, assignment := range userRoleAssignments {
		// Find user
		var user models.User
		err := facades.Orm().Query().Where("email = ?", assignment.userEmail).First(&user)
		if err != nil {
			facades.Log().Warning("User not found: " + assignment.userEmail)
			continue
		}

		// Find role
		var role models.Role
		err = facades.Orm().Query().Where("name = ?", assignment.roleName).First(&role)
		if err != nil {
			facades.Log().Warning("Role not found: " + assignment.roleName)
			continue
		}

		// Find tenant (if specified)
		var tenantID *string
		if assignment.tenantName != "" {
			var tenant models.Tenant
			err = facades.Orm().Query().Where("name = ?", assignment.tenantName).First(&tenant)
			if err != nil {
				facades.Log().Warning("Tenant not found: " + assignment.tenantName)
				continue
			}
			tenantID = &tenant.ID
		}

		// Check if user-role relationship already exists
		var existingUserRole models.UserRole
		err = facades.Orm().Query().Where("user_id = ? AND role_id = ?", user.ID, role.ID).First(&existingUserRole)
		if err == nil {
			facades.Log().Info("User-role relationship already exists: " + assignment.description)
			continue
		}

		// Create user-role relationship
		userRole := models.UserRole{
			UserID:   user.ID,
			RoleID:   role.ID,
			TenantID: tenantID,
		}

		err = facades.Orm().Query().Create(&userRole)
		if err != nil {
			facades.Log().Error("Failed to create user-role relationship: " + err.Error())
			return err
		}

		facades.Log().Info("Created user-role relationship: " + assignment.description)
	}

	// Create some additional random user-role assignments for testing
	for i, user := range users {
		if i >= 5 { // Limit to first 5 users to avoid too many assignments
			break
		}

		for j, role := range roles {
			if j >= 3 { // Limit to first 3 roles per user
				break
			}

			// Skip if this is a super-admin role and user is not superadmin
			if role.Name == "super-admin" && user.Email != "superadmin@goravel.com" {
				continue
			}

			// Check if relationship already exists
			var existingUserRole models.UserRole
			err := facades.Orm().Query().Where("user_id = ? AND role_id = ?", user.ID, role.ID).First(&existingUserRole)
			if err == nil {
				continue // Already exists
			}

			// Assign to a random tenant if available
			var tenantID *string
			if len(tenants) > 0 {
				tenantIndex := i % len(tenants)
				tenantID = &tenants[tenantIndex].ID
			}

			userRole := models.UserRole{
				UserID:   user.ID,
				RoleID:   role.ID,
				TenantID: tenantID,
			}

			err = facades.Orm().Query().Create(&userRole)
			if err != nil {
				facades.Log().Error("Failed to create additional user-role relationship: " + err.Error())
				return err
			}
		}
	}

	facades.Log().Info("User-role relationships seeded successfully")
	return nil
}
