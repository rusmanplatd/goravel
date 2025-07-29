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

	// Get all organizations
	var organizations []models.Organization
	err = facades.Orm().Query().Find(&organizations)
	if err != nil {
		facades.Log().Info("No organizations found, skipping UserRoleSeeder")
		return nil
	}

	// Create user-role assignments
	userRoleAssignments := []struct {
		userEmail        string
		roleName         string
		organizationName string
		description      string
	}{
		{
			userEmail:        "superadmin@goravel.com",
			roleName:         "super-admin",
			organizationName: "",
			description:      "Super admin with global access",
		},
		{
			userEmail:        "admin@goravel.com",
			roleName:         "admin",
			organizationName: "Default Company",
			description:      "Admin for default organization",
		},
		{
			userEmail:        "manager@goravel.com",
			roleName:         "manager",
			organizationName: "Default Company",
			description:      "Manager for default organization",
		},
		{
			userEmail:        "user@goravel.com",
			roleName:         "user",
			organizationName: "Default Company",
			description:      "Regular user for default organization",
		},
		{
			userEmail:        "test@goravel.com",
			roleName:         "user",
			organizationName: "Default Company",
			description:      "Test user for default organization",
		},
		{
			userEmail:        "guest@goravel.com",
			roleName:         "guest",
			organizationName: "Default Company",
			description:      "Guest user for default organization",
		},
		{
			userEmail:        "admin@example.com",
			roleName:         "admin",
			organizationName: "Test Company 1",
			description:      "Admin for test company 1",
		},
		{
			userEmail:        "test1@example.com",
			roleName:         "user",
			organizationName: "Test Company 1",
			description:      "User for test company 1",
		},
		{
			userEmail:        "test2@example.com",
			roleName:         "manager",
			organizationName: "Test Company 2",
			description:      "Manager for test company 2",
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

		// Find organization (if specified)
		var organizationId *string
		if assignment.organizationName != "" {
			var organization models.Organization
			err = facades.Orm().Query().Where("name = ?", assignment.organizationName).First(&organization)
			if err != nil {
				facades.Log().Warning("Organization not found: " + assignment.organizationName)
				continue
			}
			organizationId = &organization.ID
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
			UserID:         user.ID,
			RoleID:         role.ID,
			OrganizationID: organizationId,
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

			// Assign to a random organization if available
			var organizationId *string
			if len(organizations) > 0 {
				organizationIndex := i % len(organizations)
				organizationId = &organizations[organizationIndex].ID
			}

			userRole := models.UserRole{
				UserID:         user.ID,
				RoleID:         role.ID,
				OrganizationID: organizationId,
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
