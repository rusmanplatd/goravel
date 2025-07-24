package seeders

import (
	"fmt"
	"time"

	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type UserTenantSeeder struct {
}

// Signature The name and signature of the seeder.
func (s *UserTenantSeeder) Signature() string {
	return "UserTenantSeeder"
}

// Run executes the seeder logic.
func (s *UserTenantSeeder) Run() error {
	facades.Log().Info(fmt.Sprintf("%s started", s.Signature()))
	defer facades.Log().Info(fmt.Sprintf("%s completed", s.Signature()))
	// Define user-tenant assignments with roles
	assignments := []map[string]interface{}{
		{
			"userEmail":  "superadmin@goravel.com",
			"tenantSlug": "goravel-corp",
			"roleName":   "super-admin",
			"isActive":   true,
		},
		{
			"userEmail":  "admin@goravel.com",
			"tenantSlug": "goravel-corp",
			"roleName":   "admin",
			"isActive":   true,
		},
		{
			"userEmail":  "manager@goravel.com",
			"tenantSlug": "goravel-corp",
			"roleName":   "manager",
			"isActive":   true,
		},
		{
			"userEmail":  "user@goravel.com",
			"tenantSlug": "goravel-corp",
			"roleName":   "user",
			"isActive":   true,
		},
		{
			"userEmail":  "admin@goravel.com",
			"tenantSlug": "demo-company",
			"roleName":   "admin",
			"isActive":   true,
		},
		{
			"userEmail":  "manager@goravel.com",
			"tenantSlug": "demo-company",
			"roleName":   "manager",
			"isActive":   true,
		},
		{
			"userEmail":  "test@goravel.com",
			"tenantSlug": "demo-company",
			"roleName":   "user",
			"isActive":   true,
		},
		{
			"userEmail":  "manager@goravel.com",
			"tenantSlug": "test-org",
			"roleName":   "admin",
			"isActive":   true,
		},
		{
			"userEmail":  "user@goravel.com",
			"tenantSlug": "test-org",
			"roleName":   "user",
			"isActive":   true,
		},
		{
			"userEmail":  "guest@goravel.com",
			"tenantSlug": "goravel-corp",
			"roleName":   "guest",
			"isActive":   true,
		},
		{
			"userEmail":  "guest@goravel.com",
			"tenantSlug": "demo-company",
			"roleName":   "guest",
			"isActive":   true,
		},
	}

	for _, assignment := range assignments {
		// Get user
		var user models.User
		err := facades.Orm().Query().Where("email = ?", assignment["userEmail"]).First(&user)
		if err != nil {
			facades.Log().Warning("User not found: " + assignment["userEmail"].(string))
			continue
		}

		// Get tenant
		var tenant models.Tenant
		err = facades.Orm().Query().Where("slug = ?", assignment["tenantSlug"]).First(&tenant)
		if err != nil {
			facades.Log().Warning("Tenant not found: " + assignment["tenantSlug"].(string))
			continue
		}

		// Check if user-tenant relationship already exists
		var existingUserTenant models.UserTenant
		err = facades.Orm().Query().Where("user_id = ? AND tenant_id = ?", user.ID, tenant.ID).First(&existingUserTenant)
		if err != nil {
			// Create user-tenant relationship
			userTenant := models.UserTenant{
				UserID:   user.ID,
				TenantID: tenant.ID,
				IsActive: assignment["isActive"].(bool),
				JoinedAt: time.Now(),
			}

			err = facades.Orm().Query().Create(&userTenant)
			if err != nil {
				return err
			}

			facades.Log().Info("Created user-tenant relationship: " + user.Email + " -> " + tenant.Name)
		} else {
			facades.Log().Info("User-tenant relationship already exists: " + user.Email + " -> " + tenant.Name)
		}

		// Get role
		var role models.Role
		err = facades.Orm().Query().Where("name = ?", assignment["roleName"]).First(&role)
		if err != nil {
			facades.Log().Warning("Role not found: " + assignment["roleName"].(string))
			continue
		}

		// Check if user-role-tenant relationship already exists
		var existingUserRole models.UserRole
		err = facades.Orm().Query().Where("user_id = ? AND role_id = ? AND tenant_id = ?", user.ID, role.ID, tenant.ID).First(&existingUserRole)
		if err != nil {
			// Create user-role-tenant relationship
			userRole := models.UserRole{
				UserID:   user.ID,
				RoleID:   role.ID,
				TenantID: &tenant.ID,
			}

			err = facades.Orm().Query().Create(&userRole)
			if err != nil {
				return err
			}

			facades.Log().Info("Created user-role-tenant relationship: " + user.Email + " -> " + role.Name + " -> " + tenant.Name)
		} else {
			facades.Log().Info("User-role-tenant relationship already exists: " + user.Email + " -> " + role.Name + " -> " + tenant.Name)
		}
	}

	return nil
}
