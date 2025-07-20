package seeders

import (
	"time"

	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type TenantUserSeeder struct {
}

// Signature The name and signature of the seeder.
func (s *TenantUserSeeder) Signature() string {
	return "TenantUserSeeder"
}

// Run executes the seeder logic.
func (s *TenantUserSeeder) Run() error {
	facades.Log().Info("Starting tenant-user relationship seeder...")

	// Get all tenants
	var tenants []models.Tenant
	err := facades.Orm().Query().Find(&tenants)
	if err != nil {
		facades.Log().Error("Failed to fetch tenants: " + err.Error())
		return err
	}

	// Get all users
	var users []models.User
	err = facades.Orm().Query().Find(&users)
	if err != nil {
		facades.Log().Error("Failed to fetch users: " + err.Error())
		return err
	}

	if len(tenants) == 0 {
		facades.Log().Warning("No tenants found, skipping tenant-user relationship seeding")
		return nil
	}

	if len(users) == 0 {
		facades.Log().Warning("No users found, skipping tenant-user relationship seeding")
		return nil
	}

	// Create tenant-user relationships
	relationships := []map[string]interface{}{
		{
			"tenantID": tenants[0].ID, // Goravel Corporation
			"userID":   users[0].ID,
			"isActive": true,
		},
		{
			"tenantID": tenants[0].ID, // Goravel Corporation
			"userID":   users[1].ID,
			"isActive": true,
		},
		{
			"tenantID": tenants[1].ID, // Demo Company
			"userID":   users[0].ID,
			"isActive": true,
		},
		{
			"tenantID": tenants[1].ID, // Demo Company
			"userID":   users[1].ID,
			"isActive": true,
		},
		{
			"tenantID": tenants[2].ID, // Test Organization
			"userID":   users[0].ID,
			"isActive": true,
		},
		{
			"tenantID": tenants[3].ID, // Startup Inc
			"userID":   users[1].ID,
			"isActive": true,
		},
		{
			"tenantID": tenants[4].ID, // Enterprise Solutions
			"userID":   users[0].ID,
			"isActive": true,
		},
		{
			"tenantID": tenants[4].ID, // Enterprise Solutions
			"userID":   users[1].ID,
			"isActive": true,
		},
	}

	// Create relationships
	for _, relData := range relationships {
		// Check if relationship already exists
		var existingRel models.UserTenant
		err := facades.Orm().Query().Where("tenant_id = ? AND user_id = ?", relData["tenantID"], relData["userID"]).First(&existingRel)
		if err != nil {
			// Create relationship
			relationship := models.UserTenant{
				TenantID: relData["tenantID"].(string),
				UserID:   relData["userID"].(string),
				IsActive: relData["isActive"].(bool),
				JoinedAt: time.Now(),
			}

			err = facades.Orm().Query().Create(&relationship)
			if err != nil {
				facades.Log().Error("Failed to create tenant-user relationship: " + err.Error())
				return err
			}

			facades.Log().Info("Created tenant-user relationship: User " + relationship.UserID + " -> Tenant " + relationship.TenantID)
		} else {
			facades.Log().Info("Tenant-user relationship already exists: User " + existingRel.UserID + " -> Tenant " + existingRel.TenantID)
		}
	}

	facades.Log().Info("Tenant-user relationship seeder completed successfully")
	return nil
}
