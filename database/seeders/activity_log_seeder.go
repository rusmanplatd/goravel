package seeders

import (
	"encoding/json"
	"fmt"
	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type ActivityLogSeeder struct {
}

// Signature The name and signature of the seeder.
func (s *ActivityLogSeeder) Signature() string {
	return "ActivityLogSeeder"
}

// Run executes the seeder logic.
func (s *ActivityLogSeeder) Run() error {
	facades.Log().Info(fmt.Sprintf("%s started", s.Signature()))
	defer facades.Log().Info(fmt.Sprintf("%s completed", s.Signature()))
	// Get some users for activity logs
	var users []models.User
	err := facades.Orm().Query().Limit(5).Find(&users)
	if err != nil {
		return err
	}

	if len(users) == 0 {
		facades.Log().Info("No users found for activity logs")
		return nil
	}

	// Get some tenants for activity logs
	var tenants []models.Tenant
	err = facades.Orm().Query().Limit(3).Find(&tenants)
	if err != nil {
		return err
	}

	if len(tenants) == 0 {
		facades.Log().Info("No tenants found for activity logs")
		return nil
	}

	// Create sample activity logs
	activities := []map[string]interface{}{
		{
			"log_name":     "user",
			"description":  "User logged in",
			"subject_type": "goravel/app/models.User",
			"properties":   map[string]interface{}{"ip": "192.168.1.100", "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
		},
		{
			"log_name":     "user",
			"description":  "User profile updated",
			"subject_type": "goravel/app/models.User",
			"properties":   map[string]interface{}{"changes": map[string]interface{}{"name": "John Doe", "email": "john.doe@example.com"}},
		},
		{
			"log_name":     "user",
			"description":  "New user created",
			"subject_type": "goravel/app/models.User",
			"properties":   map[string]interface{}{"attributes": map[string]interface{}{"name": "Jane Smith", "email": "jane.smith@example.com"}},
		},
		{
			"log_name":     "tenant",
			"description":  "Tenant settings updated",
			"subject_type": "goravel/app/models.Tenant",
			"properties":   map[string]interface{}{"changes": map[string]interface{}{"settings": "{\"theme\":\"dark\",\"timezone\":\"UTC\"}"}},
		},
		{
			"log_name":     "role",
			"description":  "Role permissions updated",
			"subject_type": "goravel/app/models.Role",
			"properties":   map[string]interface{}{"changes": map[string]interface{}{"permissions": []string{"users.view", "users.create", "users.edit"}}},
		},
		{
			"log_name":     "permission",
			"description":  "New permission created",
			"subject_type": "goravel/app/models.Permission",
			"properties":   map[string]interface{}{"attributes": map[string]interface{}{"name": "custom.permission", "description": "Custom permission for testing"}},
		},
		{
			"log_name":     "user",
			"description":  "User logged out",
			"subject_type": "goravel/app/models.User",
			"properties":   map[string]interface{}{"ip": "192.168.1.100", "session_duration": "3600"},
		},
		{
			"log_name":     "user",
			"description":  "Password changed",
			"subject_type": "goravel/app/models.User",
			"properties":   map[string]interface{}{"changed_at": "2024-01-15T10:30:00Z"},
		},
		{
			"log_name":     "user",
			"description":  "MFA enabled",
			"subject_type": "goravel/app/models.User",
			"properties":   map[string]interface{}{"method": "totp", "enabled_at": "2024-01-15T10:30:00Z"},
		},
		{
			"log_name":     "tenant",
			"description":  "New tenant created",
			"subject_type": "goravel/app/models.Tenant",
			"properties":   map[string]interface{}{"attributes": map[string]interface{}{"name": "New Company", "slug": "new-company", "domain": "newcompany.com"}},
		},
	}

	// Create activity logs with different users and tenants
	for i, activity := range activities {
		user := users[i%len(users)]
		tenant := tenants[i%len(tenants)]

		// Check if activity log already exists
		var existingLog models.ActivityLog
		err := facades.Orm().Query().Where("description = ? AND causer_id = ?", activity["description"], user.ID).First(&existingLog)
		if err != nil {
			// Convert properties to JSON
			propertiesJSON, err := json.Marshal(activity["properties"])
			if err != nil {
				return err
			}

			// Create activity log
			log := models.ActivityLog{
				LogName:     activity["log_name"].(string),
				Description: activity["description"].(string),
				SubjectType: activity["subject_type"].(string),
				SubjectID:   user.ID, // Use user ID as subject ID for demo
				CauserType:  "goravel/app/models.User",
				CauserID:    user.ID,
				Properties:  propertiesJSON,
				TenantID:    tenant.ID,
			}

			err = facades.Orm().Query().Create(&log)
			if err != nil {
				return err
			}

			facades.Log().Info("Created activity log: " + log.Description)
		} else {
			facades.Log().Info("Activity log already exists: " + existingLog.Description)
		}
	}

	return nil
}
