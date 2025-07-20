package seeders

import (
	"encoding/json"
	"goravel/app/models"
	"time"

	"github.com/goravel/framework/facades"
)

type TestDataSeeder struct {
}

// Signature The name and signature of the seeder.
func (s *TestDataSeeder) Signature() string {
	return "TestDataSeeder"
}

// Run executes the seeder logic.
func (s *TestDataSeeder) Run() error {
	// Create test users with various scenarios
	now := time.Now()
	testUsers := []models.User{
		{
			Name:            "Test User 1",
			Email:           "test1@example.com",
			EmailVerifiedAt: &now,
			Password:        "$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi", // password
			MfaEnabled:      true,
			MfaSecret:       "test-secret-1",
			MfaEnabledAt:    &now,
			IsActive:        true,
		},
		{
			Name:            "Test User 2",
			Email:           "test2@example.com",
			EmailVerifiedAt: nil,                                                            // Not verified
			Password:        "$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi", // password
			MfaEnabled:      false,
			MfaSecret:       "",
			IsActive:        true,
		},
		{
			Name:            "Inactive User",
			Email:           "inactive@example.com",
			EmailVerifiedAt: &now,
			Password:        "$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi", // password
			MfaEnabled:      false,
			MfaSecret:       "",
			IsActive:        false,
		},
		{
			Name:            "Admin Test User",
			Email:           "admin@example.com",
			EmailVerifiedAt: &now,
			Password:        "$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi", // password
			MfaEnabled:      true,
			MfaSecret:       "admin-secret",
			MfaEnabledAt:    &now,
			IsActive:        true,
		},
	}

	// Create test users in database
	for _, user := range testUsers {
		err := facades.Orm().Query().Create(&user)
		if err != nil {
			facades.Log().Error("Failed to create test user " + user.Email + ": " + err.Error())
			return err
		}
	}

	// Create test tenants
	testTenants := []models.Tenant{
		{
			Name:     "Test Company 1",
			Domain:   "test1.com",
			IsActive: true,
		},
		{
			Name:     "Test Company 2",
			Domain:   "test2.com",
			IsActive: true,
		},
		{
			Name:     "Inactive Company",
			Domain:   "inactive.com",
			IsActive: false,
		},
	}

	// Create test tenants in database
	for _, tenant := range testTenants {
		err := facades.Orm().Query().Create(&tenant)
		if err != nil {
			facades.Log().Error("Failed to create test tenant " + tenant.Name + ": " + err.Error())
			return err
		}
	}

	// Create test roles
	testRoles := []models.Role{
		{
			Name:        "Test Role 1",
			Guard:       "web",
			Description: "Test role for testing purposes",
		},
		{
			Name:        "Test Role 2",
			Guard:       "web",
			Description: "Another test role for testing purposes",
		},
		{
			Name:        "Inactive Role",
			Guard:       "web",
			Description: "Inactive role for testing purposes",
		},
	}

	// Create test roles in database
	for _, role := range testRoles {
		err := facades.Orm().Query().Create(&role)
		if err != nil {
			facades.Log().Error("Failed to create test role " + role.Name + ": " + err.Error())
			return err
		}
	}

	// Create test permissions
	testPermissions := []models.Permission{
		{
			Name:        "test.permission.1",
			Guard:       "web",
			Description: "Test permission 1",
		},
		{
			Name:        "test.permission.2",
			Guard:       "web",
			Description: "Test permission 2",
		},
		{
			Name:        "test.permission.3",
			Guard:       "web",
			Description: "Test permission 3",
		},
		{
			Name:        "inactive.permission",
			Guard:       "web",
			Description: "Inactive permission",
		},
	}

	// Create test permissions in database
	for _, permission := range testPermissions {
		err := facades.Orm().Query().Create(&permission)
		if err != nil {
			facades.Log().Error("Failed to create test permission " + permission.Name + ": " + err.Error())
			return err
		}
	}

	// Get existing users and tenants for activity logs
	var users []models.User
	var tenants []models.Tenant
	facades.Orm().Query().Limit(3).Find(&users)
	facades.Orm().Query().Limit(2).Find(&tenants)

	if len(users) > 0 && len(tenants) > 0 {
		// Create test activity logs
		properties1, _ := json.Marshal(map[string]interface{}{"test": "data1"})
		properties2, _ := json.Marshal(map[string]interface{}{"test": "data2"})
		properties3, _ := json.Marshal(map[string]interface{}{"test": "data3"})

		testActivityLogs := []models.ActivityLog{
			{
				LogName:     "test",
				Description: "Test activity 1",
				SubjectType: "User",
				SubjectID:   users[0].ID,
				Properties:  properties1,
				TenantID:    tenants[0].ID,
			},
			{
				LogName:     "test",
				Description: "Test activity 2",
				SubjectType: "User",
				SubjectID:   users[0].ID,
				Properties:  properties2,
				TenantID:    tenants[0].ID,
			},
			{
				LogName:     "test",
				Description: "Test activity 3",
				SubjectType: "Tenant",
				SubjectID:   tenants[0].ID,
				Properties:  properties3,
				TenantID:    tenants[0].ID,
			},
		}

		// Create test activity logs in database
		for _, log := range testActivityLogs {
			err := facades.Orm().Query().Create(&log)
			if err != nil {
				facades.Log().Error("Failed to create test activity log: " + err.Error())
				return err
			}
		}
	}

	facades.Log().Info("Test data seeded successfully")
	return nil
}
