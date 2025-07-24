package seeders

import (
	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type TenantSeeder struct {
}

// Signature The name and signature of the seeder.
func (s *TenantSeeder) Signature() string {
	return "TenantSeeder"
}

// Run executes the seeder logic.
func (s *TenantSeeder) Run() error {
	// Create default tenants
	tenants := []map[string]interface{}{
		{
			"name":        "Goravel Corporation",
			"slug":        "goravel-corp",
			"domain":      "goravel.com",
			"description": "Main tenant for Goravel Corporation - Enterprise software solutions",
			"isActive":    true,
			"settings":    `{"theme":"light","timezone":"UTC","language":"en","features":{"api_access":true,"analytics":true,"multi_user":true},"branding":{"logo":"https://goravel.com/logo.png","primary_color":"#3B82F6"}}`,
		},
		{
			"name":        "Demo Company",
			"slug":        "demo-company",
			"domain":      "demo.com",
			"description": "Demo tenant for testing and demonstration purposes",
			"isActive":    true,
			"settings":    `{"theme":"dark","timezone":"America/New_York","language":"en","features":{"api_access":true,"analytics":false,"multi_user":true},"branding":{"logo":"https://demo.com/logo.png","primary_color":"#10B981"}}`,
		},
		{
			"name":        "Test Organization",
			"slug":        "test-org",
			"domain":      "test.org",
			"description": "Test organization for development and QA testing",
			"isActive":    true,
			"settings":    `{"theme":"auto","timezone":"Europe/London","language":"en","features":{"api_access":true,"analytics":true,"multi_user":false},"branding":{"logo":"https://test.org/logo.png","primary_color":"#F59E0B"}}`,
		},
		{
			"name":        "Startup Inc",
			"slug":        "startup-inc",
			"domain":      "startup.inc",
			"description": "Innovative startup company focused on AI and machine learning",
			"isActive":    true,
			"settings":    `{"theme":"dark","timezone":"America/San_Francisco","language":"en","features":{"api_access":true,"analytics":true,"multi_user":true},"branding":{"logo":"https://startup.inc/logo.png","primary_color":"#8B5CF6"}}`,
		},
		{
			"name":        "Enterprise Solutions",
			"slug":        "enterprise-solutions",
			"domain":      "enterprise.solutions",
			"description": "Large enterprise providing comprehensive business solutions",
			"isActive":    true,
			"settings":    `{"theme":"light","timezone":"America/Chicago","language":"en","features":{"api_access":true,"analytics":true,"multi_user":true,"advanced_security":true},"branding":{"logo":"https://enterprise.solutions/logo.png","primary_color":"#EF4444"}}`,
		},
		{
			"name":        "Inactive Company",
			"slug":        "inactive-company",
			"domain":      "inactive.company",
			"description": "Inactive tenant for testing suspension scenarios",
			"isActive":    false,
			"settings":    `{"theme":"light","timezone":"UTC","language":"en","features":{"api_access":false,"analytics":false,"multi_user":false},"branding":{"logo":"https://inactive.company/logo.png","primary_color":"#6B7280"}}`,
		},
	}

	for _, tenantData := range tenants {
		var existingTenant models.Tenant
		err := facades.Orm().Query().Where("slug = ?", tenantData["slug"]).First(&existingTenant)
		if err != nil || existingTenant.ID == "" {
			seederID := models.USER_SEEDER_ULID
			// Create tenant
			tenant := models.Tenant{
				BaseModel: models.BaseModel{
					CreatedBy: &seederID,
					UpdatedBy: &seederID,
					DeletedBy: nil,
				},
				Name:        tenantData["name"].(string),
				Slug:        tenantData["slug"].(string),
				Domain:      tenantData["domain"].(string),
				Description: tenantData["description"].(string),
				IsActive:    tenantData["isActive"].(bool),
				Settings:    tenantData["settings"].(string),
			}

			err = facades.Orm().Query().Create(&tenant)
			if err != nil {
				facades.Log().Error("Failed to create tenant " + tenant.Name + ": " + err.Error())
				return err
			}

			facades.Log().Info("Created tenant: " + tenant.Name + " (Slug: " + tenant.Slug + ")")
		} else {
			facades.Log().Info("Tenant already exists: " + existingTenant.Name + " (Slug: " + existingTenant.Slug + ")")
		}
	}

	facades.Log().Info("Tenant seeder completed successfully")
	return nil
}
