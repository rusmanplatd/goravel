package seeders

import (
	"time"

	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type OrganizationSeeder struct {
}

// Signature The name and signature of the seeder.
func (s *OrganizationSeeder) Signature() string {
	return "OrganizationSeeder"
}

// Run executes the seeder logic.
func (s *OrganizationSeeder) Run() error {
	facades.Log().Info("Starting organization seeder...")

	// Update existing organizations with detailed information
	organizationUpdates := []map[string]interface{}{
		{
			"organization_slug": "goravel-corp",
			"type":              "company",
			"industry":          "Technology",
			"size":              "large",
			"website":           "https://goravel.com",
			"logo":              "https://goravel.com/logo.png",
			"banner":            "https://goravel.com/banner.png",
			"contact_email":     "contact@goravel.com",
			"contact_phone":     "+1-555-123-4567",
			"address":           "123 Tech Street, San Francisco, CA 94105",
			"postal_code":       "94105",
			"is_verified":       true,
		},
		{
			"organization_slug": "demo-company",
			"type":              "company",
			"industry":          "Consulting",
			"size":              "medium",
			"website":           "https://demo.com",
			"logo":              "https://demo.com/logo.png",
			"contact_email":     "hello@demo.com",
			"contact_phone":     "+1-555-987-6543",
			"address":           "456 Business Ave, New York, NY 10001",
			"postal_code":       "10001",
			"is_verified":       true,
		},
		{
			"organization_slug": "test-org",
			"type":              "company",
			"industry":          "Artificial Intelligence",
			"size":              "startup",
			"website":           "https://test.org",
			"logo":              "https://test.org/logo.png",
			"contact_email":     "team@test.org",
			"contact_phone":     "+1-555-456-7890",
			"address":           "789 Innovation Blvd, Austin, TX 73301",
			"postal_code":       "73301",
			"is_verified":       false,
		},
		{
			"organization_slug": "startup-inc",
			"type":              "nonprofit",
			"industry":          "Education",
			"size":              "medium",
			"website":           "https://startup.inc",
			"logo":              "https://startup.inc/logo.png",
			"contact_email":     "info@startup.inc",
			"contact_phone":     "+1-555-321-6547",
			"address":           "321 Charity Lane, Boston, MA 02101",
			"postal_code":       "02101",
			"is_verified":       true,
		},
		{
			"organization_slug": "enterprise-solutions",
			"type":              "government",
			"industry":          "Government",
			"size":              "enterprise",
			"website":           "https://enterprise.solutions",
			"logo":              "https://enterprise.solutions/logo.png",
			"contact_email":     "contact@enterprise.solutions",
			"contact_phone":     "+1-555-111-2222",
			"address":           "100 Government Plaza, Washington, DC 20001",
			"postal_code":       "20001",
			"is_verified":       true,
		},
	}

	// Update organizations with detailed information
	for _, orgUpdate := range organizationUpdates {
		// Find organization by slug
		var organization models.Organization
		err := facades.Orm().Query().Where("slug = ?", orgUpdate["organization_slug"].(string)).First(&organization)
		if err != nil {
			facades.Log().Warning("Organization not found for slug: " + orgUpdate["organization_slug"].(string))
			continue
		}

		// Find the organization for this organization
		// This was causing a redeclaration error, and it's also not needed since we're already working with the organization
		// var organization models.Organization
		// err = facades.Orm().Query().Where("organization_id = ?", organization.ID).First(&organization)
		if err != nil {
			facades.Log().Warning("Organization not found for organization: " + organization.Name)
			continue
		}

		// Update organization with detailed information
		updateData := map[string]interface{}{
			"type":          orgUpdate["type"].(string),
			"industry":      orgUpdate["industry"].(string),
			"size":          orgUpdate["size"].(string),
			"website":       orgUpdate["website"].(string),
			"logo":          orgUpdate["logo"].(string),
			"contact_email": orgUpdate["contact_email"].(string),
			"contact_phone": orgUpdate["contact_phone"].(string),
			"address":       orgUpdate["address"].(string),
			"postal_code":   orgUpdate["postal_code"].(string),
			"is_verified":   orgUpdate["is_verified"].(bool),
		}

		// Add banner if present
		if banner, ok := orgUpdate["banner"]; ok {
			updateData["banner"] = banner.(string)
		}

		// Set verification date if verified
		if orgUpdate["is_verified"].(bool) {
			now := time.Now()
			updateData["verified_at"] = &now
		}

		for field, value := range updateData {
			_, err = facades.Orm().Query().Model(&organization).Where("id = ?", organization.ID).Update(field, value)
			if err != nil {
				facades.Log().Error("Failed to update organization field "+field+": "+err.Error(), map[string]interface{}{"organization_id": organization.ID})
				break
			}
		}
		if err != nil {
			facades.Log().Error("Failed to update organization: "+err.Error(), map[string]interface{}{"organization_id": organization.ID})
			continue
		}

		facades.Log().Info("Updated organization: "+organization.Name, map[string]interface{}{"organization_id": organization.ID})
	}

	// Create subsidiary organizations for existing root organizations
	subsidiaries := []map[string]interface{}{
		{
			"parent_organization_slug": "goravel-corp",
			"name":                     "Goravel Europe",
			"slug":                     "goravel-europe",
			"domain":                   "goravel-europe.com",
			"description":              "European subsidiary of Goravel Corporation",
			"type":                     "company",
			"industry":                 "Technology",
			"size":                     "medium",
			"website":                  "https://goravel-europe.com",
			"logo":                     "https://goravel-europe.com/logo.png",
			"contact_email":            "contact@goravel-europe.com",
			"contact_phone":            "+44-20-1234-5678",
			"address":                  "10 Tech Street, London, UK SW1A 1AA",
			"postal_code":              "SW1A 1AA",
			"is_active":                true,
			"is_verified":              true,
			"settings":                 `{"theme":"light","timezone":"Europe/London","language":"en","features":{"api_access":true,"analytics":true,"multi_user":true},"branding":{"logo":"https://goravel-europe.com/logo.png","primary_color":"#3B82F6"}}`,
		},
		{
			"parent_organization_slug": "demo-company",
			"name":                     "Demo Asia Pacific",
			"slug":                     "demo-asia-pacific",
			"domain":                   "demo-asia-pacific.com",
			"description":              "Asia Pacific regional office of Demo Company",
			"type":                     "company",
			"industry":                 "Consulting",
			"size":                     "small",
			"website":                  "https://demo-asia-pacific.com",
			"logo":                     "https://demo-asia-pacific.com/logo.png",
			"contact_email":            "hello@demo-asia-pacific.com",
			"contact_phone":            "+81-3-1234-5678",
			"address":                  "5 Business Street, Tokyo, Japan 100-0001",
			"postal_code":              "100-0001",
			"is_active":                true,
			"is_verified":              true,
			"settings":                 `{"theme":"dark","timezone":"Asia/Tokyo","language":"en","features":{"api_access":true,"analytics":false,"multi_user":true},"branding":{"logo":"https://demo-asia-pacific.com/logo.png","primary_color":"#10B981"}}`,
		},
	}

	// Create subsidiary organizations
	for _, subData := range subsidiaries {
		// Find parent organization
		var parentOrganization models.Organization
		err := facades.Orm().Query().Where("slug = ?", subData["parent_organization_slug"].(string)).First(&parentOrganization)
		if err != nil {
			facades.Log().Warning("Parent organization not found for slug: " + subData["parent_organization_slug"].(string))
			continue
		}

		// Find parent organization
		var parentOrg models.Organization
		err = facades.Orm().Query().Where("organization_id = ?", parentOrganization.ID).First(&parentOrg)
		if err != nil {
			facades.Log().Warning("Parent organization not found for organization: " + parentOrganization.Name)
			continue
		}

		// Check if subsidiary already exists
		var existingSubsidiary models.Organization
		err = facades.Orm().Query().Where("slug = ? AND organization_id = ?", subData["slug"].(string), parentOrganization.ID).First(&existingSubsidiary)
		if err == nil {
			facades.Log().Info("Subsidiary organization already exists: " + existingSubsidiary.Name)
			continue
		}

		seederID := models.USER_SEEDER_ULID
		subsidiary := &models.Organization{
			BaseModel: models.BaseModel{
				CreatedBy: &seederID,
				UpdatedBy: &seederID,
				DeletedBy: nil,
			},
			Name:         subData["name"].(string),
			Slug:         subData["slug"].(string),
			Domain:       subData["domain"].(string),
			Description:  subData["description"].(string),
			Type:         subData["type"].(string),
			Industry:     subData["industry"].(string),
			Size:         subData["size"].(string),
			Website:      subData["website"].(string),
			Logo:         subData["logo"].(string),
			ContactEmail: subData["contact_email"].(string),
			ContactPhone: subData["contact_phone"].(string),
			Address:      subData["address"].(string),
			PostalCode:   subData["postal_code"].(string),
			IsActive:     subData["is_active"].(bool),
			IsVerified:   subData["is_verified"].(bool),
			Settings:     subData["settings"].(string),
			// OrganizationID field doesn't exist in Organization model
			// OrganizationID:       parentOrganization.ID,
			ParentOrganizationID: &parentOrg.ID,
			Level:                1,
			Path:                 parentOrg.Path + parentOrg.ID + "/",
		}

		// Set verification date if verified
		if subsidiary.IsVerified {
			now := time.Now()
			subsidiary.VerifiedAt = &now
		}

		err = facades.Orm().Query().Create(subsidiary)
		if err != nil {
			facades.Log().Error("Failed to create subsidiary organization: "+err.Error(), map[string]interface{}{"subsidiary": subsidiary})
			continue
		}

		facades.Log().Info("Created subsidiary organization: "+subsidiary.Name, map[string]interface{}{"organization_id": subsidiary.ID})
	}

	facades.Log().Info("Organization seeder completed successfully")
	return nil
}
