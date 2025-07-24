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

	var err error

	// Create sample organizations
	organizations := []map[string]interface{}{
		{
			"name":          "Goravel Corporation",
			"slug":          "goravel-corp",
			"domain":        "goravel.com",
			"description":   "Leading enterprise software solutions provider specializing in modern web applications",
			"type":          "company",
			"industry":      "Technology",
			"size":          "large",
			"website":       "https://goravel.com",
			"logo":          "https://goravel.com/logo.png",
			"banner":        "https://goravel.com/banner.png",
			"contact_email": "contact@goravel.com",
			"contact_phone": "+1-555-123-4567",
			"address":       "123 Tech Street, San Francisco, CA 94105",
			"postal_code":   "94105",
			"is_active":     true,
			"is_verified":   true,
			"settings":      `{"theme":"light","timezone":"America/Los_Angeles","language":"en","features":{"api_access":true,"analytics":true,"multi_user":true},"branding":{"logo":"https://goravel.com/logo.png","primary_color":"#3B82F6"}}`,
		},
		{
			"name":          "Acme Solutions",
			"slug":          "acme-solutions",
			"domain":        "acme-solutions.com",
			"description":   "Innovative consulting firm providing digital transformation services",
			"type":          "company",
			"industry":      "Consulting",
			"size":          "medium",
			"website":       "https://acme-solutions.com",
			"logo":          "https://acme-solutions.com/logo.png",
			"contact_email": "hello@acme-solutions.com",
			"contact_phone": "+1-555-987-6543",
			"address":       "456 Business Ave, New York, NY 10001",
			"postal_code":   "10001",
			"is_active":     true,
			"is_verified":   true,
			"settings":      `{"theme":"dark","timezone":"America/New_York","language":"en","features":{"api_access":true,"analytics":false,"multi_user":true},"branding":{"logo":"https://acme-solutions.com/logo.png","primary_color":"#10B981"}}`,
		},
		{
			"name":          "Startup Inc",
			"slug":          "startup-inc",
			"domain":        "startup-inc.com",
			"description":   "Fast-growing startup focused on AI and machine learning solutions",
			"type":          "company",
			"industry":      "Artificial Intelligence",
			"size":          "startup",
			"website":       "https://startup-inc.com",
			"logo":          "https://startup-inc.com/logo.png",
			"contact_email": "team@startup-inc.com",
			"contact_phone": "+1-555-456-7890",
			"address":       "789 Innovation Blvd, Austin, TX 73301",
			"postal_code":   "73301",
			"is_active":     true,
			"is_verified":   false,
			"settings":      `{"theme":"auto","timezone":"America/Chicago","language":"en","features":{"api_access":true,"analytics":true,"multi_user":false},"branding":{"logo":"https://startup-inc.com/logo.png","primary_color":"#F59E0B"}}`,
		},
		{
			"name":          "NonProfit Foundation",
			"slug":          "nonprofit-foundation",
			"domain":        "nonprofit-foundation.org",
			"description":   "Dedicated to making a positive impact through technology and education",
			"type":          "nonprofit",
			"industry":      "Education",
			"size":          "medium",
			"website":       "https://nonprofit-foundation.org",
			"logo":          "https://nonprofit-foundation.org/logo.png",
			"contact_email": "info@nonprofit-foundation.org",
			"contact_phone": "+1-555-321-6547",
			"address":       "321 Charity Lane, Boston, MA 02101",
			"postal_code":   "02101",
			"is_active":     true,
			"is_verified":   true,
			"settings":      `{"theme":"light","timezone":"America/New_York","language":"en","features":{"api_access":false,"analytics":true,"multi_user":true},"branding":{"logo":"https://nonprofit-foundation.org/logo.png","primary_color":"#8B5CF6"}}`,
		},
		{
			"name":          "Government Agency",
			"slug":          "government-agency",
			"domain":        "gov-agency.gov",
			"description":   "Federal agency responsible for digital services and citizen engagement",
			"type":          "government",
			"industry":      "Government",
			"size":          "enterprise",
			"website":       "https://gov-agency.gov",
			"logo":          "https://gov-agency.gov/logo.png",
			"contact_email": "contact@gov-agency.gov",
			"contact_phone": "+1-555-111-2222",
			"address":       "100 Government Plaza, Washington, DC 20001",
			"postal_code":   "20001",
			"is_active":     true,
			"is_verified":   true,
			"settings":      `{"theme":"light","timezone":"America/New_York","language":"en","features":{"api_access":true,"analytics":true,"multi_user":true},"branding":{"logo":"https://gov-agency.gov/logo.png","primary_color":"#DC2626"}}`,
		},
	}

	// Create organizations
	for _, orgData := range organizations {
		// Find or create a tenant for this organization
		var tenant models.Tenant
		err := facades.Orm().Query().Where("slug = ?", orgData["slug"].(string)).First(&tenant)
		if err != nil {
			// Create a new tenant for this organization
			tenant = models.Tenant{
				Name:        orgData["name"].(string),
				Slug:        orgData["slug"].(string),
				Domain:      orgData["domain"].(string),
				Description: orgData["description"].(string),
				IsActive:    orgData["is_active"].(bool),
				Settings:    orgData["settings"].(string),
			}
			err = facades.Orm().Query().Create(&tenant)
			if err != nil {
				facades.Log().Error("Failed to create tenant for organization: " + err.Error())
				return err
			}
		}

		organization := &models.Organization{
			Name:         orgData["name"].(string),
			Slug:         orgData["slug"].(string),
			Domain:       orgData["domain"].(string),
			Description:  orgData["description"].(string),
			Type:         orgData["type"].(string),
			Industry:     orgData["industry"].(string),
			Size:         orgData["size"].(string),
			Website:      orgData["website"].(string),
			Logo:         orgData["logo"].(string),
			Banner:       orgData["banner"].(string),
			ContactEmail: orgData["contact_email"].(string),
			ContactPhone: orgData["contact_phone"].(string),
			Address:      orgData["address"].(string),
			PostalCode:   orgData["postal_code"].(string),
			IsActive:     orgData["is_active"].(bool),
			IsVerified:   orgData["is_verified"].(bool),
			Settings:     orgData["settings"].(string),
			TenantID:     tenant.ID,
			Level:        0,
			Path:         "/",
		}

		// Set verification date if verified
		if organization.IsVerified {
			now := time.Now()
			organization.VerifiedAt = &now
		}

		err = facades.Orm().Query().Create(organization)
		if err != nil {
			facades.Log().Error("Failed to create organization: " + err.Error())
			return err
		}

		facades.Log().Info("Created organization: " + organization.Name)
	}

	// Create subsidiary organizations
	subsidiaries := []map[string]interface{}{
		{
			"name":          "Goravel Europe",
			"slug":          "goravel-europe",
			"domain":        "goravel-europe.com",
			"description":   "European subsidiary of Goravel Corporation",
			"type":          "company",
			"industry":      "Technology",
			"size":          "medium",
			"website":       "https://goravel-europe.com",
			"logo":          "https://goravel-europe.com/logo.png",
			"contact_email": "contact@goravel-europe.com",
			"contact_phone": "+44-20-1234-5678",
			"address":       "10 Tech Street, London, UK SW1A 1AA",
			"postal_code":   "SW1A 1AA",
			"is_active":     true,
			"is_verified":   true,
			"settings":      `{"theme":"light","timezone":"Europe/London","language":"en","features":{"api_access":true,"analytics":true,"multi_user":true},"branding":{"logo":"https://goravel-europe.com/logo.png","primary_color":"#3B82F6"}}`,
		},
		{
			"name":          "Acme Asia Pacific",
			"slug":          "acme-asia-pacific",
			"domain":        "acme-asia-pacific.com",
			"description":   "Asia Pacific regional office of Acme Solutions",
			"type":          "company",
			"industry":      "Consulting",
			"size":          "small",
			"website":       "https://acme-asia-pacific.com",
			"logo":          "https://acme-asia-pacific.com/logo.png",
			"contact_email": "hello@acme-asia-pacific.com",
			"contact_phone": "+81-3-1234-5678",
			"address":       "5 Business Street, Tokyo, Japan 100-0001",
			"postal_code":   "100-0001",
			"is_active":     true,
			"is_verified":   true,
			"settings":      `{"theme":"dark","timezone":"Asia/Tokyo","language":"en","features":{"api_access":true,"analytics":false,"multi_user":true},"branding":{"logo":"https://acme-asia-pacific.com/logo.png","primary_color":"#10B981"}}`,
		},
	}

	// Get parent organizations
	var goravelOrg models.Organization
	err = facades.Orm().Query().Where("slug = ?", "goravel-corp").First(&goravelOrg)
	if err == nil {
		// Create Goravel Europe subsidiary
		goravelEurope := &models.Organization{
			Name:                 subsidiaries[0]["name"].(string),
			Slug:                 subsidiaries[0]["slug"].(string),
			Domain:               subsidiaries[0]["domain"].(string),
			Description:          subsidiaries[0]["description"].(string),
			Type:                 subsidiaries[0]["type"].(string),
			Industry:             subsidiaries[0]["industry"].(string),
			Size:                 subsidiaries[0]["size"].(string),
			Website:              subsidiaries[0]["website"].(string),
			Logo:                 subsidiaries[0]["logo"].(string),
			ContactEmail:         subsidiaries[0]["contact_email"].(string),
			ContactPhone:         subsidiaries[0]["contact_phone"].(string),
			Address:              subsidiaries[0]["address"].(string),
			PostalCode:           subsidiaries[0]["postal_code"].(string),
			IsActive:             subsidiaries[0]["is_active"].(bool),
			IsVerified:           subsidiaries[0]["is_verified"].(bool),
			Settings:             subsidiaries[0]["settings"].(string),
			TenantID:             goravelOrg.TenantID,
			ParentOrganizationID: &goravelOrg.ID,
			Level:                1,
			Path:                 goravelOrg.Path + "/" + goravelOrg.ID,
		}

		// Set verification date if verified
		if goravelEurope.IsVerified {
			now := time.Now()
			goravelEurope.VerifiedAt = &now
		}

		err = facades.Orm().Query().Create(goravelEurope)
		if err != nil {
			facades.Log().Error("Failed to create subsidiary organization: " + err.Error())
		} else {
			facades.Log().Info("Created subsidiary organization: " + goravelEurope.Name)
		}
	}

	var acmeOrg models.Organization
	err = facades.Orm().Query().Where("slug = ?", "acme-solutions").First(&acmeOrg)
	if err == nil {
		// Create Acme Asia Pacific subsidiary
		acmeAsiaPacific := &models.Organization{
			Name:                 subsidiaries[1]["name"].(string),
			Slug:                 subsidiaries[1]["slug"].(string),
			Domain:               subsidiaries[1]["domain"].(string),
			Description:          subsidiaries[1]["description"].(string),
			Type:                 subsidiaries[1]["type"].(string),
			Industry:             subsidiaries[1]["industry"].(string),
			Size:                 subsidiaries[1]["size"].(string),
			Website:              subsidiaries[1]["website"].(string),
			Logo:                 subsidiaries[1]["logo"].(string),
			ContactEmail:         subsidiaries[1]["contact_email"].(string),
			ContactPhone:         subsidiaries[1]["contact_phone"].(string),
			Address:              subsidiaries[1]["address"].(string),
			PostalCode:           subsidiaries[1]["postal_code"].(string),
			IsActive:             subsidiaries[1]["is_active"].(bool),
			IsVerified:           subsidiaries[1]["is_verified"].(bool),
			Settings:             subsidiaries[1]["settings"].(string),
			TenantID:             acmeOrg.TenantID,
			ParentOrganizationID: &acmeOrg.ID,
			Level:                1,
			Path:                 acmeOrg.Path + "/" + acmeOrg.ID,
		}

		// Set verification date if verified
		if acmeAsiaPacific.IsVerified {
			now := time.Now()
			acmeAsiaPacific.VerifiedAt = &now
		}

		err = facades.Orm().Query().Create(acmeAsiaPacific)
		if err != nil {
			facades.Log().Error("Failed to create subsidiary organization: " + err.Error())
		} else {
			facades.Log().Info("Created subsidiary organization: " + acmeAsiaPacific.Name)
		}
	}

	facades.Log().Info("Organization seeder completed successfully")
	return nil
}
