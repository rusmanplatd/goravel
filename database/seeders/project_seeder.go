package seeders

import (
	"fmt"
	"time"

	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type ProjectSeeder struct {
}

// Signature The name and signature of the seeder.
func (s *ProjectSeeder) Signature() string {
	return "ProjectSeeder"
}

// Run executes the seeder logic.
func (s *ProjectSeeder) Run() error {
	facades.Log().Info(fmt.Sprintf("%s started", s.Signature()))
	defer facades.Log().Info(fmt.Sprintf("%s completed", s.Signature()))

	// Get organizations to associate projects with
	var organizations []models.Organization
	err := facades.Orm().Query().Find(&organizations)
	if err != nil {
		return err
	}

	if len(organizations) == 0 {
		facades.Log().Warning("No organizations found, skipping project seeding")
		return nil
	}

	// Get users to assign as project managers
	var users []models.User
	err = facades.Orm().Query().Limit(10).Find(&users)
	if err != nil {
		return err
	}

	// Create sample projects
	projects := []map[string]interface{}{
		{
			"name":        "Customer Portal Redesign",
			"description": "Redesign and modernize the customer portal with improved UX and new features",
			"code":        "CPR-2024",
			"status":      "active",
			"priority":    "high",
			"color":       "#3B82F6",
			"created_by":  models.USER_SEEDER_ULID,
			"updated_by":  models.USER_SEEDER_ULID,
			"icon":        "portal",
			"is_active":   true,
			"budget":      75000.00,
			"progress":    65.5,
			"settings":    `{"timezone":"UTC","working_hours":{"start":"09:00","end":"17:00"},"features":{"kanban":true,"time_tracking":true,"file_sharing":true}}`,
		},
		{
			"name":        "API Gateway Implementation",
			"description": "Implement a centralized API gateway for better security and monitoring",
			"code":        "API-2024",
			"status":      "active",
			"priority":    "high",
			"color":       "#10B981",
			"icon":        "api",
			"is_active":   true,
			"budget":      45000.00,
			"progress":    45.0,
			"settings":    `{"timezone":"UTC","working_hours":{"start":"09:00","end":"17:00"},"features":{"rate_limiting":true,"authentication":true,"monitoring":true}}`,
		},
		{
			"name":        "Mobile App Development",
			"description": "Develop native mobile applications for iOS and Android platforms",
			"code":        "MOBILE-2024",
			"status":      "planning",
			"priority":    "medium",
			"color":       "#F59E0B",
			"icon":        "mobile",
			"is_active":   true,
			"budget":      120000.00,
			"progress":    15.0,
			"settings":    `{"timezone":"UTC","working_hours":{"start":"09:00","end":"17:00"},"features":{"push_notifications":true,"offline_sync":true,"biometrics":true}}`,
		},
		{
			"name":        "Data Analytics Platform",
			"description": "Build a comprehensive data analytics and reporting platform",
			"code":        "DATA-2024",
			"status":      "active",
			"priority":    "medium",
			"color":       "#8B5CF6",
			"icon":        "analytics",
			"is_active":   true,
			"budget":      85000.00,
			"progress":    80.0,
			"settings":    `{"timezone":"UTC","working_hours":{"start":"09:00","end":"17:00"},"features":{"real_time_dashboards":true,"data_export":true,"scheduled_reports":true}}`,
		},
		{
			"name":        "Security Audit & Compliance",
			"description": "Conduct comprehensive security audit and implement compliance measures",
			"code":        "SEC-2024",
			"status":      "active",
			"priority":    "critical",
			"color":       "#EF4444",
			"icon":        "security",
			"is_active":   true,
			"budget":      35000.00,
			"progress":    90.0,
			"settings":    `{"timezone":"UTC","working_hours":{"start":"09:00","end":"17:00"},"features":{"vulnerability_scanning":true,"compliance_reporting":true,"incident_response":true}}`,
		},
		{
			"name":        "Marketing Website Redesign",
			"description": "Redesign the company marketing website with modern design and improved SEO",
			"code":        "WEB-2024",
			"status":      "completed",
			"priority":    "low",
			"color":       "#06B6D4",
			"icon":        "website",
			"is_active":   true,
			"budget":      25000.00,
			"progress":    100.0,
			"settings":    `{"timezone":"UTC","working_hours":{"start":"09:00","end":"17:00"},"features":{"seo_optimization":true,"content_management":true,"analytics_integration":true}}`,
		},
		{
			"name":        "Employee Training Platform",
			"description": "Develop an internal training and skill development platform",
			"code":        "TRAINING-2024",
			"status":      "on-hold",
			"priority":    "low",
			"color":       "#84CC16",
			"icon":        "training",
			"is_active":   true,
			"budget":      40000.00,
			"progress":    25.0,
			"settings":    `{"timezone":"UTC","working_hours":{"start":"09:00","end":"17:00"},"features":{"course_management":true,"progress_tracking":true,"certification":true}}`,
		},
		{
			"name":        "Cloud Migration",
			"description": "Migrate on-premise infrastructure to cloud-based solutions",
			"code":        "CLOUD-2024",
			"status":      "planning",
			"priority":    "high",
			"color":       "#6B7280",
			"icon":        "cloud",
			"is_active":   true,
			"budget":      150000.00,
			"progress":    5.0,
			"settings":    `{"timezone":"UTC","working_hours":{"start":"09:00","end":"17:00"},"features":{"auto_scaling":true,"backup_recovery":true,"cost_optimization":true}}`,
		},
	}

	// Create projects for each organization
	for _, org := range organizations {
		for i, projectData := range projects {
			// Check if project already exists for this organization
			var existingProject models.Project
			err := facades.Orm().Query().Where("name = ? AND organization_id = ?", projectData["name"], org.ID).First(&existingProject)
			if err == nil {
				continue // Project already exists
			}

			// Assign a project manager (cycle through available users)
			var projectManagerID *string
			if len(users) > 0 {
				userIndex := i % len(users)
				projectManagerID = &users[userIndex].ID
			}

			// Set start and end dates
			startDate := time.Now().AddDate(0, -2, 0) // 2 months ago
			endDate := time.Now().AddDate(0, 4, 0)    // 4 months from now

			seederID := models.USER_SEEDER_ULID
			project := models.Project{
				BaseModel: models.BaseModel{
					CreatedBy: &seederID,
					UpdatedBy: &seederID,
					DeletedBy: nil,
				},
				Name:             projectData["name"].(string),
				Description:      projectData["description"].(string),
				Code:             projectData["code"].(string),
				Status:           projectData["status"].(string),
				Priority:         projectData["priority"].(string),
				Color:            projectData["color"].(string),
				Icon:             projectData["icon"].(string),
				OrganizationID:   org.ID,
				ProjectManagerID: projectManagerID,
				StartDate:        &startDate,
				EndDate:          &endDate,
				Budget:           projectData["budget"].(float64),
				Progress:         projectData["progress"].(float64),
				IsActive:         projectData["is_active"].(bool),
				Settings:         projectData["settings"].(string),
			}

			err = facades.Orm().Query().Create(&project)
			if err != nil {
				facades.Log().Error("Failed to create project: " + err.Error())
				return err
			}

			facades.Log().Info("Created project: " + project.Name + " for organization: " + org.Name)
		}
	}

	return nil
}
