package seeders

import (
	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type TeamSeeder struct {
}

// Signature The name and signature of the seeder.
func (s *TeamSeeder) Signature() string {
	return "TeamSeeder"
}

// Run executes the seeder logic.
func (s *TeamSeeder) Run() error {
	facades.Log().Info("Starting team seeder...")

	// Get organizations to associate teams with
	var organizations []models.Organization
	err := facades.Orm().Query().Find(&organizations)
	if err != nil {
		return err
	}

	if len(organizations) == 0 {
		facades.Log().Warning("No organizations found, skipping team seeding")
		return nil
	}

	// Get departments to associate teams with
	var departments []models.Department
	err = facades.Orm().Query().Find(&departments)
	if err != nil {
		return err
	}

	// Create sample teams
	teams := []map[string]interface{}{
		{
			"name":        "Backend Development",
			"description": "Backend development and API team",
			"code":        "BE-DEV",
			"type":        "functional",
			"color":       "#3B82F6",
			"icon":        "backend",
			"is_active":   true,
			"max_size":    8,
		},
		{
			"name":        "Frontend Development",
			"description": "Frontend development and UI team",
			"code":        "FE-DEV",
			"type":        "functional",
			"color":       "#10B981",
			"icon":        "frontend",
			"is_active":   true,
			"max_size":    6,
		},
		{
			"name":        "DevOps",
			"description": "Infrastructure and deployment team",
			"code":        "DEVOPS",
			"type":        "functional",
			"color":       "#F59E0B",
			"icon":        "server",
			"is_active":   true,
			"max_size":    4,
		},
		{
			"name":        "Quality Assurance",
			"description": "Testing and quality assurance team",
			"code":        "QA",
			"type":        "functional",
			"color":       "#EF4444",
			"icon":        "test",
			"is_active":   true,
			"max_size":    5,
		},
		{
			"name":        "Product Design",
			"description": "UX/UI design and research team",
			"code":        "DESIGN",
			"type":        "functional",
			"color":       "#8B5CF6",
			"icon":        "design",
			"is_active":   true,
			"max_size":    4,
		},
		{
			"name":        "Mobile Development",
			"description": "Mobile app development team",
			"code":        "MOBILE",
			"type":        "functional",
			"color":       "#06B6D4",
			"icon":        "mobile",
			"is_active":   true,
			"max_size":    6,
		},
		{
			"name":        "Data Science",
			"description": "Data analysis and machine learning team",
			"code":        "DATA",
			"type":        "functional",
			"color":       "#84CC16",
			"icon":        "data",
			"is_active":   true,
			"max_size":    4,
		},
		{
			"name":        "Security",
			"description": "Cybersecurity and compliance team",
			"code":        "SEC",
			"type":        "functional",
			"color":       "#DC2626",
			"icon":        "shield",
			"is_active":   true,
			"max_size":    3,
		},
		{
			"name":        "Customer Portal Project",
			"description": "Cross-functional team for customer portal development",
			"code":        "CP-PROJ",
			"type":        "project",
			"color":       "#F97316",
			"icon":        "project",
			"is_active":   true,
			"max_size":    12,
		},
		{
			"name":        "API Gateway Team",
			"description": "Cross-functional team for API gateway implementation",
			"code":        "API-PROJ",
			"type":        "project",
			"color":       "#6B7280",
			"icon":        "api",
			"is_active":   true,
			"max_size":    8,
		},
	}

	// Create teams for each organization
	for _, org := range organizations {
		for _, teamData := range teams {
			// Check if team already exists for this organization
			var existingTeam models.Team
			err := facades.Orm().Query().Where("name = ? AND organization_id = ?", teamData["name"], org.ID).First(&existingTeam)
			if err == nil {
				continue // Team already exists
			}

			// Find a department for this team (prefer engineering-related departments for technical teams)
			var departmentID *string
			teamName := teamData["name"].(string)
			for _, dept := range departments {
				if dept.OrganizationID == org.ID {
					if (teamName == "Backend Development" || teamName == "Frontend Development" || teamName == "DevOps" || teamName == "Quality Assurance" || teamName == "Mobile Development" || teamName == "Data Science" || teamName == "Security") && dept.Name == "Engineering" {
						departmentID = &dept.ID
						break
					} else if teamName == "Product Design" && dept.Name == "Design" {
						departmentID = &dept.ID
						break
					} else if (teamName == "Customer Portal Project" || teamName == "API Gateway Team") && dept.Name == "Engineering" {
						departmentID = &dept.ID
						break
					}
				}
			}

			team := models.Team{
				Name:           teamData["name"].(string),
				Description:    teamData["description"].(string),
				Code:           teamData["code"].(string),
				Type:           teamData["type"].(string),
				Color:          teamData["color"].(string),
				Icon:           teamData["icon"].(string),
				OrganizationID: org.ID,
				DepartmentID:   departmentID,
				IsActive:       teamData["is_active"].(bool),
				MaxSize:        teamData["max_size"].(int),
			}

			err = facades.Orm().Query().Create(&team)
			if err != nil {
				facades.Log().Error("Failed to create team: " + err.Error())
				return err
			}

			facades.Log().Info("Created team: " + team.Name + " for organization: " + org.Name)
		}
	}

	facades.Log().Info("Team seeder completed successfully")
	return nil
}
