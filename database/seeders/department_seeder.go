package seeders

import (
	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type DepartmentSeeder struct {
}

// Signature The name and signature of the seeder.
func (s *DepartmentSeeder) Signature() string {
	return "DepartmentSeeder"
}

// Run executes the seeder logic.
func (s *DepartmentSeeder) Run() error {
	facades.Log().Info("Starting department seeder...")

	// Get organizations to associate departments with
	var organizations []models.Organization
	err := facades.Orm().Query().Find(&organizations)
	if err != nil {
		return err
	}

	if len(organizations) == 0 {
		facades.Log().Warning("No organizations found, skipping department seeding")
		return nil
	}

	// Create sample departments
	departments := []map[string]interface{}{
		{
			"name":        "Engineering",
			"description": "Software development and technical operations",
			"code":        "ENG",
			"color":       "#3B82F6",
			"icon":        "code",
			"is_active":   true,
		},
		{
			"name":        "Product Management",
			"description": "Product strategy, planning, and roadmap management",
			"code":        "PM",
			"color":       "#10B981",
			"icon":        "lightbulb",
			"is_active":   true,
		},
		{
			"name":        "Design",
			"description": "User experience and visual design",
			"code":        "DES",
			"color":       "#F59E0B",
			"icon":        "palette",
			"is_active":   true,
		},
		{
			"name":        "Marketing",
			"description": "Digital marketing, content, and growth",
			"code":        "MKT",
			"color":       "#EF4444",
			"icon":        "megaphone",
			"is_active":   true,
		},
		{
			"name":        "Sales",
			"description": "Customer acquisition and revenue generation",
			"code":        "SALES",
			"color":       "#8B5CF6",
			"icon":        "trending-up",
			"is_active":   true,
		},
		{
			"name":        "Customer Success",
			"description": "Customer support and relationship management",
			"code":        "CS",
			"color":       "#06B6D4",
			"icon":        "headphones",
			"is_active":   true,
		},
		{
			"name":        "Human Resources",
			"description": "Talent acquisition and employee development",
			"code":        "HR",
			"color":       "#84CC16",
			"icon":        "users",
			"is_active":   true,
		},
		{
			"name":        "Finance",
			"description": "Financial planning and accounting",
			"code":        "FIN",
			"color":       "#6B7280",
			"icon":        "calculator",
			"is_active":   true,
		},
		{
			"name":        "Operations",
			"description": "Business operations and process optimization",
			"code":        "OPS",
			"color":       "#F97316",
			"icon":        "cog",
			"is_active":   true,
		},
		{
			"name":        "Legal",
			"description": "Legal compliance and contract management",
			"code":        "LEGAL",
			"color":       "#DC2626",
			"icon":        "scale",
			"is_active":   true,
		},
	}

	// Create departments for each organization
	for _, org := range organizations {
		for _, deptData := range departments {
			// Check if department already exists for this organization
			var existingDept models.Department
			err := facades.Orm().Query().Where("name = ? AND organization_id = ?", deptData["name"], org.ID).First(&existingDept)
			if err == nil {
				continue // Department already exists
			}

			seederID := models.USER_SEEDER_ULID
			dept := models.Department{
				BaseModel: models.BaseModel{
					CreatedBy: &seederID,
					UpdatedBy: &seederID,
					DeletedBy: nil,
				},
				Name:           deptData["name"].(string),
				Description:    deptData["description"].(string),
				Code:           deptData["code"].(string),
				Color:          deptData["color"].(string),
				Icon:           deptData["icon"].(string),
				OrganizationID: org.ID,
				IsActive:       deptData["is_active"].(bool),
			}

			err = facades.Orm().Query().Create(&dept)
			if err != nil {
				facades.Log().Error("Failed to create department: " + err.Error())
				return err
			}

			facades.Log().Info("Created department: " + dept.Name + " for organization: " + org.Name)
		}
	}

	facades.Log().Info("Department seeder completed successfully")
	return nil
}
