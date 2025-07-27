package seeders

import (
	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type JobLevelSeeder struct{}

// Signature The unique signature for the seeder.
func (s *JobLevelSeeder) Signature() string {
	return "JobLevelSeeder"
}

// Run executes the seeder.
func (s *JobLevelSeeder) Run() error {
	// Get some existing organizations to create job levels for
	var organizations []models.Organization
	if err := facades.Orm().Query().Limit(3).Find(&organizations); err != nil {
		facades.Log().Error("Failed to fetch organizations for job level seeding", map[string]interface{}{
			"error": err.Error(),
		})
		return err
	}

	if len(organizations) == 0 {
		facades.Log().Info("No organizations found to create job levels for")
		return nil
	}

	// Sample job level data
	jobLevelData := []map[string]interface{}{
		{
			"name":        "Intern",
			"description": "Entry-level position for students and new graduates",
			"level_order": 1,
			"code":        "INT",
			"color":       "#F59E0B",
			"icon":        "academic-cap",
			"min_salary":  30000.0,
			"max_salary":  45000.0,
			"currency":    "USD",
			"requirements": map[string]interface{}{
				"experience_years": 0,
				"education":        "Bachelor's degree or equivalent",
				"skills":           []string{"basic technical skills", "willingness to learn"},
			},
			"benefits": map[string]interface{}{
				"vacation_days":    15,
				"health_insurance": true,
				"learning_budget":  1000,
			},
		},
		{
			"name":        "Junior",
			"description": "Entry to mid-level position with some experience",
			"level_order": 2,
			"code":        "JR",
			"color":       "#10B981",
			"icon":        "user",
			"min_salary":  50000.0,
			"max_salary":  70000.0,
			"currency":    "USD",
			"requirements": map[string]interface{}{
				"experience_years": 1,
				"education":        "Bachelor's degree",
				"skills":           []string{"foundational skills", "basic problem solving"},
			},
			"benefits": map[string]interface{}{
				"vacation_days":    20,
				"health_insurance": true,
				"learning_budget":  2000,
			},
		},
		{
			"name":        "Mid-Level",
			"description": "Experienced professional with proven track record",
			"level_order": 3,
			"code":        "MID",
			"color":       "#3B82F6",
			"icon":        "user-group",
			"min_salary":  70000.0,
			"max_salary":  95000.0,
			"currency":    "USD",
			"requirements": map[string]interface{}{
				"experience_years": 3,
				"education":        "Bachelor's degree",
				"skills":           []string{"advanced technical skills", "project management"},
			},
			"benefits": map[string]interface{}{
				"vacation_days":    22,
				"health_insurance": true,
				"learning_budget":  3000,
				"bonus_eligible":   true,
			},
		},
		{
			"name":        "Senior",
			"description": "Senior professional with leadership capabilities",
			"level_order": 4,
			"code":        "SR",
			"color":       "#8B5CF6",
			"icon":        "star",
			"min_salary":  95000.0,
			"max_salary":  130000.0,
			"currency":    "USD",
			"requirements": map[string]interface{}{
				"experience_years": 5,
				"education":        "Bachelor's degree or equivalent experience",
				"skills":           []string{"expert technical skills", "mentoring", "leadership"},
			},
			"benefits": map[string]interface{}{
				"vacation_days":    25,
				"health_insurance": true,
				"learning_budget":  4000,
				"bonus_eligible":   true,
				"stock_options":    true,
			},
		},
		{
			"name":        "Lead",
			"description": "Technical lead with team management responsibilities",
			"level_order": 5,
			"code":        "LEAD",
			"color":       "#EF4444",
			"icon":        "shield-check",
			"min_salary":  120000.0,
			"max_salary":  160000.0,
			"currency":    "USD",
			"requirements": map[string]interface{}{
				"experience_years": 7,
				"education":        "Bachelor's degree or equivalent experience",
				"skills":           []string{"expert technical skills", "team leadership", "strategic thinking"},
			},
			"benefits": map[string]interface{}{
				"vacation_days":    28,
				"health_insurance": true,
				"learning_budget":  5000,
				"bonus_eligible":   true,
				"stock_options":    true,
				"management_bonus": true,
			},
		},
		{
			"name":        "Principal",
			"description": "Principal level with strategic and architectural responsibilities",
			"level_order": 6,
			"code":        "PRIN",
			"color":       "#DC2626",
			"icon":        "lightning-bolt",
			"min_salary":  150000.0,
			"max_salary":  200000.0,
			"currency":    "USD",
			"requirements": map[string]interface{}{
				"experience_years": 10,
				"education":        "Bachelor's degree or equivalent experience",
				"skills":           []string{"architectural expertise", "strategic leadership", "cross-functional collaboration"},
			},
			"benefits": map[string]interface{}{
				"vacation_days":      30,
				"health_insurance":   true,
				"learning_budget":    6000,
				"bonus_eligible":     true,
				"stock_options":      true,
				"management_bonus":   true,
				"executive_benefits": true,
			},
		},
	}

	// Create job levels for each organization
	for _, org := range organizations {
		for _, data := range jobLevelData {
			jobLevel := models.JobLevel{
				Name:           data["name"].(string),
				Description:    data["description"].(string),
				LevelOrder:     data["level_order"].(int),
				Code:           jobLevelStringPtr(data["code"]),
				Color:          jobLevelStringPtr(data["color"]),
				Icon:           jobLevelStringPtr(data["icon"]),
				IsActive:       true,
				MinSalary:      jobLevelFloatPtr(data["min_salary"]),
				MaxSalary:      jobLevelFloatPtr(data["max_salary"]),
				Currency:       data["currency"].(string),
				OrganizationID: org.ID,
			}

			// Set requirements
			if requirements, ok := data["requirements"].(map[string]interface{}); ok {
				if err := jobLevel.SetRequirements(requirements); err != nil {
					facades.Log().Warning("Failed to set job level requirements", map[string]interface{}{
						"organization_id": org.ID,
						"job_level":       data["name"],
						"error":           err.Error(),
					})
				}
			}

			// Set benefits
			if benefits, ok := data["benefits"].(map[string]interface{}); ok {
				if err := jobLevel.SetBenefits(benefits); err != nil {
					facades.Log().Warning("Failed to set job level benefits", map[string]interface{}{
						"organization_id": org.ID,
						"job_level":       data["name"],
						"error":           err.Error(),
					})
				}
			}

			// Create the job level
			if err := facades.Orm().Query().Create(&jobLevel); err != nil {
				facades.Log().Error("Failed to create job level", map[string]interface{}{
					"organization_id": org.ID,
					"job_level":       data["name"],
					"error":           err.Error(),
				})
				continue
			}

			facades.Log().Info("Created job level", map[string]interface{}{
				"organization_id": org.ID,
				"job_level_id":    jobLevel.ID,
				"name":            jobLevel.Name,
				"level_order":     jobLevel.LevelOrder,
			})
		}
	}

	facades.Log().Info("Job level seeding completed", map[string]interface{}{
		"organizations_processed": len(organizations),
		"levels_per_org":          len(jobLevelData),
	})

	return nil
}

// Helper function to convert interface{} to *string
func jobLevelStringPtr(value interface{}) *string {
	if value == nil {
		return nil
	}
	if str, ok := value.(string); ok && str != "" {
		return &str
	}
	return nil
}

// Helper function to convert interface{} to *float64
func jobLevelFloatPtr(value interface{}) *float64 {
	if value == nil {
		return nil
	}
	if f, ok := value.(float64); ok {
		return &f
	}
	return nil
}
