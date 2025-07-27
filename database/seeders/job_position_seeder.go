package seeders

import (
	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type JobPositionSeeder struct{}

// Signature The unique signature for the seeder.
func (s *JobPositionSeeder) Signature() string {
	return "JobPositionSeeder"
}

// Run executes the seeder.
func (s *JobPositionSeeder) Run() error {
	// Get existing job levels and departments
	var jobLevels []models.JobLevel
	if err := facades.Orm().Query().With("Organization").Find(&jobLevels); err != nil {
		facades.Log().Error("Failed to fetch job levels for job position seeding", map[string]interface{}{
			"error": err.Error(),
		})
		return err
	}

	if len(jobLevels) == 0 {
		facades.Log().Info("No job levels found to create job positions for")
		return nil
	}

	// Get departments
	var departments []models.Department
	if err := facades.Orm().Query().Find(&departments); err != nil {
		facades.Log().Error("Failed to fetch departments for job position seeding", map[string]interface{}{
			"error": err.Error(),
		})
		return err
	}

	// Sample job position data by level
	positionTemplates := map[string][]map[string]interface{}{
		"Intern": {
			{
				"title":           "Software Engineering Intern",
				"description":     "Learn and contribute to software development projects under mentorship",
				"code":            "SWE-INT",
				"color":           "#F59E0B",
				"icon":            "code",
				"employment_type": "intern",
				"requirements": map[string]interface{}{
					"skills":    []string{"basic programming", "willingness to learn"},
					"education": "Currently pursuing Computer Science or related degree",
					"languages": []string{"any programming language"},
				},
				"responsibilities": map[string]interface{}{
					"primary":   []string{"write simple code", "fix bugs", "write tests"},
					"secondary": []string{"participate in code reviews", "learn from team"},
				},
			},
			{
				"title":           "Marketing Intern",
				"description":     "Support marketing campaigns and learn digital marketing strategies",
				"code":            "MKT-INT",
				"color":           "#F59E0B",
				"icon":            "megaphone",
				"employment_type": "intern",
				"requirements": map[string]interface{}{
					"skills":    []string{"communication", "creativity", "social media"},
					"education": "Marketing, Business, or related degree",
				},
				"responsibilities": map[string]interface{}{
					"primary":   []string{"content creation", "social media management", "market research"},
					"secondary": []string{"campaign analysis", "competitor research"},
				},
			},
		},
		"Junior": {
			{
				"title":           "Junior Software Engineer",
				"description":     "Develop and maintain software applications with guidance",
				"code":            "SWE-JR",
				"color":           "#10B981",
				"icon":            "code",
				"employment_type": "full_time",
				"requirements": map[string]interface{}{
					"skills":           []string{"programming", "debugging", "version control"},
					"experience_years": 1,
					"languages":        []string{"JavaScript", "Python", "Java", "Go"},
				},
				"responsibilities": map[string]interface{}{
					"primary":   []string{"implement features", "fix bugs", "write unit tests"},
					"secondary": []string{"code reviews", "documentation"},
				},
			},
			{
				"title":           "Junior Data Analyst",
				"description":     "Analyze data and create reports to support business decisions",
				"code":            "DA-JR",
				"color":           "#10B981",
				"icon":            "chart-bar",
				"employment_type": "full_time",
				"requirements": map[string]interface{}{
					"skills": []string{"SQL", "Excel", "data visualization", "statistics"},
					"tools":  []string{"Tableau", "Power BI", "Python", "R"},
				},
				"responsibilities": map[string]interface{}{
					"primary":   []string{"data collection", "report generation", "trend analysis"},
					"secondary": []string{"dashboard maintenance", "data quality checks"},
				},
			},
		},
		"Mid-Level": {
			{
				"title":           "Software Engineer",
				"description":     "Design and implement software solutions independently",
				"code":            "SWE",
				"color":           "#3B82F6",
				"icon":            "code",
				"employment_type": "full_time",
				"requirements": map[string]interface{}{
					"skills":           []string{"system design", "API development", "database design"},
					"experience_years": 3,
					"languages":        []string{"JavaScript", "Python", "Java", "Go"},
				},
				"responsibilities": map[string]interface{}{
					"primary":   []string{"feature development", "system architecture", "mentoring juniors"},
					"secondary": []string{"technical documentation", "performance optimization"},
				},
			},
			{
				"title":           "Product Manager",
				"description":     "Drive product strategy and coordinate cross-functional teams",
				"code":            "PM",
				"color":           "#3B82F6",
				"icon":            "briefcase",
				"employment_type": "full_time",
				"requirements": map[string]interface{}{
					"skills":           []string{"product strategy", "project management", "user research"},
					"experience_years": 3,
					"tools":            []string{"Jira", "Figma", "Analytics tools"},
				},
				"responsibilities": map[string]interface{}{
					"primary":   []string{"product roadmap", "stakeholder management", "feature prioritization"},
					"secondary": []string{"market research", "user feedback analysis"},
				},
			},
		},
		"Senior": {
			{
				"title":           "Senior Software Engineer",
				"description":     "Lead technical initiatives and mentor development teams",
				"code":            "SWE-SR",
				"color":           "#8B5CF6",
				"icon":            "star",
				"employment_type": "full_time",
				"requirements": map[string]interface{}{
					"skills":           []string{"system architecture", "team leadership", "performance optimization"},
					"experience_years": 5,
					"languages":        []string{"Multiple programming languages", "Cloud platforms"},
				},
				"responsibilities": map[string]interface{}{
					"primary":   []string{"architectural decisions", "code reviews", "team mentoring"},
					"secondary": []string{"technical strategy", "cross-team collaboration"},
				},
			},
			{
				"title":           "Senior Product Manager",
				"description":     "Define product vision and lead product development initiatives",
				"code":            "PM-SR",
				"color":           "#8B5CF6",
				"icon":            "star",
				"employment_type": "full_time",
				"requirements": map[string]interface{}{
					"skills":           []string{"product vision", "strategic planning", "team leadership"},
					"experience_years": 5,
				},
				"responsibilities": map[string]interface{}{
					"primary":   []string{"product strategy", "team leadership", "stakeholder alignment"},
					"secondary": []string{"market analysis", "competitive intelligence"},
				},
			},
		},
		"Lead": {
			{
				"title":           "Engineering Team Lead",
				"description":     "Lead engineering teams and drive technical excellence",
				"code":            "ENG-LEAD",
				"color":           "#EF4444",
				"icon":            "shield-check",
				"employment_type": "full_time",
				"requirements": map[string]interface{}{
					"skills":           []string{"team management", "technical leadership", "strategic planning"},
					"experience_years": 7,
				},
				"responsibilities": map[string]interface{}{
					"primary":   []string{"team management", "technical strategy", "cross-functional collaboration"},
					"secondary": []string{"hiring", "performance management", "technical mentoring"},
				},
			},
		},
		"Principal": {
			{
				"title":           "Principal Engineer",
				"description":     "Drive technical strategy and architecture across the organization",
				"code":            "ENG-PRIN",
				"color":           "#DC2626",
				"icon":            "lightning-bolt",
				"employment_type": "full_time",
				"requirements": map[string]interface{}{
					"skills":           []string{"system architecture", "technical strategy", "organizational leadership"},
					"experience_years": 10,
				},
				"responsibilities": map[string]interface{}{
					"primary":   []string{"technical strategy", "architecture decisions", "organizational impact"},
					"secondary": []string{"technical mentoring", "innovation leadership", "external representation"},
				},
			},
		},
	}

	positionsCreated := 0

	// Create job positions for each job level
	for _, jobLevel := range jobLevels {
		if templates, exists := positionTemplates[jobLevel.Name]; exists {
			for _, template := range templates {
				// Find appropriate department (simplified logic)
				var departmentID *string
				if len(departments) > 0 {
					// Simple mapping logic - in a real scenario, you'd have more sophisticated mapping
					for _, dept := range departments {
						if dept.OrganizationID == jobLevel.OrganizationID {
							departmentID = &dept.ID
							break
						}
					}
				}

				jobPosition := models.JobPosition{
					Title:          template["title"].(string),
					Description:    template["description"].(string),
					Code:           jobPositionStringPtr(template["code"]),
					Color:          jobPositionStringPtr(template["color"]),
					Icon:           jobPositionStringPtr(template["icon"]),
					IsActive:       true,
					IsRemote:       false, // Default to false, can be customized
					EmploymentType: template["employment_type"].(string),
					Currency:       "USD",
					JobLevelID:     jobLevel.ID,
					DepartmentID:   departmentID,
					OrganizationID: jobLevel.OrganizationID,
					Headcount:      2, // Default headcount
					FilledCount:    0,
				}

				// Set requirements
				if requirements, ok := template["requirements"].(map[string]interface{}); ok {
					if err := jobPosition.SetRequirements(requirements); err != nil {
						facades.Log().Warning("Failed to set job position requirements", map[string]interface{}{
							"job_level":    jobLevel.Name,
							"job_position": template["title"],
							"error":        err.Error(),
						})
					}
				}

				// Set responsibilities
				if responsibilities, ok := template["responsibilities"].(map[string]interface{}); ok {
					if err := jobPosition.SetResponsibilities(responsibilities); err != nil {
						facades.Log().Warning("Failed to set job position responsibilities", map[string]interface{}{
							"job_level":    jobLevel.Name,
							"job_position": template["title"],
							"error":        err.Error(),
						})
					}
				}

				// Set benefits (inherit from job level)
				benefits := map[string]interface{}{
					"health_insurance": true,
					"flexible_hours":   true,
					"remote_work":      jobLevel.Name != "Intern", // Interns typically work on-site
				}
				if err := jobPosition.SetBenefits(benefits); err != nil {
					facades.Log().Warning("Failed to set job position benefits", map[string]interface{}{
						"job_level":    jobLevel.Name,
						"job_position": template["title"],
						"error":        err.Error(),
					})
				}

				// Create the job position
				if err := facades.Orm().Query().Create(&jobPosition); err != nil {
					facades.Log().Error("Failed to create job position", map[string]interface{}{
						"job_level":    jobLevel.Name,
						"job_position": template["title"],
						"error":        err.Error(),
					})
					continue
				}

				positionsCreated++

				facades.Log().Info("Created job position", map[string]interface{}{
					"job_position_id": jobPosition.ID,
					"title":           jobPosition.Title,
					"job_level":       jobLevel.Name,
					"organization_id": jobLevel.OrganizationID,
				})
			}
		}
	}

	facades.Log().Info("Job position seeding completed", map[string]interface{}{
		"positions_created":    positionsCreated,
		"job_levels_processed": len(jobLevels),
	})

	return nil
}

// Helper function to convert interface{} to *string
func jobPositionStringPtr(value interface{}) *string {
	if value == nil {
		return nil
	}
	if str, ok := value.(string); ok && str != "" {
		return &str
	}
	return nil
}
