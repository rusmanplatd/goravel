package seeders

import (
	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type ProjectTemplateSeeder struct {
}

// Signature The unique signature for the seeder.
func (r *ProjectTemplateSeeder) Signature() string {
	return "ProjectTemplateSeeder"
}

// Run the seeder.
func (r *ProjectTemplateSeeder) Run() error {
	// Check if templates already exist
	var count int64
	count, err := facades.Orm().Query().Model(&models.ProjectTemplate{}).Count()
	if err != nil {
		return err
	}

	if count > 0 {
		facades.Log().Info("Project templates already exist, skipping seeder")
		return nil
	}

	templates := []map[string]interface{}{
		{
			"name":        "Software Development",
			"description": "Complete template for software development projects with agile workflow",
			"category":    "development",
			"icon":        "code",
			"color":       "#3B82F6",
			"is_public":   true,
			"is_featured": true,
			"configuration": `{
				"default_views": [
					{
						"name": "Sprint Board",
						"type": "board",
						"description": "Kanban board for sprint management",
						"layout": {
							"columns": ["backlog", "todo", "in_progress", "review", "done"],
							"groupBy": "status"
						},
						"filters": {
							"assignee": "all",
							"priority": "all"
						}
					},
					{
						"name": "Product Roadmap",
						"type": "roadmap",
						"description": "Timeline view for product planning",
						"layout": {
							"timeframe": "quarterly",
							"groupBy": "milestone"
						}
					},
					{
						"name": "Task Table",
						"type": "table",
						"description": "Detailed table view of all tasks",
						"layout": {
							"columns": ["title", "assignee", "status", "priority", "due_date"]
						}
					}
				],
				"custom_fields": [
					{
						"name": "Priority",
						"type": "select",
						"description": "Task priority level",
						"options": {
							"options": ["Low", "Medium", "High", "Critical"],
							"colors": {
								"Low": "#10B981",
								"Medium": "#F59E0B",
								"High": "#EF4444",
								"Critical": "#7C3AED"
							}
						},
						"is_required": true
					},
					{
						"name": "Story Points",
						"type": "number",
						"description": "Effort estimation in story points"
					},
					{
						"name": "Epic",
						"type": "select",
						"description": "Epic categorization",
						"options": {
							"options": ["User Management", "Payment System", "Dashboard", "Mobile App"]
						}
					}
				]
			}`,
		},
		{
			"name":        "Marketing Campaign",
			"description": "Template for marketing campaign planning and execution",
			"category":    "marketing",
			"icon":        "megaphone",
			"color":       "#EC4899",
			"is_public":   true,
			"is_featured": true,
			"configuration": `{
				"default_views": [
					{
						"name": "Campaign Timeline",
						"type": "roadmap",
						"description": "Campaign timeline and milestones",
						"layout": {
							"timeframe": "monthly",
							"groupBy": "campaign_phase"
						}
					},
					{
						"name": "Task Board",
						"type": "board",
						"description": "Marketing tasks kanban board",
						"layout": {
							"columns": ["ideas", "planning", "in_progress", "review", "published"],
							"groupBy": "status"
						}
					}
				],
				"custom_fields": [
					{
						"name": "Campaign Phase",
						"type": "select",
						"description": "Campaign phase",
						"options": {
							"options": ["Research", "Planning", "Creation", "Launch", "Analysis"],
							"colors": {
								"Research": "#8B5CF6",
								"Planning": "#3B82F6",
								"Creation": "#F59E0B",
								"Launch": "#EF4444",
								"Analysis": "#10B981"
							}
						}
					},
					{
						"name": "Budget",
						"type": "number",
						"description": "Allocated budget for this task"
					},
					{
						"name": "Target Audience",
						"type": "multi_select",
						"description": "Target audience segments",
						"options": {
							"options": ["Young Adults", "Professionals", "Families", "Seniors", "Students"]
						}
					}
				]
			}`,
		},
		{
			"name":        "Product Design",
			"description": "Template for product design and UX projects",
			"category":    "design",
			"icon":        "palette",
			"color":       "#F59E0B",
			"is_public":   true,
			"is_featured": false,
			"configuration": `{
				"default_views": [
					{
						"name": "Design Process",
						"type": "board",
						"description": "Design workflow board",
						"layout": {
							"columns": ["discovery", "ideation", "design", "prototype", "test", "handoff"],
							"groupBy": "status"
						}
					},
					{
						"name": "Design Timeline",
						"type": "roadmap",
						"description": "Design project timeline",
						"layout": {
							"timeframe": "weekly",
							"groupBy": "design_phase"
						}
					}
				],
				"custom_fields": [
					{
						"name": "Design Phase",
						"type": "select",
						"description": "Current design phase",
						"options": {
							"options": ["Research", "Wireframing", "Visual Design", "Prototyping", "Testing"],
							"colors": {
								"Research": "#8B5CF6",
								"Wireframing": "#3B82F6",
								"Visual Design": "#F59E0B",
								"Prototyping": "#EF4444",
								"Testing": "#10B981"
							}
						}
					},
					{
						"name": "Design Tool",
						"type": "select",
						"description": "Primary design tool used",
						"options": {
							"options": ["Figma", "Sketch", "Adobe XD", "InVision", "Framer"]
						}
					},
					{
						"name": "Device Target",
						"type": "multi_select",
						"description": "Target devices",
						"options": {
							"options": ["Desktop", "Tablet", "Mobile", "Watch", "TV"]
						}
					}
				]
			}`,
		},
		{
			"name":        "Event Planning",
			"description": "Template for event planning and management",
			"category":    "general",
			"icon":        "calendar",
			"color":       "#10B981",
			"is_public":   true,
			"is_featured": false,
			"configuration": `{
				"default_views": [
					{
						"name": "Event Timeline",
						"type": "roadmap",
						"description": "Event planning timeline",
						"layout": {
							"timeframe": "weekly",
							"groupBy": "event_phase"
						}
					},
					{
						"name": "Task Board",
						"type": "board",
						"description": "Event planning tasks",
						"layout": {
							"columns": ["planning", "booking", "promotion", "preparation", "execution", "followup"],
							"groupBy": "status"
						}
					}
				],
				"custom_fields": [
					{
						"name": "Event Phase",
						"type": "select",
						"description": "Event planning phase",
						"options": {
							"options": ["Pre-Planning", "Venue & Vendors", "Marketing", "Final Prep", "Event Day", "Post-Event"]
						}
					},
					{
						"name": "Budget Category",
						"type": "select",
						"description": "Budget category",
						"options": {
							"options": ["Venue", "Catering", "Marketing", "Entertainment", "Staff", "Miscellaneous"]
						}
					},
					{
						"name": "Vendor Required",
						"type": "checkbox",
						"description": "Does this task require vendor coordination?"
					}
				]
			}`,
		},
	}

	seederID := models.USER_SEEDER_ULID

	for _, templateData := range templates {
		template := models.ProjectTemplate{
			BaseModel: models.BaseModel{
				CreatedBy: &seederID,
				UpdatedBy: &seederID,
			},
			Name:          templateData["name"].(string),
			Description:   templateData["description"].(string),
			Category:      templateData["category"].(string),
			Icon:          templateData["icon"].(string),
			Color:         templateData["color"].(string),
			IsPublic:      templateData["is_public"].(bool),
			IsFeatured:    templateData["is_featured"].(bool),
			Configuration: templateData["configuration"].(string),
			UsageCount:    0,
		}

		err := facades.Orm().Query().Create(&template)
		if err != nil {
			facades.Log().Error("Failed to create project template: " + err.Error())
			return err
		}

		facades.Log().Info("Created project template: " + template.Name)
	}

	return nil
}
