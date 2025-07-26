package web

import (
	"github.com/goravel/framework/contracts/http"
)

type ProjectController struct {
	//Dependent services
}

func NewProjectController() *ProjectController {
	return &ProjectController{}
}

// Index displays the projects page
func (r *ProjectController) Index(ctx http.Context) http.Response {
	user := ctx.Value("user")
	if user == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	// Get projects data
	data := map[string]interface{}{
		"title": "Projects",
		"user":  user,
		"projects": []map[string]interface{}{
			{
				"id":              1,
				"name":            "Project Alpha",
				"description":     "Core platform development with authentication and user management",
				"status":          "active",
				"progress":        75,
				"start_date":      "2024-01-01",
				"end_date":        "2024-03-31",
				"team_size":       8,
				"tasks_total":     45,
				"tasks_completed": 34,
				"budget":          "$150,000",
			},
			{
				"id":              2,
				"name":            "Project Beta",
				"description":     "Mobile application development and API integration",
				"status":          "planning",
				"progress":        15,
				"start_date":      "2024-02-01",
				"end_date":        "2024-06-30",
				"team_size":       5,
				"tasks_total":     32,
				"tasks_completed": 5,
				"budget":          "$200,000",
			},
			{
				"id":              3,
				"name":            "Project Gamma",
				"description":     "Data analytics and reporting dashboard",
				"status":          "completed",
				"progress":        100,
				"start_date":      "2023-10-01",
				"end_date":        "2023-12-31",
				"team_size":       6,
				"tasks_total":     28,
				"tasks_completed": 28,
				"budget":          "$120,000",
			},
		},
	}

	return ctx.Response().View().Make("projects/index.tmpl", data)
}

// Show displays a specific project
func (r *ProjectController) Show(ctx http.Context) http.Response {
	user := ctx.Value("user")
	if user == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	projectId := ctx.Request().Route("id")

	// Get specific project data
	data := map[string]interface{}{
		"title": "Project Details",
		"user":  user,
		"project": map[string]interface{}{
			"id":          projectId,
			"name":        "Project Alpha",
			"description": "Core platform development with authentication and user management. This project focuses on building a robust foundation for our application.",
			"status":      "active",
			"progress":    75,
			"start_date":  "2024-01-01",
			"end_date":    "2024-03-31",
			"budget":      "$150,000",
			"team": []map[string]interface{}{
				{"name": "John Doe", "role": "Project Manager", "avatar": "JD"},
				{"name": "Jane Smith", "role": "Frontend Developer", "avatar": "JS"},
				{"name": "Mike Johnson", "role": "Backend Developer", "avatar": "MJ"},
				{"name": "Sarah Wilson", "role": "UI/UX Designer", "avatar": "SW"},
			},
			"recent_tasks": []map[string]interface{}{
				{"title": "Implement user authentication", "status": "in_progress"},
				{"title": "Design dashboard UI", "status": "pending"},
				{"title": "Setup database schema", "status": "completed"},
			},
		},
	}

	return ctx.Response().View().Make("projects/show.tmpl", data)
}

// Create displays the form to create a new project
func (r *ProjectController) Create(ctx http.Context) http.Response {
	user := ctx.Value("user")
	if user == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	data := map[string]interface{}{
		"title": "Create Project",
		"user":  user,
	}

	return ctx.Response().View().Make("projects/create.tmpl", data)
}

// Store handles the creation of a new project
func (r *ProjectController) Store(ctx http.Context) http.Response {
	user := ctx.Value("user")
	if user == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	// Validate and store the project
	// For now, just redirect with success message
	ctx.Request().Session().Flash("success", "Project created successfully!")
	return ctx.Response().Redirect(302, "/projects")
}
