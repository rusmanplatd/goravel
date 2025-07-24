package seeders

import (
	"time"

	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type TeamProjectSeeder struct {
}

// Signature The name and signature of the seeder.
func (s *TeamProjectSeeder) Signature() string {
	return "TeamProjectSeeder"
}

// Run executes the seeder logic.
func (s *TeamProjectSeeder) Run() error {
	facades.Log().Info("Starting team project seeder...")

	// Get teams
	var teams []models.Team
	err := facades.Orm().Query().Find(&teams)
	if err != nil {
		return err
	}

	if len(teams) == 0 {
		facades.Log().Warning("No teams found, skipping team project seeding")
		return nil
	}

	// Get projects
	var projects []models.Project
	err = facades.Orm().Query().Find(&projects)
	if err != nil {
		return err
	}

	if len(projects) == 0 {
		facades.Log().Warning("No projects found, skipping team project seeding")
		return nil
	}

	// Create team-project relationships
	for i, team := range teams {
		// Assign team to 1-3 projects
		numProjects := 1
		if i%3 == 0 { // Every 3rd team gets assigned to 2 projects
			numProjects = 2
		} else if i%5 == 0 { // Every 5th team gets assigned to 3 projects
			numProjects = 3
		}

		for j := 0; j < numProjects && j < len(projects); j++ {
			projectIndex := (i + j) % len(projects)
			project := projects[projectIndex]

			// Check if relationship already exists
			var existing models.TeamProject
			err := facades.Orm().Query().Where("team_id = ? AND project_id = ?", team.ID, project.ID).First(&existing)
			if err == nil {
				continue // Relationship already exists
			}

			// Determine team role based on team type and project
			var role string
			if team.Type == "functional" {
				if team.Name == "Backend Development" || team.Name == "Frontend Development" {
					role = "lead"
				} else {
					role = "contributor"
				}
			} else {
				role = "lead" // Project teams are usually leads
			}

			// Set allocation percentage based on role
			var allocation float64
			switch role {
			case "lead":
				allocation = 100.0
			case "contributor":
				allocation = 80.0
			case "reviewer":
				allocation = 20.0
			default:
				allocation = 60.0
			}

			teamProject := models.TeamProject{
				TeamID:     team.ID,
				ProjectID:  project.ID,
				Role:       role,
				IsActive:   true,
				JoinedAt:   time.Now().AddDate(0, -(i % 6), 0), // Random join date
				Allocation: allocation,
			}

			err = facades.Orm().Query().Create(&teamProject)
			if err != nil {
				facades.Log().Error("Failed to create team project: " + err.Error())
				return err
			}

			facades.Log().Info("Created team project relationship: " + team.Name + " -> " + project.Name + " (" + role + ")")
		}
	}

	facades.Log().Info("Team project seeder completed successfully")
	return nil
}
