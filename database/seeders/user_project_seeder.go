package seeders

import (
	"fmt"
	"time"

	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type UserProjectSeeder struct {
}

// Signature The name and signature of the seeder.
func (s *UserProjectSeeder) Signature() string {
	return "UserProjectSeeder"
}

// Run executes the seeder logic.
func (s *UserProjectSeeder) Run() error {
	facades.Log().Info(fmt.Sprintf("%s started", s.Signature()))
	defer facades.Log().Info(fmt.Sprintf("%s completed", s.Signature()))

	// Get users
	var users []models.User
	err := facades.Orm().Query().Find(&users)
	if err != nil {
		return err
	}

	if len(users) == 0 {
		facades.Log().Warning("No users found, skipping user project seeding")
		return nil
	}

	// Get projects
	var projects []models.Project
	err = facades.Orm().Query().Find(&projects)
	if err != nil {
		return err
	}

	if len(projects) == 0 {
		facades.Log().Warning("No projects found, skipping user project seeding")
		return nil
	}

	// Create user-project relationships
	for i, user := range users {
		// Assign user to 1-4 projects
		numProjects := 1
		if i%3 == 0 { // Every 3rd user gets assigned to 2 projects
			numProjects = 2
		} else if i%5 == 0 { // Every 5th user gets assigned to 3 projects
			numProjects = 3
		} else if i%7 == 0 { // Every 7th user gets assigned to 4 projects
			numProjects = 4
		}

		for j := 0; j < numProjects && j < len(projects); j++ {
			projectIndex := (i + j) % len(projects)
			project := projects[projectIndex]

			// Check if relationship already exists
			var existing models.UserProject
			err := facades.Orm().Query().Where("user_id = ? AND project_id = ?", user.ID, project.ID).First(&existing)
			if err == nil {
				continue // Relationship already exists
			}

			// Determine user role based on index
			var role string
			if i == 0 {
				role = "manager" // First user is manager
			} else if i < 3 {
				role = "member" // Next 2 users are members
			} else if i < 6 {
				role = "contributor" // Next 3 users are contributors
			} else {
				role = "reviewer" // Rest are reviewers
			}

			// Set allocation percentage based on role
			var allocation float64
			switch role {
			case "manager":
				allocation = 100.0
			case "member":
				allocation = 80.0
			case "contributor":
				allocation = 60.0
			case "reviewer":
				allocation = 20.0
			default:
				allocation = 50.0
			}

			userProject := models.UserProject{
				UserID:     user.ID,
				ProjectID:  project.ID,
				Role:       role,
				IsActive:   true,
				JoinedAt:   time.Now().AddDate(0, -(i % 6), 0), // Random join date
				Allocation: allocation,
			}

			err = facades.Orm().Query().Create(&userProject)
			if err != nil {
				facades.Log().Error("Failed to create user project: " + err.Error())
				return err
			}

			facades.Log().Info("Created user project relationship: " + user.Name + " -> " + project.Name + " (" + role + ")")
		}
	}

	return nil
}
