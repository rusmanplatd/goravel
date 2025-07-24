package seeders

import (
	"time"

	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type UserTeamSeeder struct {
}

// Signature The name and signature of the seeder.
func (s *UserTeamSeeder) Signature() string {
	return "UserTeamSeeder"
}

// Run executes the seeder logic.
func (s *UserTeamSeeder) Run() error {
	facades.Log().Info("Starting user team seeder...")

	// Get users
	var users []models.User
	err := facades.Orm().Query().Find(&users)
	if err != nil {
		return err
	}

	if len(users) == 0 {
		facades.Log().Warning("No users found, skipping user team seeding")
		return nil
	}

	// Get teams
	var teams []models.Team
	err = facades.Orm().Query().Find(&teams)
	if err != nil {
		return err
	}

	if len(teams) == 0 {
		facades.Log().Warning("No teams found, skipping user team seeding")
		return nil
	}

	// Create user-team relationships
	for i, user := range users {
		// Assign user to 1-3 teams
		numTeams := 1
		if i%3 == 0 { // Every 3rd user gets assigned to 2 teams
			numTeams = 2
		} else if i%5 == 0 { // Every 5th user gets assigned to 3 teams
			numTeams = 3
		}

		for j := 0; j < numTeams && j < len(teams); j++ {
			teamIndex := (i + j) % len(teams)
			team := teams[teamIndex]

			// Check if relationship already exists
			var existing models.UserTeam
			err := facades.Orm().Query().Where("user_id = ? AND team_id = ?", user.ID, team.ID).First(&existing)
			if err == nil {
				continue // Relationship already exists
			}

			// Determine user role based on index
			var role string
			if i == 0 {
				role = "lead" // First user is lead
			} else if i < 3 {
				role = "member" // Next 2 users are members
			} else {
				role = "contributor" // Rest are contributors
			}

			userTeam := models.UserTeam{
				UserID:   user.ID,
				TeamID:   team.ID,
				Role:     role,
				IsActive: true,
				JoinedAt: time.Now().AddDate(0, -(i % 6), 0), // Random join date
			}

			err = facades.Orm().Query().Create(&userTeam)
			if err != nil {
				facades.Log().Error("Failed to create user team: " + err.Error())
				return err
			}

			facades.Log().Info("Created user team relationship: " + user.Name + " -> " + team.Name + " (" + role + ")")
		}
	}

	facades.Log().Info("User team seeder completed successfully")
	return nil
}
