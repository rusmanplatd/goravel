package seeders

import (
	"time"

	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type UserDepartmentSeeder struct {
}

// Signature The name and signature of the seeder.
func (s *UserDepartmentSeeder) Signature() string {
	return "UserDepartmentSeeder"
}

// Run executes the seeder logic.
func (s *UserDepartmentSeeder) Run() error {
	facades.Log().Info("Starting user department seeder...")

	// Get users
	var users []models.User
	err := facades.Orm().Query().Find(&users)
	if err != nil {
		return err
	}

	if len(users) == 0 {
		facades.Log().Warning("No users found, skipping user department seeding")
		return nil
	}

	// Get departments
	var departments []models.Department
	err = facades.Orm().Query().Find(&departments)
	if err != nil {
		return err
	}

	if len(departments) == 0 {
		facades.Log().Warning("No departments found, skipping user department seeding")
		return nil
	}

	// Create user-department relationships
	for i, user := range users {
		// Assign user to 1-2 departments
		numDepts := 1
		if i%4 == 0 { // Every 4th user gets assigned to 2 departments
			numDepts = 2
		}

		for j := 0; j < numDepts && j < len(departments); j++ {
			deptIndex := (i + j) % len(departments)
			dept := departments[deptIndex]

			// Check if relationship already exists
			var existing models.UserDepartment
			err := facades.Orm().Query().Where("user_id = ? AND department_id = ?", user.ID, dept.ID).First(&existing)
			if err == nil {
				continue // Relationship already exists
			}

			// Determine user role based on index
			var role string
			if i == 0 {
				role = "manager" // First user is manager
			} else if i < 3 {
				role = "lead" // Next 2 users are leads
			} else {
				role = "member" // Rest are members
			}

			userDept := models.UserDepartment{
				UserID:       user.ID,
				DepartmentID: dept.ID,
				Role:         role,
				IsActive:     true,
				JoinedAt:     time.Now().AddDate(0, -(i % 6), 0), // Random join date
			}

			err = facades.Orm().Query().Create(&userDept)
			if err != nil {
				facades.Log().Error("Failed to create user department: " + err.Error())
				return err
			}

			facades.Log().Info("Created user department relationship: " + user.Name + " -> " + dept.Name + " (" + role + ")")
		}
	}

	facades.Log().Info("User department seeder completed successfully")
	return nil
}
