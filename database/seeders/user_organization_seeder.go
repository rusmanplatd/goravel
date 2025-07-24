package seeders

import (
	"time"

	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type UserOrganizationSeeder struct {
}

// Signature The name and signature of the seeder.
func (s *UserOrganizationSeeder) Signature() string {
	return "UserOrganizationSeeder"
}

// Run executes the seeder logic.
func (s *UserOrganizationSeeder) Run() error {
	facades.Log().Info("Starting user organization seeder...")

	// Get users
	var users []models.User
	err := facades.Orm().Query().Find(&users)
	if err != nil {
		return err
	}

	if len(users) == 0 {
		facades.Log().Warning("No users found, skipping user organization seeding")
		return nil
	}

	// Get organizations
	var organizations []models.Organization
	err = facades.Orm().Query().Find(&organizations)
	if err != nil {
		return err
	}

	if len(organizations) == 0 {
		facades.Log().Warning("No organizations found, skipping user organization seeding")
		return nil
	}

	// Get departments for assignment
	var departments []models.Department
	err = facades.Orm().Query().Find(&departments)
	if err != nil {
		return err
	}

	// Get teams for assignment
	var teams []models.Team
	err = facades.Orm().Query().Find(&teams)
	if err != nil {
		return err
	}

	// Create user-organization relationships
	for i, user := range users {
		// Assign user to 1-2 organizations
		numOrgs := 1
		if i%3 == 0 { // Every 3rd user gets assigned to 2 organizations
			numOrgs = 2
		}

		for j := 0; j < numOrgs && j < len(organizations); j++ {
			orgIndex := (i + j) % len(organizations)
			org := organizations[orgIndex]

			// Check if relationship already exists
			var existing models.UserOrganization
			err := facades.Orm().Query().Where("user_id = ? AND organization_id = ?", user.ID, org.ID).First(&existing)
			if err == nil {
				continue // Relationship already exists
			}

			// Determine user role based on index
			var role string
			if i == 0 {
				role = "owner" // First user is owner
			} else if i < 3 {
				role = "admin" // Next 2 users are admins
			} else if i < 10 {
				role = "member" // Next 7 users are members
			} else {
				role = "guest" // Rest are guests
			}

			// Find a department for this user in this organization
			var departmentID *string
			for _, dept := range departments {
				if dept.OrganizationID == org.ID {
					departmentID = &dept.ID
					break
				}
			}

			// Find a team for this user in this organization
			var teamID *string
			for _, team := range teams {
				if team.OrganizationID == org.ID {
					teamID = &team.ID
					break
				}
			}

			// Find a manager (use a different user as manager)
			var managerID *string
			if len(users) > 1 && i > 0 {
				managerIndex := (i - 1) % len(users)
				managerID = &users[managerIndex].ID
			}

			// Set hire date
			hireDate := time.Now().AddDate(0, -(i % 12), 0) // Random hire date within last year

			userOrg := models.UserOrganization{
				UserID:         user.ID,
				OrganizationID: org.ID,
				Role:           role,
				Status:         "active",
				IsActive:       true,
				JoinedAt:       time.Now().AddDate(0, -(i % 6), 0), // Random join date
				Title:          getRandomTitle(role),
				EmployeeID:     generateEmployeeID(i),
				DepartmentID:   departmentID,
				TeamID:         teamID,
				ManagerID:      managerID,
				HireDate:       &hireDate,
				Permissions:    getPermissionsForRole(role),
			}

			err = facades.Orm().Query().Create(&userOrg)
			if err != nil {
				facades.Log().Error("Failed to create user organization: " + err.Error())
				return err
			}

			facades.Log().Info("Created user organization relationship: " + user.Name + " -> " + org.Name + " (" + role + ")")
		}
	}

	facades.Log().Info("User organization seeder completed successfully")
	return nil
}

// Helper function to get random title based on role
func getRandomTitle(role string) string {
	titles := map[string][]string{
		"owner":  {"CEO", "Founder", "President"},
		"admin":  {"CTO", "VP Engineering", "Director", "Senior Manager"},
		"member": {"Senior Software Engineer", "Software Engineer", "Product Manager", "Designer", "DevOps Engineer"},
		"guest":  {"Consultant", "Contractor", "Intern"},
	}

	if roleTitles, exists := titles[role]; exists && len(roleTitles) > 0 {
		return roleTitles[0] // For simplicity, just return the first title
	}
	return "Member"
}

// Helper function to generate employee ID
func generateEmployeeID(index int) string {
	return "EMP" + string(rune('0'+index%10)) + string(rune('0'+(index/10)%10)) + string(rune('0'+(index/100)%10))
}

// Helper function to get permissions for role
func getPermissionsForRole(role string) string {
	permissions := map[string][]string{
		"owner":  {"*"}, // All permissions
		"admin":  {"read:*", "write:*", "delete:projects", "manage:users", "manage:teams"},
		"member": {"read:projects", "write:tasks", "read:reports", "manage:own_tasks"},
		"guest":  {"read:public_projects", "read:public_reports"},
	}

	if rolePerms, exists := permissions[role]; exists {
		// Convert to JSON array string
		result := "["
		for i, perm := range rolePerms {
			if i > 0 {
				result += ","
			}
			result += `"` + perm + `"`
		}
		result += "]"
		return result
	}
	return "[]"
}
