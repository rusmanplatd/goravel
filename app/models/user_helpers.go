package models

import (
	"time"

	"github.com/goravel/framework/facades"
)

// HasRole checks if user has a specific role in an organization
func (u *User) HasRole(roleName string, organizationID string) bool {
	var count int64
	err := facades.Orm().Query().
		Table("user_roles ur").
		Select("count(*)").
		Where("ur.user_id = ? AND ur.organization_id = ?", u.ID, organizationID).
		Where("EXISTS (SELECT 1 FROM roles r WHERE r.id = ur.role_id AND r.name = ?)", roleName).
		Scan(&count)

	if err != nil {
		return false
	}

	return count > 0
}

// HasPermission checks if user has a specific permission in an organization
func (u *User) HasPermission(permissionName string, organizationID string) bool {
	var count int64
	err := facades.Orm().Query().
		Table("user_roles ur").
		Select("count(*)").
		Where("ur.user_id = ? AND ur.organization_id = ?", u.ID, organizationID).
		Where("EXISTS (SELECT 1 FROM role_permissions rp JOIN permissions p ON rp.permission_id = p.id WHERE rp.role_id = ur.role_id AND p.name = ?)", permissionName).
		Scan(&count)

	if err != nil {
		return false
	}

	return count > 0
}

// GetRolesForOrganization returns all roles for user in a specific organization
func (u *User) GetRolesForOrganization(organizationID string) ([]Role, error) {
	var roles []Role
	err := facades.Orm().Query().
		Where("id IN (SELECT role_id FROM user_roles WHERE user_id = ? AND organization_id = ?)", u.ID, organizationID).
		Find(&roles)

	return roles, err
}

// GetPermissionsForOrganization returns all permissions for user in a specific organization
func (u *User) GetPermissionsForOrganization(organizationID string) ([]Permission, error) {
	var permissions []Permission
	err := facades.Orm().Query().
		Where("id IN (SELECT permission_id FROM role_permissions rp JOIN user_roles ur ON rp.role_id = ur.role_id WHERE ur.user_id = ? AND ur.organization_id = ?)", u.ID, organizationID).
		Find(&permissions)

	return permissions, err
}

// BelongsToOrganization checks if user belongs to a specific organization
func (u *User) BelongsToOrganization(organizationID string) bool {
	var count int64
	facades.Orm().Query().
		Raw("SELECT COUNT(*) FROM user_organizations WHERE user_id = ? AND organization_id = ? AND is_active = ?", u.ID, organizationID, true).
		Scan(&count)

	return count > 0
}

// AssignRole assigns a role to user in a specific organization
func (u *User) AssignRole(roleID string, organizationID string) error {
	userRole := UserRole{
		UserID:         u.ID,
		RoleID:         roleID,
		OrganizationID: &organizationID,
	}

	return facades.Orm().Query().Create(&userRole)
}

// RemoveRole removes a role from user in a specific organization
func (u *User) RemoveRole(roleID string, organizationID string) error {
	_, err := facades.Orm().Query().
		Where("user_id = ? AND role_id = ? AND organization_id = ?", u.ID, roleID, organizationID).
		Delete(&UserRole{})

	return err
}

// AddToOrganization adds user to an organization
func (u *User) AddToOrganization(organizationID string) error {
	userOrg := UserOrganization{
		UserID:         u.ID,
		OrganizationID: organizationID,
		IsActive:       true,
		JoinedAt:       time.Now(),
		Role:           "member",
		Status:         "active",
	}

	return facades.Orm().Query().Create(&userOrg)
}

// RemoveFromOrganization removes user from an organization
func (u *User) RemoveFromOrganization(organizationID string) error {
	_, err := facades.Orm().Query().
		Where("user_id = ? AND organization_id = ?", u.ID, organizationID).
		Delete(&UserOrganization{})

	return err
}

// GetCurrentJobPosition returns the user's current job position in an organization
func (u *User) GetCurrentJobPosition(organizationID string) (*JobPosition, error) {
	var userOrg UserOrganization
	err := facades.Orm().Query().
		Where("user_id", u.ID).
		Where("organization_id", organizationID).
		Where("is_active", true).
		With("JobPosition").
		With("JobLevel").
		First(&userOrg)

	if err != nil {
		return nil, err
	}
	return userOrg.JobPosition, nil
}

// GetCurrentJobLevel returns the user's current job level in an organization
func (u *User) GetCurrentJobLevel(organizationID string) (*JobLevel, error) {
	var userOrg UserOrganization
	err := facades.Orm().Query().
		Where("user_id", u.ID).
		Where("organization_id", organizationID).
		Where("is_active", true).
		With("JobLevel").
		First(&userOrg)

	if err != nil {
		return nil, err
	}
	return userOrg.JobLevel, nil
}

// GetEmploymentHistory returns the user's employment history across all organizations
func (u *User) GetEmploymentHistory() ([]UserEmploymentHistory, error) {
	var history []UserEmploymentHistory
	err := facades.Orm().Query().
		Where("user_id", u.ID).
		OrderBy("effective_date", "desc").
		With("Organization").
		With("JobPosition").
		With("JobLevel").
		With("Department").
		Find(&history)

	if err != nil {
		return nil, err
	}
	return history, nil
}

// GetEmploymentHistoryForOrganization returns the user's employment history for a specific organization
func (u *User) GetEmploymentHistoryForOrganization(organizationID string) ([]UserEmploymentHistory, error) {
	var history []UserEmploymentHistory
	err := facades.Orm().Query().
		Where("user_id", u.ID).
		Where("organization_id", organizationID).
		OrderBy("effective_date", "desc").
		With("JobPosition").
		With("JobLevel").
		With("Department").
		Find(&history)

	if err != nil {
		return nil, err
	}
	return history, nil
}

// GetCareerProgression returns the user's career progression path
func (u *User) GetCareerProgression(organizationID string) (map[string]interface{}, error) {
	history, err := u.GetEmploymentHistoryForOrganization(organizationID)
	if err != nil {
		return nil, err
	}

	result := make(map[string]interface{})
	result["history"] = history

	// Get current position
	currentPosition, err := u.GetCurrentJobPosition(organizationID)
	if err == nil && currentPosition != nil {
		result["current_position"] = currentPosition

		// Get promotion targets
		promotionTargets, err := currentPosition.GetPromotionTargets()
		if err == nil {
			result["promotion_targets"] = promotionTargets
		}

		// Get lateral move options
		lateralMoves, err := currentPosition.GetLateralMoveTargets()
		if err == nil {
			result["lateral_moves"] = lateralMoves
		}
	}

	// Get current job level
	currentLevel, err := u.GetCurrentJobLevel(organizationID)
	if err == nil && currentLevel != nil {
		result["current_level"] = currentLevel

		// Get next level in career path
		nextLevel, err := currentLevel.GetNextLevel(organizationID)
		if err == nil {
			result["next_level"] = nextLevel
		}

		// Get career path
		careerPath, err := currentLevel.GetCareerPath(organizationID, 5)
		if err == nil {
			result["career_path"] = careerPath
		}
	}

	return result, nil
}

// GetTenureInCurrentPosition returns the tenure in current position
func (u *User) GetTenureInCurrentPosition(organizationID string) (time.Duration, error) {
	var currentHistory UserEmploymentHistory
	err := facades.Orm().Query().
		Where("user_id", u.ID).
		Where("organization_id", organizationID).
		Where("is_current", true).
		First(&currentHistory)

	if err != nil {
		return 0, err
	}

	return currentHistory.GetDuration(), nil
}

// GetTotalTenureInOrganization returns the total tenure in organization
func (u *User) GetTotalTenureInOrganization(organizationID string) (time.Duration, error) {
	var userOrg UserOrganization
	err := facades.Orm().Query().
		Where("user_id", u.ID).
		Where("organization_id", organizationID).
		Where("is_active", true).
		First(&userOrg)

	if err != nil {
		return 0, err
	}

	return time.Since(userOrg.JoinedAt), nil
}

// CanBePromotedTo checks if user can be promoted to a specific job level
func (u *User) CanBePromotedTo(organizationID string, targetLevelID string) (bool, error) {
	currentLevel, err := u.GetCurrentJobLevel(organizationID)
	if err != nil {
		return false, err
	}

	if currentLevel == nil {
		return false, nil
	}

	var targetLevel JobLevel
	err = facades.Orm().Query().Where("id", targetLevelID).First(&targetLevel)
	if err != nil {
		return false, err
	}

	return currentLevel.CanPromoteTo(&targetLevel), nil
}

// GetPerformanceHistory returns the user's performance ratings over time
func (u *User) GetPerformanceHistory(organizationID string) ([]float64, error) {
	var history []UserEmploymentHistory
	err := facades.Orm().Query().
		Where("user_id", u.ID).
		Where("organization_id", organizationID).
		Where("performance_rating IS NOT NULL").
		OrderBy("effective_date").
		Find(&history)

	if err != nil {
		return nil, err
	}

	var ratings []float64
	for _, h := range history {
		if h.PerformanceRating != nil {
			ratings = append(ratings, *h.PerformanceRating)
		}
	}

	return ratings, nil
}

// GetAveragePerformanceRating returns the user's average performance rating
func (u *User) GetAveragePerformanceRating(organizationID string) (float64, error) {
	ratings, err := u.GetPerformanceHistory(organizationID)
	if err != nil {
		return 0, err
	}

	if len(ratings) == 0 {
		return 0, nil
	}

	var sum float64
	for _, rating := range ratings {
		sum += rating
	}

	return sum / float64(len(ratings)), nil
}

// CreateEmploymentHistoryEntry creates a new employment history entry
func (u *User) CreateEmploymentHistoryEntry(entry UserEmploymentHistory) error {
	// Set user ID
	entry.UserID = u.ID

	// End current position if this is a new current position
	if entry.IsCurrent {
		var currentHistory UserEmploymentHistory
		err := facades.Orm().Query().
			Where("user_id", u.ID).
			Where("organization_id", entry.OrganizationID).
			Where("is_current", true).
			First(&currentHistory)

		if err == nil {
			// End the current position
			now := time.Now()
			currentHistory.EndDate = &now
			currentHistory.IsCurrent = false
			facades.Orm().Query().Save(&currentHistory)
		}
	}

	// Create new entry
	return facades.Orm().Query().Create(&entry)
}
