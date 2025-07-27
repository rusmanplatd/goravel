package services

import (
	"fmt"
	"time"

	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

// JobProgressionValidationService handles job progression validation and rules
type JobProgressionValidationService struct{}

// NewJobProgressionValidationService creates a new instance
func NewJobProgressionValidationService() *JobProgressionValidationService {
	return &JobProgressionValidationService{}
}

// ValidationResult represents the result of a job progression validation
type ValidationResult struct {
	IsValid     bool     `json:"is_valid"`
	Messages    []string `json:"messages"`
	Warnings    []string `json:"warnings"`
	Suggestions []string `json:"suggestions"`
}

// ValidatePromotion validates if a user can be promoted to a specific job level
func (jpvs *JobProgressionValidationService) ValidatePromotion(userID, organizationID, targetLevelID string) (*ValidationResult, error) {
	result := &ValidationResult{
		IsValid:     true,
		Messages:    []string{},
		Warnings:    []string{},
		Suggestions: []string{},
	}

	// Get user
	var user models.User
	if err := facades.Orm().Query().Where("id", userID).First(&user); err != nil {
		return nil, fmt.Errorf("user not found: %v", err)
	}

	// Get current job level
	currentLevel, err := user.GetCurrentJobLevel(organizationID)
	if err != nil {
		result.IsValid = false
		result.Messages = append(result.Messages, "User has no current job level in this organization")
		return result, nil
	}

	// Get target job level
	var targetLevel models.JobLevel
	if err := facades.Orm().Query().Where("id", targetLevelID).First(&targetLevel); err != nil {
		return nil, fmt.Errorf("target job level not found: %v", err)
	}

	// Validate basic promotion rules
	if !currentLevel.CanPromoteTo(&targetLevel) {
		result.IsValid = false
		result.Messages = append(result.Messages, fmt.Sprintf("Cannot promote from level %s to %s - target level must be higher", currentLevel.Name, targetLevel.Name))
		return result, nil
	}

	// Check if skipping levels (optional warning)
	if targetLevel.LevelOrder > currentLevel.LevelOrder+1 {
		result.Warnings = append(result.Warnings, fmt.Sprintf("Promotion skips %d level(s) - consider intermediate promotions", targetLevel.LevelOrder-currentLevel.LevelOrder-1))
	}

	// Check tenure requirements
	tenureResult, err := jpvs.validateTenureRequirements(userID, organizationID, &targetLevel)
	if err != nil {
		return nil, err
	}
	jpvs.mergeValidationResults(result, tenureResult)

	// Check performance requirements
	performanceResult, err := jpvs.validatePerformanceRequirements(userID, organizationID, &targetLevel)
	if err != nil {
		return nil, err
	}
	jpvs.mergeValidationResults(result, performanceResult)

	// Check skill requirements
	skillResult, err := jpvs.validateSkillRequirements(userID, organizationID, &targetLevel)
	if err != nil {
		return nil, err
	}
	jpvs.mergeValidationResults(result, skillResult)

	// Check position availability
	availabilityResult, err := jpvs.validatePositionAvailability(organizationID, targetLevelID)
	if err != nil {
		return nil, err
	}
	jpvs.mergeValidationResults(result, availabilityResult)

	return result, nil
}

// validateTenureRequirements checks if user meets tenure requirements
func (jpvs *JobProgressionValidationService) validateTenureRequirements(userID, organizationID string, targetLevel *models.JobLevel) (*ValidationResult, error) {
	result := &ValidationResult{IsValid: true}

	// Get target level requirements
	requirements, err := targetLevel.GetRequirements()
	if err != nil {
		return result, nil // Skip if no requirements
	}

	// Check experience years requirement
	if experienceYears, ok := requirements["experience_years"].(float64); ok {
		var user models.User
		facades.Orm().Query().Where("id", userID).First(&user)

		totalTenure, err := user.GetTotalTenureInOrganization(organizationID)
		if err == nil {
			tenureYears := totalTenure.Hours() / (24 * 365)
			if tenureYears < experienceYears {
				result.IsValid = false
				result.Messages = append(result.Messages, fmt.Sprintf("Requires %.1f years of experience, user has %.1f years", experienceYears, tenureYears))
			}
		}
	}

	// Check minimum time in current position
	if minTimeInPosition, ok := requirements["min_time_in_current_position_months"].(float64); ok {
		var user models.User
		facades.Orm().Query().Where("id", userID).First(&user)

		currentTenure, err := user.GetTenureInCurrentPosition(organizationID)
		if err == nil {
			tenureMonths := currentTenure.Hours() / (24 * 30)
			if tenureMonths < minTimeInPosition {
				result.IsValid = false
				result.Messages = append(result.Messages, fmt.Sprintf("Requires %.1f months in current position, user has %.1f months", minTimeInPosition, tenureMonths))
			}
		}
	}

	return result, nil
}

// validatePerformanceRequirements checks if user meets performance requirements
func (jpvs *JobProgressionValidationService) validatePerformanceRequirements(userID, organizationID string, targetLevel *models.JobLevel) (*ValidationResult, error) {
	result := &ValidationResult{IsValid: true}

	// Get target level requirements
	requirements, err := targetLevel.GetRequirements()
	if err != nil {
		return result, nil
	}

	// Check minimum performance rating
	if minRating, ok := requirements["min_performance_rating"].(float64); ok {
		var user models.User
		facades.Orm().Query().Where("id", userID).First(&user)

		avgRating, err := user.GetAveragePerformanceRating(organizationID)
		if err == nil && avgRating < minRating {
			result.IsValid = false
			result.Messages = append(result.Messages, fmt.Sprintf("Requires minimum performance rating of %.1f, user has %.1f", minRating, avgRating))
		}
	}

	// Check recent performance trend
	if requiresImprovement, ok := requirements["requires_performance_improvement"].(bool); ok && requiresImprovement {
		var user models.User
		facades.Orm().Query().Where("id", userID).First(&user)

		ratings, err := user.GetPerformanceHistory(organizationID)
		if err == nil && len(ratings) >= 2 {
			// Check if performance is improving (last rating > previous rating)
			lastRating := ratings[len(ratings)-1]
			previousRating := ratings[len(ratings)-2]
			if lastRating <= previousRating {
				result.Warnings = append(result.Warnings, "Performance improvement trend recommended for this promotion")
			}
		}
	}

	return result, nil
}

// validateSkillRequirements checks if user meets skill requirements
func (jpvs *JobProgressionValidationService) validateSkillRequirements(userID, organizationID string, targetLevel *models.JobLevel) (*ValidationResult, error) {
	result := &ValidationResult{IsValid: true}

	// Get target level requirements
	requirements, err := targetLevel.GetRequirements()
	if err != nil {
		return result, nil
	}

	// Check required skills
	if requiredSkills, ok := requirements["skills"].([]interface{}); ok {
		// This would typically integrate with a skills tracking system
		// For now, we'll add suggestions
		skillNames := make([]string, len(requiredSkills))
		for i, skill := range requiredSkills {
			if skillStr, ok := skill.(string); ok {
				skillNames[i] = skillStr
			}
		}
		if len(skillNames) > 0 {
			result.Suggestions = append(result.Suggestions, fmt.Sprintf("Ensure user has demonstrated competency in: %v", skillNames))
		}
	}

	// Check leadership requirements
	if requiresLeadership, ok := requirements["requires_leadership"].(bool); ok && requiresLeadership {
		result.Suggestions = append(result.Suggestions, "Verify user has demonstrated leadership capabilities")
	}

	return result, nil
}

// validatePositionAvailability checks if there are available positions at the target level
func (jpvs *JobProgressionValidationService) validatePositionAvailability(organizationID, targetLevelID string) (*ValidationResult, error) {
	result := &ValidationResult{IsValid: true}

	// Get positions at target level
	var positions []models.JobPosition
	err := facades.Orm().Query().
		Where("job_level_id", targetLevelID).
		Where("organization_id", organizationID).
		Where("is_active", true).
		Find(&positions)

	if err != nil {
		return result, nil
	}

	availablePositions := 0
	for _, position := range positions {
		availablePositions += position.GetAvailablePositions()
	}

	if availablePositions == 0 {
		result.Warnings = append(result.Warnings, "No available positions at target level - promotion may require creating new position or waiting for opening")
	} else {
		result.Suggestions = append(result.Suggestions, fmt.Sprintf("%d position(s) available at target level", availablePositions))
	}

	return result, nil
}

// ValidateJobAssignment validates if a user can be assigned to a specific job position
func (jpvs *JobProgressionValidationService) ValidateJobAssignment(userID, jobPositionID string) (*ValidationResult, error) {
	result := &ValidationResult{
		IsValid:     true,
		Messages:    []string{},
		Warnings:    []string{},
		Suggestions: []string{},
	}

	// Get job position
	var position models.JobPosition
	if err := facades.Orm().Query().Where("id", jobPositionID).With("JobLevel").First(&position); err != nil {
		return nil, fmt.Errorf("job position not found: %v", err)
	}

	// Check if position can accommodate user
	if !position.CanAccommodateUser() {
		result.IsValid = false
		result.Messages = append(result.Messages, "Position is not active or has no available slots")
		return result, nil
	}

	// Check position requirements
	requirements, err := position.GetRequirements()
	if err == nil && len(requirements) > 0 {
		// Add suggestions based on position requirements
		if skills, ok := requirements["skills"].([]interface{}); ok {
			skillNames := make([]string, len(skills))
			for i, skill := range skills {
				if skillStr, ok := skill.(string); ok {
					skillNames[i] = skillStr
				}
			}
			result.Suggestions = append(result.Suggestions, fmt.Sprintf("Position requires skills: %v", skillNames))
		}

		if experienceYears, ok := requirements["experience_years"].(float64); ok {
			result.Suggestions = append(result.Suggestions, fmt.Sprintf("Position requires %.1f years of experience", experienceYears))
		}
	}

	return result, nil
}

// GetPromotionRecommendations provides recommendations for user career progression
func (jpvs *JobProgressionValidationService) GetPromotionRecommendations(userID, organizationID string) (map[string]interface{}, error) {
	var user models.User
	if err := facades.Orm().Query().Where("id", userID).First(&user); err != nil {
		return nil, fmt.Errorf("user not found: %v", err)
	}

	// Get current level
	currentLevel, err := user.GetCurrentJobLevel(organizationID)
	if err != nil {
		return map[string]interface{}{
			"message": "User has no current job level in this organization",
		}, nil
	}

	// Get next level
	nextLevel, err := currentLevel.GetNextLevel(organizationID)
	if err != nil {
		return map[string]interface{}{
			"message":       "No higher level available for promotion",
			"current_level": currentLevel,
		}, nil
	}

	// Validate promotion to next level
	validation, err := jpvs.ValidatePromotion(userID, organizationID, nextLevel.ID)
	if err != nil {
		return nil, err
	}

	// Get career path
	careerPath, err := currentLevel.GetCareerPath(organizationID, 5)
	if err != nil {
		careerPath = []models.JobLevel{}
	}

	// Calculate readiness score
	readinessScore := jpvs.calculateReadinessScore(validation)

	return map[string]interface{}{
		"current_level":   currentLevel,
		"next_level":      nextLevel,
		"validation":      validation,
		"career_path":     careerPath,
		"readiness_score": readinessScore,
		"recommendations": jpvs.generateRecommendations(validation, readinessScore),
		"generated_at":    time.Now(),
	}, nil
}

// calculateReadinessScore calculates a readiness score based on validation results
func (jpvs *JobProgressionValidationService) calculateReadinessScore(validation *ValidationResult) float64 {
	if !validation.IsValid {
		return 0.0
	}

	score := 100.0

	// Reduce score for each warning
	score -= float64(len(validation.Warnings)) * 10.0

	// Ensure score doesn't go below 0
	if score < 0 {
		score = 0
	}

	return score
}

// generateRecommendations generates actionable recommendations
func (jpvs *JobProgressionValidationService) generateRecommendations(validation *ValidationResult, readinessScore float64) []string {
	recommendations := []string{}

	if readinessScore >= 80 {
		recommendations = append(recommendations, "User is ready for promotion - consider initiating promotion process")
	} else if readinessScore >= 60 {
		recommendations = append(recommendations, "User is mostly ready for promotion - address warnings before proceeding")
	} else if readinessScore >= 40 {
		recommendations = append(recommendations, "User needs development - create targeted improvement plan")
	} else {
		recommendations = append(recommendations, "User requires significant development before promotion consideration")
	}

	// Add specific recommendations from validation
	recommendations = append(recommendations, validation.Suggestions...)

	return recommendations
}

// mergeValidationResults merges two validation results
func (jpvs *JobProgressionValidationService) mergeValidationResults(target, source *ValidationResult) {
	if !source.IsValid {
		target.IsValid = false
	}
	target.Messages = append(target.Messages, source.Messages...)
	target.Warnings = append(target.Warnings, source.Warnings...)
	target.Suggestions = append(target.Suggestions, source.Suggestions...)
}
