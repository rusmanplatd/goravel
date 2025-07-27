package models

import (
	"encoding/json"
	"fmt"

	"github.com/goravel/framework/facades"
)

// JobLevel represents a job level within an organization
// @Description Job level model for organizational hierarchy and career progression
type JobLevel struct {
	BaseModel

	// Job level name
	// @example Senior
	Name string `gorm:"not null" json:"name" example:"Senior"`

	// Job level description
	// @example Senior level position with advanced responsibilities
	Description string `json:"description" example:"Senior level position with advanced responsibilities"`

	// Hierarchical order of the level (1=lowest, higher numbers=higher levels)
	// @example 3
	LevelOrder int `gorm:"not null" json:"level_order" example:"3"`

	// Job level code/abbreviation
	// @example SR
	Code *string `json:"code,omitempty" example:"SR"`

	// Job level color for UI display
	// @example #3B82F6
	Color *string `json:"color,omitempty" example:"#3B82F6"`

	// Job level icon for UI display
	// @example star
	Icon *string `json:"icon,omitempty" example:"star"`

	// Whether job level is active
	// @example true
	IsActive bool `gorm:"default:true" json:"is_active" example:"true"`

	// Minimum salary range for this level
	// @example 80000.00
	MinSalary *float64 `json:"min_salary,omitempty" example:"80000.00"`

	// Maximum salary range for this level
	// @example 120000.00
	MaxSalary *float64 `json:"max_salary,omitempty" example:"120000.00"`

	// Currency for salary range
	// @example USD
	Currency string `gorm:"default:USD" json:"currency" example:"USD"`

	// Job level requirements (experience, skills, etc.)
	// @example {"experience_years":5,"skills":["leadership","technical"]}
	Requirements *string `gorm:"type:text" json:"requirements,omitempty" example:"{\"experience_years\":5,\"skills\":[\"leadership\",\"technical\"]}"`

	// Job level benefits and perks
	// @example {"vacation_days":25,"health_insurance":true}
	Benefits *string `gorm:"type:text" json:"benefits,omitempty" example:"{\"vacation_days\":25,\"health_insurance\":true}"`

	// Organization reference
	// @example 01HXYZ123456789ABCDEFGHIJK
	OrganizationID string `gorm:"not null;type:char(26)" json:"organization_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Relationships
	// @Description Organization this job level belongs to
	Organization *Organization `gorm:"foreignKey:OrganizationID" json:"organization,omitempty"`
}

// TableName returns the table name for the model
func (JobLevel) TableName() string {
	return "job_levels"
}

// GetRequirements returns the requirements as a map
func (jl *JobLevel) GetRequirements() (map[string]interface{}, error) {
	if jl.Requirements == nil || *jl.Requirements == "" {
		return make(map[string]interface{}), nil
	}

	var requirements map[string]interface{}
	err := json.Unmarshal([]byte(*jl.Requirements), &requirements)
	if err != nil {
		return nil, err
	}

	return requirements, nil
}

// SetRequirements sets the requirements from a map
func (jl *JobLevel) SetRequirements(requirements map[string]interface{}) error {
	if requirements == nil {
		jl.Requirements = nil
		return nil
	}

	data, err := json.Marshal(requirements)
	if err != nil {
		return err
	}

	requirementsStr := string(data)
	jl.Requirements = &requirementsStr
	return nil
}

// GetBenefits returns the benefits as a map
func (jl *JobLevel) GetBenefits() (map[string]interface{}, error) {
	if jl.Benefits == nil || *jl.Benefits == "" {
		return make(map[string]interface{}), nil
	}

	var benefits map[string]interface{}
	err := json.Unmarshal([]byte(*jl.Benefits), &benefits)
	if err != nil {
		return nil, err
	}

	return benefits, nil
}

// SetBenefits sets the benefits from a map
func (jl *JobLevel) SetBenefits(benefits map[string]interface{}) error {
	if benefits == nil {
		jl.Benefits = nil
		return nil
	}

	data, err := json.Marshal(benefits)
	if err != nil {
		return err
	}

	benefitsStr := string(data)
	jl.Benefits = &benefitsStr
	return nil
}

// GetSalaryRange returns a formatted salary range string
func (jl *JobLevel) GetSalaryRange() string {
	if jl.MinSalary == nil && jl.MaxSalary == nil {
		return ""
	}

	currency := jl.Currency
	if currency == "" {
		currency = "USD"
	}

	if jl.MinSalary != nil && jl.MaxSalary != nil {
		return currency + " " + formatSalary(*jl.MinSalary) + " - " + formatSalary(*jl.MaxSalary)
	} else if jl.MinSalary != nil {
		return currency + " " + formatSalary(*jl.MinSalary) + "+"
	} else if jl.MaxSalary != nil {
		return "Up to " + currency + " " + formatSalary(*jl.MaxSalary)
	}

	return ""
}

// Helper function to format salary
func formatSalary(salary float64) string {
	if salary >= 1000000 {
		return fmt.Sprintf("%.1fM", salary/1000000)
	} else if salary >= 1000 {
		return fmt.Sprintf("%.0fK", salary/1000)
	}
	return fmt.Sprintf("%.0f", salary)
}

// GetNextLevel returns the next job level in the hierarchy
func (jl *JobLevel) GetNextLevel(organizationID string) (*JobLevel, error) {
	var nextLevel JobLevel
	err := facades.Orm().Query().Where("organization_id", organizationID).
		Where("level_order", ">", jl.LevelOrder).
		Where("is_active", true).
		OrderBy("level_order").
		First(&nextLevel)

	if err != nil {
		return nil, err
	}
	return &nextLevel, nil
}

// GetPreviousLevel returns the previous job level in the hierarchy
func (jl *JobLevel) GetPreviousLevel(organizationID string) (*JobLevel, error) {
	var prevLevel JobLevel
	err := facades.Orm().Query().Where("organization_id", organizationID).
		Where("level_order", "<", jl.LevelOrder).
		Where("is_active", true).
		OrderBy("level_order", "desc").
		First(&prevLevel)

	if err != nil {
		return nil, err
	}
	return &prevLevel, nil
}

// GetCareerPath returns the career progression path from this level
func (jl *JobLevel) GetCareerPath(organizationID string, steps int) ([]JobLevel, error) {
	var levels []JobLevel
	err := facades.Orm().Query().Where("organization_id", organizationID).
		Where("level_order", ">=", jl.LevelOrder).
		Where("is_active", true).
		OrderBy("level_order").
		Limit(steps).
		Find(&levels)

	if err != nil {
		return nil, err
	}
	return levels, nil
}

// CanPromoteTo checks if promotion to target level is valid
func (jl *JobLevel) CanPromoteTo(targetLevel *JobLevel) bool {
	if targetLevel == nil {
		return false
	}
	return targetLevel.LevelOrder > jl.LevelOrder
}

// GetPromotionRequirements returns requirements for promotion to next level
func (jl *JobLevel) GetPromotionRequirements(organizationID string) (map[string]interface{}, error) {
	nextLevel, err := jl.GetNextLevel(organizationID)
	if err != nil {
		return nil, err
	}

	return nextLevel.GetRequirements()
}

// GetUsersAtLevel returns users currently at this job level
func (jl *JobLevel) GetUsersAtLevel(organizationID string) ([]User, error) {
	var users []User
	err := facades.Orm().Query().
		Join("user_organizations", "users.id", "=", "user_organizations.user_id").
		Where("user_organizations.organization_id", organizationID).
		Where("user_organizations.job_level_id", jl.ID).
		Where("user_organizations.is_active", true).
		Where("users.is_active", true).
		Find(&users)

	if err != nil {
		return nil, err
	}
	return users, nil
}
