package models

import (
	"encoding/json"

	"github.com/goravel/framework/facades"
)

// JobPosition represents a specific job position within an organization
// @Description Job position model for specific roles and positions
type JobPosition struct {
	BaseModel

	// Job position title
	// @example Software Engineer
	Title string `gorm:"not null" json:"title" example:"Software Engineer"`

	// Job position description and responsibilities
	// @example Develop and maintain web applications using modern technologies
	Description string `json:"description" example:"Develop and maintain web applications using modern technologies"`

	// Job position code/abbreviation
	// @example SWE
	Code *string `json:"code,omitempty" example:"SWE"`

	// Job position color for UI display
	// @example #10B981
	Color *string `json:"color,omitempty" example:"#10B981"`

	// Job position icon for UI display
	// @example code
	Icon *string `json:"icon,omitempty" example:"code"`

	// Whether job position is active
	// @example true
	IsActive bool `gorm:"default:true" json:"is_active" example:"true"`

	// Whether position supports remote work
	// @example true
	IsRemote bool `gorm:"default:false" json:"is_remote" example:"true"`

	// Employment type (full_time, part_time, contract, intern)
	// @example full_time
	EmploymentType string `gorm:"default:full_time" json:"employment_type" example:"full_time"`

	// Minimum salary range for this position
	// @example 70000.00
	MinSalary *float64 `json:"min_salary,omitempty" example:"70000.00"`

	// Maximum salary range for this position
	// @example 100000.00
	MaxSalary *float64 `json:"max_salary,omitempty" example:"100000.00"`

	// Currency for salary range
	// @example USD
	Currency string `gorm:"default:USD" json:"currency" example:"USD"`

	// Job position requirements (skills, experience, etc.)
	// @example {"skills":["golang","javascript"],"experience_years":3}
	Requirements *string `gorm:"type:text" json:"requirements,omitempty" example:"{\"skills\":[\"golang\",\"javascript\"],\"experience_years\":3}"`

	// Job position responsibilities and duties
	// @example {"primary":["coding","testing"],"secondary":["mentoring"]}
	Responsibilities *string `gorm:"type:text" json:"responsibilities,omitempty" example:"{\"primary\":[\"coding\",\"testing\"],\"secondary\":[\"mentoring\"]}"`

	// Job position benefits and perks
	// @example {"health_insurance":true,"flexible_hours":true}
	Benefits *string `gorm:"type:text" json:"benefits,omitempty" example:"{\"health_insurance\":true,\"flexible_hours\":true}"`

	// Job level reference
	// @example 01HXYZ123456789ABCDEFGHIJK
	JobLevelID string `gorm:"not null;type:char(26)" json:"job_level_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Department reference
	// @example 01HXYZ123456789ABCDEFGHIJK
	DepartmentID *string `gorm:"type:char(26)" json:"department_id,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Organization reference
	// @example 01HXYZ123456789ABCDEFGHIJK
	OrganizationID string `gorm:"not null;type:char(26)" json:"organization_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Position this role reports to
	// @example 01HXYZ123456789ABCDEFGHIJK
	ReportsToPositionID *string `gorm:"type:char(26)" json:"reports_to_position_id,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Number of positions available
	// @example 2
	Headcount int `gorm:"default:1" json:"headcount" example:"2"`

	// Number of positions filled
	// @example 1
	FilledCount int `gorm:"default:0" json:"filled_count" example:"1"`

	// Relationships
	// @Description Job level this position belongs to
	JobLevel *JobLevel `gorm:"foreignKey:JobLevelID" json:"job_level,omitempty"`
	// @Description Department this position belongs to
	Department *Department `gorm:"foreignKey:DepartmentID" json:"department,omitempty"`
	// @Description Organization this position belongs to
	Organization *Organization `gorm:"foreignKey:OrganizationID" json:"organization,omitempty"`
	// @Description Position this role reports to
	ReportsToPosition *JobPosition `gorm:"foreignKey:ReportsToPositionID" json:"reports_to_position,omitempty"`
}

// TableName returns the table name for the model
func (JobPosition) TableName() string {
	return "job_positions"
}

// GetRequirements returns the requirements as a map
func (jp *JobPosition) GetRequirements() (map[string]interface{}, error) {
	if jp.Requirements == nil || *jp.Requirements == "" {
		return make(map[string]interface{}), nil
	}

	var requirements map[string]interface{}
	err := json.Unmarshal([]byte(*jp.Requirements), &requirements)
	if err != nil {
		return nil, err
	}

	return requirements, nil
}

// SetRequirements sets the requirements from a map
func (jp *JobPosition) SetRequirements(requirements map[string]interface{}) error {
	if requirements == nil {
		jp.Requirements = nil
		return nil
	}

	data, err := json.Marshal(requirements)
	if err != nil {
		return err
	}

	requirementsStr := string(data)
	jp.Requirements = &requirementsStr
	return nil
}

// GetResponsibilities returns the responsibilities as a map
func (jp *JobPosition) GetResponsibilities() (map[string]interface{}, error) {
	if jp.Responsibilities == nil || *jp.Responsibilities == "" {
		return make(map[string]interface{}), nil
	}

	var responsibilities map[string]interface{}
	err := json.Unmarshal([]byte(*jp.Responsibilities), &responsibilities)
	if err != nil {
		return nil, err
	}

	return responsibilities, nil
}

// SetResponsibilities sets the responsibilities from a map
func (jp *JobPosition) SetResponsibilities(responsibilities map[string]interface{}) error {
	if responsibilities == nil {
		jp.Responsibilities = nil
		return nil
	}

	data, err := json.Marshal(responsibilities)
	if err != nil {
		return err
	}

	responsibilitiesStr := string(data)
	jp.Responsibilities = &responsibilitiesStr
	return nil
}

// GetBenefits returns the benefits as a map
func (jp *JobPosition) GetBenefits() (map[string]interface{}, error) {
	if jp.Benefits == nil || *jp.Benefits == "" {
		return make(map[string]interface{}), nil
	}

	var benefits map[string]interface{}
	err := json.Unmarshal([]byte(*jp.Benefits), &benefits)
	if err != nil {
		return nil, err
	}

	return benefits, nil
}

// SetBenefits sets the benefits from a map
func (jp *JobPosition) SetBenefits(benefits map[string]interface{}) error {
	if benefits == nil {
		jp.Benefits = nil
		return nil
	}

	data, err := json.Marshal(benefits)
	if err != nil {
		return err
	}

	benefitsStr := string(data)
	jp.Benefits = &benefitsStr
	return nil
}

// IsAvailable returns true if there are available positions
func (jp *JobPosition) IsAvailable() bool {
	return jp.FilledCount < jp.Headcount
}

// GetAvailablePositions returns the number of available positions
func (jp *JobPosition) GetAvailablePositions() int {
	available := jp.Headcount - jp.FilledCount
	if available < 0 {
		return 0
	}
	return available
}

// GetCareerProgressionPaths returns possible career progression paths from this position
func (jp *JobPosition) GetCareerProgressionPaths() ([]JobPosition, error) {
	var positions []JobPosition

	// Get positions that report to this position (direct reports)
	err := facades.Orm().Query().Where("reports_to_position_id", jp.ID).
		Where("is_active", true).
		With("JobLevel").
		Find(&positions)

	if err != nil {
		return nil, err
	}
	return positions, nil
}

// GetPromotionTargets returns positions this role can be promoted to
func (jp *JobPosition) GetPromotionTargets() ([]JobPosition, error) {
	var positions []JobPosition

	// Get positions at higher job levels in the same department or organization
	query := facades.Orm().Query().
		Join("job_levels", "job_positions.job_level_id", "=", "job_levels.id").
		Join("current_level", "current_level.id", "=", jp.JobLevelID).
		Where("job_levels.level_order", ">", facades.Orm().Query().Raw("current_level.level_order")).
		Where("job_positions.organization_id", jp.OrganizationID).
		Where("job_positions.is_active", true)

	// Prefer same department if available
	if jp.DepartmentID != nil {
		query = query.Where("job_positions.department_id", *jp.DepartmentID)
	}

	err := query.With("JobLevel").Find(&positions)
	if err != nil {
		return nil, err
	}
	return positions, nil
}

// GetLateralMoveTargets returns positions at the same level for lateral moves
func (jp *JobPosition) GetLateralMoveTargets() ([]JobPosition, error) {
	var positions []JobPosition

	err := facades.Orm().Query().Where("job_level_id", jp.JobLevelID).
		Where("organization_id", jp.OrganizationID).
		Where("is_active", true).
		Where("id", "!=", jp.ID).
		With("JobLevel").
		With("Department").
		Find(&positions)

	if err != nil {
		return nil, err
	}
	return positions, nil
}

// GetCurrentEmployees returns users currently in this position
func (jp *JobPosition) GetCurrentEmployees() ([]User, error) {
	var users []User

	err := facades.Orm().Query().
		Join("user_organizations", "users.id", "=", "user_organizations.user_id").
		Where("user_organizations.job_position_id", jp.ID).
		Where("user_organizations.is_active", true).
		Where("users.is_active", true).
		With("Profile").
		Find(&users)

	if err != nil {
		return nil, err
	}
	return users, nil
}

// GetEmploymentHistory returns the employment history for this position
func (jp *JobPosition) GetEmploymentHistory() ([]UserEmploymentHistory, error) {
	var history []UserEmploymentHistory

	err := facades.Orm().Query().Where("job_position_id", jp.ID).
		OrderBy("effective_date", "desc").
		With("User").
		With("JobLevel").
		Find(&history)

	if err != nil {
		return nil, err
	}
	return history, nil
}

// CanAccommodateUser checks if this position can accommodate a new user
func (jp *JobPosition) CanAccommodateUser() bool {
	return jp.IsActive && jp.IsAvailable()
}

// GetSalaryRange returns a formatted salary range string for this position
func (jp *JobPosition) GetSalaryRange() string {
	if jp.MinSalary == nil && jp.MaxSalary == nil {
		return ""
	}

	currency := jp.Currency
	if currency == "" {
		currency = "USD"
	}

	if jp.MinSalary != nil && jp.MaxSalary != nil {
		return currency + " " + formatSalary(*jp.MinSalary) + " - " + formatSalary(*jp.MaxSalary)
	} else if jp.MinSalary != nil {
		return currency + " " + formatSalary(*jp.MinSalary) + "+"
	} else if jp.MaxSalary != nil {
		return "Up to " + currency + " " + formatSalary(*jp.MaxSalary)
	}

	return ""
}

// GetReportingStructure returns the reporting hierarchy for this position
func (jp *JobPosition) GetReportingStructure() (map[string]interface{}, error) {
	result := make(map[string]interface{})

	// Get manager position
	if jp.ReportsToPositionID != nil {
		var managerPosition JobPosition
		err := facades.Orm().Query().Where("id", *jp.ReportsToPositionID).
			With("JobLevel").
			First(&managerPosition)
		if err == nil {
			result["reports_to"] = managerPosition
		}
	}

	// Get direct reports
	directReports, err := jp.GetCareerProgressionPaths()
	if err == nil {
		result["direct_reports"] = directReports
	}

	return result, nil
}
