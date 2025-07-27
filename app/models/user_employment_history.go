package models

import (
	"time"
)

// UserEmploymentHistory represents the employment history of a user
// @Description User employment history model for tracking job changes and career progression
type UserEmploymentHistory struct {
	BaseModel

	// User reference
	// @example 01HXYZ123456789ABCDEFGHIJK
	UserID string `gorm:"not null;type:char(26);index" json:"user_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Organization reference
	// @example 01HXYZ123456789ABCDEFGHIJK
	OrganizationID string `gorm:"not null;type:char(26);index" json:"organization_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Job position reference
	// @example 01HXYZ123456789ABCDEFGHIJK
	JobPositionID *string `gorm:"type:char(26);index" json:"job_position_id,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Job level reference
	// @example 01HXYZ123456789ABCDEFGHIJK
	JobLevelID *string `gorm:"type:char(26);index" json:"job_level_id,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Department reference
	// @example 01HXYZ123456789ABCDEFGHIJK
	DepartmentID *string `gorm:"type:char(26);index" json:"department_id,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Team reference
	// @example 01HXYZ123456789ABCDEFGHIJK
	TeamID *string `gorm:"type:char(26);index" json:"team_id,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Manager reference
	// @example 01HXYZ123456789ABCDEFGHIJK
	ManagerID *string `gorm:"type:char(26);index" json:"manager_id,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Job title at the time
	// @example Senior Software Engineer
	JobTitle string `gorm:"not null" json:"job_title" example:"Senior Software Engineer"`

	// Employee ID at the time
	// @example EMP001
	EmployeeID string `json:"employee_id" example:"EMP001"`

	// Employment type (full_time, part_time, contract, intern)
	// @example full_time
	EmploymentType string `gorm:"default:full_time" json:"employment_type" example:"full_time"`

	// Change type (hire, promotion, transfer, demotion, termination, role_change)
	// @example promotion
	ChangeType string `gorm:"not null;index" json:"change_type" example:"promotion"`

	// Reason for the change
	// @example Performance-based promotion
	ChangeReason string `json:"change_reason" example:"Performance-based promotion"`

	// Effective date of the change
	// @example 2024-01-15T00:00:00Z
	EffectiveDate time.Time `gorm:"not null;index" json:"effective_date" example:"2024-01-15T00:00:00Z"`

	// End date of this position (null if current)
	// @example 2024-12-31T00:00:00Z
	EndDate *time.Time `gorm:"index" json:"end_date,omitempty" example:"2024-12-31T00:00:00Z"`

	// Whether this is the current position
	// @example true
	IsCurrent bool `gorm:"default:false;index" json:"is_current" example:"true"`

	// Salary at the time (encrypted)
	// @example encrypted_salary_data
	Salary string `json:"salary,omitempty" example:"encrypted_salary_data"`

	// Currency for salary
	// @example USD
	Currency string `gorm:"default:USD" json:"currency" example:"USD"`

	// Performance rating at the time of change
	// @example 4.5
	PerformanceRating *float64 `json:"performance_rating,omitempty" example:"4.5"`

	// Additional notes about the employment change
	// @example Promoted based on exceptional performance and leadership skills
	Notes string `gorm:"type:text" json:"notes,omitempty" example:"Promoted based on exceptional performance and leadership skills"`

	// Relationships
	User         User         `gorm:"foreignKey:UserID" json:"user,omitempty"`
	Organization Organization `gorm:"foreignKey:OrganizationID" json:"organization,omitempty"`
	JobPosition  *JobPosition `gorm:"foreignKey:JobPositionID" json:"job_position,omitempty"`
	JobLevel     *JobLevel    `gorm:"foreignKey:JobLevelID" json:"job_level,omitempty"`
	Department   *Department  `gorm:"foreignKey:DepartmentID" json:"department,omitempty"`
	Team         *Team        `gorm:"foreignKey:TeamID" json:"team,omitempty"`
	Manager      *User        `gorm:"foreignKey:ManagerID" json:"manager,omitempty"`
}

// TableName returns the table name for the model
func (UserEmploymentHistory) TableName() string {
	return "user_employment_history"
}

// GetDuration returns the duration of this employment period
func (ueh *UserEmploymentHistory) GetDuration() time.Duration {
	endDate := time.Now()
	if ueh.EndDate != nil {
		endDate = *ueh.EndDate
	}
	return endDate.Sub(ueh.EffectiveDate)
}

// GetDurationInMonths returns the duration in months
func (ueh *UserEmploymentHistory) GetDurationInMonths() int {
	duration := ueh.GetDuration()
	return int(duration.Hours() / (24 * 30))
}

// GetDurationInYears returns the duration in years
func (ueh *UserEmploymentHistory) GetDurationInYears() float64 {
	duration := ueh.GetDuration()
	return duration.Hours() / (24 * 365)
}
