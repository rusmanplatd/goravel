package services

import (
	"fmt"
	"time"

	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

// JobAnalyticsService provides analytics and reporting for job levels and positions
type JobAnalyticsService struct{}

// NewJobAnalyticsService creates a new instance of JobAnalyticsService
func NewJobAnalyticsService() *JobAnalyticsService {
	return &JobAnalyticsService{}
}

// GetOrganizationJobLevelDistribution returns the distribution of users across job levels
func (jas *JobAnalyticsService) GetOrganizationJobLevelDistribution(organizationID string) (map[string]interface{}, error) {
	var results []struct {
		JobLevelID   string `json:"job_level_id"`
		JobLevelName string `json:"job_level_name"`
		LevelOrder   int    `json:"level_order"`
		UserCount    int    `json:"user_count"`
	}

	err := facades.Orm().Query().
		Table("user_organizations").
		Select("job_levels.id as job_level_id, job_levels.name as job_level_name, job_levels.level_order, COUNT(user_organizations.user_id) as user_count").
		Join("job_levels", "user_organizations.job_level_id", "=", "job_levels.id").
		Where("user_organizations.organization_id", organizationID).
		Where("user_organizations.is_active", true).
		Where("job_levels.is_active", true).
		Group("job_levels.id, job_levels.name, job_levels.level_order").
		OrderBy("job_levels.level_order").
		Find(&results)

	if err != nil {
		return nil, err
	}

	response := map[string]interface{}{
		"organization_id": organizationID,
		"distribution":    results,
		"total_users":     0,
		"generated_at":    time.Now(),
	}

	// Calculate total users
	totalUsers := 0
	for _, result := range results {
		totalUsers += result.UserCount
	}
	response["total_users"] = totalUsers

	return response, nil
}

// GetJobPositionUtilization returns utilization statistics for job positions
func (jas *JobAnalyticsService) GetJobPositionUtilization(organizationID string) (map[string]interface{}, error) {
	var results []struct {
		JobPositionID    string  `json:"job_position_id"`
		JobPositionTitle string  `json:"job_position_title"`
		JobLevelName     string  `json:"job_level_name"`
		Headcount        int     `json:"headcount"`
		FilledCount      int     `json:"filled_count"`
		UtilizationRate  float64 `json:"utilization_rate"`
	}

	err := facades.Orm().Query().
		Table("job_positions").
		Select("job_positions.id as job_position_id, job_positions.title as job_position_title, job_levels.name as job_level_name, job_positions.headcount, job_positions.filled_count, CASE WHEN job_positions.headcount > 0 THEN (job_positions.filled_count::float / job_positions.headcount::float) * 100 ELSE 0 END as utilization_rate").
		Join("job_levels", "job_positions.job_level_id", "=", "job_levels.id").
		Where("job_positions.organization_id", organizationID).
		Where("job_positions.is_active", true).
		OrderBy("utilization_rate", "desc").
		Find(&results)

	if err != nil {
		return nil, err
	}

	// Calculate summary statistics
	totalPositions := len(results)
	totalHeadcount := 0
	totalFilled := 0
	fullyUtilized := 0
	underUtilized := 0

	for _, result := range results {
		totalHeadcount += result.Headcount
		totalFilled += result.FilledCount
		if result.UtilizationRate == 100 {
			fullyUtilized++
		} else if result.UtilizationRate < 80 {
			underUtilized++
		}
	}

	overallUtilization := 0.0
	if totalHeadcount > 0 {
		overallUtilization = (float64(totalFilled) / float64(totalHeadcount)) * 100
	}

	return map[string]interface{}{
		"organization_id": organizationID,
		"positions":       results,
		"summary": map[string]interface{}{
			"total_positions":     totalPositions,
			"total_headcount":     totalHeadcount,
			"total_filled":        totalFilled,
			"overall_utilization": overallUtilization,
			"fully_utilized":      fullyUtilized,
			"under_utilized":      underUtilized,
		},
		"generated_at": time.Now(),
	}, nil
}

// GetCareerProgressionAnalytics returns analytics on career progression patterns
func (jas *JobAnalyticsService) GetCareerProgressionAnalytics(organizationID string, timeRange int) (map[string]interface{}, error) {
	startDate := time.Now().AddDate(0, 0, -timeRange)

	var promotions []struct {
		UserID          string    `json:"user_id"`
		UserName        string    `json:"user_name"`
		ToLevelName     string    `json:"to_level_name"`
		ToPositionTitle string    `json:"to_position_title"`
		EffectiveDate   time.Time `json:"effective_date"`
		ChangeReason    string    `json:"change_reason"`
	}

	err := facades.Orm().Query().
		Table("user_employment_history").
		Select("user_employment_history.user_id, users.name as user_name, job_levels.name as to_level_name, job_positions.title as to_position_title, user_employment_history.effective_date, user_employment_history.change_reason").
		Join("users", "user_employment_history.user_id", "=", "users.id").
		Join("job_levels", "user_employment_history.job_level_id", "=", "job_levels.id").
		Join("job_positions", "user_employment_history.job_position_id", "=", "job_positions.id").
		Where("user_employment_history.organization_id", organizationID).
		Where("user_employment_history.change_type", "promotion").
		Where("user_employment_history.effective_date", ">=", startDate).
		OrderBy("user_employment_history.effective_date", "desc").
		Find(&promotions)

	if err != nil {
		return nil, err
	}

	// Get promotion statistics by level
	var levelStats []struct {
		JobLevelName   string `json:"job_level_name"`
		PromotionCount int    `json:"promotion_count"`
	}

	err = facades.Orm().Query().
		Table("user_employment_history").
		Select("job_levels.name as job_level_name, COUNT(*) as promotion_count").
		Join("job_levels", "user_employment_history.job_level_id", "=", "job_levels.id").
		Where("user_employment_history.organization_id", organizationID).
		Where("user_employment_history.change_type", "promotion").
		Where("user_employment_history.effective_date", ">=", startDate).
		Group("job_levels.id, job_levels.name").
		OrderBy("promotion_count", "desc").
		Find(&levelStats)

	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"organization_id":  organizationID,
		"time_range_days":  timeRange,
		"promotions":       promotions,
		"level_statistics": levelStats,
		"total_promotions": len(promotions),
		"generated_at":     time.Now(),
	}, nil
}

// GetEmployeeTurnoverByJobLevel returns turnover analytics by job level
func (jas *JobAnalyticsService) GetEmployeeTurnoverByJobLevel(organizationID string, timeRange int) (map[string]interface{}, error) {
	startDate := time.Now().AddDate(0, 0, -timeRange)

	// Get current employees by job level
	var currentEmployees []struct {
		JobLevelID     string `json:"job_level_id"`
		JobLevelName   string `json:"job_level_name"`
		TotalEmployees int    `json:"total_employees"`
	}

	err := facades.Orm().Query().
		Table("user_organizations").
		Select("job_levels.id as job_level_id, job_levels.name as job_level_name, COUNT(*) as total_employees").
		Join("job_levels", "user_organizations.job_level_id", "=", "job_levels.id").
		Where("user_organizations.organization_id", organizationID).
		Where("user_organizations.is_active", true).
		Group("job_levels.id, job_levels.name").
		Find(&currentEmployees)

	if err != nil {
		return nil, err
	}

	// Get departures by job level
	var departures []struct {
		JobLevelID string `json:"job_level_id"`
		Departures int    `json:"departures"`
	}

	err = facades.Orm().Query().
		Table("user_employment_history").
		Select("job_level_id, COUNT(*) as departures").
		Where("organization_id", organizationID).
		Where("change_type", "termination").
		Where("effective_date", ">=", startDate).
		Group("job_level_id").
		Find(&departures)

	if err != nil {
		return nil, err
	}

	// Combine data
	departureMap := make(map[string]int)
	for _, d := range departures {
		departureMap[d.JobLevelID] = d.Departures
	}

	var turnoverData []struct {
		JobLevelID     string  `json:"job_level_id"`
		JobLevelName   string  `json:"job_level_name"`
		TotalEmployees int     `json:"total_employees"`
		Departures     int     `json:"departures"`
		TurnoverRate   float64 `json:"turnover_rate"`
	}

	totalEmployees := 0
	totalDepartures := 0

	for _, emp := range currentEmployees {
		departures := departureMap[emp.JobLevelID]
		turnoverRate := 0.0
		if emp.TotalEmployees > 0 {
			turnoverRate = (float64(departures) / float64(emp.TotalEmployees)) * 100
		}

		turnoverData = append(turnoverData, struct {
			JobLevelID     string  `json:"job_level_id"`
			JobLevelName   string  `json:"job_level_name"`
			TotalEmployees int     `json:"total_employees"`
			Departures     int     `json:"departures"`
			TurnoverRate   float64 `json:"turnover_rate"`
		}{
			JobLevelID:     emp.JobLevelID,
			JobLevelName:   emp.JobLevelName,
			TotalEmployees: emp.TotalEmployees,
			Departures:     departures,
			TurnoverRate:   turnoverRate,
		})

		totalEmployees += emp.TotalEmployees
		totalDepartures += departures
	}

	overallTurnoverRate := 0.0
	if totalEmployees > 0 {
		overallTurnoverRate = (float64(totalDepartures) / float64(totalEmployees)) * 100
	}

	return map[string]interface{}{
		"organization_id":       organizationID,
		"time_range_days":       timeRange,
		"turnover_by_level":     turnoverData,
		"overall_turnover_rate": overallTurnoverRate,
		"total_employees":       totalEmployees,
		"total_departures":      totalDepartures,
		"generated_at":          time.Now(),
	}, nil
}

// GetSalaryAnalyticsByJobLevel returns salary analytics by job level
func (jas *JobAnalyticsService) GetSalaryAnalyticsByJobLevel(organizationID string) (map[string]interface{}, error) {
	var salaryData []struct {
		JobLevelID    string  `json:"job_level_id"`
		JobLevelName  string  `json:"job_level_name"`
		LevelOrder    int     `json:"level_order"`
		MinSalary     float64 `json:"min_salary"`
		MaxSalary     float64 `json:"max_salary"`
		EmployeeCount int     `json:"employee_count"`
	}

	err := facades.Orm().Query().
		Table("job_levels").
		Select("job_levels.id as job_level_id, job_levels.name as job_level_name, job_levels.level_order, job_levels.min_salary, job_levels.max_salary").
		Where("job_levels.organization_id", organizationID).
		Where("job_levels.is_active", true).
		OrderBy("job_levels.level_order").
		Find(&salaryData)

	if err != nil {
		return nil, err
	}

	// Get employee counts for each level
	var employeeCounts []struct {
		JobLevelID    string `json:"job_level_id"`
		EmployeeCount int    `json:"employee_count"`
	}

	err = facades.Orm().Query().
		Table("user_organizations").
		Select("job_level_id, COUNT(*) as employee_count").
		Where("organization_id", organizationID).
		Where("is_active", true).
		Group("job_level_id").
		Find(&employeeCounts)

	if err != nil {
		return nil, err
	}

	// Combine data
	employeeCountMap := make(map[string]int)
	for _, ec := range employeeCounts {
		employeeCountMap[ec.JobLevelID] = ec.EmployeeCount
	}

	for i := range salaryData {
		salaryData[i].EmployeeCount = employeeCountMap[salaryData[i].JobLevelID]
	}

	return map[string]interface{}{
		"organization_id": organizationID,
		"salary_data":     salaryData,
		"generated_at":    time.Now(),
	}, nil
}

// GetJobLevelProgressionMatrix returns a matrix showing progression patterns between levels
func (jas *JobAnalyticsService) GetJobLevelProgressionMatrix(organizationID string, timeRange int) (map[string]interface{}, error) {
	startDate := time.Now().AddDate(0, 0, -timeRange)

	// Get all promotions in the time range
	var promotions []struct {
		UserID        string    `json:"user_id"`
		JobLevelID    string    `json:"job_level_id"`
		JobLevelName  string    `json:"job_level_name"`
		EffectiveDate time.Time `json:"effective_date"`
	}

	err := facades.Orm().Query().
		Table("user_employment_history").
		Select("user_employment_history.user_id, user_employment_history.job_level_id, job_levels.name as job_level_name, user_employment_history.effective_date").
		Join("job_levels", "user_employment_history.job_level_id", "=", "job_levels.id").
		Where("user_employment_history.organization_id", organizationID).
		Where("user_employment_history.change_type", "promotion").
		Where("user_employment_history.effective_date", ">=", startDate).
		OrderBy("user_employment_history.user_id, user_employment_history.effective_date").
		Find(&promotions)

	if err != nil {
		return nil, err
	}

	// Process progression patterns (simplified approach)
	progressionCounts := make(map[string]int)
	for _, promotion := range promotions {
		key := fmt.Sprintf("%s_to_%s", promotion.JobLevelName, promotion.JobLevelName)
		progressionCounts[key]++
	}

	return map[string]interface{}{
		"organization_id":    organizationID,
		"time_range_days":    timeRange,
		"promotions":         promotions,
		"progression_counts": progressionCounts,
		"generated_at":       time.Now(),
	}, nil
}

// GenerateJobLevelReport generates a report for a specific job level
func (jas *JobAnalyticsService) GenerateJobLevelReport(jobLevelID string) (map[string]interface{}, error) {
	var jobLevel models.JobLevel
	err := facades.Orm().Query().Where("id", jobLevelID).With("Organization").First(&jobLevel)
	if err != nil {
		return nil, fmt.Errorf("job level not found: %v", err)
	}

	// Get users at this level
	users, err := jobLevel.GetUsersAtLevel(jobLevel.OrganizationID)
	if err != nil {
		return nil, err
	}

	// Get positions at this level
	var positions []models.JobPosition
	err = facades.Orm().Query().Where("job_level_id", jobLevelID).
		Where("is_active", true).
		With("Department").
		Find(&positions)
	if err != nil {
		return nil, err
	}

	// Get career path
	careerPath, err := jobLevel.GetCareerPath(jobLevel.OrganizationID, 10)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"job_level":   jobLevel,
		"users":       users,
		"positions":   positions,
		"career_path": careerPath,
		"statistics": map[string]interface{}{
			"total_users":     len(users),
			"total_positions": len(positions),
			"utilization":     fmt.Sprintf("%.1f%%", (float64(len(users))/float64(len(positions)))*100),
		},
		"generated_at": time.Now(),
	}, nil
}
