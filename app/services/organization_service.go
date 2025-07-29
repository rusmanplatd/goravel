package services

import (
	"errors"
	"strings"
	"time"

	"github.com/goravel/framework/facades"

	"goravel/app/models"
)

type OrganizationService struct {
	auditService *AuditService
}

func NewOrganizationService() *OrganizationService {
	return &OrganizationService{
		auditService: NewAuditService(),
	}
}

func (s *OrganizationService) CreateOrganization(data map[string]interface{}) (*models.Organization, error) {
	organization := &models.Organization{}

	// Set basic fields
	if name, exists := data["name"]; exists && name != nil {
		organization.Name = name.(string)
	} else {
		return nil, errors.New("name is required")
	}

	if slug, exists := data["slug"]; exists && slug != nil {
		organization.Slug = slug.(string)
	} else {
		// Generate slug from name
		organization.Slug = strings.ToLower(strings.ReplaceAll(organization.Name, " ", "-"))
	}

	if description, exists := data["description"]; exists && description != nil {
		organization.Description = description.(string)
	}

	if website, exists := data["website"]; exists && website != nil {
		organization.Website = website.(string)
	}

	if contactEmail, exists := data["contact_email"]; exists && contactEmail != nil {
		organization.ContactEmail = contactEmail.(string)
	}

	if contactPhone, exists := data["contact_phone"]; exists && contactPhone != nil {
		organization.ContactPhone = contactPhone.(string)
	}

	if logo, exists := data["logo"]; exists && logo != nil {
		organization.Logo = logo.(string)
	}

	if industry, exists := data["industry"]; exists && industry != nil {
		organization.Industry = industry.(string)
	}

	if size, exists := data["size"]; exists && size != nil {
		organization.Size = size.(string)
	}

	if foundedAt, exists := data["founded_at"]; exists && foundedAt != nil {
		foundedTime, ok := foundedAt.(time.Time)
		if ok {
			organization.FoundedAt = &foundedTime
		}
	}

	if isActive, exists := data["is_active"]; exists {
		organization.IsActive = isActive.(bool)
	}

	if isVerified, exists := data["is_verified"]; exists {
		organization.IsVerified = isVerified.(bool)
	}

	// Handle parent organization
	if parentOrgID, exists := data["parent_organization_id"]; exists {
		if parentOrgID != nil {
			parentOrgIDStr := parentOrgID.(string)
			organization.ParentOrganizationID = &parentOrgIDStr
		} else {
			organization.ParentOrganizationID = nil
		}
	}

	// Handle address fields
	if address, exists := data["address"]; exists && address != nil {
		organization.Address = address.(string)
	}

	if cityID, exists := data["city_id"]; exists && cityID != nil {
		cityIDStr := cityID.(string)
		organization.CityID = &cityIDStr
	}

	if provinceID, exists := data["province_id"]; exists && provinceID != nil {
		provinceIDStr := provinceID.(string)
		organization.ProvinceID = &provinceIDStr
	}

	if countryID, exists := data["country_id"]; exists && countryID != nil {
		countryIDStr := countryID.(string)
		organization.CountryID = &countryIDStr
	}

	if postalCode, exists := data["postal_code"]; exists && postalCode != nil {
		organization.PostalCode = postalCode.(string)
	}

	// Create organization
	err := facades.Orm().Query().Create(organization)
	if err != nil {
		return nil, err
	}

	// Create path for hierarchical structure
	if organization.ParentOrganizationID != nil {
		// Get parent organization
		var parent models.Organization
		err := facades.Orm().Query().Where("id = ?", *organization.ParentOrganizationID).First(&parent)
		if err != nil {
			return nil, err
		}

		// Set path as parent path + / + organization ID
		organization.Path = parent.Path + "/" + organization.ID
	} else {
		// Root organization
		organization.Path = "/" + organization.ID
	}

	// Update path
	_, err = facades.Orm().Query().Model(organization).Update("path", organization.Path)
	if err != nil {
		return nil, err
	}

	return organization, nil
}

// CreateProject creates a new project
func (s *OrganizationService) CreateProject(data map[string]interface{}) (*models.Project, error) {
	project := &models.Project{}

	// Set basic fields
	if name, exists := data["name"]; exists && name != nil {
		project.Name = name.(string)
	} else {
		return nil, errors.New("name is required")
	}

	if description, exists := data["description"]; exists && description != nil {
		project.Description = description.(string)
	}

	if code, exists := data["code"]; exists && code != nil {
		project.Code = code.(string)
	}

	if organizationID, exists := data["organization_id"]; exists && organizationID != nil {
		project.OrganizationID = organizationID.(string)
	} else {
		return nil, errors.New("organization_id is required")
	}

	// Create project
	err := facades.Orm().Query().Create(project)
	if err != nil {
		return nil, err
	}

	return project, nil
}

// GetDepartment gets a department by ID
func (s *OrganizationService) GetDepartment(id string) (*models.Department, error) {
	var department models.Department
	err := facades.Orm().Query().Where("id = ?", id).First(&department)
	if err != nil {
		return nil, err
	}
	return &department, nil
}

// CreateDepartment creates a new department
func (s *OrganizationService) CreateDepartment(data map[string]interface{}) (*models.Department, error) {
	department := &models.Department{}

	// Set basic fields
	if name, exists := data["name"]; exists && name != nil {
		department.Name = name.(string)
	} else {
		return nil, errors.New("name is required")
	}

	if description, exists := data["description"]; exists && description != nil {
		department.Description = description.(string)
	}

	if code, exists := data["code"]; exists && code != nil {
		department.Code = code.(string)
	}

	if organizationID, exists := data["organization_id"]; exists && organizationID != nil {
		department.OrganizationID = organizationID.(string)
	} else {
		return nil, errors.New("organization_id is required")
	}

	// Create department
	err := facades.Orm().Query().Create(department)
	if err != nil {
		return nil, err
	}

	return department, nil
}

// UpdateDepartment updates an existing department
func (s *OrganizationService) UpdateDepartment(id string, data map[string]interface{}) (*models.Department, error) {
	department, err := s.GetDepartment(id)
	if err != nil {
		return nil, err
	}

	// Update fields
	if name, exists := data["name"]; exists && name != nil {
		department.Name = name.(string)
	}

	if description, exists := data["description"]; exists && description != nil {
		department.Description = description.(string)
	}

	if code, exists := data["code"]; exists && code != nil {
		department.Code = code.(string)
	}

	// Save department
	err = facades.Orm().Query().Save(department)
	if err != nil {
		return nil, err
	}

	return department, nil
}

// DeleteDepartment deletes a department
func (s *OrganizationService) DeleteDepartment(id string) error {
	_, err := facades.Orm().Query().Delete(&models.Department{}, "id = ?", id)
	return err
}

// GetDepartmentUsers gets users in a department with pagination
func (s *OrganizationService) GetDepartmentUsers(id string, filters map[string]interface{}, cursor string, limit int) ([]models.User, map[string]interface{}, error) {
	var users []models.User

	// Build query
	query := facades.Orm().Query().Raw(`
		SELECT users.* FROM users 
		JOIN user_departments ON users.id = user_departments.user_id 
		WHERE user_departments.department_id = ?
	`, id)

	// Apply filters if any
	if role, ok := filters["role"]; ok && role != nil {
		query = facades.Orm().Query().Raw(`
			SELECT users.* FROM users 
			JOIN user_departments ON users.id = user_departments.user_id 
			WHERE user_departments.department_id = ? AND user_departments.role = ?
		`, id, role)
	}

	// Apply pagination
	if limit <= 0 {
		limit = 10
	}

	// Execute query
	err := query.Limit(limit).Scan(&users)
	if err != nil {
		return nil, nil, err
	}

	// Prepare pagination info
	paginationInfo := map[string]interface{}{
		"count": len(users),
		"limit": limit,
	}

	return users, paginationInfo, nil
}

// AddUserToDepartment adds a user to a department
func (s *OrganizationService) AddUserToDepartment(departmentID string, userID string, data map[string]interface{}) error {
	// Prepare user department data
	userDepartment := models.UserDepartment{
		UserID:       userID,
		DepartmentID: departmentID,
		Role:         "member", // Default role
		IsActive:     true,
		JoinedAt:     time.Now(),
	}

	// Set role if provided
	if role, ok := data["role"]; ok && role != nil {
		userDepartment.Role = role.(string)
	}

	// Create user department relationship
	err := facades.Orm().Query().Create(&userDepartment)
	if err != nil {
		return err
	}

	return nil
}

// RemoveUserFromDepartment removes a user from a department
func (s *OrganizationService) RemoveUserFromDepartment(departmentID string, userID string) error {
	_, err := facades.Orm().Query().Delete(&models.UserDepartment{}, "user_id = ? AND department_id = ?", userID, departmentID)
	if err != nil {
		return err
	}

	return nil
}

// GetOrganization gets an organization by ID
func (s *OrganizationService) GetOrganization(id string) (*models.Organization, error) {
	var organization models.Organization
	err := facades.Orm().Query().Where("id = ?", id).First(&organization)
	if err != nil {
		return nil, err
	}
	return &organization, nil
}

// UpdateOrganization updates an existing organization
func (s *OrganizationService) UpdateOrganization(id string, data map[string]interface{}) (*models.Organization, error) {
	organization, err := s.GetOrganization(id)
	if err != nil {
		return nil, err
	}

	// Update fields
	if name, exists := data["name"]; exists && name != nil {
		organization.Name = name.(string)
	}

	if description, exists := data["description"]; exists && description != nil {
		organization.Description = description.(string)
	}

	if website, exists := data["website"]; exists && website != nil {
		organization.Website = website.(string)
	}

	if contactEmail, exists := data["contact_email"]; exists && contactEmail != nil {
		organization.ContactEmail = contactEmail.(string)
	}

	if contactPhone, exists := data["contact_phone"]; exists && contactPhone != nil {
		organization.ContactPhone = contactPhone.(string)
	}

	// Save organization
	err = facades.Orm().Query().Save(organization)
	if err != nil {
		return nil, err
	}

	return organization, nil
}

// DeleteOrganization deletes an organization
func (s *OrganizationService) DeleteOrganization(id string) error {
	_, err := facades.Orm().Query().Delete(&models.Organization{}, "id = ?", id)
	return err
}

// GetOrganizationUsers gets users in an organization
func (s *OrganizationService) GetOrganizationUsers(id string, filters map[string]interface{}, cursor string, limit int) ([]models.User, map[string]interface{}, error) {
	var users []models.User

	// Build query
	query := facades.Orm().Query().Raw(`
		SELECT users.* FROM users 
		JOIN user_organizations ON users.id = user_organizations.user_id 
		WHERE user_organizations.organization_id = ?
	`, id)

	// Apply filters if any
	if role, ok := filters["role"]; ok && role != nil {
		query = facades.Orm().Query().Raw(`
			SELECT users.* FROM users 
			JOIN user_organizations ON users.id = user_organizations.user_id 
			WHERE user_organizations.organization_id = ? AND user_organizations.role = ?
		`, id, role)
	}

	// Apply pagination
	if limit <= 0 {
		limit = 10
	}

	// Execute query
	err := query.Limit(limit).Scan(&users)
	if err != nil {
		return nil, nil, err
	}

	// Prepare pagination info
	paginationInfo := map[string]interface{}{
		"count": len(users),
		"limit": limit,
	}

	return users, paginationInfo, nil
}

// AddUserToOrganization adds a user to an organization
func (s *OrganizationService) AddUserToOrganization(organizationID string, userID string, data map[string]interface{}) error {
	// Prepare user organization data
	userOrganization := models.UserOrganization{
		UserID:         userID,
		OrganizationID: organizationID,
		Role:           "member", // Default role
		Status:         "active",
		IsActive:       true,
		JoinedAt:       time.Now(),
	}

	// Set role if provided
	if role, ok := data["role"]; ok && role != nil {
		userOrganization.Role = role.(string)
	}

	// Set status if provided
	if status, ok := data["status"]; ok && status != nil {
		userOrganization.Status = status.(string)
	}

	// Create user organization relationship
	err := facades.Orm().Query().Create(&userOrganization)
	if err != nil {
		return err
	}

	return nil
}

// RemoveUserFromOrganization removes a user from an organization
func (s *OrganizationService) RemoveUserFromOrganization(organizationID string, userID string) error {
	_, err := facades.Orm().Query().Delete(&models.UserOrganization{}, "user_id = ? AND organization_id = ?", userID, organizationID)
	if err != nil {
		return err
	}

	return nil
}

// GetOrganizationHierarchy gets the organization hierarchy
func (s *OrganizationService) GetOrganizationHierarchy(id string) (map[string]interface{}, error) {
	// Get the organization
	organization, err := s.GetOrganization(id)
	if err != nil {
		return nil, err
	}

	// Get subsidiaries
	var subsidiaries []models.Organization
	err = facades.Orm().Query().Where("parent_organization_id = ?", id).Find(&subsidiaries)
	if err != nil {
		return nil, err
	}

	// Build hierarchy
	hierarchy := map[string]interface{}{
		"id":           organization.ID,
		"name":         organization.Name,
		"description":  organization.Description,
		"path":         organization.Path,
		"level":        organization.Level,
		"subsidiaries": subsidiaries,
	}

	return hierarchy, nil
}

// GetOrganizationStats gets organization statistics
func (s *OrganizationService) GetOrganizationStats(id string) (map[string]interface{}, error) {
	// Get user count
	var userCount int64
	err := facades.Orm().Query().Raw(`
		SELECT COUNT(*) FROM users 
		JOIN user_organizations ON users.id = user_organizations.user_id 
		WHERE user_organizations.organization_id = ?
	`, id).Scan(&userCount)
	if err != nil {
		return nil, err
	}

	// Get department count
	var departmentCount int64
	err = facades.Orm().Query().Raw("SELECT COUNT(*) FROM departments WHERE organization_id = ?", id).Scan(&departmentCount)
	if err != nil {
		return nil, err
	}

	// Get team count
	var teamCount int64
	err = facades.Orm().Query().Raw("SELECT COUNT(*) FROM teams WHERE organization_id = ?", id).Scan(&teamCount)
	if err != nil {
		return nil, err
	}

	// Get project count
	var projectCount int64
	err = facades.Orm().Query().Raw("SELECT COUNT(*) FROM projects WHERE organization_id = ?", id).Scan(&projectCount)
	if err != nil {
		return nil, err
	}

	// Build stats
	stats := map[string]interface{}{
		"user_count":       userCount,
		"department_count": departmentCount,
		"team_count":       teamCount,
		"project_count":    projectCount,
	}

	return stats, nil
}

// VerifyOrganization marks an organization as verified
func (s *OrganizationService) VerifyOrganization(id string) error {
	// Get the organization first
	organization, err := s.GetOrganization(id)
	if err != nil {
		return err
	}

	// Update fields
	organization.IsVerified = true
	now := time.Now()
	organization.VerifiedAt = &now

	// Save changes
	err = facades.Orm().Query().Save(organization)
	if err != nil {
		return err
	}

	return nil
}

// GetProject gets a project by ID
func (s *OrganizationService) GetProject(id string) (*models.Project, error) {
	var project models.Project
	err := facades.Orm().Query().Where("id = ?", id).First(&project)
	if err != nil {
		return nil, err
	}
	return &project, nil
}

// UpdateProject updates an existing project
func (s *OrganizationService) UpdateProject(id string, data map[string]interface{}) (*models.Project, error) {
	project, err := s.GetProject(id)
	if err != nil {
		return nil, err
	}

	// Update fields
	if name, exists := data["name"]; exists && name != nil {
		project.Name = name.(string)
	}

	if description, exists := data["description"]; exists && description != nil {
		project.Description = description.(string)
	}

	if code, exists := data["code"]; exists && code != nil {
		project.Code = code.(string)
	}

	if status, exists := data["status"]; exists && status != nil {
		project.Status = status.(string)
	}

	if priority, exists := data["priority"]; exists && priority != nil {
		project.Priority = priority.(string)
	}

	// Save project
	err = facades.Orm().Query().Save(project)
	if err != nil {
		return nil, err
	}

	return project, nil
}

// DeleteProject deletes a project
func (s *OrganizationService) DeleteProject(id string) error {
	_, err := facades.Orm().Query().Delete(&models.Project{}, "id = ?", id)
	return err
}

// GetProjectUsers gets users in a project
func (s *OrganizationService) GetProjectUsers(id string, filters map[string]interface{}, cursor string, limit int) ([]models.User, map[string]interface{}, error) {
	var users []models.User

	// Build query
	query := facades.Orm().Query().Raw(`
		SELECT users.* FROM users 
		JOIN user_projects ON users.id = user_projects.user_id 
		WHERE user_projects.project_id = ?
	`, id)

	// Apply filters if any
	if role, ok := filters["role"]; ok && role != nil {
		query = facades.Orm().Query().Raw(`
			SELECT users.* FROM users 
			JOIN user_projects ON users.id = user_projects.user_id 
			WHERE user_projects.project_id = ? AND user_projects.role = ?
		`, id, role)
	}

	// Apply pagination
	if limit <= 0 {
		limit = 10
	}

	// Execute query
	err := query.Limit(limit).Scan(&users)
	if err != nil {
		return nil, nil, err
	}

	// Prepare pagination info
	paginationInfo := map[string]interface{}{
		"count": len(users),
		"limit": limit,
	}

	return users, paginationInfo, nil
}

// AddUserToProject adds a user to a project
func (s *OrganizationService) AddUserToProject(projectID string, userID string, data map[string]interface{}) error {
	// Prepare user project data
	userProject := models.UserProject{
		UserID:    userID,
		ProjectID: projectID,
		Role:      "member", // Default role
		IsActive:  true,
		JoinedAt:  time.Now(),
	}

	// Set role if provided
	if role, ok := data["role"]; ok && role != nil {
		userProject.Role = role.(string)
	}

	// Set allocation if provided
	if allocation, ok := data["allocation"]; ok && allocation != nil {
		userProject.Allocation = allocation.(float64)
	}

	// Create user project relationship
	err := facades.Orm().Query().Create(&userProject)
	if err != nil {
		return err
	}

	return nil
}

// RemoveUserFromProject removes a user from a project
func (s *OrganizationService) RemoveUserFromProject(projectID string, userID string) error {
	_, err := facades.Orm().Query().Delete(&models.UserProject{}, "user_id = ? AND project_id = ?", userID, projectID)
	if err != nil {
		return err
	}

	return nil
}

// GetTeam gets a team by ID
func (s *OrganizationService) GetTeam(id string) (*models.Team, error) {
	var team models.Team
	err := facades.Orm().Query().Where("id = ?", id).First(&team)
	if err != nil {
		return nil, err
	}
	return &team, nil
}

// CreateTeam creates a new team
func (s *OrganizationService) CreateTeam(data map[string]interface{}) (*models.Team, error) {
	team := &models.Team{}

	// Set basic fields
	if name, exists := data["name"]; exists && name != nil {
		team.Name = name.(string)
	} else {
		return nil, errors.New("name is required")
	}

	if description, exists := data["description"]; exists && description != nil {
		team.Description = description.(string)
	}

	if code, exists := data["code"]; exists && code != nil {
		team.Code = code.(string)
	}

	if organizationID, exists := data["organization_id"]; exists && organizationID != nil {
		team.OrganizationID = organizationID.(string)
	} else {
		return nil, errors.New("organization_id is required")
	}

	if departmentID, exists := data["department_id"]; exists && departmentID != nil {
		deptID := departmentID.(string)
		team.DepartmentID = &deptID
	}

	if teamLeadID, exists := data["team_lead_id"]; exists && teamLeadID != nil {
		leadID := teamLeadID.(string)
		team.TeamLeadID = &leadID
	}

	// Create team
	err := facades.Orm().Query().Create(team)
	if err != nil {
		return nil, err
	}

	return team, nil
}

// UpdateTeam updates an existing team
func (s *OrganizationService) UpdateTeam(id string, data map[string]interface{}) (*models.Team, error) {
	team, err := s.GetTeam(id)
	if err != nil {
		return nil, err
	}

	// Update fields
	if name, exists := data["name"]; exists && name != nil {
		team.Name = name.(string)
	}

	if description, exists := data["description"]; exists && description != nil {
		team.Description = description.(string)
	}

	if code, exists := data["code"]; exists && code != nil {
		team.Code = code.(string)
	}

	if departmentID, exists := data["department_id"]; exists {
		if departmentID != nil {
			deptID := departmentID.(string)
			team.DepartmentID = &deptID
		} else {
			team.DepartmentID = nil
		}
	}

	if teamLeadID, exists := data["team_lead_id"]; exists {
		if teamLeadID != nil {
			leadID := teamLeadID.(string)
			team.TeamLeadID = &leadID
		} else {
			team.TeamLeadID = nil
		}
	}

	// Save team
	err = facades.Orm().Query().Save(team)
	if err != nil {
		return nil, err
	}

	return team, nil
}

// DeleteTeam deletes a team
func (s *OrganizationService) DeleteTeam(id string) error {
	_, err := facades.Orm().Query().Delete(&models.Team{}, "id = ?", id)
	return err
}

// GetProjectTeams gets teams in a project
func (s *OrganizationService) GetProjectTeams(id string, filters map[string]interface{}, cursor string, limit int) ([]models.Team, map[string]interface{}, error) {
	var teams []models.Team

	// Build query
	query := facades.Orm().Query().Raw(`
		SELECT teams.* FROM teams 
		JOIN team_projects ON teams.id = team_projects.team_id 
		WHERE team_projects.project_id = ?
	`, id)

	// Apply filters if any
	if role, ok := filters["role"]; ok && role != nil {
		query = facades.Orm().Query().Raw(`
			SELECT teams.* FROM teams 
			JOIN team_projects ON teams.id = team_projects.team_id 
			WHERE team_projects.project_id = ? AND team_projects.role = ?
		`, id, role)
	}

	// Apply pagination
	if limit <= 0 {
		limit = 10
	}

	// Execute query
	err := query.Limit(limit).Scan(&teams)
	if err != nil {
		return nil, nil, err
	}

	// Prepare pagination info
	paginationInfo := map[string]interface{}{
		"count": len(teams),
		"limit": limit,
	}

	return teams, paginationInfo, nil
}

// AddTeamToProject adds a team to a project
func (s *OrganizationService) AddTeamToProject(projectID string, teamID string, data map[string]interface{}) error {
	// Prepare team project data
	teamProject := models.TeamProject{
		TeamID:    teamID,
		ProjectID: projectID,
		Role:      "contributor", // Default role
		IsActive:  true,
		JoinedAt:  time.Now(),
	}

	// Set role if provided
	if role, ok := data["role"]; ok && role != nil {
		teamProject.Role = role.(string)
	}

	// Set allocation if provided
	if allocation, ok := data["allocation"]; ok && allocation != nil {
		teamProject.Allocation = allocation.(float64)
	}

	// Create team project relationship
	err := facades.Orm().Query().Create(&teamProject)
	if err != nil {
		return err
	}

	return nil
}

// RemoveTeamFromProject removes a team from a project
func (s *OrganizationService) RemoveTeamFromProject(projectID string, teamID string) error {
	_, err := facades.Orm().Query().Delete(&models.TeamProject{}, "team_id = ? AND project_id = ?", teamID, projectID)
	if err != nil {
		return err
	}

	return nil
}

// GetTeamUsers gets users in a team
func (s *OrganizationService) GetTeamUsers(id string, filters map[string]interface{}, cursor string, limit int) ([]models.User, map[string]interface{}, error) {
	var users []models.User

	// Build query
	query := facades.Orm().Query().Raw(`
		SELECT users.* FROM users 
		JOIN user_teams ON users.id = user_teams.user_id 
		WHERE user_teams.team_id = ?
	`, id)

	// Apply filters if any
	if role, ok := filters["role"]; ok && role != nil {
		query = facades.Orm().Query().Raw(`
			SELECT users.* FROM users 
			JOIN user_teams ON users.id = user_teams.user_id 
			WHERE user_teams.team_id = ? AND user_teams.role = ?
		`, id, role)
	}

	// Apply pagination
	if limit <= 0 {
		limit = 10
	}

	// Execute query
	err := query.Limit(limit).Scan(&users)
	if err != nil {
		return nil, nil, err
	}

	// Prepare pagination info
	paginationInfo := map[string]interface{}{
		"count": len(users),
		"limit": limit,
	}

	return users, paginationInfo, nil
}

// AddUserToTeam adds a user to a team
func (s *OrganizationService) AddUserToTeam(teamID string, userID string, data map[string]interface{}) error {
	// Prepare user team data
	userTeam := models.UserTeam{
		UserID:   userID,
		TeamID:   teamID,
		Role:     "member", // Default role
		IsActive: true,
		JoinedAt: time.Now(),
	}

	// Set role if provided
	if role, ok := data["role"]; ok && role != nil {
		userTeam.Role = role.(string)
	}

	// Create user team relationship
	err := facades.Orm().Query().Create(&userTeam)
	if err != nil {
		return err
	}

	return nil
}

// RemoveUserFromTeam removes a user from a team
func (s *OrganizationService) RemoveUserFromTeam(teamID string, userID string) error {
	_, err := facades.Orm().Query().Delete(&models.UserTeam{}, "user_id = ? AND team_id = ?", userID, teamID)
	if err != nil {
		return err
	}

	return nil
}
