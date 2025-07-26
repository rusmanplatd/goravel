package services

import (
	"errors"
	"strings"
	"time"

	"goravel/app/helpers"
	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type OrganizationService struct {
	auditService *AuditService
}

func NewOrganizationService() *OrganizationService {
	return &OrganizationService{
		auditService: NewAuditService(),
	}
}

// CreateOrganization creates a new organization
func (s *OrganizationService) CreateOrganization(data map[string]interface{}) (*models.Organization, error) {
	// Generate slug if not provided
	if data["slug"] == "" || data["slug"] == nil {
		name := data["name"].(string)
		slug := helpers.GenerateSlug(name)
		data["slug"] = slug
	}

	// Set default values
	if data["type"] == "" || data["type"] == nil {
		data["type"] = "company"
	}
	if data["size"] == "" || data["size"] == nil {
		data["size"] = "medium"
	}
	if data["is_active"] == nil {
		data["is_active"] = true
	}
	if data["is_verified"] == nil {
		data["is_verified"] = false
	}
	if data["level"] == nil {
		data["level"] = 0
	}

	// Handle parent organization
	if parentID, exists := data["parent_organization_id"]; exists && parentID != nil && parentID != "" {
		parentOrg := &models.Organization{}
		err := facades.Orm().Query().Where("id = ?", parentID).First(parentOrg)
		if err != nil {
			return nil, errors.New("parent organization not found")
		}
		data["level"] = parentOrg.Level + 1
		data["path"] = parentOrg.Path + "/" + parentOrg.ID
	} else {
		data["path"] = "/"
	}

	// Create organization
	organization := &models.Organization{
		Name:        data["name"].(string),
		Slug:        data["slug"].(string),
		Domain:      data["domain"].(string),
		Description: data["description"].(string),
		Type:        data["type"].(string),
		Industry:    data["industry"].(string),
		Size:        data["size"].(string),
		IsActive:    data["is_active"].(bool),
		IsVerified:  data["is_verified"].(bool),
		Level:       data["level"].(int),
		Path:        data["path"].(string),
	}

	// Set optional fields
	if foundedAt, exists := data["founded_at"]; exists && foundedAt != nil {
		organization.FoundedAt = foundedAt.(*time.Time)
	}
	if website, exists := data["website"]; exists && website != nil {
		organization.Website = website.(string)
	}
	if logo, exists := data["logo"]; exists && logo != nil {
		organization.Logo = logo.(string)
	}
	if banner, exists := data["banner"]; exists && banner != nil {
		organization.Banner = banner.(string)
	}
	if contactEmail, exists := data["contact_email"]; exists && contactEmail != nil {
		organization.ContactEmail = contactEmail.(string)
	}
	if contactPhone, exists := data["contact_phone"]; exists && contactPhone != nil {
		organization.ContactPhone = contactPhone.(string)
	}
	if address, exists := data["address"]; exists && address != nil {
		organization.Address = address.(string)
	}
	if countryID, exists := data["country_id"]; exists && countryID != nil {
		countryIDStr := countryID.(string)
		organization.CountryID = &countryIDStr
	}
	if provinceID, exists := data["province_id"]; exists && provinceID != nil {
		provinceIDStr := provinceID.(string)
		organization.ProvinceID = &provinceIDStr
	}
	if cityID, exists := data["city_id"]; exists && cityID != nil {
		cityIDStr := cityID.(string)
		organization.CityID = &cityIDStr
	}
	if districtID, exists := data["district_id"]; exists && districtID != nil {
		districtIDStr := districtID.(string)
		organization.DistrictID = &districtIDStr
	}
	if postalCode, exists := data["postal_code"]; exists && postalCode != nil {
		organization.PostalCode = postalCode.(string)
	}
	if tenantID, exists := data["tenant_id"]; exists && tenantID != nil {
		organization.TenantID = tenantID.(string)
	} else {
		return nil, errors.New("tenant_id is required")
	}
	if parentOrgID, exists := data["parent_organization_id"]; exists && parentOrgID != nil {
		parentOrgIDStr := parentOrgID.(string)
		organization.ParentOrganizationID = &parentOrgIDStr
	}
	if settings, exists := data["settings"]; exists && settings != nil {
		organization.Settings = settings.(string)
	}

	err := facades.Orm().Query().Create(organization)
	if err != nil {
		return nil, err
	}

	// Log the creation
	s.auditService.LogSimpleEvent(
		EventOrganizationCreated,
		"Organization created",
		map[string]interface{}{
			"organization_id":   organization.ID,
			"organization_name": organization.Name,
		},
	)

	return organization, nil
}

// GetOrganization retrieves an organization by ID
func (s *OrganizationService) GetOrganization(id string) (*models.Organization, error) {
	var organization models.Organization
	err := facades.Orm().Query().Where("id = ?", id).First(&organization)
	if err != nil {
		return nil, err
	}
	return &organization, nil
}

// GetOrganizationBySlug retrieves an organization by slug
func (s *OrganizationService) GetOrganizationBySlug(slug string) (*models.Organization, error) {
	var organization models.Organization
	err := facades.Orm().Query().Where("slug = ?", slug).First(&organization)
	if err != nil {
		return nil, err
	}
	return &organization, nil
}

// UpdateOrganization updates an existing organization
func (s *OrganizationService) UpdateOrganization(id string, data map[string]interface{}) (*models.Organization, error) {
	organization := &models.Organization{}
	err := facades.Orm().Query().Where("id = ?", id).First(organization)
	if err != nil {
		return nil, err
	}

	// Update organization fields
	if name, exists := data["name"]; exists {
		organization.Name = name.(string)
	}
	if slug, exists := data["slug"]; exists {
		organization.Slug = slug.(string)
	}
	if domain, exists := data["domain"]; exists {
		organization.Domain = domain.(string)
	}
	if description, exists := data["description"]; exists {
		organization.Description = description.(string)
	}
	if orgType, exists := data["type"]; exists {
		organization.Type = orgType.(string)
	}
	if industry, exists := data["industry"]; exists {
		organization.Industry = industry.(string)
	}
	if size, exists := data["size"]; exists {
		organization.Size = size.(string)
	}
	if isActive, exists := data["is_active"]; exists {
		organization.IsActive = isActive.(bool)
	}
	if isVerified, exists := data["is_verified"]; exists {
		organization.IsVerified = isVerified.(bool)
	}

	// Handle tenant_id field (required)
	if tenantID, exists := data["tenant_id"]; exists {
		if tenantID != nil {
			organization.TenantID = tenantID.(string)
		} else {
			return nil, errors.New("tenant_id is required")
		}
	}
	if parentOrgID, exists := data["parent_organization_id"]; exists {
		if parentOrgID != nil {
			parentOrgIDStr := parentOrgID.(string)
			organization.ParentOrganizationID = &parentOrgIDStr
		} else {
			organization.ParentOrganizationID = nil
		}
	}
	if website, exists := data["website"]; exists {
		organization.Website = website.(string)
	}
	if logo, exists := data["logo"]; exists {
		organization.Logo = logo.(string)
	}
	if banner, exists := data["banner"]; exists {
		organization.Banner = banner.(string)
	}
	if contactEmail, exists := data["contact_email"]; exists {
		organization.ContactEmail = contactEmail.(string)
	}
	if contactPhone, exists := data["contact_phone"]; exists {
		organization.ContactPhone = contactPhone.(string)
	}
	if address, exists := data["address"]; exists {
		organization.Address = address.(string)
	}
	if countryID, exists := data["country_id"]; exists {
		if countryID != nil {
			countryIDStr := countryID.(string)
			organization.CountryID = &countryIDStr
		} else {
			organization.CountryID = nil
		}
	}
	if provinceID, exists := data["province_id"]; exists {
		if provinceID != nil {
			provinceIDStr := provinceID.(string)
			organization.ProvinceID = &provinceIDStr
		} else {
			organization.ProvinceID = nil
		}
	}
	if cityID, exists := data["city_id"]; exists {
		if cityID != nil {
			cityIDStr := cityID.(string)
			organization.CityID = &cityIDStr
		} else {
			organization.CityID = nil
		}
	}
	if districtID, exists := data["district_id"]; exists {
		if districtID != nil {
			districtIDStr := districtID.(string)
			organization.DistrictID = &districtIDStr
		} else {
			organization.DistrictID = nil
		}
	}
	if postalCode, exists := data["postal_code"]; exists {
		organization.PostalCode = postalCode.(string)
	}
	if settings, exists := data["settings"]; exists {
		organization.Settings = settings.(string)
	}

	// Save organization
	err = facades.Orm().Query().Save(organization)
	if err != nil {
		return nil, err
	}

	// Log activity
	s.auditService.LogEventCompat(nil, "organization.updated", "Organization updated", "", "", map[string]interface{}{
		"organization_id": organization.ID,
		"name":            organization.Name,
	}, "low")

	return organization, nil
}

// DeleteOrganization deletes an organization
func (s *OrganizationService) DeleteOrganization(id string) error {
	organization := &models.Organization{}
	err := facades.Orm().Query().Where("id = ?", id).First(organization)
	if err != nil {
		return err
	}

	// Check if organization has subsidiaries
	var subsidiaryCount int64
	facades.Orm().Query().Model(&models.Organization{}).Where("parent_organization_id = ?", id).Count()
	if subsidiaryCount > 0 {
		return errors.New("cannot delete organization with subsidiaries")
	}

	// Check if organization has users
	var userCount int64
	facades.Orm().Query().Model(&models.UserOrganization{}).Where("organization_id = ?", id).Count()
	if userCount > 0 {
		return errors.New("cannot delete organization with users")
	}

	// Delete organization
	_, err = facades.Orm().Query().Where("id = ?", id).Delete(organization)
	if err != nil {
		return err
	}

	// Log activity
	s.auditService.LogEventCompat(nil, "organization.deleted", "Organization deleted", "", "", map[string]interface{}{
		"organization_id": organization.ID,
		"name":            organization.Name,
	}, "low")

	return nil
}

// ListOrganizations retrieves organizations with filtering and pagination
func (s *OrganizationService) ListOrganizations(filters map[string]interface{}, cursor string, limit int) ([]models.Organization, map[string]interface{}, error) {
	query := facades.Orm().Query()

	// Apply filters
	if search, exists := filters["search"]; exists && search != "" {
		searchStr := search.(string)
		query = query.Where("name LIKE ? OR domain LIKE ? OR description LIKE ?", "%"+searchStr+"%", "%"+searchStr+"%", "%"+searchStr+"%")
	}

	if orgType, exists := filters["type"]; exists && orgType != "" {
		query = query.Where("type = ?", orgType)
	}

	if industry, exists := filters["industry"]; exists && industry != "" {
		query = query.Where("industry = ?", industry)
	}

	if size, exists := filters["size"]; exists && size != "" {
		query = query.Where("size = ?", size)
	}

	if isActive, exists := filters["is_active"]; exists {
		query = query.Where("is_active = ?", isActive)
	}

	if isVerified, exists := filters["is_verified"]; exists {
		query = query.Where("is_verified = ?", isVerified)
	}

	if parentID, exists := filters["parent_organization_id"]; exists {
		if parentID == nil {
			query = query.Where("parent_organization_id IS NULL")
		} else {
			query = query.Where("parent_organization_id = ?", parentID)
		}
	}

	if tenantID, exists := filters["tenant_id"]; exists {
		if tenantID == nil {
			query = query.Where("tenant_id IS NULL")
		} else {
			query = query.Where("tenant_id = ?", tenantID)
		}
	}

	// Apply cursor-based pagination
	query, err := helpers.ApplyCursorPagination(query, cursor, limit, false)
	if err != nil {
		return nil, nil, err
	}

	var organizations []models.Organization
	err = query.Find(&organizations)
	if err != nil {
		return nil, nil, err
	}

	// Check if there are more results
	hasMore := len(organizations) > limit
	if hasMore {
		organizations = organizations[:limit] // Remove the extra item
	}

	// Build pagination info
	paginationInfo := helpers.BuildPaginationInfo(organizations, limit, cursor, hasMore)

	return organizations, paginationInfo, nil
}

// AddUserToOrganization adds a user to an organization
func (s *OrganizationService) AddUserToOrganization(organizationID, userID string, data map[string]interface{}) error {
	// Check if user is already in organization
	var existing models.UserOrganization
	err := facades.Orm().Query().Where("organization_id = ? AND user_id = ?", organizationID, userID).First(&existing)
	if err == nil {
		return errors.New("user is already a member of this organization")
	}

	// Set default values
	if data["role"] == "" || data["role"] == nil {
		data["role"] = "member"
	}
	if data["status"] == "" || data["status"] == nil {
		data["status"] = "active"
	}
	if data["is_active"] == nil {
		data["is_active"] = true
	}
	if data["joined_at"] == nil {
		data["joined_at"] = time.Now()
	}

	// Create user-organization relationship
	userOrg := &models.UserOrganization{
		UserID:         userID,
		OrganizationID: organizationID,
		Role:           data["role"].(string),
		Status:         data["status"].(string),
		IsActive:       data["is_active"].(bool),
		JoinedAt:       data["joined_at"].(time.Time),
	}

	// Set optional fields
	if title, exists := data["title"]; exists && title != nil {
		userOrg.Title = title.(string)
	}
	if employeeID, exists := data["employee_id"]; exists && employeeID != nil {
		userOrg.EmployeeID = employeeID.(string)
	}
	if departmentID, exists := data["department_id"]; exists && departmentID != nil {
		departmentIDStr := departmentID.(string)
		userOrg.DepartmentID = &departmentIDStr
	}
	if teamID, exists := data["team_id"]; exists && teamID != nil {
		teamIDStr := teamID.(string)
		userOrg.TeamID = &teamIDStr
	}
	if managerID, exists := data["manager_id"]; exists && managerID != nil {
		managerIDStr := managerID.(string)
		userOrg.ManagerID = &managerIDStr
	}
	if hireDate, exists := data["hire_date"]; exists && hireDate != nil {
		userOrg.HireDate = hireDate.(*time.Time)
	}
	if permissions, exists := data["permissions"]; exists && permissions != nil {
		userOrg.Permissions = permissions.(string)
	}

	err = facades.Orm().Query().Create(userOrg)
	if err != nil {
		return err
	}

	// Log activity
	s.auditService.LogEventCompat(nil, "organization.user_added", "User added to organization", "", "", map[string]interface{}{
		"organization_id": organizationID,
		"user_id":         userID,
		"role":            userOrg.Role,
	}, "low")

	return nil
}

// RemoveUserFromOrganization removes a user from an organization
func (s *OrganizationService) RemoveUserFromOrganization(organizationID, userID string) error {
	// Check if user is in organization
	var userOrg models.UserOrganization
	err := facades.Orm().Query().Where("organization_id = ? AND user_id = ?", organizationID, userID).First(&userOrg)
	if err != nil {
		return errors.New("user is not a member of this organization")
	}

	// Delete user-organization relationship
	_, err = facades.Orm().Query().Where("organization_id = ? AND user_id = ?", organizationID, userID).Delete(&userOrg)
	if err != nil {
		return err
	}

	// Log activity
	s.auditService.LogEventCompat(nil, "organization.user_removed", "User removed from organization", "", "", map[string]interface{}{
		"organization_id": organizationID,
		"user_id":         userID,
	}, "low")

	return nil
}

// GetOrganizationUsers retrieves users in an organization
func (s *OrganizationService) GetOrganizationUsers(organizationID string, filters map[string]interface{}, cursor string, limit int) ([]models.User, map[string]interface{}, error) {
	// First get user IDs from user_organizations table
	var userOrgs []models.UserOrganization
	userOrgQuery := facades.Orm().Query().Where("organization_id = ?", organizationID)

	// Apply filters
	if role, exists := filters["role"]; exists && role != "" {
		userOrgQuery = userOrgQuery.Where("role = ?", role)
	}

	if status, exists := filters["status"]; exists && status != "" {
		userOrgQuery = userOrgQuery.Where("status = ?", status)
	}

	if isActive, exists := filters["is_active"]; exists {
		userOrgQuery = userOrgQuery.Where("is_active = ?", isActive)
	}

	err := userOrgQuery.Find(&userOrgs)
	if err != nil {
		return nil, nil, err
	}

	// Extract user IDs
	var userIDs []string
	for _, userOrg := range userOrgs {
		userIDs = append(userIDs, userOrg.UserID)
	}

	if len(userIDs) == 0 {
		return []models.User{}, map[string]interface{}{
			"next_cursor": "",
			"prev_cursor": "",
			"has_more":    false,
			"has_prev":    false,
			"count":       0,
			"limit":       limit,
		}, nil
	}

	// Get users by IDs
	query := facades.Orm().Query().Where("id IN ?", userIDs)

	// Apply search filter
	if search, exists := filters["search"]; exists && search != "" {
		searchStr := search.(string)
		query = query.Where("name LIKE ? OR email LIKE ?", "%"+searchStr+"%", "%"+searchStr+"%")
	}

	// Apply cursor-based pagination
	query, err = helpers.ApplyCursorPagination(query, cursor, limit, false)
	if err != nil {
		return nil, nil, err
	}

	var users []models.User
	err = query.Find(&users)
	if err != nil {
		return nil, nil, err
	}

	// Check if there are more results
	hasMore := len(users) > limit
	if hasMore {
		users = users[:limit] // Remove the extra item
	}

	// Build pagination info
	paginationInfo := helpers.BuildPaginationInfo(users, limit, cursor, hasMore)

	return users, paginationInfo, nil
}

// GetOrganizationHierarchy retrieves the organization hierarchy
func (s *OrganizationService) GetOrganizationHierarchy(organizationID string) (map[string]interface{}, error) {
	organization := &models.Organization{}
	err := facades.Orm().Query().Where("id = ?", organizationID).First(organization)
	if err != nil {
		return nil, err
	}

	// Get parent organizations
	var parents []models.Organization
	if organization.Path != "/" {
		pathParts := strings.Split(organization.Path, "/")
		parentIDs := pathParts[1 : len(pathParts)-1] // Exclude first empty and last current org
		if len(parentIDs) > 0 {
			err = facades.Orm().Query().Where("id IN ?", parentIDs).Find(&parents)
			if err != nil {
				return nil, err
			}
		}
	}

	// Get subsidiaries
	var subsidiaries []models.Organization
	err = facades.Orm().Query().Where("parent_organization_id = ?", organizationID).Find(&subsidiaries)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"organization": organization,
		"parents":      parents,
		"subsidiaries": subsidiaries,
	}, nil
}

// VerifyOrganization marks an organization as verified
func (s *OrganizationService) VerifyOrganization(organizationID string) error {
	organization := &models.Organization{}
	err := facades.Orm().Query().Where("id = ?", organizationID).First(organization)
	if err != nil {
		return err
	}

	now := time.Now()
	organization.IsVerified = true
	organization.VerifiedAt = &now

	err = facades.Orm().Query().Save(organization)
	if err != nil {
		return err
	}

	// Log activity
	s.auditService.LogEventCompat(nil, "organization.verified", "Organization verified", "", "", map[string]interface{}{
		"organization_id": organizationID,
		"name":            organization.Name,
	}, "low")

	return nil
}

// GetOrganizationStats retrieves statistics for an organization
func (s *OrganizationService) GetOrganizationStats(organizationID string) (map[string]interface{}, error) {
	// Get user count
	userCount, _ := facades.Orm().Query().Model(&models.UserOrganization{}).Where("organization_id = ? AND is_active = ?", organizationID, true).Count()

	// Get department count
	departmentCount, _ := facades.Orm().Query().Model(&models.Department{}).Where("organization_id = ? AND is_active = ?", organizationID, true).Count()

	// Get team count
	teamCount, _ := facades.Orm().Query().Model(&models.Team{}).Where("organization_id = ? AND is_active = ?", organizationID, true).Count()

	// Get project count
	projectCount, _ := facades.Orm().Query().Model(&models.Project{}).Where("organization_id = ? AND is_active = ?", organizationID, true).Count()

	// Get active project count
	activeProjectCount, _ := facades.Orm().Query().Model(&models.Project{}).Where("organization_id = ? AND is_active = ? AND status = ?", organizationID, true, "active").Count()

	// Get subsidiary count
	subsidiaryCount, _ := facades.Orm().Query().Model(&models.Organization{}).Where("parent_organization_id = ? AND is_active = ?", organizationID, true).Count()

	return map[string]interface{}{
		"total_users":        userCount,
		"total_departments":  departmentCount,
		"total_teams":        teamCount,
		"total_projects":     projectCount,
		"active_projects":    activeProjectCount,
		"total_subsidiaries": subsidiaryCount,
	}, nil
}

// CreateDepartment creates a new department
func (s *OrganizationService) CreateDepartment(data map[string]interface{}) (*models.Department, error) {
	// Set default values
	if data["is_active"] == nil {
		data["is_active"] = true
	}
	if data["level"] == nil {
		data["level"] = 0
	}

	// Handle parent department
	if parentID, exists := data["parent_department_id"]; exists && parentID != nil && parentID != "" {
		parentDept := &models.Department{}
		err := facades.Orm().Query().Where("id = ?", parentID).First(parentDept)
		if err != nil {
			return nil, errors.New("parent department not found")
		}
		data["level"] = parentDept.Level + 1
		data["path"] = parentDept.Path + "/" + parentDept.ID
	} else {
		data["path"] = "/"
	}

	// Create department
	department := &models.Department{
		Name:           data["name"].(string),
		Code:           data["code"].(string),
		Description:    data["description"].(string),
		Color:          data["color"].(string),
		Icon:           data["icon"].(string),
		IsActive:       data["is_active"].(bool),
		OrganizationID: data["organization_id"].(string),
		Level:          data["level"].(int),
		Path:           data["path"].(string),
	}

	// Set optional fields
	if parentDeptID, exists := data["parent_department_id"]; exists && parentDeptID != nil {
		parentDeptIDStr := parentDeptID.(string)
		department.ParentDepartmentID = &parentDeptIDStr
	}
	if managerID, exists := data["manager_id"]; exists && managerID != nil {
		managerIDStr := managerID.(string)
		department.ManagerID = &managerIDStr
	}

	err := facades.Orm().Query().Create(department)
	if err != nil {
		return nil, err
	}

	// Log activity
	s.auditService.LogEventCompat(nil, "department.created", "Department created", "", "", map[string]interface{}{
		"department_id":   department.ID,
		"name":            department.Name,
		"organization_id": department.OrganizationID,
	}, "low")

	return department, nil
}

// GetDepartment retrieves a department by ID
func (s *OrganizationService) GetDepartment(id string) (*models.Department, error) {
	department := &models.Department{}
	err := facades.Orm().Query().Where("id = ?", id).First(department)
	if err != nil {
		return nil, err
	}
	return department, nil
}

// UpdateDepartment updates a department
func (s *OrganizationService) UpdateDepartment(id string, data map[string]interface{}) (*models.Department, error) {
	department := &models.Department{}
	err := facades.Orm().Query().Where("id = ?", id).First(department)
	if err != nil {
		return nil, err
	}

	// Update department fields
	if name, exists := data["name"]; exists {
		department.Name = name.(string)
	}
	if code, exists := data["code"]; exists {
		department.Code = code.(string)
	}
	if description, exists := data["description"]; exists {
		department.Description = description.(string)
	}
	if color, exists := data["color"]; exists {
		department.Color = color.(string)
	}
	if icon, exists := data["icon"]; exists {
		department.Icon = icon.(string)
	}
	if isActive, exists := data["is_active"]; exists {
		department.IsActive = isActive.(bool)
	}
	if parentDeptID, exists := data["parent_department_id"]; exists {
		if parentDeptID != nil {
			parentDeptIDStr := parentDeptID.(string)
			department.ParentDepartmentID = &parentDeptIDStr
		} else {
			department.ParentDepartmentID = nil
		}
	}
	if managerID, exists := data["manager_id"]; exists {
		if managerID != nil {
			managerIDStr := managerID.(string)
			department.ManagerID = &managerIDStr
		} else {
			department.ManagerID = nil
		}
	}

	// Save department
	err = facades.Orm().Query().Save(department)
	if err != nil {
		return nil, err
	}

	// Log activity
	s.auditService.LogEventCompat(nil, "department.updated", "Department updated", "", "", map[string]interface{}{
		"department_id":   department.ID,
		"name":            department.Name,
		"organization_id": department.OrganizationID,
	}, "low")

	return department, nil
}

// DeleteDepartment deletes a department
func (s *OrganizationService) DeleteDepartment(id string) error {
	department := &models.Department{}
	err := facades.Orm().Query().Where("id = ?", id).First(department)
	if err != nil {
		return err
	}

	// Check if department has sub-departments
	var subDeptCount int64
	subDeptCount, _ = facades.Orm().Query().Model(&models.Department{}).Where("parent_department_id = ?", id).Count()
	if subDeptCount > 0 {
		return errors.New("cannot delete department with sub-departments")
	}

	// Check if department has users
	var userCount int64
	userCount, _ = facades.Orm().Query().Model(&models.UserDepartment{}).Where("department_id = ?", id).Count()
	if userCount > 0 {
		return errors.New("cannot delete department with users")
	}

	// Delete department
	_, err = facades.Orm().Query().Where("id = ?", id).Delete(department)
	if err != nil {
		return err
	}

	// Log activity
	s.auditService.LogEventCompat(nil, "department.deleted", "Department deleted", "", "", map[string]interface{}{
		"department_id":   department.ID,
		"name":            department.Name,
		"organization_id": department.OrganizationID,
	}, "low")

	return nil
}

// ListDepartments retrieves departments with filtering and pagination
func (s *OrganizationService) ListDepartments(filters map[string]interface{}, cursor string, limit int) ([]models.Department, map[string]interface{}, error) {
	query := facades.Orm().Query().Model(&models.Department{})

	// Apply filters
	if organizationID, exists := filters["organization_id"]; exists {
		query = query.Where("organization_id = ?", organizationID)
	}
	if search, exists := filters["search"]; exists && search != "" {
		searchStr := search.(string)
		query = query.Where("name LIKE ? OR description LIKE ?", "%"+searchStr+"%", "%"+searchStr+"%")
	}
	if isActive, exists := filters["is_active"]; exists {
		query = query.Where("is_active = ?", isActive)
	}
	if parentDeptID, exists := filters["parent_department_id"]; exists && parentDeptID != "" {
		query = query.Where("parent_department_id = ?", parentDeptID)
	}

	// Apply cursor-based pagination
	query, err := helpers.ApplyCursorPagination(query, cursor, limit, false)
	if err != nil {
		return nil, nil, err
	}

	var departments []models.Department
	err = query.Find(&departments)
	if err != nil {
		return nil, nil, err
	}

	// Check if there are more results
	hasMore := false
	if len(departments) > limit {
		hasMore = true
		departments = departments[:limit] // Remove the extra item
	}

	// Build pagination info
	paginationInfo := helpers.BuildPaginationInfo(departments, limit, cursor, hasMore)

	return departments, paginationInfo, nil
}

// AddUserToDepartment adds a user to a department
func (s *OrganizationService) AddUserToDepartment(departmentID, userID string, data map[string]interface{}) error {
	// Check if user-department relationship already exists
	var existingUserDept models.UserDepartment
	err := facades.Orm().Query().Where("department_id = ? AND user_id = ?", departmentID, userID).First(&existingUserDept)
	if err == nil {
		return errors.New("user is already in this department")
	}

	// Set default values
	if data["role"] == nil || data["role"] == "" {
		data["role"] = "member"
	}
	if data["is_active"] == nil {
		data["is_active"] = true
	}

	// Create user-department relationship
	userDept := &models.UserDepartment{
		UserID:       userID,
		DepartmentID: departmentID,
		Role:         data["role"].(string),
		IsActive:     data["is_active"].(bool),
		JoinedAt:     time.Now(),
	}

	err = facades.Orm().Query().Create(userDept)
	if err != nil {
		return err
	}

	// Log activity
	s.auditService.LogEventCompat(nil, "department.user_added", "User added to department", "", "", map[string]interface{}{
		"department_id": departmentID,
		"user_id":       userID,
		"role":          userDept.Role,
	}, "low")

	return nil
}

// RemoveUserFromDepartment removes a user from a department
func (s *OrganizationService) RemoveUserFromDepartment(departmentID, userID string) error {
	// Check if user-department relationship exists
	var userDept models.UserDepartment
	err := facades.Orm().Query().Where("department_id = ? AND user_id = ?", departmentID, userID).First(&userDept)
	if err != nil {
		return errors.New("user is not in this department")
	}

	// Delete user-department relationship
	_, err = facades.Orm().Query().Where("department_id = ? AND user_id = ?", departmentID, userID).Delete(&userDept)
	if err != nil {
		return err
	}

	// Log activity
	s.auditService.LogEventCompat(nil, "department.user_removed", "User removed from department", "", "", map[string]interface{}{
		"department_id": departmentID,
		"user_id":       userID,
	}, "low")

	return nil
}

// GetDepartmentUsers retrieves users in a department
func (s *OrganizationService) GetDepartmentUsers(departmentID string, filters map[string]interface{}, cursor string, limit int) ([]models.User, map[string]interface{}, error) {
	// First get user IDs from user_departments table
	var userDepts []models.UserDepartment
	userDeptQuery := facades.Orm().Query().Where("department_id = ?", departmentID)

	// Apply filters
	if role, exists := filters["role"]; exists && role != "" {
		userDeptQuery = userDeptQuery.Where("role = ?", role)
	}

	err := userDeptQuery.Find(&userDepts)
	if err != nil {
		return nil, nil, err
	}

	// Extract user IDs
	var userIDs []string
	for _, userDept := range userDepts {
		userIDs = append(userIDs, userDept.UserID)
	}

	if len(userIDs) == 0 {
		return []models.User{}, map[string]interface{}{
			"next_cursor": "",
			"prev_cursor": "",
			"has_more":    false,
			"has_prev":    false,
			"count":       0,
			"limit":       limit,
		}, nil
	}

	// Get users by IDs
	query := facades.Orm().Query().Where("id IN ?", userIDs)

	// Apply search filter
	if search, exists := filters["search"]; exists && search != "" {
		searchStr := search.(string)
		query = query.Where("name LIKE ? OR email LIKE ?", "%"+searchStr+"%", "%"+searchStr+"%")
	}

	// Apply cursor-based pagination
	query, err = helpers.ApplyCursorPagination(query, cursor, limit, false)
	if err != nil {
		return nil, nil, err
	}

	var users []models.User
	err = query.Find(&users)
	if err != nil {
		return nil, nil, err
	}

	// Check if there are more results
	hasMore := false
	if len(users) > limit {
		hasMore = true
		users = users[:limit] // Remove the extra item
	}

	// Build pagination info
	paginationInfo := helpers.BuildPaginationInfo(users, limit, cursor, hasMore)

	return users, paginationInfo, nil
}

// CreateTeam creates a new team
func (s *OrganizationService) CreateTeam(data map[string]interface{}) (*models.Team, error) {
	// Set default values
	if data["is_active"] == nil {
		data["is_active"] = true
	}
	if data["current_size"] == nil {
		data["current_size"] = 0
	}
	if data["max_size"] == nil {
		data["max_size"] = 10
	}

	// Create team
	team := &models.Team{
		Name:           data["name"].(string),
		Code:           data["code"].(string),
		Description:    data["description"].(string),
		Type:           data["type"].(string),
		Color:          data["color"].(string),
		Icon:           data["icon"].(string),
		IsActive:       data["is_active"].(bool),
		OrganizationID: data["organization_id"].(string),
		MaxSize:        data["max_size"].(int),
		CurrentSize:    data["current_size"].(int),
	}

	// Set optional fields
	if departmentID, exists := data["department_id"]; exists && departmentID != nil {
		departmentIDStr := departmentID.(string)
		team.DepartmentID = &departmentIDStr
	}
	if teamLeadID, exists := data["team_lead_id"]; exists && teamLeadID != nil {
		teamLeadIDStr := teamLeadID.(string)
		team.TeamLeadID = &teamLeadIDStr
	}

	err := facades.Orm().Query().Create(team)
	if err != nil {
		return nil, err
	}

	// Log activity
	s.auditService.LogEventCompat(nil, "team.created", "Team created", "", "", map[string]interface{}{
		"team_id":         team.ID,
		"name":            team.Name,
		"organization_id": team.OrganizationID,
	}, "low")

	return team, nil
}

// GetTeam retrieves a team by ID
func (s *OrganizationService) GetTeam(id string) (*models.Team, error) {
	team := &models.Team{}
	err := facades.Orm().Query().Where("id = ?", id).First(team)
	if err != nil {
		return nil, err
	}
	return team, nil
}

// UpdateTeam updates a team
func (s *OrganizationService) UpdateTeam(id string, data map[string]interface{}) (*models.Team, error) {
	team := &models.Team{}
	err := facades.Orm().Query().Where("id = ?", id).First(team)
	if err != nil {
		return nil, err
	}

	// Update team fields
	if name, exists := data["name"]; exists {
		team.Name = name.(string)
	}
	if code, exists := data["code"]; exists {
		team.Code = code.(string)
	}
	if description, exists := data["description"]; exists {
		team.Description = description.(string)
	}
	if teamType, exists := data["type"]; exists {
		team.Type = teamType.(string)
	}
	if color, exists := data["color"]; exists {
		team.Color = color.(string)
	}
	if icon, exists := data["icon"]; exists {
		team.Icon = icon.(string)
	}
	if maxSize, exists := data["max_size"]; exists {
		team.MaxSize = maxSize.(int)
	}
	if departmentID, exists := data["department_id"]; exists {
		if departmentID != nil {
			departmentIDStr := departmentID.(string)
			team.DepartmentID = &departmentIDStr
		} else {
			team.DepartmentID = nil
		}
	}
	if teamLeadID, exists := data["team_lead_id"]; exists {
		if teamLeadID != nil {
			teamLeadIDStr := teamLeadID.(string)
			team.TeamLeadID = &teamLeadIDStr
		} else {
			team.TeamLeadID = nil
		}
	}

	// Save team
	err = facades.Orm().Query().Save(team)
	if err != nil {
		return nil, err
	}

	// Log activity
	s.auditService.LogEventCompat(nil, "team.updated", "Team updated", "", "", map[string]interface{}{
		"team_id":         team.ID,
		"name":            team.Name,
		"organization_id": team.OrganizationID,
	}, "low")

	return team, nil
}

// DeleteTeam deletes a team
func (s *OrganizationService) DeleteTeam(id string) error {
	team := &models.Team{}
	err := facades.Orm().Query().Where("id = ?", id).First(team)
	if err != nil {
		return err
	}

	// Check if team has users
	var userCount int64
	userCount, _ = facades.Orm().Query().Model(&models.UserTeam{}).Where("team_id = ?", id).Count()
	if userCount > 0 {
		return errors.New("cannot delete team with users")
	}

	// Check if team has projects
	var projectCount int64
	projectCount, _ = facades.Orm().Query().Model(&models.TeamProject{}).Where("team_id = ?", id).Count()
	if projectCount > 0 {
		return errors.New("cannot delete team with projects")
	}

	// Delete team
	_, err = facades.Orm().Query().Where("id = ?", id).Delete(team)
	if err != nil {
		return err
	}

	// Log activity
	s.auditService.LogEventCompat(nil, "team.deleted", "Team deleted", "", "", map[string]interface{}{
		"team_id":         team.ID,
		"name":            team.Name,
		"organization_id": team.OrganizationID,
	}, "low")

	return nil
}

// ListTeams retrieves teams with filtering and pagination
func (s *OrganizationService) ListTeams(filters map[string]interface{}, cursor string, limit int) ([]models.Team, map[string]interface{}, error) {
	query := facades.Orm().Query().Model(&models.Team{})

	// Apply filters
	if organizationID, exists := filters["organization_id"]; exists {
		query = query.Where("organization_id = ?", organizationID)
	}
	if search, exists := filters["search"]; exists && search != "" {
		searchStr := search.(string)
		query = query.Where("name LIKE ? OR description LIKE ?", "%"+searchStr+"%", "%"+searchStr+"%")
	}
	if teamType, exists := filters["type"]; exists && teamType != "" {
		query = query.Where("type = ?", teamType)
	}
	if isActive, exists := filters["is_active"]; exists {
		query = query.Where("is_active = ?", isActive)
	}
	if departmentID, exists := filters["department_id"]; exists && departmentID != "" {
		query = query.Where("department_id = ?", departmentID)
	}

	// Apply cursor-based pagination
	query, err := helpers.ApplyCursorPagination(query, cursor, limit, false)
	if err != nil {
		return nil, nil, err
	}

	var teams []models.Team
	err = query.Find(&teams)
	if err != nil {
		return nil, nil, err
	}

	// Check if there are more results
	hasMore := false
	if len(teams) > limit {
		hasMore = true
		teams = teams[:limit] // Remove the extra item
	}

	// Build pagination info
	paginationInfo := helpers.BuildPaginationInfo(teams, limit, cursor, hasMore)

	return teams, paginationInfo, nil
}

// AddUserToTeam adds a user to a team
func (s *OrganizationService) AddUserToTeam(teamID, userID string, data map[string]interface{}) error {
	// Check if user-team relationship already exists
	var existingUserTeam models.UserTeam
	err := facades.Orm().Query().Where("team_id = ? AND user_id = ?", teamID, userID).First(&existingUserTeam)
	if err == nil {
		return errors.New("user is already in this team")
	}

	// Set default values
	if data["role"] == nil || data["role"] == "" {
		data["role"] = "member"
	}
	if data["is_active"] == nil {
		data["is_active"] = true
	}
	if data["allocation"] == nil {
		data["allocation"] = 100.0
	}

	// Create user-team relationship
	userTeam := &models.UserTeam{
		UserID:   userID,
		TeamID:   teamID,
		Role:     data["role"].(string),
		IsActive: data["is_active"].(bool),
		JoinedAt: time.Now(),
	}

	err = facades.Orm().Query().Create(userTeam)
	if err != nil {
		return err
	}

	// Update team current size
	_, err = facades.Orm().Query().Model(&models.Team{}).Where("id = ?", teamID).Update("current_size", facades.Orm().Query().Raw("current_size + 1"))
	if err != nil {
		return err
	}

	// Log activity
	s.auditService.LogEventCompat(nil, "team.user_added", "User added to team", "", "", map[string]interface{}{
		"team_id": teamID,
		"user_id": userID,
		"role":    userTeam.Role,
	}, "low")

	return nil
}

// RemoveUserFromTeam removes a user from a team
func (s *OrganizationService) RemoveUserFromTeam(teamID, userID string) error {
	// Check if user-team relationship exists
	var userTeam models.UserTeam
	err := facades.Orm().Query().Where("team_id = ? AND user_id = ?", teamID, userID).First(&userTeam)
	if err != nil {
		return errors.New("user is not in this team")
	}

	// Delete user-team relationship
	_, err = facades.Orm().Query().Where("team_id = ? AND user_id = ?", teamID, userID).Delete(&userTeam)
	if err != nil {
		return err
	}

	// Update team current size
	_, err = facades.Orm().Query().Model(&models.Team{}).Where("id = ?", teamID).Update("current_size", facades.Orm().Query().Raw("GREATEST(current_size - 1, 0)"))
	if err != nil {
		return err
	}

	// Log activity
	s.auditService.LogEventCompat(nil, "team.user_removed", "User removed from team", "", "", map[string]interface{}{
		"team_id": teamID,
		"user_id": userID,
	}, "low")

	return nil
}

// GetTeamUsers retrieves users in a team
func (s *OrganizationService) GetTeamUsers(teamID string, filters map[string]interface{}, cursor string, limit int) ([]models.User, map[string]interface{}, error) {
	// First get user IDs from user_teams table
	var userTeams []models.UserTeam
	userTeamQuery := facades.Orm().Query().Where("team_id = ?", teamID)

	// Apply filters
	if role, exists := filters["role"]; exists && role != "" {
		userTeamQuery = userTeamQuery.Where("role = ?", role)
	}

	err := userTeamQuery.Find(&userTeams)
	if err != nil {
		return nil, nil, err
	}

	// Extract user IDs
	var userIDs []string
	for _, userTeam := range userTeams {
		userIDs = append(userIDs, userTeam.UserID)
	}

	if len(userIDs) == 0 {
		return []models.User{}, map[string]interface{}{
			"next_cursor": "",
			"prev_cursor": "",
			"has_more":    false,
			"has_prev":    false,
			"count":       0,
			"limit":       limit,
		}, nil
	}

	// Get users by IDs
	query := facades.Orm().Query().Where("id IN ?", userIDs)

	// Apply search filter
	if search, exists := filters["search"]; exists && search != "" {
		searchStr := search.(string)
		query = query.Where("name LIKE ? OR email LIKE ?", "%"+searchStr+"%", "%"+searchStr+"%")
	}

	// Apply cursor-based pagination
	query, err = helpers.ApplyCursorPagination(query, cursor, limit, false)
	if err != nil {
		return nil, nil, err
	}

	var users []models.User
	err = query.Find(&users)
	if err != nil {
		return nil, nil, err
	}

	// Check if there are more results
	hasMore := false
	if len(users) > limit {
		hasMore = true
		users = users[:limit] // Remove the extra item
	}

	// Build pagination info
	paginationInfo := helpers.BuildPaginationInfo(users, limit, cursor, hasMore)

	return users, paginationInfo, nil
}

// CreateProject creates a new project
func (s *OrganizationService) CreateProject(data map[string]interface{}) (*models.Project, error) {
	// Set default values
	if data["is_active"] == nil {
		data["is_active"] = true
	}
	if data["progress"] == nil {
		data["progress"] = 0.0
	}
	if data["budget"] == nil {
		data["budget"] = 0.0
	}

	// Create project
	project := &models.Project{
		Name:           data["name"].(string),
		Code:           data["code"].(string),
		Description:    data["description"].(string),
		Status:         data["status"].(string),
		Priority:       data["priority"].(string),
		Color:          data["color"].(string),
		Icon:           data["icon"].(string),
		IsActive:       data["is_active"].(bool),
		OrganizationID: data["organization_id"].(string),
		Budget:         data["budget"].(float64),
		Progress:       data["progress"].(float64),
	}

	// Set optional fields
	if projectManagerID, exists := data["project_manager_id"]; exists && projectManagerID != nil {
		projectManagerIDStr := projectManagerID.(string)
		project.ProjectManagerID = &projectManagerIDStr
	}
	if startDate, exists := data["start_date"]; exists && startDate != nil {
		project.StartDate = startDate.(*time.Time)
	}
	if endDate, exists := data["end_date"]; exists && endDate != nil {
		project.EndDate = endDate.(*time.Time)
	}
	if settings, exists := data["settings"]; exists && settings != nil {
		project.Settings = settings.(string)
	}

	err := facades.Orm().Query().Create(project)
	if err != nil {
		return nil, err
	}

	// Log activity
	s.auditService.LogEventCompat(nil, "project.created", "Project created", "", "", map[string]interface{}{
		"project_id":      project.ID,
		"name":            project.Name,
		"organization_id": project.OrganizationID,
	}, "low")

	return project, nil
}

// GetProject retrieves a project by ID
func (s *OrganizationService) GetProject(id string) (*models.Project, error) {
	project := &models.Project{}
	err := facades.Orm().Query().Where("id = ?", id).First(project)
	if err != nil {
		return nil, err
	}
	return project, nil
}

// UpdateProject updates a project
func (s *OrganizationService) UpdateProject(id string, data map[string]interface{}) (*models.Project, error) {
	project := &models.Project{}
	err := facades.Orm().Query().Where("id = ?", id).First(project)
	if err != nil {
		return nil, err
	}

	// Update project fields
	if name, exists := data["name"]; exists {
		project.Name = name.(string)
	}
	if code, exists := data["code"]; exists {
		project.Code = code.(string)
	}
	if description, exists := data["description"]; exists {
		project.Description = description.(string)
	}
	if status, exists := data["status"]; exists {
		project.Status = status.(string)
	}
	if priority, exists := data["priority"]; exists {
		project.Priority = priority.(string)
	}
	if color, exists := data["color"]; exists {
		project.Color = color.(string)
	}
	if icon, exists := data["icon"]; exists {
		project.Icon = icon.(string)
	}
	if budget, exists := data["budget"]; exists {
		project.Budget = budget.(float64)
	}
	if startDate, exists := data["start_date"]; exists {
		if startDate != nil {
			project.StartDate = startDate.(*time.Time)
		} else {
			project.StartDate = nil
		}
	}
	if endDate, exists := data["end_date"]; exists {
		if endDate != nil {
			project.EndDate = endDate.(*time.Time)
		} else {
			project.EndDate = nil
		}
	}
	if projectManagerID, exists := data["project_manager_id"]; exists {
		if projectManagerID != nil {
			projectManagerIDStr := projectManagerID.(string)
			project.ProjectManagerID = &projectManagerIDStr
		} else {
			project.ProjectManagerID = nil
		}
	}
	if settings, exists := data["settings"]; exists {
		project.Settings = settings.(string)
	}

	// Save project
	err = facades.Orm().Query().Save(project)
	if err != nil {
		return nil, err
	}

	// Log activity
	s.auditService.LogEventCompat(nil, "project.updated", "Project updated", "", "", map[string]interface{}{
		"project_id":      project.ID,
		"name":            project.Name,
		"organization_id": project.OrganizationID,
	}, "low")

	return project, nil
}

// DeleteProject deletes a project
func (s *OrganizationService) DeleteProject(id string) error {
	project := &models.Project{}
	err := facades.Orm().Query().Where("id = ?", id).First(project)
	if err != nil {
		return err
	}

	// Check if project has users
	var userCount int64
	userCount, _ = facades.Orm().Query().Model(&models.UserProject{}).Where("project_id = ?", id).Count()
	if userCount > 0 {
		return errors.New("cannot delete project with users")
	}

	// Check if project has teams
	var teamCount int64
	teamCount, _ = facades.Orm().Query().Model(&models.TeamProject{}).Where("project_id = ?", id).Count()
	if teamCount > 0 {
		return errors.New("cannot delete project with teams")
	}

	// Delete project
	_, err = facades.Orm().Query().Where("id = ?", id).Delete(project)
	if err != nil {
		return err
	}

	// Log activity
	s.auditService.LogEventCompat(nil, "project.deleted", "Project deleted", "", "", map[string]interface{}{
		"project_id":      project.ID,
		"name":            project.Name,
		"organization_id": project.OrganizationID,
	}, "low")

	return nil
}

// ListProjects retrieves projects with filtering and pagination
func (s *OrganizationService) ListProjects(filters map[string]interface{}, cursor string, limit int) ([]models.Project, map[string]interface{}, error) {
	query := facades.Orm().Query().Model(&models.Project{})

	// Apply filters
	if organizationID, exists := filters["organization_id"]; exists {
		query = query.Where("organization_id = ?", organizationID)
	}
	if search, exists := filters["search"]; exists && search != "" {
		searchStr := search.(string)
		query = query.Where("name LIKE ? OR description LIKE ?", "%"+searchStr+"%", "%"+searchStr+"%")
	}
	if status, exists := filters["status"]; exists && status != "" {
		query = query.Where("status = ?", status)
	}
	if priority, exists := filters["priority"]; exists && priority != "" {
		query = query.Where("priority = ?", priority)
	}
	if isActive, exists := filters["is_active"]; exists {
		query = query.Where("is_active = ?", isActive)
	}

	// Apply cursor-based pagination
	query, err := helpers.ApplyCursorPagination(query, cursor, limit, false)
	if err != nil {
		return nil, nil, err
	}

	var projects []models.Project
	err = query.Find(&projects)
	if err != nil {
		return nil, nil, err
	}

	// Check if there are more results
	hasMore := false
	if len(projects) > limit {
		hasMore = true
		projects = projects[:limit] // Remove the extra item
	}

	// Build pagination info
	paginationInfo := helpers.BuildPaginationInfo(projects, limit, cursor, hasMore)

	return projects, paginationInfo, nil
}

// AddUserToProject adds a user to a project
func (s *OrganizationService) AddUserToProject(projectID, userID string, data map[string]interface{}) error {
	// Check if user-project relationship already exists
	var existingUserProject models.UserProject
	err := facades.Orm().Query().Where("project_id = ? AND user_id = ?", projectID, userID).First(&existingUserProject)
	if err == nil {
		return errors.New("user is already in this project")
	}

	// Set default values
	if data["role"] == nil || data["role"] == "" {
		data["role"] = "member"
	}
	if data["is_active"] == nil {
		data["is_active"] = true
	}
	if data["allocation"] == nil {
		data["allocation"] = 100.0
	}

	// Create user-project relationship
	userProject := &models.UserProject{
		UserID:     userID,
		ProjectID:  projectID,
		Role:       data["role"].(string),
		IsActive:   data["is_active"].(bool),
		Allocation: data["allocation"].(float64),
		JoinedAt:   time.Now(),
	}

	err = facades.Orm().Query().Create(userProject)
	if err != nil {
		return err
	}

	// Log activity
	s.auditService.LogEventCompat(nil, "project.user_added", "User added to project", "", "", map[string]interface{}{
		"project_id": projectID,
		"user_id":    userID,
		"role":       userProject.Role,
	}, "low")

	return nil
}

// RemoveUserFromProject removes a user from a project
func (s *OrganizationService) RemoveUserFromProject(projectID, userID string) error {
	// Check if user-project relationship exists
	var userProject models.UserProject
	err := facades.Orm().Query().Where("project_id = ? AND user_id = ?", projectID, userID).First(&userProject)
	if err != nil {
		return errors.New("user is not in this project")
	}

	// Delete user-project relationship
	_, err = facades.Orm().Query().Where("project_id = ? AND user_id = ?", projectID, userID).Delete(&userProject)
	if err != nil {
		return err
	}

	// Log activity
	s.auditService.LogEventCompat(nil, "project.user_removed", "User removed from project", "", "", map[string]interface{}{
		"project_id": projectID,
		"user_id":    userID,
	}, "low")

	return nil
}

// GetProjectUsers retrieves users in a project
func (s *OrganizationService) GetProjectUsers(projectID string, filters map[string]interface{}, cursor string, limit int) ([]models.User, map[string]interface{}, error) {
	// First get user IDs from user_projects table
	var userProjects []models.UserProject
	userProjectQuery := facades.Orm().Query().Where("project_id = ?", projectID)

	// Apply filters
	if role, exists := filters["role"]; exists && role != "" {
		userProjectQuery = userProjectQuery.Where("role = ?", role)
	}

	err := userProjectQuery.Find(&userProjects)
	if err != nil {
		return nil, nil, err
	}

	// Extract user IDs
	var userIDs []string
	for _, userProject := range userProjects {
		userIDs = append(userIDs, userProject.UserID)
	}

	if len(userIDs) == 0 {
		return []models.User{}, map[string]interface{}{
			"next_cursor": "",
			"prev_cursor": "",
			"has_more":    false,
			"has_prev":    false,
			"count":       0,
			"limit":       limit,
		}, nil
	}

	// Get users by IDs
	query := facades.Orm().Query().Where("id IN ?", userIDs)

	// Apply search filter
	if search, exists := filters["search"]; exists && search != "" {
		searchStr := search.(string)
		query = query.Where("name LIKE ? OR email LIKE ?", "%"+searchStr+"%", "%"+searchStr+"%")
	}

	// Apply cursor-based pagination
	query, err = helpers.ApplyCursorPagination(query, cursor, limit, false)
	if err != nil {
		return nil, nil, err
	}

	var users []models.User
	err = query.Find(&users)
	if err != nil {
		return nil, nil, err
	}

	// Check if there are more results
	hasMore := false
	if len(users) > limit {
		hasMore = true
		users = users[:limit] // Remove the extra item
	}

	// Build pagination info
	paginationInfo := helpers.BuildPaginationInfo(users, limit, cursor, hasMore)

	return users, paginationInfo, nil
}

// GetProjectTeams retrieves teams in a project
func (s *OrganizationService) GetProjectTeams(projectID string, filters map[string]interface{}, cursor string, limit int) ([]models.Team, map[string]interface{}, error) {
	// First get team IDs from team_projects table
	var teamProjects []models.TeamProject
	teamProjectQuery := facades.Orm().Query().Where("project_id = ?", projectID)

	// Apply filters
	if role, exists := filters["role"]; exists && role != "" {
		teamProjectQuery = teamProjectQuery.Where("role = ?", role)
	}

	err := teamProjectQuery.Find(&teamProjects)
	if err != nil {
		return nil, nil, err
	}

	// Extract team IDs
	var teamIDs []string
	for _, teamProject := range teamProjects {
		teamIDs = append(teamIDs, teamProject.TeamID)
	}

	if len(teamIDs) == 0 {
		return []models.Team{}, map[string]interface{}{
			"next_cursor": "",
			"prev_cursor": "",
			"has_more":    false,
			"has_prev":    false,
			"count":       0,
			"limit":       limit,
		}, nil
	}

	// Get teams by IDs
	query := facades.Orm().Query().Where("id IN ?", teamIDs)

	// Apply search filter
	if search, exists := filters["search"]; exists && search != "" {
		searchStr := search.(string)
		query = query.Where("name LIKE ? OR description LIKE ?", "%"+searchStr+"%", "%"+searchStr+"%")
	}

	// Apply cursor-based pagination
	query, err = helpers.ApplyCursorPagination(query, cursor, limit, false)
	if err != nil {
		return nil, nil, err
	}

	var teams []models.Team
	err = query.Find(&teams)
	if err != nil {
		return nil, nil, err
	}

	// Check if there are more results
	hasMore := false
	if len(teams) > limit {
		hasMore = true
		teams = teams[:limit] // Remove the extra item
	}

	// Build pagination info
	paginationInfo := helpers.BuildPaginationInfo(teams, limit, cursor, hasMore)

	return teams, paginationInfo, nil
}

// AddTeamToProject adds a team to a project
func (s *OrganizationService) AddTeamToProject(projectID, teamID string, data map[string]interface{}) error {
	// Check if team-project relationship already exists
	var existingTeamProject models.TeamProject
	err := facades.Orm().Query().Where("project_id = ? AND team_id = ?", projectID, teamID).First(&existingTeamProject)
	if err == nil {
		return errors.New("team is already in this project")
	}

	// Set default values
	if data["role"] == nil || data["role"] == "" {
		data["role"] = "contributor"
	}
	if data["is_active"] == nil {
		data["is_active"] = true
	}
	if data["allocation"] == nil {
		data["allocation"] = 100.0
	}

	// Create team-project relationship
	teamProject := &models.TeamProject{
		TeamID:     teamID,
		ProjectID:  projectID,
		Role:       data["role"].(string),
		IsActive:   data["is_active"].(bool),
		Allocation: data["allocation"].(float64),
		JoinedAt:   time.Now(),
	}

	err = facades.Orm().Query().Create(teamProject)
	if err != nil {
		return err
	}

	// Log activity
	s.auditService.LogEventCompat(nil, "project.team_added", "Team added to project", "", "", map[string]interface{}{
		"project_id": projectID,
		"team_id":    teamID,
		"role":       teamProject.Role,
	}, "low")

	return nil
}

// RemoveTeamFromProject removes a team from a project
func (s *OrganizationService) RemoveTeamFromProject(projectID, teamID string) error {
	// Check if team-project relationship exists
	var teamProject models.TeamProject
	err := facades.Orm().Query().Where("project_id = ? AND team_id = ?", projectID, teamID).First(&teamProject)
	if err != nil {
		return errors.New("team is not in this project")
	}

	// Delete team-project relationship
	_, err = facades.Orm().Query().Where("project_id = ? AND team_id = ?", projectID, teamID).Delete(&teamProject)
	if err != nil {
		return err
	}

	// Log activity
	s.auditService.LogEventCompat(nil, "project.team_removed", "Team removed from project", "", "", map[string]interface{}{
		"project_id": projectID,
		"team_id":    teamID,
	}, "low")

	return nil
}
