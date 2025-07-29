package v1

import (
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/http/requests"
	"goravel/app/http/responses"
	"goravel/app/models"
)

type ProjectPermissionsController struct{}

func NewProjectPermissionsController() *ProjectPermissionsController {
	return &ProjectPermissionsController{}
}

// ListProjectMembers lists all members with their permissions for a project
// @Summary List project members
// @Description Get all members and their permissions for a project (GitHub Projects v2 style)
// @Tags project-permissions
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param per_page query int false "Results per page" minimum(1) maximum(100) default(30)
// @Param page query int false "Page number" minimum(1) default(1)
// @Param role query string false "Filter by role" Enums(admin,write,read)
// @Success 200 {array} object
// @Failure 400 {object} responses.ErrorResponse
// @Router /projects/{project_id}/members [get]
func (ppc *ProjectPermissionsController) ListProjectMembers(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	userID := ctx.Value("user_id").(string)

	// Verify project exists and user has permission to view members
	var project models.Project
	if err := facades.Orm().Query().Where("id = ?", projectID).First(&project); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project not found",
			Timestamp: time.Now(),
		})
	}

	// Check if user has permission to view project members
	if !ppc.canViewProjectMembers(userID, projectID, project.Visibility) {
		return ctx.Response().Status(403).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Insufficient permissions to view project members",
			Timestamp: time.Now(),
		})
	}

	// Get project members with their roles and permissions
	type ProjectMember struct {
		UserID      string     `json:"user_id"`
		Name        string     `json:"name"`
		Email       string     `json:"email"`
		Avatar      string     `json:"avatar"`
		Role        string     `json:"role"`
		Permissions []string   `json:"permissions"`
		JoinedAt    time.Time  `json:"joined_at"`
		LastActive  *time.Time `json:"last_active"`
	}

	var members []ProjectMember

	// Get organization members if project belongs to an organization
	if project.OrganizationID != "" {
		err := facades.Orm().Query().Raw(`
			SELECT 
				u.id as user_id,
				u.name,
				u.email,
				u.avatar,
				uo.role,
				uo.created_at as joined_at,
				al.last_activity as last_active
			FROM users u
			JOIN user_organizations uo ON u.id = uo.user_id
			LEFT JOIN (
				SELECT causer_id, MAX(created_at) as last_activity
				FROM activity_logs 
				WHERE subject_id = ? AND subject_type = 'Project'
				GROUP BY causer_id
			) al ON u.id = al.causer_id
			WHERE uo.organization_id = ? AND uo.is_active = true
			ORDER BY uo.role, u.name
		`, projectID, project.OrganizationID).Scan(&members)

		if err != nil {
			return ctx.Response().Status(500).Json(responses.ErrorResponse{
				Status:    "error",
				Message:   "Failed to retrieve project members: " + err.Error(),
				Timestamp: time.Now(),
			})
		}
	} else {
		// For personal projects, get the owner and any explicitly added members
		var owner models.User
		if project.OwnerID != nil && *project.OwnerID != "" {
			if err := facades.Orm().Query().Where("id = ?", *project.OwnerID).First(&owner); err == nil {
				members = append(members, ProjectMember{
					UserID:      owner.ID,
					Name:        owner.Name,
					Email:       owner.Email,
					Avatar:      owner.Avatar,
					Role:        "admin",
					Permissions: []string{"read", "write", "admin", "delete"},
					JoinedAt:    project.CreatedAt,
				})
			}
		}
	}

	// Add role-based permissions
	for i := range members {
		members[i].Permissions = ppc.getRolePermissions(members[i].Role)
	}

	// Apply pagination
	page := ctx.Request().InputInt("page", 1)
	perPage := ctx.Request().InputInt("per_page", 30)

	start := (page - 1) * perPage
	end := start + perPage

	if start > len(members) {
		start = len(members)
	}
	if end > len(members) {
		end = len(members)
	}

	paginatedMembers := members[start:end]

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:  "success",
		Message: "Project members retrieved successfully",
		Data: map[string]interface{}{
			"members": paginatedMembers,
			"pagination": map[string]interface{}{
				"current_page": page,
				"per_page":     perPage,
				"total":        len(members),
				"total_pages":  (len(members) + perPage - 1) / perPage,
			},
		},
		Timestamp: time.Now(),
	})
}

// InviteMember invites a user to the project
// @Summary Invite member to project
// @Description Invite a user to collaborate on a project (GitHub Projects v2 style)
// @Tags project-permissions
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param request body requests.ProjectInviteRequest true "Invitation data"
// @Success 201 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Router /projects/{project_id}/members/invite [post]
func (ppc *ProjectPermissionsController) InviteMember(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	userID := ctx.Value("user_id").(string)

	var request requests.ProjectInviteRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(422).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Validation failed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Verify project exists and user has admin permission
	var project models.Project
	if err := facades.Orm().Query().Where("id = ?", projectID).First(&project); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project not found",
			Timestamp: time.Now(),
		})
	}

	if !ppc.canManageProjectMembers(userID, projectID) {
		return ctx.Response().Status(403).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Insufficient permissions to invite members",
			Timestamp: time.Now(),
		})
	}

	// Verify the user to invite exists
	var invitedUser models.User
	if err := facades.Orm().Query().Where("email = ?", request.Email).First(&invitedUser); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "User not found",
			Timestamp: time.Now(),
		})
	}

	// For organization projects, add user to organization if not already a member
	if project.OrganizationID != "" {
		var existingMember models.UserOrganization
		err := facades.Orm().Query().
			Where("user_id = ? AND organization_id = ?", invitedUser.ID, project.OrganizationID).
			First(&existingMember)

		if err != nil {
			// User is not a member, create organization membership
			newMember := models.UserOrganization{
				UserID:         invitedUser.ID,
				OrganizationID: project.OrganizationID,
				Role:           request.Role,
				IsActive:       true,
				JoinedAt:       time.Now(),
			}

			if err := facades.Orm().Query().Create(&newMember); err != nil {
				return ctx.Response().Status(500).Json(responses.ErrorResponse{
					Status:    "error",
					Message:   "Failed to add user to organization: " + err.Error(),
					Timestamp: time.Now(),
				})
			}
		} else if !existingMember.IsActive {
			// Reactivate existing membership
			existingMember.IsActive = true
			existingMember.Role = request.Role

			if err := facades.Orm().Query().Save(&existingMember); err != nil {
				return ctx.Response().Status(500).Json(responses.ErrorResponse{
					Status:    "error",
					Message:   "Failed to reactivate organization membership: " + err.Error(),
					Timestamp: time.Now(),
				})
			}
		}
	}

	// Create activity log for the invitation
	activity := models.ActivityLog{
		LogName:     "member_invited",
		Description: "User " + invitedUser.Name + " was invited to the project with role: " + request.Role,
		Category:    models.CategoryUser,
		Severity:    models.SeverityInfo,
		SubjectID:   projectID,
		SubjectType: "Project",
		CauserID:    userID,
		CauserType:  "User",
	}

	facades.Orm().Query().Create(&activity)

	// TODO: Send invitation notification to the user
	// This would integrate with the notification system

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:  "success",
		Message: "User invited to project successfully",
		Data: map[string]interface{}{
			"invited_user": map[string]interface{}{
				"id":    invitedUser.ID,
				"name":  invitedUser.Name,
				"email": invitedUser.Email,
			},
			"role":        request.Role,
			"permissions": ppc.getRolePermissions(request.Role),
		},
		Timestamp: time.Now(),
	})
}

// UpdateMemberRole updates a member's role in the project
// @Summary Update member role
// @Description Update a project member's role and permissions
// @Tags project-permissions
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param user_id path string true "User ID"
// @Param request body requests.ProjectRoleUpdateRequest true "Role update data"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Router /projects/{project_id}/members/{user_id}/role [patch]
func (ppc *ProjectPermissionsController) UpdateMemberRole(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	memberUserID := ctx.Request().Route("user_id")
	currentUserID := ctx.Value("user_id").(string)

	var request requests.ProjectRoleUpdateRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(422).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Validation failed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Verify project exists and user has admin permission
	var project models.Project
	if err := facades.Orm().Query().Where("id = ?", projectID).First(&project); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project not found",
			Timestamp: time.Now(),
		})
	}

	if !ppc.canManageProjectMembers(currentUserID, projectID) {
		return ctx.Response().Status(403).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Insufficient permissions to update member roles",
			Timestamp: time.Now(),
		})
	}

	// Prevent users from changing their own role (except organization owners)
	if currentUserID == memberUserID && !ppc.isOrganizationOwner(currentUserID, &project.OrganizationID) {
		return ctx.Response().Status(403).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Cannot change your own role",
			Timestamp: time.Now(),
		})
	}

	// Update the user's role in the organization
	if project.OrganizationID != "" {
		var userOrg models.UserOrganization
		if err := facades.Orm().Query().
			Where("user_id = ? AND organization_id = ?", memberUserID, project.OrganizationID).
			First(&userOrg); err != nil {
			return ctx.Response().Status(404).Json(responses.ErrorResponse{
				Status:    "error",
				Message:   "User is not a member of this project",
				Timestamp: time.Now(),
			})
		}

		oldRole := userOrg.Role
		userOrg.Role = request.Role

		if err := facades.Orm().Query().Save(&userOrg); err != nil {
			return ctx.Response().Status(500).Json(responses.ErrorResponse{
				Status:    "error",
				Message:   "Failed to update member role: " + err.Error(),
				Timestamp: time.Now(),
			})
		}

		// Create activity log
		activity := models.ActivityLog{
			LogName:     "member_role_updated",
			Description: "Member role changed from " + oldRole + " to " + request.Role,
			Category:    models.CategoryUser,
			Severity:    models.SeverityInfo,
			SubjectID:   projectID,
			SubjectType: "Project",
			CauserID:    currentUserID,
			CauserType:  "User",
		}

		facades.Orm().Query().Create(&activity)
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:  "success",
		Message: "Member role updated successfully",
		Data: map[string]interface{}{
			"user_id":     memberUserID,
			"new_role":    request.Role,
			"permissions": ppc.getRolePermissions(request.Role),
		},
		Timestamp: time.Now(),
	})
}

// RemoveMember removes a member from the project
// @Summary Remove project member
// @Description Remove a user from project collaboration
// @Tags project-permissions
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param user_id path string true "User ID"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Router /projects/{project_id}/members/{user_id} [delete]
func (ppc *ProjectPermissionsController) RemoveMember(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	memberUserID := ctx.Request().Route("user_id")
	currentUserID := ctx.Value("user_id").(string)

	// Verify project exists and user has admin permission
	var project models.Project
	if err := facades.Orm().Query().Where("id = ?", projectID).First(&project); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project not found",
			Timestamp: time.Now(),
		})
	}

	if !ppc.canManageProjectMembers(currentUserID, projectID) {
		return ctx.Response().Status(403).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Insufficient permissions to remove members",
			Timestamp: time.Now(),
		})
	}

	// Prevent removing the project owner
	if project.OwnerID != nil && memberUserID == *project.OwnerID {
		return ctx.Response().Status(403).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Cannot remove the project owner",
			Timestamp: time.Now(),
		})
	}

	// For organization projects, deactivate the user's membership
	if project.OrganizationID != "" {
		var userOrg models.UserOrganization
		if err := facades.Orm().Query().
			Where("user_id = ? AND organization_id = ?", memberUserID, project.OrganizationID).
			First(&userOrg); err != nil {
			return ctx.Response().Status(404).Json(responses.ErrorResponse{
				Status:    "error",
				Message:   "User is not a member of this project",
				Timestamp: time.Now(),
			})
		}

		userOrg.IsActive = false

		if err := facades.Orm().Query().Save(&userOrg); err != nil {
			return ctx.Response().Status(500).Json(responses.ErrorResponse{
				Status:    "error",
				Message:   "Failed to remove member: " + err.Error(),
				Timestamp: time.Now(),
			})
		}

		// Create activity log
		activity := models.ActivityLog{
			LogName:     "member_removed",
			Description: "Member was removed from the project",
			Category:    models.CategoryUser,
			Severity:    models.SeverityInfo,
			SubjectID:   projectID,
			SubjectType: "Project",
			CauserID:    currentUserID,
			CauserType:  "User",
		}

		facades.Orm().Query().Create(&activity)
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Member removed from project successfully",
		Data:      map[string]interface{}{"removed_user_id": memberUserID},
		Timestamp: time.Now(),
	})
}

// GetProjectPermissions gets the current user's permissions for a project
// @Summary Get user permissions
// @Description Get the current user's permissions for a specific project
// @Tags project-permissions
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/permissions [get]
func (ppc *ProjectPermissionsController) GetProjectPermissions(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	userID := ctx.Value("user_id").(string)

	// Verify project exists
	var project models.Project
	if err := facades.Orm().Query().Where("id = ?", projectID).First(&project); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project not found",
			Timestamp: time.Now(),
		})
	}

	// Get user's role and permissions
	role := ppc.getUserProjectRole(userID, projectID)
	permissions := ppc.getRolePermissions(role)
	canAccess := ppc.canAccessProject(userID, projectID, project.Visibility)

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:  "success",
		Message: "User permissions retrieved successfully",
		Data: map[string]interface{}{
			"project_id":  projectID,
			"user_id":     userID,
			"role":        role,
			"permissions": permissions,
			"can_access":  canAccess,
			"visibility":  project.Visibility,
			"is_owner":    project.OwnerID != nil && userID == *project.OwnerID,
		},
		Timestamp: time.Now(),
	})
}

// Helper methods for permission checking

func (ppc *ProjectPermissionsController) canAccessProject(userID, projectID, visibility string) bool {
	if visibility == "public" {
		return true
	}

	// Check if user is project owner
	var project models.Project
	if err := facades.Orm().Query().Where("id = ? AND owner_id = ?", projectID, userID).First(&project); err == nil {
		return true
	}

	// Check if user is organization member
	if err := facades.Orm().Query().Raw(`
		SELECT 1 FROM user_organizations uo
		JOIN projects p ON uo.organization_id = p.organization_id
		WHERE p.id = ? AND uo.user_id = ? AND uo.is_active = true
	`, projectID, userID).First(&struct{}{}); err == nil {
		return true
	}

	return false
}

func (ppc *ProjectPermissionsController) canViewProjectMembers(userID, projectID, visibility string) bool {
	return ppc.canAccessProject(userID, projectID, visibility)
}

func (ppc *ProjectPermissionsController) canManageProjectMembers(userID, projectID string) bool {
	// Check if user is project owner
	var project models.Project
	if err := facades.Orm().Query().Where("id = ? AND owner_id = ?", projectID, userID).First(&project); err == nil {
		return true
	}

	// Check if user is organization admin
	if err := facades.Orm().Query().Raw(`
		SELECT 1 FROM user_organizations uo
		JOIN projects p ON uo.organization_id = p.organization_id
		WHERE p.id = ? AND uo.user_id = ? AND uo.role IN ('admin', 'owner') AND uo.is_active = true
	`, projectID, userID).First(&struct{}{}); err == nil {
		return true
	}

	return false
}

func (ppc *ProjectPermissionsController) isOrganizationOwner(userID string, organizationID *string) bool {
	if organizationID == nil {
		return false
	}

	var userOrg models.UserOrganization
	err := facades.Orm().Query().
		Where("user_id = ? AND organization_id = ? AND role = ? AND is_active = true", userID, *organizationID, "owner").
		First(&userOrg)

	return err == nil
}

func (ppc *ProjectPermissionsController) getUserProjectRole(userID, projectID string) string {
	// Check if user is project owner
	var project models.Project
	if err := facades.Orm().Query().Where("id = ? AND owner_id = ?", projectID, userID).First(&project); err == nil {
		return "admin"
	}

	// Get role from organization membership
	var userOrg models.UserOrganization
	if err := facades.Orm().Query().Raw(`
		SELECT uo.* FROM user_organizations uo
		JOIN projects p ON uo.organization_id = p.organization_id
		WHERE p.id = ? AND uo.user_id = ? AND uo.is_active = true
	`, projectID, userID).First(&userOrg); err == nil {
		return userOrg.Role
	}

	// Default to read-only for public projects
	if err := facades.Orm().Query().Where("id = ? AND visibility = ?", projectID, "public").First(&project); err == nil {
		return "read"
	}

	return "none"
}

func (ppc *ProjectPermissionsController) getRolePermissions(role string) []string {
	switch role {
	case "admin", "owner":
		return []string{"read", "write", "admin", "delete", "manage_members", "manage_settings"}
	case "write", "maintainer":
		return []string{"read", "write", "create_items", "edit_items"}
	case "read", "member":
		return []string{"read", "view_items", "comment"}
	default:
		return []string{}
	}
}
