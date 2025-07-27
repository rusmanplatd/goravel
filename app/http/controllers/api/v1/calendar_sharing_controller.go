package v1

import (
	"time"

	"github.com/goravel/framework/contracts/http"

	"goravel/app/http/responses"
	"goravel/app/services"
)

type CalendarSharingController struct {
	sharingService *services.CalendarSharingService
}

func NewCalendarSharingController() *CalendarSharingController {
	return &CalendarSharingController{
		sharingService: services.NewCalendarSharingService(),
	}
}

// ShareCalendar creates a new calendar share
// @Summary Share calendar with another user
// @Description Share your calendar with another user with specified permissions
// @Tags calendar-sharing
// @Accept json
// @Produce json
// @Param request body services.ShareCalendarRequest true "Share calendar request"
// @Param shared_with_id path string true "User ID to share calendar with"
// @Success 200 {object} responses.APIResponse{data=models.CalendarShare}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /calendar-sharing/share/{shared_with_id} [post]
func (csc *CalendarSharingController) ShareCalendar(ctx http.Context) http.Response {
	userID := ctx.Value("user_id").(string)
	tenantID := ctx.Value("tenant_id").(string)
	sharedWithID := ctx.Request().Route("shared_with_id")

	if sharedWithID == userID {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Cannot share calendar with yourself",
			Timestamp: time.Now(),
		})
	}

	var request services.ShareCalendarRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Validate permission level
	validPermissions := []string{"view", "edit", "manage"}
	isValidPermission := false
	for _, perm := range validPermissions {
		if request.Permission == perm {
			isValidPermission = true
			break
		}
	}
	if !isValidPermission {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid permission level. Must be: view, edit, or manage",
			Timestamp: time.Now(),
		})
	}

	share, err := csc.sharingService.ShareCalendar(userID, sharedWithID, tenantID, &request)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to share calendar: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      share,
		Message:   "Calendar shared successfully",
		Timestamp: time.Now(),
	})
}

// AcceptCalendarShare accepts a calendar share invitation
// @Summary Accept calendar share invitation
// @Description Accept an invitation to access someone's shared calendar
// @Tags calendar-sharing
// @Accept json
// @Produce json
// @Param share_id path string true "Calendar share ID"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /calendar-sharing/accept/{share_id} [post]
func (csc *CalendarSharingController) AcceptCalendarShare(ctx http.Context) http.Response {
	userID := ctx.Value("user_id").(string)
	shareID := ctx.Request().Route("share_id")

	err := csc.sharingService.AcceptCalendarShare(shareID, userID)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to accept calendar share: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Calendar share accepted successfully",
		Timestamp: time.Now(),
	})
}

// CreateDelegation creates a new calendar delegation
// @Summary Create calendar delegation
// @Description Create a delegation allowing another user to manage your calendar
// @Tags calendar-delegation
// @Accept json
// @Produce json
// @Param request body services.CreateDelegationRequest true "Create delegation request"
// @Param delegate_id path string true "User ID to delegate to"
// @Success 200 {object} responses.APIResponse{data=models.CalendarDelegate}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /calendar-delegation/create/{delegate_id} [post]
func (csc *CalendarSharingController) CreateDelegation(ctx http.Context) http.Response {
	userID := ctx.Value("user_id").(string)
	tenantID := ctx.Value("tenant_id").(string)
	delegateID := ctx.Request().Route("delegate_id")

	if delegateID == userID {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Cannot delegate to yourself",
			Timestamp: time.Now(),
		})
	}

	var request services.CreateDelegationRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Validate permission level
	validPermissions := []string{"view", "schedule", "manage", "full"}
	isValidPermission := false
	for _, perm := range validPermissions {
		if request.Permission == perm {
			isValidPermission = true
			break
		}
	}
	if !isValidPermission {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid permission level. Must be: view, schedule, manage, or full",
			Timestamp: time.Now(),
		})
	}

	delegation, err := csc.sharingService.CreateDelegation(userID, delegateID, tenantID, &request)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to create delegation: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      delegation,
		Message:   "Delegation created successfully",
		Timestamp: time.Now(),
	})
}

// AcceptDelegation accepts a delegation invitation
// @Summary Accept delegation invitation
// @Description Accept an invitation to manage someone's calendar as a delegate
// @Tags calendar-delegation
// @Accept json
// @Produce json
// @Param delegation_id path string true "Delegation ID"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /calendar-delegation/accept/{delegation_id} [post]
func (csc *CalendarSharingController) AcceptDelegation(ctx http.Context) http.Response {
	userID := ctx.Value("user_id").(string)
	delegationID := ctx.Request().Route("delegation_id")

	err := csc.sharingService.AcceptDelegation(delegationID, userID)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to accept delegation: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Delegation accepted successfully",
		Timestamp: time.Now(),
	})
}

// GetSharedCalendars returns all shared calendars for a user
// @Summary Get shared calendars
// @Description Get a comprehensive view of all calendars shared with or by the user
// @Tags calendar-sharing
// @Accept json
// @Produce json
// @Success 200 {object} responses.APIResponse{data=models.SharedCalendarView}
// @Failure 500 {object} responses.ErrorResponse
// @Router /calendar-sharing/shared-calendars [get]
func (csc *CalendarSharingController) GetSharedCalendars(ctx http.Context) http.Response {
	userID := ctx.Value("user_id").(string)

	view, err := csc.sharingService.GetSharedCalendarsView(userID)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to get shared calendars: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      view,
		Timestamp: time.Now(),
	})
}

// CheckPermission checks if user has specific permission for a calendar resource
// @Summary Check calendar permission
// @Description Check if the current user has a specific permission for a calendar resource
// @Tags calendar-permissions
// @Accept json
// @Produce json
// @Param resource_type query string true "Resource type (calendar, event, template)"
// @Param resource_id query string true "Resource ID"
// @Param permission query string true "Permission to check (view, create, edit, delete, share, delegate)"
// @Success 200 {object} responses.APIResponse{data=map[string]interface{}}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /calendar-permissions/check [get]
func (csc *CalendarSharingController) CheckPermission(ctx http.Context) http.Response {
	userID := ctx.Value("user_id").(string)
	resourceType := ctx.Request().Input("resource_type", "")
	resourceID := ctx.Request().Input("resource_id", "")
	permission := ctx.Request().Input("permission", "")

	if resourceType == "" || resourceID == "" || permission == "" {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "resource_type, resource_id, and permission are required",
			Timestamp: time.Now(),
		})
	}

	hasPermission, err := csc.sharingService.CheckCalendarPermission(userID, resourceType, resourceID, permission)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to check permission: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status: "success",
		Data: map[string]interface{}{
			"user_id":        userID,
			"resource_type":  resourceType,
			"resource_id":    resourceID,
			"permission":     permission,
			"has_permission": hasPermission,
		},
		Timestamp: time.Now(),
	})
}

// RevokeCalendarShare revokes a calendar share
// @Summary Revoke calendar share
// @Description Revoke access to a shared calendar
// @Tags calendar-sharing
// @Accept json
// @Produce json
// @Param share_id path string true "Calendar share ID"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /calendar-sharing/revoke/{share_id} [delete]
func (csc *CalendarSharingController) RevokeCalendarShare(ctx http.Context) http.Response {
	userID := ctx.Value("user_id").(string)
	shareID := ctx.Request().Route("share_id")

	err := csc.revokeCalendarShare(shareID, userID)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to revoke calendar share: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Calendar share revoked successfully",
		Timestamp: time.Now(),
	})
}

// RevokeDelegation revokes a calendar delegation
// @Summary Revoke delegation
// @Description Revoke a calendar delegation
// @Tags calendar-delegation
// @Accept json
// @Produce json
// @Param delegation_id path string true "Delegation ID"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /calendar-delegation/revoke/{delegation_id} [delete]
func (csc *CalendarSharingController) RevokeDelegation(ctx http.Context) http.Response {
	userID := ctx.Value("user_id").(string)
	delegationID := ctx.Request().Route("delegation_id")

	err := csc.revokeDelegation(delegationID, userID)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to revoke delegation: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Delegation revoked successfully",
		Timestamp: time.Now(),
	})
}

// GetDelegationActivities returns delegation activity logs
// @Summary Get delegation activities
// @Description Get activity logs for delegations where user is principal or delegate
// @Tags calendar-delegation
// @Accept json
// @Produce json
// @Param delegation_id query string false "Specific delegation ID to filter by"
// @Param limit query int false "Number of activities to return" default(50)
// @Param offset query int false "Number of activities to skip" default(0)
// @Success 200 {object} responses.APIResponse{data=[]models.DelegationActivity}
// @Failure 500 {object} responses.ErrorResponse
// @Router /calendar-delegation/activities [get]
func (csc *CalendarSharingController) GetDelegationActivities(ctx http.Context) http.Response {
	userID := ctx.Value("user_id").(string)
	delegationID := ctx.Request().Input("delegation_id", "")
	limit := ctx.Request().InputInt("limit", 50)
	offset := ctx.Request().InputInt("offset", 0)

	activities, err := csc.getDelegationActivities(userID, delegationID, limit, offset)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to get delegation activities: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      activities,
		Timestamp: time.Now(),
	})
}

// Helper methods

func (csc *CalendarSharingController) revokeCalendarShare(shareID, userID string) error {
	// Implementation would revoke the calendar share
	// This is a simplified version - in production, you'd want to:
	// 1. Verify user owns the share or has permission to revoke
	// 2. Update the share to inactive
	// 3. Revoke associated permissions
	// 4. Send notifications

	return nil // Placeholder
}

func (csc *CalendarSharingController) revokeDelegation(delegationID, userID string) error {
	// Implementation would revoke the delegation
	// This is a simplified version - in production, you'd want to:
	// 1. Verify user owns the delegation or has permission to revoke
	// 2. Update the delegation to inactive
	// 3. Revoke associated permissions
	// 4. Send notifications

	return nil // Placeholder
}

func (csc *CalendarSharingController) getDelegationActivities(userID, delegationID string, limit, offset int) (interface{}, error) {
	// Implementation would get delegation activities
	// This is a simplified version - in production, you'd query the database
	// for delegation activities where the user is either principal or delegate

	return []interface{}{}, nil // Placeholder
}
