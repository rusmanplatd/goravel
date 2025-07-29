package v1

import (
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/http/responses"
	"goravel/app/models"
	"goravel/app/services"
)

type AclController struct {
	calendarSharingService *services.CalendarSharingService
	auditService           *services.AuditService
}

func NewAclController() *AclController {
	return &AclController{
		calendarSharingService: services.NewCalendarSharingService(),
		auditService:           services.GetAuditService(),
	}
}

// List returns the rules in the access control list for the calendar
// @Summary Get ACL rules
// @Description Returns the rules in the access control list for the calendar
// @Tags acl
// @Accept json
// @Produce json
// @Param calendarId path string true "Calendar ID"
// @Param maxResults query int false "Maximum number of entries returned" default(100)
// @Param showDeleted query bool false "Whether to include deleted ACL entries" default(false)
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Router /calendars/{calendarId}/acl [get]
func (ac *AclController) List(ctx http.Context) http.Response {
	calendarID := ctx.Request().Route("calendarId")
	userID := ctx.Value("user_id").(string)
	maxResults := ctx.Request().QueryInt("maxResults", 100)
	showDeleted := ctx.Request().QueryBool("showDeleted", false)

	// Validate calendar ownership
	var calendar models.UserCalendar
	err := facades.Orm().Query().
		Where("id = ? AND user_id = ?", calendarID, userID).
		First(&calendar)

	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Calendar not found",
			Timestamp: time.Now(),
		})
	}

	// Get calendar shares (ACL entries)
	query := facades.Orm().Query().
		Where("owner_id = ?", userID).
		Limit(maxResults)

	if !showDeleted {
		query = query.Where("deleted_at IS NULL")
	}

	var shares []models.CalendarShare
	err = query.Find(&shares)

	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve ACL entries",
			Timestamp: time.Now(),
		})
	}

	// Transform to Google Calendar API format
	aclItems := make([]map[string]interface{}, len(shares)+1)

	// Add owner entry
	aclItems[0] = map[string]interface{}{
		"kind": "calendar#aclRule",
		"etag": generateETag(&calendar.UpdatedAt),
		"id":   "user:" + userID,
		"scope": map[string]interface{}{
			"type":  "user",
			"value": userID,
		},
		"role": "owner",
	}

	// Add shared entries
	for i, share := range shares {
		aclItems[i+1] = map[string]interface{}{
			"kind": "calendar#aclRule",
			"etag": generateETag(&share.UpdatedAt),
			"id":   "user:" + share.SharedWithID,
			"scope": map[string]interface{}{
				"type":  "user",
				"value": share.SharedWithID,
			},
			"role": mapPermissionToRole(share.Permission),
		}
	}

	response := map[string]interface{}{
		"kind":          "calendar#acl",
		"etag":          generateListETag(),
		"nextPageToken": "",
		"items":         aclItems,
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      response,
		Timestamp: time.Now(),
	})
}

// Get returns an access control rule
// @Summary Get ACL rule
// @Description Returns an access control rule by ID
// @Tags acl
// @Accept json
// @Produce json
// @Param calendarId path string true "Calendar ID"
// @Param ruleId path string true "ACL rule ID"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Router /calendars/{calendarId}/acl/{ruleId} [get]
func (ac *AclController) Get(ctx http.Context) http.Response {
	calendarID := ctx.Request().Route("calendarId")
	ruleID := ctx.Request().Route("ruleId")
	userID := ctx.Value("user_id").(string)

	// Validate calendar ownership
	var calendar models.UserCalendar
	err := facades.Orm().Query().
		Where("id = ? AND user_id = ?", calendarID, userID).
		First(&calendar)

	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Calendar not found",
			Timestamp: time.Now(),
		})
	}

	// Check if requesting owner rule
	if ruleID == "user:"+userID {
		aclRule := map[string]interface{}{
			"kind": "calendar#aclRule",
			"etag": generateETag(&calendar.UpdatedAt),
			"id":   "user:" + userID,
			"scope": map[string]interface{}{
				"type":  "user",
				"value": userID,
			},
			"role": "owner",
		}

		return ctx.Response().Success().Json(responses.APIResponse{
			Status:    "success",
			Data:      aclRule,
			Timestamp: time.Now(),
		})
	}

	// Extract user ID from rule ID (format: "user:userId")
	if len(ruleID) < 5 || ruleID[:5] != "user:" {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid rule ID format",
			Timestamp: time.Now(),
		})
	}

	targetUserID := ruleID[5:]

	// Find the calendar share
	var share models.CalendarShare
	err = facades.Orm().Query().
		Where("owner_id = ? AND shared_with_id = ?", userID, targetUserID).
		First(&share)

	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "ACL rule not found",
			Timestamp: time.Now(),
		})
	}

	aclRule := map[string]interface{}{
		"kind": "calendar#aclRule",
		"etag": generateETag(&share.UpdatedAt),
		"id":   "user:" + share.SharedWithID,
		"scope": map[string]interface{}{
			"type":  "user",
			"value": share.SharedWithID,
		},
		"role": mapPermissionToRole(share.Permission),
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      aclRule,
		Timestamp: time.Now(),
	})
}

// Insert creates an access control rule
// @Summary Create ACL rule
// @Description Creates an access control rule for the calendar
// @Tags acl
// @Accept json
// @Produce json
// @Param calendarId path string true "Calendar ID"
// @Param rule body object{scope=object{type=string,value=string},role=string} true "ACL rule"
// @Success 201 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Router /calendars/{calendarId}/acl [post]
func (ac *AclController) Insert(ctx http.Context) http.Response {
	calendarID := ctx.Request().Route("calendarId")
	userID := ctx.Value("user_id").(string)

	var request struct {
		Scope struct {
			Type  string `json:"type" binding:"required"`
			Value string `json:"value" binding:"required"`
		} `json:"scope" binding:"required"`
		Role string `json:"role" binding:"required"`
	}

	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Timestamp: time.Now(),
		})
	}

	// Validate calendar ownership
	var calendar models.UserCalendar
	err := facades.Orm().Query().
		Where("id = ? AND user_id = ?", calendarID, userID).
		First(&calendar)

	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Calendar not found",
			Timestamp: time.Now(),
		})
	}

	// Validate scope type (only user supported for now)
	if request.Scope.Type != "user" {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Only user scope type is supported",
			Timestamp: time.Now(),
		})
	}

	// Create calendar share
	share := models.CalendarShare{
		OwnerID:      userID,
		SharedWithID: request.Scope.Value,
		ShareName:    calendar.Name + " (Shared)",
		Permission:   mapRoleToPermission(request.Role),
		IsActive:     true,
	}

	if err := facades.Orm().Query().Create(&share); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to create ACL rule",
			Timestamp: time.Now(),
		})
	}

	aclRule := map[string]interface{}{
		"kind": "calendar#aclRule",
		"etag": generateETag(&share.UpdatedAt),
		"id":   "user:" + share.SharedWithID,
		"scope": map[string]interface{}{
			"type":  "user",
			"value": share.SharedWithID,
		},
		"role": request.Role,
	}

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:    "success",
		Message:   "ACL rule created successfully",
		Data:      aclRule,
		Timestamp: time.Now(),
	})
}

// Update updates an access control rule
// @Summary Update ACL rule
// @Description Updates an access control rule
// @Tags acl
// @Accept json
// @Produce json
// @Param calendarId path string true "Calendar ID"
// @Param ruleId path string true "ACL rule ID"
// @Param rule body object{role=string} true "ACL rule"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Router /calendars/{calendarId}/acl/{ruleId} [put]
func (ac *AclController) Update(ctx http.Context) http.Response {
	calendarID := ctx.Request().Route("calendarId")
	ruleID := ctx.Request().Route("ruleId")
	userID := ctx.Value("user_id").(string)

	var request struct {
		Role string `json:"role" binding:"required"`
	}

	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Timestamp: time.Now(),
		})
	}

	// Validate calendar ownership
	var calendar models.UserCalendar
	err := facades.Orm().Query().
		Where("id = ? AND user_id = ?", calendarID, userID).
		First(&calendar)

	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Calendar not found",
			Timestamp: time.Now(),
		})
	}

	// Cannot update owner rule
	if ruleID == "user:"+userID {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Cannot update owner permissions",
			Timestamp: time.Now(),
		})
	}

	// Extract user ID from rule ID
	if len(ruleID) < 5 || ruleID[:5] != "user:" {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid rule ID format",
			Timestamp: time.Now(),
		})
	}

	targetUserID := ruleID[5:]

	// Find and update the calendar share
	var share models.CalendarShare
	err = facades.Orm().Query().
		Where("owner_id = ? AND shared_with_id = ?", userID, targetUserID).
		First(&share)

	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "ACL rule not found",
			Timestamp: time.Now(),
		})
	}

	share.Permission = mapRoleToPermission(request.Role)

	if err := facades.Orm().Query().Save(&share); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to update ACL rule",
			Timestamp: time.Now(),
		})
	}

	aclRule := map[string]interface{}{
		"kind": "calendar#aclRule",
		"etag": generateETag(&share.UpdatedAt),
		"id":   "user:" + share.SharedWithID,
		"scope": map[string]interface{}{
			"type":  "user",
			"value": share.SharedWithID,
		},
		"role": request.Role,
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "ACL rule updated successfully",
		Data:      aclRule,
		Timestamp: time.Now(),
	})
}

// Patch updates an access control rule using patch semantics
// @Summary Patch ACL rule
// @Description Updates an access control rule using patch semantics
// @Tags acl
// @Accept json
// @Produce json
// @Param calendarId path string true "Calendar ID"
// @Param ruleId path string true "ACL rule ID"
// @Param rule body object{role=string} true "ACL rule"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Router /calendars/{calendarId}/acl/{ruleId} [patch]
func (ac *AclController) Patch(ctx http.Context) http.Response {
	// Patch is identical to Update in this implementation
	return ac.Update(ctx)
}

// Delete deletes an access control rule
// @Summary Delete ACL rule
// @Description Deletes an access control rule
// @Tags acl
// @Accept json
// @Produce json
// @Param calendarId path string true "Calendar ID"
// @Param ruleId path string true "ACL rule ID"
// @Success 204 "No Content"
// @Failure 404 {object} responses.ErrorResponse
// @Router /calendars/{calendarId}/acl/{ruleId} [delete]
func (ac *AclController) Delete(ctx http.Context) http.Response {
	calendarID := ctx.Request().Route("calendarId")
	ruleID := ctx.Request().Route("ruleId")
	userID := ctx.Value("user_id").(string)

	// Validate calendar ownership
	var calendar models.UserCalendar
	err := facades.Orm().Query().
		Where("id = ? AND user_id = ?", calendarID, userID).
		First(&calendar)

	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Calendar not found",
			Timestamp: time.Now(),
		})
	}

	// Cannot delete owner rule
	if ruleID == "user:"+userID {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Cannot delete owner permissions",
			Timestamp: time.Now(),
		})
	}

	// Extract user ID from rule ID
	if len(ruleID) < 5 || ruleID[:5] != "user:" {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid rule ID format",
			Timestamp: time.Now(),
		})
	}

	targetUserID := ruleID[5:]

	// Find and delete the calendar share
	var share models.CalendarShare
	err = facades.Orm().Query().
		Where("owner_id = ? AND shared_with_id = ?", userID, targetUserID).
		First(&share)

	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "ACL rule not found",
			Timestamp: time.Now(),
		})
	}

	_, err = facades.Orm().Query().Delete(&share)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to delete ACL rule",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(204).Json(nil)
}

// Helper functions

func mapPermissionToRole(permission string) string {
	switch permission {
	case "view":
		return "reader"
	case "edit":
		return "writer"
	case "manage":
		return "owner"
	default:
		return "reader"
	}
}

func mapRoleToPermission(role string) string {
	switch role {
	case "reader":
		return "view"
	case "writer":
		return "edit"
	case "owner":
		return "manage"
	default:
		return "view"
	}
}
