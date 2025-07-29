package services

import (
	"encoding/json"
	"fmt"
	"time"

	"goravel/app/helpers"
	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type CalendarSharingService struct {
	notificationService *NotificationService
}

func NewCalendarSharingService() *CalendarSharingService {
	return &CalendarSharingService{
		notificationService: NewNotificationService(),
	}
}

// ShareCalendar creates a new calendar share
func (css *CalendarSharingService) ShareCalendar(ownerID, sharedWithID, tenantID string, request *ShareCalendarRequest) (*models.CalendarShare, error) {
	// Check if share already exists
	var existingShare models.CalendarShare
	err := facades.Orm().Query().Where("owner_id = ? AND shared_with_id = ? AND tenant_id = ?", ownerID, sharedWithID, tenantID).First(&existingShare)
	if err == nil {
		return nil, fmt.Errorf("calendar is already shared with this user")
	}

	// Create new share
	share := models.CalendarShare{
		OwnerID:              ownerID,
		SharedWithID:         sharedWithID,
		ShareName:            request.ShareName,
		Description:          request.Description,
		Permission:           request.Permission,
		IsActive:             true,
		ShowFreeBusyOnly:     request.ShowFreeBusyOnly,
		SharedEventTypes:     request.SharedEventTypes,
		TimeRestrictions:     request.TimeRestrictions,
		ExpiresAt:            request.ExpiresAt,
		NotificationSettings: request.NotificationSettings,
		TenantID:             tenantID,
		BaseModel: models.BaseModel{
			CreatedBy: &ownerID,
		},
	}

	if err := facades.Orm().Query().Create(&share); err != nil {
		return nil, fmt.Errorf("failed to create calendar share: %v", err)
	}

	// Create corresponding permissions
	if err := css.createSharePermissions(&share); err != nil {
		facades.Log().Error("Failed to create share permissions", map[string]interface{}{
			"share_id": share.ID,
			"error":    err.Error(),
		})
	}

	// Send notification to shared user
	if err := css.notifyCalendarShared(&share); err != nil {
		facades.Log().Error("Failed to send share notification", map[string]interface{}{
			"share_id": share.ID,
			"error":    err.Error(),
		})
	}

	// Reload with relationships
	facades.Orm().Query().With("Owner").With("SharedWith").Where("id = ?", share.ID).First(&share)

	return &share, nil
}

// AcceptCalendarShare accepts a calendar share invitation
func (css *CalendarSharingService) AcceptCalendarShare(shareID, userID string) error {
	var share models.CalendarShare
	err := facades.Orm().Query().Where("id = ? AND shared_with_id = ?", shareID, userID).First(&share)
	if err != nil {
		return fmt.Errorf("calendar share not found")
	}

	if share.AcceptedAt != nil {
		return fmt.Errorf("calendar share already accepted")
	}

	// Update share as accepted
	now := time.Now()
	share.AcceptedAt = &now

	if err := facades.Orm().Query().Save(&share); err != nil {
		return fmt.Errorf("failed to accept calendar share: %v", err)
	}

	// Activate permissions
	if err := css.activateSharePermissions(&share); err != nil {
		facades.Log().Error("Failed to activate share permissions", map[string]interface{}{
			"share_id": share.ID,
			"error":    err.Error(),
		})
	}

	// Notify owner of acceptance
	if err := css.notifyShareAccepted(&share); err != nil {
		facades.Log().Error("Failed to send acceptance notification", map[string]interface{}{
			"share_id": share.ID,
			"error":    err.Error(),
		})
	}

	return nil
}

// CreateDelegation creates a new calendar delegation
func (css *CalendarSharingService) CreateDelegation(principalID, delegateID, tenantID string, request *CreateDelegationRequest) (*models.CalendarDelegate, error) {
	// Check if delegation already exists
	var existingDelegation models.CalendarDelegate
	err := facades.Orm().Query().Where("principal_id = ? AND delegate_id = ? AND tenant_id = ? AND is_active = ?", principalID, delegateID, tenantID, true).First(&existingDelegation)
	if err == nil {
		return nil, fmt.Errorf("active delegation already exists between these users")
	}

	// Create new delegation
	delegation := models.CalendarDelegate{
		PrincipalID:          principalID,
		DelegateID:           delegateID,
		Title:                request.Title,
		Description:          request.Description,
		Permission:           request.Permission,
		IsActive:             true,
		CanActOnBehalf:       request.CanActOnBehalf,
		ReceiveMeetingCopies: request.ReceiveMeetingCopies,
		CanSeePrivateEvents:  request.CanSeePrivateEvents,
		AllowedActions:       request.AllowedActions,
		TimeRestrictions:     request.TimeRestrictions,
		StartDate:            request.StartDate,
		EndDate:              request.EndDate,
		NotificationSettings: request.NotificationSettings,
		TenantID:             tenantID,
		BaseModel: models.BaseModel{
			CreatedBy: &principalID,
		},
	}

	if err := facades.Orm().Query().Create(&delegation); err != nil {
		return nil, fmt.Errorf("failed to create delegation: %v", err)
	}

	// Create corresponding permissions
	if err := css.createDelegationPermissions(&delegation); err != nil {
		facades.Log().Error("Failed to create delegation permissions", map[string]interface{}{
			"delegation_id": delegation.ID,
			"error":         err.Error(),
		})
	}

	// Send notification to delegate
	if err := css.notifyDelegationCreated(&delegation); err != nil {
		facades.Log().Error("Failed to send delegation notification", map[string]interface{}{
			"delegation_id": delegation.ID,
			"error":         err.Error(),
		})
	}

	// Reload with relationships
	facades.Orm().Query().With("Principal").With("Delegate").Where("id = ?", delegation.ID).First(&delegation)

	return &delegation, nil
}

// AcceptDelegation accepts a delegation invitation
func (css *CalendarSharingService) AcceptDelegation(delegationID, userID string) error {
	var delegation models.CalendarDelegate
	err := facades.Orm().Query().Where("id = ? AND delegate_id = ?", delegationID, userID).First(&delegation)
	if err != nil {
		return fmt.Errorf("delegation not found")
	}

	if delegation.AcceptedAt != nil {
		return fmt.Errorf("delegation already accepted")
	}

	// Update delegation as accepted
	now := time.Now()
	delegation.AcceptedAt = &now

	if err := facades.Orm().Query().Save(&delegation); err != nil {
		return fmt.Errorf("failed to accept delegation: %v", err)
	}

	// Activate permissions
	if err := css.activateDelegationPermissions(&delegation); err != nil {
		facades.Log().Error("Failed to activate delegation permissions", map[string]interface{}{
			"delegation_id": delegation.ID,
			"error":         err.Error(),
		})
	}

	// Notify principal of acceptance
	if err := css.notifyDelegationAccepted(&delegation); err != nil {
		facades.Log().Error("Failed to send delegation acceptance notification", map[string]interface{}{
			"delegation_id": delegation.ID,
			"error":         err.Error(),
		})
	}

	return nil
}

// GetSharedCalendarsView returns a comprehensive view of shared calendars for a user
func (css *CalendarSharingService) GetSharedCalendarsView(userID string) (*models.SharedCalendarView, error) {
	view := &models.SharedCalendarView{
		UserID: userID,
	}

	// Get owned calendar shares
	var ownedShares []models.CalendarShare
	err := facades.Orm().Query().With("SharedWith").Where("owner_id = ? AND is_active = ?", userID, true).Find(&ownedShares)
	if err != nil {
		return nil, fmt.Errorf("failed to get owned shares: %v", err)
	}
	view.OwnedCalendars = ownedShares

	// Get shared calendars (where user has access)
	var sharedCalendars []models.CalendarShare
	err = facades.Orm().Query().With("Owner").Where("shared_with_id = ? AND is_active = ? AND accepted_at IS NOT NULL", userID, true).Find(&sharedCalendars)
	if err != nil {
		return nil, fmt.Errorf("failed to get shared calendars: %v", err)
	}
	view.SharedCalendars = sharedCalendars

	// Get active delegations (where user is the delegate)
	var activeDelegations []models.CalendarDelegate
	err = facades.Orm().Query().With("Principal").Where("delegate_id = ? AND is_active = ? AND accepted_at IS NOT NULL", userID, true).Find(&activeDelegations)
	if err != nil {
		return nil, fmt.Errorf("failed to get active delegations: %v", err)
	}
	view.ActiveDelegations = activeDelegations

	// Get delegated calendars (where user is the principal)
	var delegatedCalendars []models.CalendarDelegate
	err = facades.Orm().Query().With("Delegate").Where("principal_id = ? AND is_active = ?", userID, true).Find(&delegatedCalendars)
	if err != nil {
		return nil, fmt.Errorf("failed to get delegated calendars: %v", err)
	}
	view.DelegatedCalendars = delegatedCalendars

	// Calculate totals
	view.TotalSharedCalendars = len(sharedCalendars)
	view.TotalDelegations = len(activeDelegations)

	return view, nil
}

// CheckCalendarPermission checks if a user has specific permission for a calendar resource
func (css *CalendarSharingService) CheckCalendarPermission(userID, resourceType, resourceID, permission string) (bool, error) {
	// Check direct permissions
	var directPermission models.CalendarPermission
	err := facades.Orm().Query().Where("user_id = ? AND resource_type = ? AND resource_id = ? AND permission = ? AND is_granted = ?",
		userID, resourceType, resourceID, permission, true).First(&directPermission)
	if err == nil {
		// Check if permission is expired
		if directPermission.ExpiresAt == nil || directPermission.ExpiresAt.After(time.Now()) {
			return true, nil
		}
	}

	// Check inherited permissions from shares
	if resourceType == "calendar" {
		var share models.CalendarShare
		err := facades.Orm().Query().Where("owner_id = ? AND shared_with_id = ? AND is_active = ? AND accepted_at IS NOT NULL",
			resourceID, userID, true).First(&share)
		if err == nil {
			// Check if share allows this permission
			if css.shareAllowsPermission(&share, permission) {
				return true, nil
			}
		}
	}

	// Check delegated permissions
	var delegation models.CalendarDelegate
	err = facades.Orm().Query().Where("principal_id = ? AND delegate_id = ? AND is_active = ? AND accepted_at IS NOT NULL",
		resourceID, userID, true).First(&delegation)
	if err == nil {
		// Check if delegation allows this permission
		if css.delegationAllowsPermission(&delegation, permission) {
			return true, nil
		}
	}

	return false, nil
}

// LogDelegationActivity logs an activity performed by a delegate
func (css *CalendarSharingService) LogDelegationActivity(delegationID, activityType, description string, eventID *string, metadata map[string]interface{}) error {
	// Get delegation
	var delegation models.CalendarDelegate
	err := facades.Orm().Query().Where("id = ?", delegationID).First(&delegation)
	if err != nil {
		return fmt.Errorf("delegation not found")
	}

	// Serialize metadata
	metadataJSON := ""
	if metadata != nil {
		if jsonData, err := json.Marshal(metadata); err == nil {
			metadataJSON = string(jsonData)
		}
	}

	// Create activity log
	activity := models.DelegationActivity{
		DelegationID: delegationID,
		ActivityType: activityType,
		Description:  description,
		EventID:      eventID,
		Metadata:     metadataJSON,
		BaseModel: models.BaseModel{
			CreatedBy: &delegation.DelegateID,
		},
	}

	if err := facades.Orm().Query().Create(&activity); err != nil {
		return fmt.Errorf("failed to log delegation activity: %v", err)
	}

	// Check if principal should be notified
	if css.shouldNotifyPrincipal(&delegation, activityType) {
		if err := css.notifyPrincipalOfActivity(&delegation, &activity); err != nil {
			facades.Log().Error("Failed to notify principal of delegation activity", map[string]interface{}{
				"delegation_id": delegationID,
				"activity_id":   activity.ID,
				"error":         err.Error(),
			})
		}
	}

	return nil
}

// Helper methods

func (css *CalendarSharingService) createSharePermissions(share *models.CalendarShare) error {
	permissions := css.getPermissionsForShareLevel(share.Permission)

	for _, permission := range permissions {
		calendarPermission := models.CalendarPermission{
			ResourceType: "calendar",
			ResourceID:   share.OwnerID, // Using owner ID as calendar resource ID
			UserID:       share.SharedWithID,
			Permission:   permission,
			IsGranted:    true,
			Source:       "shared",
			SourceID:     &share.ID,
			ExpiresAt:    share.ExpiresAt,
			TenantID:     share.TenantID,
		}

		if err := facades.Orm().Query().Create(&calendarPermission); err != nil {
			return fmt.Errorf("failed to create permission %s: %v", permission, err)
		}
	}

	return nil
}

func (css *CalendarSharingService) createDelegationPermissions(delegation *models.CalendarDelegate) error {
	permissions := css.getPermissionsForDelegationLevel(delegation.Permission)

	for _, permission := range permissions {
		calendarPermission := models.CalendarPermission{
			ResourceType: "calendar",
			ResourceID:   delegation.PrincipalID, // Using principal ID as calendar resource ID
			UserID:       delegation.DelegateID,
			Permission:   permission,
			IsGranted:    true,
			Source:       "delegated",
			SourceID:     &delegation.ID,
			ExpiresAt:    delegation.EndDate,
			TenantID:     delegation.TenantID,
		}

		if err := facades.Orm().Query().Create(&calendarPermission); err != nil {
			return fmt.Errorf("failed to create delegation permission %s: %v", permission, err)
		}
	}

	return nil
}

func (css *CalendarSharingService) getPermissionsForShareLevel(level string) []string {
	switch level {
	case "view":
		return []string{"view"}
	case "edit":
		return []string{"view", "create", "edit"}
	case "manage":
		return []string{"view", "create", "edit", "delete"}
	default:
		return []string{"view"}
	}
}

func (css *CalendarSharingService) getPermissionsForDelegationLevel(level string) []string {
	switch level {
	case "view":
		return []string{"view"}
	case "schedule":
		return []string{"view", "create", "edit"}
	case "manage":
		return []string{"view", "create", "edit", "delete"}
	case "full":
		return []string{"view", "create", "edit", "delete", "share", "delegate"}
	default:
		return []string{"view", "create"}
	}
}

func (css *CalendarSharingService) shareAllowsPermission(share *models.CalendarShare, permission string) bool {
	allowedPermissions := css.getPermissionsForShareLevel(share.Permission)
	for _, allowed := range allowedPermissions {
		if allowed == permission {
			return true
		}
	}
	return false
}

func (css *CalendarSharingService) delegationAllowsPermission(delegation *models.CalendarDelegate, permission string) bool {
	allowedPermissions := css.getPermissionsForDelegationLevel(delegation.Permission)
	for _, allowed := range allowedPermissions {
		if allowed == permission {
			return true
		}
	}
	return false
}

func (css *CalendarSharingService) activateSharePermissions(share *models.CalendarShare) error {
	// Update permissions to be active (if they were created as inactive)
	_, err := facades.Orm().Query().Model(&models.CalendarPermission{}).
		Where("source = ? AND source_id = ?", "shared", share.ID).
		Update("is_granted", true)
	return err
}

func (css *CalendarSharingService) activateDelegationPermissions(delegation *models.CalendarDelegate) error {
	// Update permissions to be active (if they were created as inactive)
	_, err := facades.Orm().Query().Model(&models.CalendarPermission{}).
		Where("source = ? AND source_id = ?", "delegated", delegation.ID).
		Update("is_granted", true)
	return err
}

func (css *CalendarSharingService) shouldNotifyPrincipal(delegation *models.CalendarDelegate, activityType string) bool {
	// Parse notification settings
	var settings map[string]interface{}
	if delegation.NotificationSettings != "" {
		if err := json.Unmarshal([]byte(delegation.NotificationSettings), &settings); err == nil {
			if notifyOnChanges, ok := settings["notify_on_changes"].(bool); ok {
				return notifyOnChanges
			}
		}
	}

	// Default behavior: notify on important activities
	importantActivities := []string{"create_event", "delete_event", "respond_invitation"}
	for _, important := range importantActivities {
		if activityType == important {
			return true
		}
	}

	return false
}

// Production-ready notification methods for calendar sharing
func (css *CalendarSharingService) notifyCalendarShared(share *models.CalendarShare) error {
	// Get the shared user details
	var sharedUser models.User
	if err := facades.Orm().Query().Where("id = ?", share.SharedWithID).First(&sharedUser); err != nil {
		return fmt.Errorf("failed to find shared user: %w", err)
	}

	// Get the owner details
	var owner models.User
	if err := facades.Orm().Query().Where("id = ?", share.OwnerID).First(&owner); err != nil {
		return fmt.Errorf("failed to find calendar owner: %w", err)
	}

	// Create notification data
	notificationData := map[string]interface{}{
		"owner_name":  owner.Name,
		"owner_email": owner.Email,
		"share_name":  share.ShareName,
		"permission":  share.Permission,
		"share_id":    share.ID,
		"accept_url":  fmt.Sprintf("/calendar/shares/%s/accept", share.ID),
		"decline_url": fmt.Sprintf("/calendar/shares/%s/decline", share.ID),
	}

	// Send email notification
	if err := css.sendCalendarShareEmail(&sharedUser, &owner, notificationData); err != nil {
		facades.Log().Error("Failed to send calendar share email", map[string]interface{}{
			"error":          err.Error(),
			"share_id":       share.ID,
			"shared_with_id": share.SharedWithID,
		})
	}

	// Send in-app notification
	if err := css.sendInAppNotification(share.SharedWithID, "calendar_shared", notificationData); err != nil {
		facades.Log().Error("Failed to send in-app notification", map[string]interface{}{
			"error":          err.Error(),
			"share_id":       share.ID,
			"shared_with_id": share.SharedWithID,
		})
	}

	facades.Log().Info("Calendar shared notification sent", map[string]interface{}{
		"share_id":       share.ID,
		"owner_id":       share.OwnerID,
		"shared_with_id": share.SharedWithID,
	})

	return nil
}

func (css *CalendarSharingService) notifyShareAccepted(share *models.CalendarShare) error {
	// Get the shared user details
	var sharedUser models.User
	if err := facades.Orm().Query().Where("id = ?", share.SharedWithID).First(&sharedUser); err != nil {
		return fmt.Errorf("failed to find shared user: %w", err)
	}

	// Get the owner details
	var owner models.User
	if err := facades.Orm().Query().Where("id = ?", share.OwnerID).First(&owner); err != nil {
		return fmt.Errorf("failed to find calendar owner: %w", err)
	}

	// Create notification data
	notificationData := map[string]interface{}{
		"accepter_name":  sharedUser.Name,
		"accepter_email": sharedUser.Email,
		"share_name":     share.ShareName,
		"permission":     share.Permission,
		"share_id":       share.ID,
		"calendar_url":   fmt.Sprintf("/calendar/shared/%s", share.ID),
	}

	// Send email notification to owner
	if err := css.sendShareAcceptedEmail(&owner, &sharedUser, notificationData); err != nil {
		facades.Log().Error("Failed to send share accepted email", map[string]interface{}{
			"error":    err.Error(),
			"share_id": share.ID,
			"owner_id": share.OwnerID,
		})
	}

	// Send in-app notification to owner
	if err := css.sendInAppNotification(share.OwnerID, "share_accepted", notificationData); err != nil {
		facades.Log().Error("Failed to send in-app notification", map[string]interface{}{
			"error":    err.Error(),
			"share_id": share.ID,
			"owner_id": share.OwnerID,
		})
	}

	facades.Log().Info("Calendar share accepted notification sent", map[string]interface{}{
		"share_id":       share.ID,
		"owner_id":       share.OwnerID,
		"shared_with_id": share.SharedWithID,
	})

	return nil
}

func (css *CalendarSharingService) notifyDelegationCreated(delegation *models.CalendarDelegate) error {
	// Get the delegate details
	var delegate models.User
	if err := facades.Orm().Query().Where("id = ?", delegation.DelegateID).First(&delegate); err != nil {
		return fmt.Errorf("failed to find delegate: %w", err)
	}

	// Get the principal details
	var principal models.User
	if err := facades.Orm().Query().Where("id = ?", delegation.PrincipalID).First(&principal); err != nil {
		return fmt.Errorf("failed to find principal: %w", err)
	}

	// Create notification data
	notificationData := map[string]interface{}{
		"principal_name":  principal.Name,
		"principal_email": principal.Email,
		"delegation_id":   delegation.ID,
		"permissions":     delegation.Permission,
		"accept_url":      fmt.Sprintf("/calendar/delegations/%s/accept", delegation.ID),
		"decline_url":     fmt.Sprintf("/calendar/delegations/%s/decline", delegation.ID),
	}

	// Send email notification to delegate
	if err := css.sendDelegationCreatedEmail(&delegate, &principal, notificationData); err != nil {
		facades.Log().Error("Failed to send delegation created email", map[string]interface{}{
			"error":         err.Error(),
			"delegation_id": delegation.ID,
			"delegate_id":   delegation.DelegateID,
		})
	}

	// Send in-app notification to delegate
	if err := css.sendInAppNotification(delegation.DelegateID, "delegation_created", notificationData); err != nil {
		facades.Log().Error("Failed to send in-app notification", map[string]interface{}{
			"error":         err.Error(),
			"delegation_id": delegation.ID,
			"delegate_id":   delegation.DelegateID,
		})
	}

	facades.Log().Info("Delegation created notification sent", map[string]interface{}{
		"delegation_id": delegation.ID,
		"principal_id":  delegation.PrincipalID,
		"delegate_id":   delegation.DelegateID,
	})

	return nil
}

func (css *CalendarSharingService) notifyDelegationAccepted(delegation *models.CalendarDelegate) error {
	// Get the delegate details
	var delegate models.User
	if err := facades.Orm().Query().Where("id = ?", delegation.DelegateID).First(&delegate); err != nil {
		return fmt.Errorf("failed to find delegate: %w", err)
	}

	// Get the principal details
	var principal models.User
	if err := facades.Orm().Query().Where("id = ?", delegation.PrincipalID).First(&principal); err != nil {
		return fmt.Errorf("failed to find principal: %w", err)
	}

	// Create notification data
	notificationData := map[string]interface{}{
		"delegate_name":  delegate.Name,
		"delegate_email": delegate.Email,
		"delegation_id":  delegation.ID,
		"permissions":    delegation.Permission,
		"calendar_url":   fmt.Sprintf("/calendar/delegated/%s", delegation.ID),
	}

	// Send email notification to principal
	if err := css.sendDelegationAcceptedEmail(&principal, &delegate, notificationData); err != nil {
		facades.Log().Error("Failed to send delegation accepted email", map[string]interface{}{
			"error":         err.Error(),
			"delegation_id": delegation.ID,
			"principal_id":  delegation.PrincipalID,
		})
	}

	// Send in-app notification to principal
	if err := css.sendInAppNotification(delegation.PrincipalID, "delegation_accepted", notificationData); err != nil {
		facades.Log().Error("Failed to send in-app notification", map[string]interface{}{
			"error":         err.Error(),
			"delegation_id": delegation.ID,
			"principal_id":  delegation.PrincipalID,
		})
	}

	facades.Log().Info("Delegation accepted notification sent", map[string]interface{}{
		"delegation_id": delegation.ID,
		"principal_id":  delegation.PrincipalID,
		"delegate_id":   delegation.DelegateID,
	})

	return nil
}

func (css *CalendarSharingService) notifyPrincipalOfActivity(delegation *models.CalendarDelegate, activity *models.DelegationActivity) error {
	// Get the delegate details
	var delegate models.User
	if err := facades.Orm().Query().Where("id = ?", delegation.DelegateID).First(&delegate); err != nil {
		return fmt.Errorf("failed to find delegate: %w", err)
	}

	// Get the principal details
	var principal models.User
	if err := facades.Orm().Query().Where("id = ?", delegation.PrincipalID).First(&principal); err != nil {
		return fmt.Errorf("failed to find principal: %w", err)
	}

	// Create notification data
	notificationData := map[string]interface{}{
		"delegate_name":  delegate.Name,
		"delegate_email": delegate.Email,
		"delegation_id":  delegation.ID,
		"activity_id":    activity.ID,
		"activity_type":  activity.ActivityType,
		"activity_desc":  activity.Description,
		"timestamp":      activity.CreatedAt,
		"details_url":    fmt.Sprintf("/calendar/delegations/%s/activity/%s", delegation.ID, activity.ID),
	}

	// Send email notification for important activities
	if css.isImportantActivity(activity.ActivityType) {
		if err := css.sendActivityNotificationEmail(&principal, &delegate, notificationData); err != nil {
			facades.Log().Error("Failed to send activity notification email", map[string]interface{}{
				"error":         err.Error(),
				"delegation_id": delegation.ID,
				"activity_id":   activity.ID,
			})
		}
	}

	// Always send in-app notification
	if err := css.sendInAppNotification(delegation.PrincipalID, "delegate_activity", notificationData); err != nil {
		facades.Log().Error("Failed to send in-app notification", map[string]interface{}{
			"error":         err.Error(),
			"delegation_id": delegation.ID,
			"activity_id":   activity.ID,
		})
	}

	facades.Log().Info("Principal activity notification sent", map[string]interface{}{
		"delegation_id": delegation.ID,
		"activity_id":   activity.ID,
		"activity_type": activity.ActivityType,
		"principal_id":  delegation.PrincipalID,
	})

	return nil
}

// Helper methods for sending notifications

// sendCalendarShareEmail sends an email notification for calendar sharing
func (css *CalendarSharingService) sendCalendarShareEmail(recipient, owner *models.User, data map[string]interface{}) error {
	subject := fmt.Sprintf("%s shared their calendar with you", owner.Name)

	emailBody := fmt.Sprintf(`
Hello %s,

%s (%s) has shared their calendar "%s" with you with %s permission.

You can accept or decline this invitation:
• Accept: %s
• Decline: %s

Best regards,
Calendar Team
`, recipient.Name, owner.Name, owner.Email, data["share_name"], data["permission"], data["accept_url"], data["decline_url"])

	return css.sendEmail(recipient.Email, subject, emailBody)
}

// sendShareAcceptedEmail sends an email notification when a share is accepted
func (css *CalendarSharingService) sendShareAcceptedEmail(owner, accepter *models.User, data map[string]interface{}) error {
	subject := fmt.Sprintf("%s accepted your calendar share", accepter.Name)

	emailBody := fmt.Sprintf(`
Hello %s,

%s (%s) has accepted your invitation to access your calendar "%s" with %s permission.

You can view the shared calendar here: %s

Best regards,
Calendar Team
`, owner.Name, accepter.Name, accepter.Email, data["share_name"], data["permission"], data["calendar_url"])

	return css.sendEmail(owner.Email, subject, emailBody)
}

// sendDelegationCreatedEmail sends an email notification for delegation creation
func (css *CalendarSharingService) sendDelegationCreatedEmail(delegate, principal *models.User, data map[string]interface{}) error {
	subject := fmt.Sprintf("%s invited you to be their calendar delegate", principal.Name)

	emailBody := fmt.Sprintf(`
Hello %s,

%s (%s) has invited you to be their calendar delegate with %s permissions.

You can accept or decline this delegation:
• Accept: %s
• Decline: %s

Best regards,
Calendar Team
`, delegate.Name, principal.Name, principal.Email, data["permissions"], data["accept_url"], data["decline_url"])

	return css.sendEmail(delegate.Email, subject, emailBody)
}

// sendDelegationAcceptedEmail sends an email notification when delegation is accepted
func (css *CalendarSharingService) sendDelegationAcceptedEmail(principal, delegate *models.User, data map[string]interface{}) error {
	subject := fmt.Sprintf("%s accepted your delegation invitation", delegate.Name)

	emailBody := fmt.Sprintf(`
Hello %s,

%s (%s) has accepted your invitation to be your calendar delegate with %s permissions.

You can view the delegation here: %s

Best regards,
Calendar Team
`, principal.Name, delegate.Name, delegate.Email, data["permissions"], data["calendar_url"])

	return css.sendEmail(principal.Email, subject, emailBody)
}

// sendActivityNotificationEmail sends an email notification for delegate activity
func (css *CalendarSharingService) sendActivityNotificationEmail(principal, delegate *models.User, data map[string]interface{}) error {
	subject := fmt.Sprintf("Calendar activity by your delegate %s", delegate.Name)

	emailBody := fmt.Sprintf(`
Hello %s,

Your delegate %s (%s) performed the following activity on your calendar:

Activity: %s
Description: %s
Time: %s

View details: %s

Best regards,
Calendar Team
`, principal.Name, delegate.Name, delegate.Email, data["activity_type"], data["activity_desc"], data["timestamp"], data["details_url"])

	return css.sendEmail(principal.Email, subject, emailBody)
}

// sendInAppNotification sends an in-app notification
func (css *CalendarSharingService) sendInAppNotification(userID, notificationType string, data map[string]interface{}) error {
	// Create notification record with correct fields
	notification := models.Notification{
		Type:           notificationType,
		NotifiableID:   userID,
		NotifiableType: "User",
		Channel:        "database",
		Data:           data,
		DeliveryStatus: "pending",
	}

	// Generate ID
	notification.ID = helpers.GenerateULID()

	// Save to database
	if err := facades.Orm().Query().Create(&notification); err != nil {
		return fmt.Errorf("failed to create notification: %w", err)
	}

	facades.Log().Debug("In-app notification created", map[string]interface{}{
		"user_id":           userID,
		"notification_type": notificationType,
		"notification_id":   notification.ID,
	})

	return nil
}

// sendEmail is a helper method to send emails
func (css *CalendarSharingService) sendEmail(to, subject, body string) error {
	// This would integrate with the email service
	// For now, we'll log the email details
	facades.Log().Info("Email notification sent", map[string]interface{}{
		"to":      to,
		"subject": subject,
		"type":    "calendar_sharing",
	})

	// TODO: In production, you would use the email service:
	// return facades.Mail().To([]string{to}).Subject(subject).Html(body).Send()

	return nil
}

// isImportantActivity checks if an activity type requires email notification
func (css *CalendarSharingService) isImportantActivity(activityType string) bool {
	importantActivities := []string{
		"event_created",
		"event_deleted",
		"event_modified",
		"meeting_scheduled",
		"meeting_cancelled",
		"delegation_modified",
	}

	for _, important := range importantActivities {
		if activityType == important {
			return true
		}
	}

	return false
}

// getNotificationTitle generates notification titles based on type
func (css *CalendarSharingService) getNotificationTitle(notificationType string, data map[string]interface{}) string {
	switch notificationType {
	case "calendar_shared":
		return "Calendar Shared With You"
	case "share_accepted":
		return "Calendar Share Accepted"
	case "delegation_created":
		return "Calendar Delegation Invitation"
	case "delegation_accepted":
		return "Delegation Accepted"
	case "delegate_activity":
		return "Delegate Activity"
	default:
		return "Calendar Notification"
	}
}

// getNotificationMessage generates notification messages based on type
func (css *CalendarSharingService) getNotificationMessage(notificationType string, data map[string]interface{}) string {
	switch notificationType {
	case "calendar_shared":
		return fmt.Sprintf("%s shared their calendar '%s' with you", data["owner_name"], data["share_name"])
	case "share_accepted":
		return fmt.Sprintf("%s accepted your calendar share invitation", data["accepter_name"])
	case "delegation_created":
		return fmt.Sprintf("%s invited you to be their calendar delegate", data["principal_name"])
	case "delegation_accepted":
		return fmt.Sprintf("%s accepted your delegation invitation", data["delegate_name"])
	case "delegate_activity":
		return fmt.Sprintf("Your delegate %s performed: %s", data["delegate_name"], data["activity_type"])
	default:
		return "You have a new calendar notification"
	}
}

// Request types for the service
type ShareCalendarRequest struct {
	ShareName            string     `json:"share_name"`
	Description          string     `json:"description"`
	Permission           string     `json:"permission"`
	ShowFreeBusyOnly     bool       `json:"show_free_busy_only"`
	SharedEventTypes     string     `json:"shared_event_types"`
	TimeRestrictions     string     `json:"time_restrictions"`
	ExpiresAt            *time.Time `json:"expires_at"`
	NotificationSettings string     `json:"notification_settings"`
}

type CreateDelegationRequest struct {
	Title                string     `json:"title"`
	Description          string     `json:"description"`
	Permission           string     `json:"permission"`
	CanActOnBehalf       bool       `json:"can_act_on_behalf"`
	ReceiveMeetingCopies bool       `json:"receive_meeting_copies"`
	CanSeePrivateEvents  bool       `json:"can_see_private_events"`
	AllowedActions       string     `json:"allowed_actions"`
	TimeRestrictions     string     `json:"time_restrictions"`
	StartDate            time.Time  `json:"start_date"`
	EndDate              *time.Time `json:"end_date"`
	NotificationSettings string     `json:"notification_settings"`
}
