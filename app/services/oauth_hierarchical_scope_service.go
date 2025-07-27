package services

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/goravel/framework/facades"

	"goravel/app/models"
)

// OAuthHierarchicalScopeService handles hierarchical OAuth2 scopes
type OAuthHierarchicalScopeService struct {
	// No dependencies to avoid circular imports
}

// ScopeDefinition represents a hierarchical scope with permissions
type ScopeDefinition struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Category    string                 `json:"category"`
	Level       int                    `json:"level"`       // Hierarchy level (0 = root, higher = more specific)
	Parent      string                 `json:"parent"`      // Parent scope name
	Children    []string               `json:"children"`    // Child scope names
	Permissions []string               `json:"permissions"` // Specific permissions granted
	Resources   []string               `json:"resources"`   // Resources this scope can access
	Actions     []string               `json:"actions"`     // Actions allowed on resources
	Conditions  map[string]interface{} `json:"conditions"`  // Conditional access rules
	Metadata    map[string]interface{} `json:"metadata"`    // Additional metadata
	Deprecated  bool                   `json:"deprecated"`  // Whether scope is deprecated
	ExpiresAt   *time.Time             `json:"expires_at"`  // Optional expiration for scope
}

// ScopeHierarchy represents the complete scope hierarchy
type ScopeHierarchy struct {
	Scopes    map[string]*ScopeDefinition `json:"scopes"`
	Roots     []string                    `json:"roots"`   // Root-level scopes
	Version   string                      `json:"version"` // Hierarchy version
	UpdatedAt time.Time                   `json:"updated_at"`
}

// ScopeValidationResult contains scope validation results
type ScopeValidationResult struct {
	Valid                bool                   `json:"valid"`
	GrantedScopes        []string               `json:"granted_scopes"`
	DeniedScopes         []string               `json:"denied_scopes"`
	ImpliedScopes        []string               `json:"implied_scopes"`
	ConflictingScopes    []string               `json:"conflicting_scopes"`
	EffectivePermissions []string               `json:"effective_permissions"`
	ResourceAccess       map[string][]string    `json:"resource_access"`
	Warnings             []string               `json:"warnings"`
	Recommendations      []string               `json:"recommendations"`
	Details              map[string]interface{} `json:"details"`
}

// TokenScopeInfo contains enriched scope information for tokens
type TokenScopeInfo struct {
	Scopes           []string               `json:"scopes"`
	Permissions      []string               `json:"permissions"`
	Resources        map[string][]string    `json:"resources"`
	Hierarchy        map[string]interface{} `json:"hierarchy"`
	ExpirationPolicy map[string]time.Time   `json:"expiration_policy"`
	Conditions       map[string]interface{} `json:"conditions"`
	Metadata         map[string]interface{} `json:"metadata"`
}

// NewOAuthHierarchicalScopeService creates a new hierarchical scope service
func NewOAuthHierarchicalScopeService() *OAuthHierarchicalScopeService {
	return &OAuthHierarchicalScopeService{}
}

// GetScopeHierarchy returns the complete scope hierarchy (Google-like)
func (s *OAuthHierarchicalScopeService) GetScopeHierarchy() (*ScopeHierarchy, error) {
	hierarchy := &ScopeHierarchy{
		Scopes:    make(map[string]*ScopeDefinition),
		Version:   "1.0",
		UpdatedAt: time.Now(),
	}

	// Define Google-like hierarchical scopes
	scopes := s.getDefaultScopeDefinitions()

	for _, scope := range scopes {
		hierarchy.Scopes[scope.Name] = scope
		if scope.Parent == "" {
			hierarchy.Roots = append(hierarchy.Roots, scope.Name)
		}
	}

	// Build parent-child relationships
	for _, scope := range hierarchy.Scopes {
		if scope.Parent != "" {
			if parent, exists := hierarchy.Scopes[scope.Parent]; exists {
				parent.Children = append(parent.Children, scope.Name)
			}
		}
	}

	return hierarchy, nil
}

// getDefaultScopeDefinitions returns Google-like scope definitions
func (s *OAuthHierarchicalScopeService) getDefaultScopeDefinitions() []*ScopeDefinition {
	return []*ScopeDefinition{
		// OpenID Connect scopes
		{
			Name:        "openid",
			Description: "OpenID Connect authentication",
			Category:    "identity",
			Level:       0,
			Permissions: []string{"authenticate", "get_id_token"},
			Resources:   []string{"identity"},
			Actions:     []string{"read"},
		},
		{
			Name:        "profile",
			Description: "Access to basic profile information",
			Category:    "identity",
			Level:       1,
			Parent:      "openid",
			Permissions: []string{"read_profile", "get_name", "get_picture"},
			Resources:   []string{"user.profile"},
			Actions:     []string{"read"},
		},
		{
			Name:        "email",
			Description: "Access to email address",
			Category:    "identity",
			Level:       1,
			Parent:      "openid",
			Permissions: []string{"read_email", "verify_email"},
			Resources:   []string{"user.email"},
			Actions:     []string{"read"},
		},

		// User data scopes (Google-like hierarchy)
		{
			Name:        "user",
			Description: "Access to user data",
			Category:    "user_data",
			Level:       0,
			Permissions: []string{"access_user_data"},
			Resources:   []string{"user"},
			Actions:     []string{"read"},
		},
		{
			Name:        "user.read",
			Description: "Read user information",
			Category:    "user_data",
			Level:       1,
			Parent:      "user",
			Permissions: []string{"read_user_basic", "read_user_profile"},
			Resources:   []string{"user.basic", "user.profile"},
			Actions:     []string{"read"},
		},
		{
			Name:        "user.write",
			Description: "Modify user information",
			Category:    "user_data",
			Level:       1,
			Parent:      "user",
			Permissions: []string{"write_user_profile", "update_user_settings"},
			Resources:   []string{"user.profile", "user.settings"},
			Actions:     []string{"write", "update"},
		},
		{
			Name:        "user.admin",
			Description: "Administrative access to user data",
			Category:    "user_data",
			Level:       2,
			Parent:      "user.write",
			Permissions: []string{"admin_user_data", "delete_user", "impersonate_user"},
			Resources:   []string{"user.*"},
			Actions:     []string{"read", "write", "delete", "admin"},
		},

		// Organization scopes (Google Workspace-like)
		{
			Name:        "organization",
			Description: "Access to organization data",
			Category:    "organization",
			Level:       0,
			Permissions: []string{"access_organization"},
			Resources:   []string{"organization"},
			Actions:     []string{"read"},
		},
		{
			Name:        "organization.read",
			Description: "Read organization information",
			Category:    "organization",
			Level:       1,
			Parent:      "organization",
			Permissions: []string{"read_org_info", "list_org_members"},
			Resources:   []string{"organization.info", "organization.members"},
			Actions:     []string{"read", "list"},
		},
		{
			Name:        "organization.manage",
			Description: "Manage organization settings",
			Category:    "organization",
			Level:       2,
			Parent:      "organization.read",
			Permissions: []string{"manage_org_settings", "invite_members", "remove_members"},
			Resources:   []string{"organization.settings", "organization.members"},
			Actions:     []string{"read", "write", "invite", "remove"},
		},

		// Calendar scopes (Google Calendar-like)
		{
			Name:        "calendar",
			Description: "Access to calendar data",
			Category:    "productivity",
			Level:       0,
			Permissions: []string{"access_calendar"},
			Resources:   []string{"calendar"},
			Actions:     []string{"read"},
		},
		{
			Name:        "calendar.readonly",
			Description: "Read-only access to calendar events",
			Category:    "productivity",
			Level:       1,
			Parent:      "calendar",
			Permissions: []string{"read_calendar_events", "list_calendars"},
			Resources:   []string{"calendar.events", "calendar.list"},
			Actions:     []string{"read", "list"},
		},
		{
			Name:        "calendar.events",
			Description: "Manage calendar events",
			Category:    "productivity",
			Level:       2,
			Parent:      "calendar.readonly",
			Permissions: []string{"create_events", "update_events", "delete_events"},
			Resources:   []string{"calendar.events"},
			Actions:     []string{"read", "write", "create", "update", "delete"},
		},

		// File storage scopes (Google Drive-like)
		{
			Name:        "drive",
			Description: "Access to file storage",
			Category:    "storage",
			Level:       0,
			Permissions: []string{"access_drive"},
			Resources:   []string{"drive"},
			Actions:     []string{"read"},
		},
		{
			Name:        "drive.readonly",
			Description: "Read-only access to files",
			Category:    "storage",
			Level:       1,
			Parent:      "drive",
			Permissions: []string{"read_files", "list_files", "download_files"},
			Resources:   []string{"drive.files"},
			Actions:     []string{"read", "list", "download"},
		},
		{
			Name:        "drive.file",
			Description: "Manage individual files",
			Category:    "storage",
			Level:       2,
			Parent:      "drive.readonly",
			Permissions: []string{"upload_files", "update_files", "delete_files"},
			Resources:   []string{"drive.files"},
			Actions:     []string{"read", "write", "create", "update", "delete"},
		},
		{
			Name:        "drive.metadata",
			Description: "Access file metadata only",
			Category:    "storage",
			Level:       1,
			Parent:      "drive",
			Permissions: []string{"read_file_metadata", "list_file_metadata"},
			Resources:   []string{"drive.metadata"},
			Actions:     []string{"read", "list"},
		},

		// Admin scopes (Google Admin-like)
		{
			Name:        "admin",
			Description: "Administrative access",
			Category:    "administration",
			Level:       0,
			Permissions: []string{"admin_access"},
			Resources:   []string{"admin"},
			Actions:     []string{"admin"},
			Conditions: map[string]interface{}{
				"require_mfa":  true,
				"ip_whitelist": true,
			},
		},
		{
			Name:        "admin.directory",
			Description: "Directory administration",
			Category:    "administration",
			Level:       1,
			Parent:      "admin",
			Permissions: []string{"manage_users", "manage_groups", "manage_org_units"},
			Resources:   []string{"admin.users", "admin.groups", "admin.org_units"},
			Actions:     []string{"read", "write", "create", "update", "delete"},
		},
		{
			Name:        "admin.security",
			Description: "Security administration",
			Category:    "administration",
			Level:       1,
			Parent:      "admin",
			Permissions: []string{"manage_security_settings", "view_audit_logs", "manage_oauth_clients"},
			Resources:   []string{"admin.security", "admin.audit", "admin.oauth"},
			Actions:     []string{"read", "write", "audit", "manage"},
		},
	}
}

// ValidateScopes validates requested scopes against hierarchy (Google-like)
func (s *OAuthHierarchicalScopeService) ValidateScopes(requestedScopes []string, clientID, userID string) (*ScopeValidationResult, error) {
	result := &ScopeValidationResult{
		Valid:                false,
		GrantedScopes:        []string{},
		DeniedScopes:         []string{},
		ImpliedScopes:        []string{},
		ConflictingScopes:    []string{},
		EffectivePermissions: []string{},
		ResourceAccess:       make(map[string][]string),
		Warnings:             []string{},
		Recommendations:      []string{},
		Details:              make(map[string]interface{}),
	}

	hierarchy, err := s.GetScopeHierarchy()
	if err != nil {
		return result, fmt.Errorf("failed to get scope hierarchy: %w", err)
	}

	// Get client permissions
	clientScopes, err := s.getClientAllowedScopes(clientID)
	if err != nil {
		return result, fmt.Errorf("failed to get client scopes: %w", err)
	}

	// Get user permissions
	userScopes, err := s.getUserAllowedScopes(userID)
	if err != nil {
		return result, fmt.Errorf("failed to get user scopes: %w", err)
	}

	permissionsMap := make(map[string]bool)
	resourceAccessMap := make(map[string]map[string]bool)

	for _, scopeName := range requestedScopes {
		scope, exists := hierarchy.Scopes[scopeName]
		if !exists {
			result.DeniedScopes = append(result.DeniedScopes, scopeName)
			result.Warnings = append(result.Warnings, fmt.Sprintf("Unknown scope: %s", scopeName))
			continue
		}

		// Check if client is allowed this scope
		if !s.contains(clientScopes, scopeName) {
			result.DeniedScopes = append(result.DeniedScopes, scopeName)
			result.Warnings = append(result.Warnings, fmt.Sprintf("Client not authorized for scope: %s", scopeName))
			continue
		}

		// Check if user is allowed this scope
		if !s.contains(userScopes, scopeName) {
			result.DeniedScopes = append(result.DeniedScopes, scopeName)
			result.Warnings = append(result.Warnings, fmt.Sprintf("User not authorized for scope: %s", scopeName))
			continue
		}

		// Check scope conditions
		if !s.checkScopeConditions(scope, clientID, userID) {
			result.DeniedScopes = append(result.DeniedScopes, scopeName)
			result.Warnings = append(result.Warnings, fmt.Sprintf("Scope conditions not met: %s", scopeName))
			continue
		}

		// Check if scope is deprecated
		if scope.Deprecated {
			result.Warnings = append(result.Warnings, fmt.Sprintf("Scope is deprecated: %s", scopeName))
			result.Recommendations = append(result.Recommendations, fmt.Sprintf("Consider migrating from deprecated scope: %s", scopeName))
		}

		// Check scope expiration
		if scope.ExpiresAt != nil && time.Now().After(*scope.ExpiresAt) {
			result.DeniedScopes = append(result.DeniedScopes, scopeName)
			result.Warnings = append(result.Warnings, fmt.Sprintf("Scope has expired: %s", scopeName))
			continue
		}

		// Grant the scope
		result.GrantedScopes = append(result.GrantedScopes, scopeName)

		// Add permissions
		for _, permission := range scope.Permissions {
			permissionsMap[permission] = true
		}

		// Add resource access
		for _, resource := range scope.Resources {
			if resourceAccessMap[resource] == nil {
				resourceAccessMap[resource] = make(map[string]bool)
			}
			for _, action := range scope.Actions {
				resourceAccessMap[resource][action] = true
			}
		}

		// Add implied scopes (parent scopes)
		impliedScopes := s.getImpliedScopes(scope, hierarchy)
		for _, impliedScope := range impliedScopes {
			if !s.contains(result.ImpliedScopes, impliedScope) {
				result.ImpliedScopes = append(result.ImpliedScopes, impliedScope)
			}
		}
	}

	// Convert maps to slices
	for permission := range permissionsMap {
		result.EffectivePermissions = append(result.EffectivePermissions, permission)
	}

	for resource, actions := range resourceAccessMap {
		actionList := make([]string, 0, len(actions))
		for action := range actions {
			actionList = append(actionList, action)
		}
		sort.Strings(actionList)
		result.ResourceAccess[resource] = actionList
	}

	// Check for conflicting scopes
	result.ConflictingScopes = s.findConflictingScopes(result.GrantedScopes, hierarchy)

	// Sort results
	sort.Strings(result.GrantedScopes)
	sort.Strings(result.DeniedScopes)
	sort.Strings(result.ImpliedScopes)
	sort.Strings(result.EffectivePermissions)

	result.Valid = len(result.GrantedScopes) > 0

	// Add detailed information
	result.Details["total_requested"] = len(requestedScopes)
	result.Details["total_granted"] = len(result.GrantedScopes)
	result.Details["total_denied"] = len(result.DeniedScopes)
	result.Details["total_permissions"] = len(result.EffectivePermissions)
	result.Details["total_resources"] = len(result.ResourceAccess)

	return result, nil
}

// CreateTokenScopeInfo creates enriched scope information for tokens
func (s *OAuthHierarchicalScopeService) CreateTokenScopeInfo(scopes []string) (*TokenScopeInfo, error) {
	hierarchy, err := s.GetScopeHierarchy()
	if err != nil {
		return nil, fmt.Errorf("failed to get scope hierarchy: %w", err)
	}

	info := &TokenScopeInfo{
		Scopes:           scopes,
		Permissions:      []string{},
		Resources:        make(map[string][]string),
		Hierarchy:        make(map[string]interface{}),
		ExpirationPolicy: make(map[string]time.Time),
		Conditions:       make(map[string]interface{}),
		Metadata:         make(map[string]interface{}),
	}

	permissionsMap := make(map[string]bool)
	resourcesMap := make(map[string]map[string]bool)

	for _, scopeName := range scopes {
		scope, exists := hierarchy.Scopes[scopeName]
		if !exists {
			continue
		}

		// Add permissions
		for _, permission := range scope.Permissions {
			permissionsMap[permission] = true
		}

		// Add resources
		for _, resource := range scope.Resources {
			if resourcesMap[resource] == nil {
				resourcesMap[resource] = make(map[string]bool)
			}
			for _, action := range scope.Actions {
				resourcesMap[resource][action] = true
			}
		}

		// Add hierarchy information
		info.Hierarchy[scopeName] = map[string]interface{}{
			"level":       scope.Level,
			"parent":      scope.Parent,
			"children":    scope.Children,
			"category":    scope.Category,
			"description": scope.Description,
		}

		// Add expiration policy
		if scope.ExpiresAt != nil {
			info.ExpirationPolicy[scopeName] = *scope.ExpiresAt
		}

		// Add conditions
		for key, value := range scope.Conditions {
			info.Conditions[key] = value
		}

		// Add metadata
		for key, value := range scope.Metadata {
			info.Metadata[key] = value
		}
	}

	// Convert maps to slices
	for permission := range permissionsMap {
		info.Permissions = append(info.Permissions, permission)
	}

	for resource, actions := range resourcesMap {
		actionList := make([]string, 0, len(actions))
		for action := range actions {
			actionList = append(actionList, action)
		}
		sort.Strings(actionList)
		info.Resources[resource] = actionList
	}

	sort.Strings(info.Permissions)

	return info, nil
}

// Helper functions

func (s *OAuthHierarchicalScopeService) getClientAllowedScopes(clientID string) ([]string, error) {
	// Get client from database directly
	var client models.OAuthClient
	err := facades.Orm().Query().Where("id = ?", clientID).First(&client)
	if err != nil {
		return nil, fmt.Errorf("failed to get client: %w", err)
	}

	// Query client-specific scopes from OAuth consents and access tokens
	var consents []models.OAuthConsent
	err = facades.Orm().Query().
		Where("client_id = ? AND granted = ? AND revoked = ?", clientID, true, false).
		Find(&consents)
	if err != nil {
		facades.Log().Warning("Failed to query OAuth consents for client scopes", map[string]interface{}{
			"client_id": clientID,
			"error":     err.Error(),
		})
	}

	// Collect unique scopes from consents
	scopeSet := make(map[string]bool)
	for _, consent := range consents {
		if consent.IsActive() {
			scopes := consent.GetScopes()
			for _, scope := range scopes {
				scopeSet[scope] = true
			}
		}
	}

	// If client has granted scopes, use them
	if len(scopeSet) > 0 {
		result := make([]string, 0, len(scopeSet))
		for scope := range scopeSet {
			result = append(result, scope)
		}
		return result, nil
	}

	// Fallback to default scopes based on client type
	if client.IsPublic() {
		return []string{
			"openid", "profile", "email",
			"user.read", "calendar.readonly", "drive.readonly",
		}, nil
	}

	// Confidential clients get more permissions
	return []string{
		"openid", "profile", "email",
		"user", "user.read", "user.write",
		"organization.read", "calendar", "calendar.readonly", "calendar.events",
		"drive", "drive.readonly", "drive.file", "drive.metadata",
	}, nil
}

func (s *OAuthHierarchicalScopeService) getUserAllowedScopes(userID string) ([]string, error) {
	// Query user roles and permissions from database
	var user models.User
	err := facades.Orm().Query().
		With("Roles.Permissions").
		Where("id = ?", userID).
		First(&user)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Collect unique scopes from user roles and permissions
	scopeSet := make(map[string]bool)

	// Add basic scopes for authenticated users
	scopeSet["openid"] = true
	scopeSet["profile"] = true
	scopeSet["email"] = true
	scopeSet["user.read"] = true

	// Process user roles and their permissions
	for _, role := range user.Roles {
		// Add role-based scopes
		switch role.Name {
		case "admin", "super_admin":
			// Admin users get all scopes
			adminScopes := []string{
				"user", "user.read", "user.write", "user.admin",
				"organization", "organization.read", "organization.manage",
				"calendar", "calendar.readonly", "calendar.events", "calendar.admin",
				"drive", "drive.readonly", "drive.file", "drive.metadata", "drive.admin",
				"admin", "admin.directory", "admin.security",
			}
			for _, scope := range adminScopes {
				scopeSet[scope] = true
			}
		case "manager":
			// Manager users get management scopes
			managerScopes := []string{
				"user.read", "user.write",
				"organization.read", "organization.manage",
				"calendar", "calendar.readonly", "calendar.events",
				"drive", "drive.readonly", "drive.file", "drive.metadata",
			}
			for _, scope := range managerScopes {
				scopeSet[scope] = true
			}
		case "user":
			// Regular users get basic scopes
			userScopes := []string{
				"calendar.readonly", "calendar.events",
				"drive.readonly", "drive.file",
			}
			for _, scope := range userScopes {
				scopeSet[scope] = true
			}
		}

		// Process individual permissions
		for _, permission := range role.Permissions {
			// Map permission names to OAuth scopes
			scope := s.mapPermissionToScope(permission.Name)
			if scope != "" {
				scopeSet[scope] = true
			}
		}
	}

	// Convert set to slice
	result := make([]string, 0, len(scopeSet))
	for scope := range scopeSet {
		result = append(result, scope)
	}

	return result, nil
}

func (s *OAuthHierarchicalScopeService) checkScopeConditions(scope *ScopeDefinition, clientID, userID string) bool {
	for key, value := range scope.Conditions {
		switch key {
		case "require_mfa":
			if value.(bool) && !s.userHasMFA(userID) {
				return false
			}
		case "ip_whitelist":
			if value.(bool) && !s.isClientIPWhitelisted(clientID) {
				return false
			}
		}
	}
	return true
}

func (s *OAuthHierarchicalScopeService) getImpliedScopes(scope *ScopeDefinition, hierarchy *ScopeHierarchy) []string {
	var implied []string

	// Add parent scopes (implied by having child scope)
	current := scope
	for current.Parent != "" {
		parent, exists := hierarchy.Scopes[current.Parent]
		if !exists {
			break
		}
		implied = append(implied, parent.Name)
		current = parent
	}

	return implied
}

func (s *OAuthHierarchicalScopeService) findConflictingScopes(scopes []string, hierarchy *ScopeHierarchy) []string {
	var conflicts []string

	// Check for mutually exclusive scopes
	hasReadOnly := s.contains(scopes, "drive.readonly")
	hasWrite := s.contains(scopes, "drive.file")

	if hasReadOnly && hasWrite {
		conflicts = append(conflicts, "drive.readonly conflicts with drive.file")
	}

	return conflicts
}

func (s *OAuthHierarchicalScopeService) contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func (s *OAuthHierarchicalScopeService) isUserAdmin(userID string) bool {
	// Implement proper role-based authorization
	facades.Log().Info("Checking admin status for user", map[string]interface{}{
		"user_id": userID,
	})

	// Query user roles from database
	var userRoles []models.Role
	err := facades.Orm().Query().
		Raw("SELECT r.* FROM roles r INNER JOIN user_roles ur ON r.id = ur.role_id WHERE ur.user_id = ? AND r.is_active = ?", userID, true).
		Scan(&userRoles)

	if err != nil {
		facades.Log().Error("Failed to query user roles", map[string]interface{}{
			"user_id": userID,
			"error":   err.Error(),
		})
		return false // Default to false for safety
	}

	// Check for admin roles
	adminRoleNames := []string{"admin", "super_admin", "system_admin", "oauth_admin"}
	for _, role := range userRoles {
		roleName := strings.ToLower(role.Name)
		for _, adminRole := range adminRoleNames {
			if roleName == adminRole {
				facades.Log().Info("User has admin role", map[string]interface{}{
					"user_id":   userID,
					"role_name": role.Name,
				})
				return true
			}
		}

		// Check for specific permissions that indicate admin access
		if s.roleHasAdminPermissions(role.ID) {
			facades.Log().Info("User has admin permissions through role", map[string]interface{}{
				"user_id":   userID,
				"role_name": role.Name,
				"role_id":   role.ID,
			})
			return true
		}
	}

	facades.Log().Info("User does not have admin privileges", map[string]interface{}{
		"user_id":    userID,
		"role_count": len(userRoles),
	})

	return false
}

func (s *OAuthHierarchicalScopeService) userHasMFA(userID string) bool {
	// Check if user has MFA enabled - simplified
	return true // Default to true for this example
}

func (s *OAuthHierarchicalScopeService) isClientIPWhitelisted(clientID string) bool {
	// Check if client IP is whitelisted - simplified
	return true // Default to true for this example
}

// GetScopePermissions returns all permissions for given scopes
func (s *OAuthHierarchicalScopeService) GetScopePermissions(scopes []string) ([]string, error) {
	hierarchy, err := s.GetScopeHierarchy()
	if err != nil {
		return nil, err
	}

	permissionsMap := make(map[string]bool)

	for _, scopeName := range scopes {
		if scope, exists := hierarchy.Scopes[scopeName]; exists {
			for _, permission := range scope.Permissions {
				permissionsMap[permission] = true
			}
		}
	}

	permissions := make([]string, 0, len(permissionsMap))
	for permission := range permissionsMap {
		permissions = append(permissions, permission)
	}

	sort.Strings(permissions)
	return permissions, nil
}

// GetScopesByCategory returns scopes filtered by category
func (s *OAuthHierarchicalScopeService) GetScopesByCategory(category string) ([]string, error) {
	hierarchy, err := s.GetScopeHierarchy()
	if err != nil {
		return nil, err
	}

	var scopes []string
	for name, scope := range hierarchy.Scopes {
		if scope.Category == category {
			scopes = append(scopes, name)
		}
	}

	sort.Strings(scopes)
	return scopes, nil
}

// OptimizeScopes removes redundant scopes based on hierarchy
func (s *OAuthHierarchicalScopeService) OptimizeScopes(scopes []string) ([]string, error) {
	hierarchy, err := s.GetScopeHierarchy()
	if err != nil {
		return scopes, err
	}

	optimized := make(map[string]bool)

	for _, scopeName := range scopes {
		scope, exists := hierarchy.Scopes[scopeName]
		if !exists {
			optimized[scopeName] = true
			continue
		}

		// Check if any parent scope is already included
		hasParent := false
		current := scope
		for current.Parent != "" {
			if s.contains(scopes, current.Parent) {
				hasParent = true
				break
			}
			parent, exists := hierarchy.Scopes[current.Parent]
			if !exists {
				break
			}
			current = parent
		}

		if !hasParent {
			optimized[scopeName] = true
		}
	}

	result := make([]string, 0, len(optimized))
	for scope := range optimized {
		result = append(result, scope)
	}

	sort.Strings(result)
	return result, nil
}

func (s *OAuthHierarchicalScopeService) mapPermissionToScope(permissionName string) string {
	switch permissionName {
	case "read_profile":
		return "profile"
	case "get_name":
		return "profile"
	case "get_picture":
		return "profile"
	case "read_email":
		return "email"
	case "verify_email":
		return "email"
	case "access_user_data":
		return "user"
	case "read_user_basic":
		return "user.read"
	case "read_user_profile":
		return "user.read"
	case "write_user_profile":
		return "user.write"
	case "update_user_settings":
		return "user.write"
	case "admin_user_data":
		return "user.admin"
	case "delete_user":
		return "user.admin"
	case "impersonate_user":
		return "user.admin"
	case "access_organization":
		return "organization"
	case "read_org_info":
		return "organization.read"
	case "list_org_members":
		return "organization.read"
	case "manage_org_settings":
		return "organization.manage"
	case "invite_members":
		return "organization.manage"
	case "remove_members":
		return "organization.manage"
	case "access_calendar":
		return "calendar"
	case "read_calendar_events":
		return "calendar.readonly"
	case "list_calendars":
		return "calendar.readonly"
	case "create_events":
		return "calendar.events"
	case "update_events":
		return "calendar.events"
	case "delete_events":
		return "calendar.events"
	case "read_files":
		return "drive.readonly"
	case "list_files":
		return "drive.readonly"
	case "download_files":
		return "drive.readonly"
	case "upload_files":
		return "drive.file"
	case "update_files":
		return "drive.file"
	case "delete_files":
		return "drive.file"
	case "read_file_metadata":
		return "drive.metadata"
	case "list_file_metadata":
		return "drive.metadata"
	case "manage_users":
		return "admin.directory"
	case "manage_groups":
		return "admin.directory"
	case "manage_org_units":
		return "admin.directory"
	case "manage_security_settings":
		return "admin.security"
	case "view_audit_logs":
		return "admin.security"
	case "manage_oauth_clients":
		return "admin.security"
	case "admin_access":
		return "admin"
	}
	return ""
}

// roleHasAdminPermissions checks if a role has admin permissions
func (s *OAuthHierarchicalScopeService) roleHasAdminPermissions(roleID string) bool {
	facades.Log().Info("Checking admin permissions for role", map[string]interface{}{
		"role_id": roleID,
	})

	// Query role permissions
	var permissions []models.Permission
	err := facades.Orm().Query().
		Raw("SELECT p.* FROM permissions p INNER JOIN role_permissions rp ON p.id = rp.permission_id WHERE rp.role_id = ? AND p.is_active = ?", roleID, true).
		Scan(&permissions)

	if err != nil {
		facades.Log().Error("Failed to query role permissions", map[string]interface{}{
			"role_id": roleID,
			"error":   err.Error(),
		})
		return false
	}

	// Check for admin permissions
	adminPermissions := []string{
		"admin",
		"super_admin",
		"system_admin",
		"oauth_admin",
		"manage_users",
		"manage_roles",
		"manage_permissions",
		"manage_oauth_clients",
		"admin_access",
		"system_management",
	}

	for _, permission := range permissions {
		permissionName := strings.ToLower(permission.Name)
		for _, adminPerm := range adminPermissions {
			if permissionName == adminPerm || strings.Contains(permissionName, adminPerm) {
				facades.Log().Info("Role has admin permission", map[string]interface{}{
					"role_id":         roleID,
					"permission_name": permission.Name,
				})
				return true
			}
		}
	}

	facades.Log().Info("Role does not have admin permissions", map[string]interface{}{
		"role_id":          roleID,
		"permission_count": len(permissions),
	})

	return false
}
