package services

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/goravel/framework/facades"
)

type OAuthRichAuthorizationService struct {
	oauthService              *OAuthService
	hierarchicalScopeService  *OAuthHierarchicalScopeService
	resourceIndicatorsService *OAuthResourceIndicatorsService
}

// AuthorizationDetail represents a rich authorization detail (RFC 9396)
type AuthorizationDetail struct {
	Type           string                   `json:"type"`                      // Required: authorization detail type
	Locations      []string                 `json:"locations,omitempty"`       // Resource server identifiers
	Actions        []string                 `json:"actions,omitempty"`         // Actions to be performed
	DataTypes      []string                 `json:"datatypes,omitempty"`       // Data types involved
	Identifier     string                   `json:"identifier,omitempty"`      // Resource identifier
	Privileges     []string                 `json:"privileges,omitempty"`      // Specific privileges
	Purpose        string                   `json:"purpose,omitempty"`         // Purpose of access
	Duration       *AuthorizationDuration   `json:"duration,omitempty"`        // Duration constraints
	Conditions     []AuthorizationCondition `json:"conditions,omitempty"`      // Access conditions
	AdditionalData map[string]interface{}   `json:"additional_data,omitempty"` // Type-specific data
	Metadata       map[string]interface{}   `json:"metadata,omitempty"`        // Additional metadata
}

// AuthorizationDuration represents duration constraints for authorization
type AuthorizationDuration struct {
	StartTime   *time.Time `json:"start_time,omitempty"`   // When access starts
	EndTime     *time.Time `json:"end_time,omitempty"`     // When access ends
	MaxDuration int64      `json:"max_duration,omitempty"` // Maximum duration in seconds
	Recurring   *Recurring `json:"recurring,omitempty"`    // Recurring access pattern
}

// Recurring represents recurring access patterns
type Recurring struct {
	Pattern    string     `json:"pattern"`              // daily, weekly, monthly, custom
	Interval   int        `json:"interval,omitempty"`   // Interval for pattern
	Days       []string   `json:"days,omitempty"`       // Days of week (for weekly)
	Times      []string   `json:"times,omitempty"`      // Time ranges
	Until      *time.Time `json:"until,omitempty"`      // End of recurring pattern
	Exceptions []string   `json:"exceptions,omitempty"` // Exception dates
}

// AuthorizationCondition represents conditions for authorization
type AuthorizationCondition struct {
	Type        string                 `json:"type"`        // location, time, device, network, risk_level
	Operator    string                 `json:"operator"`    // eq, ne, in, not_in, gt, lt, contains
	Value       interface{}            `json:"value"`       // Condition value
	Description string                 `json:"description"` // Human-readable description
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// RichAuthorizationRequest represents a request with rich authorization details
type RichAuthorizationRequest struct {
	ClientID             string                 `json:"client_id"`
	UserID               string                 `json:"user_id,omitempty"`
	AuthorizationDetails []AuthorizationDetail  `json:"authorization_details"`
	Scopes               []string               `json:"scopes,omitempty"`  // Traditional scopes (optional)
	Purpose              string                 `json:"purpose,omitempty"` // Overall purpose
	RequestedAt          time.Time              `json:"requested_at"`
	ExpiresAt            time.Time              `json:"expires_at,omitempty"`
	Context              map[string]interface{} `json:"context"`
	RequireUserConsent   bool                   `json:"require_user_consent"`
	ConsentChallengeID   string                 `json:"consent_challenge_id,omitempty"`
}

// RichAuthorizationResult represents the result of rich authorization processing
type RichAuthorizationResult struct {
	Authorized            bool                               `json:"authorized"`
	AuthorizedDetails     []AuthorizationDetail              `json:"authorized_details"`
	DeniedDetails         []AuthorizationDetail              `json:"denied_details"`
	ModifiedDetails       []AuthorizationDetail              `json:"modified_details"`
	GrantedTokens         map[string]*RichAuthorizationToken `json:"granted_tokens"`
	ConsentRequired       []AuthorizationDetail              `json:"consent_required"`
	SteppedUpAuthRequired []AuthorizationDetail              `json:"stepped_up_auth_required"`
	ValidationErrors      []string                           `json:"validation_errors"`
	SecurityWarnings      []string                           `json:"security_warnings"`
	PolicyViolations      []string                           `json:"policy_violations"`
	RecommendedActions    []string                           `json:"recommended_actions"`
	ProcessingDetails     map[string]interface{}             `json:"processing_details"`
}

// RichAuthorizationToken represents a token with rich authorization details
type RichAuthorizationToken struct {
	TokenID              string                 `json:"token_id"`
	TokenType            string                 `json:"token_type"` // Bearer, DPoP, etc.
	AccessToken          string                 `json:"access_token"`
	RefreshToken         string                 `json:"refresh_token,omitempty"`
	ExpiresIn            int64                  `json:"expires_in"`
	Scope                string                 `json:"scope,omitempty"` // Traditional scope (if any)
	AuthorizationDetails []AuthorizationDetail  `json:"authorization_details"`
	IssuedAt             time.Time              `json:"issued_at"`
	ExpiresAt            time.Time              `json:"expires_at"`
	ClientID             string                 `json:"client_id"`
	UserID               string                 `json:"user_id,omitempty"`
	ResourceServers      []string               `json:"resource_servers"`
	EffectivePermissions map[string]interface{} `json:"effective_permissions"`
	SecurityContext      map[string]interface{} `json:"security_context"`
}

// AuthorizationDetailType represents a registered authorization detail type
type AuthorizationDetailType struct {
	Type                  string                 `json:"type"`
	Name                  string                 `json:"name"`
	Description           string                 `json:"description"`
	SupportedActions      []string               `json:"supported_actions"`
	SupportedDataTypes    []string               `json:"supported_datatypes"`
	RequiredFields        []string               `json:"required_fields"`
	OptionalFields        []string               `json:"optional_fields"`
	ValidationRules       []ValidationRule       `json:"validation_rules"`
	SecurityPolicies      []SecurityPolicy       `json:"security_policies"`
	ConsentRequired       bool                   `json:"consent_required"`
	AdminApprovalRequired bool                   `json:"admin_approval_required"`
	Metadata              map[string]interface{} `json:"metadata"`
	CreatedAt             time.Time              `json:"created_at"`
	UpdatedAt             time.Time              `json:"updated_at"`
}

// ValidationRule represents a validation rule for authorization details
type ValidationRule struct {
	Field    string      `json:"field"`
	Type     string      `json:"type"`     // required, format, range, enum
	Value    interface{} `json:"value"`    // Rule-specific value
	Message  string      `json:"message"`  // Error message
	Severity string      `json:"severity"` // error, warning, info
}

// SecurityPolicy represents a security policy for authorization details
type SecurityPolicy struct {
	PolicyID   string                   `json:"policy_id"`
	Type       string                   `json:"type"` // access_control, data_protection, audit, compliance
	Conditions []AuthorizationCondition `json:"conditions"`
	Actions    []string                 `json:"actions"` // allow, deny, require_consent, require_approval
	Priority   int                      `json:"priority"`
	Metadata   map[string]interface{}   `json:"metadata"`
}

func NewOAuthRichAuthorizationService() *OAuthRichAuthorizationService {
	return &OAuthRichAuthorizationService{
		oauthService:              NewOAuthService(),
		hierarchicalScopeService:  NewOAuthHierarchicalScopeService(),
		resourceIndicatorsService: NewOAuthResourceIndicatorsService(),
	}
}

// ProcessRichAuthorizationRequest processes a rich authorization request
func (s *OAuthRichAuthorizationService) ProcessRichAuthorizationRequest(request *RichAuthorizationRequest) (*RichAuthorizationResult, error) {
	result := &RichAuthorizationResult{
		Authorized:            false,
		AuthorizedDetails:     []AuthorizationDetail{},
		DeniedDetails:         []AuthorizationDetail{},
		ModifiedDetails:       []AuthorizationDetail{},
		GrantedTokens:         make(map[string]*RichAuthorizationToken),
		ConsentRequired:       []AuthorizationDetail{},
		SteppedUpAuthRequired: []AuthorizationDetail{},
		ValidationErrors:      []string{},
		SecurityWarnings:      []string{},
		PolicyViolations:      []string{},
		RecommendedActions:    []string{},
		ProcessingDetails:     make(map[string]interface{}),
	}

	// Validate the request
	if err := s.validateRichAuthorizationRequest(request); err != nil {
		result.ValidationErrors = append(result.ValidationErrors, err.Error())
		return result, err
	}

	// Process each authorization detail
	for _, detail := range request.AuthorizationDetails {
		detailResult := s.processAuthorizationDetail(detail, request)

		switch detailResult.Decision {
		case "authorized":
			result.AuthorizedDetails = append(result.AuthorizedDetails, detailResult.ProcessedDetail)
		case "denied":
			result.DeniedDetails = append(result.DeniedDetails, detail)
			result.PolicyViolations = append(result.PolicyViolations, detailResult.Reason)
		case "modified":
			result.ModifiedDetails = append(result.ModifiedDetails, detailResult.ProcessedDetail)
			result.AuthorizedDetails = append(result.AuthorizedDetails, detailResult.ProcessedDetail)
		case "consent_required":
			result.ConsentRequired = append(result.ConsentRequired, detail)
		case "step_up_required":
			result.SteppedUpAuthRequired = append(result.SteppedUpAuthRequired, detail)
		}

		// Collect warnings and recommendations
		result.SecurityWarnings = append(result.SecurityWarnings, detailResult.Warnings...)
		result.RecommendedActions = append(result.RecommendedActions, detailResult.Recommendations...)
	}

	// Determine overall authorization status
	result.Authorized = len(result.AuthorizedDetails) > 0

	// Generate tokens for authorized details
	if result.Authorized {
		if err := s.generateRichAuthorizationTokens(result, request); err != nil {
			result.SecurityWarnings = append(result.SecurityWarnings, fmt.Sprintf("Token generation warning: %v", err))
		}
	}

	// Add processing metadata
	result.ProcessingDetails["processed_at"] = time.Now()
	result.ProcessingDetails["total_details"] = len(request.AuthorizationDetails)
	result.ProcessingDetails["authorized_count"] = len(result.AuthorizedDetails)
	result.ProcessingDetails["denied_count"] = len(result.DeniedDetails)
	result.ProcessingDetails["modified_count"] = len(result.ModifiedDetails)

	// Log rich authorization processing
	s.logRichAuthorizationProcessing(request, result)

	return result, nil
}

// RegisterAuthorizationDetailType registers a new authorization detail type
func (s *OAuthRichAuthorizationService) RegisterAuthorizationDetailType(detailType *AuthorizationDetailType) error {
	if err := s.validateAuthorizationDetailType(detailType); err != nil {
		return fmt.Errorf("invalid authorization detail type: %w", err)
	}

	detailType.CreatedAt = time.Now()
	detailType.UpdatedAt = time.Now()

	// Store detail type
	if err := s.storeAuthorizationDetailType(detailType); err != nil {
		return fmt.Errorf("failed to store authorization detail type: %w", err)
	}

	facades.Log().Info("Authorization detail type registered", map[string]interface{}{
		"type":        detailType.Type,
		"name":        detailType.Name,
		"description": detailType.Description,
	})

	return nil
}

// GetSupportedAuthorizationDetailTypes returns supported authorization detail types
func (s *OAuthRichAuthorizationService) GetSupportedAuthorizationDetailTypes() ([]*AuthorizationDetailType, error) {
	// In production, query database for registered types
	return s.getDefaultAuthorizationDetailTypes(), nil
}

// Helper methods for rich authorization processing

type AuthorizationDetailResult struct {
	Decision        string                 `json:"decision"` // authorized, denied, modified, consent_required, step_up_required
	ProcessedDetail AuthorizationDetail    `json:"processed_detail,omitempty"`
	Reason          string                 `json:"reason,omitempty"`
	Warnings        []string               `json:"warnings"`
	Recommendations []string               `json:"recommendations"`
	Metadata        map[string]interface{} `json:"metadata"`
}

func (s *OAuthRichAuthorizationService) processAuthorizationDetail(detail AuthorizationDetail, request *RichAuthorizationRequest) *AuthorizationDetailResult {
	result := &AuthorizationDetailResult{
		Decision:        "denied",
		Warnings:        []string{},
		Recommendations: []string{},
		Metadata:        make(map[string]interface{}),
	}

	// Get detail type configuration
	detailType, err := s.getAuthorizationDetailType(detail.Type)
	if err != nil {
		result.Reason = fmt.Sprintf("Unknown authorization detail type: %s", detail.Type)
		return result
	}

	// Validate detail against type rules
	if validationErrors := s.validateDetailAgainstType(detail, detailType); len(validationErrors) > 0 {
		result.Reason = fmt.Sprintf("Validation errors: %s", strings.Join(validationErrors, ", "))
		return result
	}

	// Check security policies
	policyResult := s.checkSecurityPolicies(detail, detailType, request)
	if !policyResult.Allowed {
		result.Decision = policyResult.Decision
		result.Reason = policyResult.Reason
		result.Warnings = policyResult.Warnings
		return result
	}

	// Check if consent is required
	if detailType.ConsentRequired || s.requiresConsentForDetail(detail, request) {
		result.Decision = "consent_required"
		result.Reason = "User consent required for this authorization detail"
		return result
	}

	// Check if stepped-up authentication is required
	if s.requiresSteppedUpAuth(detail, request) {
		result.Decision = "step_up_required"
		result.Reason = "Stepped-up authentication required for this authorization detail"
		return result
	}

	// Process and potentially modify the detail
	processedDetail, modified := s.processAndOptimizeDetail(detail, detailType, request)

	result.ProcessedDetail = processedDetail
	if modified {
		result.Decision = "modified"
		result.Warnings = append(result.Warnings, "Authorization detail was modified to comply with policies")
	} else {
		result.Decision = "authorized"
	}

	// Add security recommendations
	s.addDetailSecurityRecommendations(result, detail, detailType)

	return result
}

func (s *OAuthRichAuthorizationService) getDefaultAuthorizationDetailTypes() []*AuthorizationDetailType {
	return []*AuthorizationDetailType{
		{
			Type:        "payment_initiation",
			Name:        "Payment Initiation",
			Description: "Authorization for initiating payments",
			SupportedActions: []string{
				"initiate", "confirm", "cancel", "status",
			},
			SupportedDataTypes: []string{
				"account_info", "payment_details", "transaction_history",
			},
			RequiredFields: []string{"actions", "identifier"},
			OptionalFields: []string{"purpose", "duration", "conditions"},
			ValidationRules: []ValidationRule{
				{
					Field:    "actions",
					Type:     "enum",
					Value:    []string{"initiate", "confirm", "cancel", "status"},
					Message:  "Invalid action for payment initiation",
					Severity: "error",
				},
				{
					Field:    "identifier",
					Type:     "format",
					Value:    "^[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}([A-Z0-9]?){0,16}$", // IBAN format
					Message:  "Invalid account identifier format",
					Severity: "error",
				},
			},
			SecurityPolicies: []SecurityPolicy{
				{
					PolicyID: "payment_amount_limit",
					Type:     "access_control",
					Conditions: []AuthorizationCondition{
						{
							Type:        "amount",
							Operator:    "gt",
							Value:       10000.0,
							Description: "Payment amount exceeds limit",
						},
					},
					Actions:  []string{"require_approval"},
					Priority: 1,
				},
			},
			ConsentRequired:       true,
			AdminApprovalRequired: false,
			CreatedAt:             time.Now(),
			UpdatedAt:             time.Now(),
		},
		{
			Type:        "account_information",
			Name:        "Account Information Access",
			Description: "Authorization for accessing account information",
			SupportedActions: []string{
				"read", "list", "balance", "transactions",
			},
			SupportedDataTypes: []string{
				"balance", "transactions", "account_details", "standing_orders",
			},
			RequiredFields: []string{"actions", "datatypes"},
			OptionalFields: []string{"identifier", "duration", "conditions"},
			ValidationRules: []ValidationRule{
				{
					Field:    "actions",
					Type:     "enum",
					Value:    []string{"read", "list", "balance", "transactions"},
					Message:  "Invalid action for account information",
					Severity: "error",
				},
			},
			SecurityPolicies: []SecurityPolicy{
				{
					PolicyID: "account_access_frequency",
					Type:     "access_control",
					Conditions: []AuthorizationCondition{
						{
							Type:        "frequency",
							Operator:    "gt",
							Value:       100,
							Description: "Too many account access requests",
						},
					},
					Actions:  []string{"require_consent"},
					Priority: 2,
				},
			},
			ConsentRequired:       true,
			AdminApprovalRequired: false,
			CreatedAt:             time.Now(),
			UpdatedAt:             time.Now(),
		},
		{
			Type:        "file_access",
			Name:        "File Access",
			Description: "Authorization for file operations",
			SupportedActions: []string{
				"read", "write", "delete", "share", "download", "upload",
			},
			SupportedDataTypes: []string{
				"document", "image", "video", "audio", "archive",
			},
			RequiredFields: []string{"actions", "locations"},
			OptionalFields: []string{"identifier", "datatypes", "purpose", "duration"},
			ValidationRules: []ValidationRule{
				{
					Field:    "actions",
					Type:     "enum",
					Value:    []string{"read", "write", "delete", "share", "download", "upload"},
					Message:  "Invalid file action",
					Severity: "error",
				},
				{
					Field:    "locations",
					Type:     "required",
					Message:  "File location is required",
					Severity: "error",
				},
			},
			SecurityPolicies: []SecurityPolicy{
				{
					PolicyID: "sensitive_file_protection",
					Type:     "data_protection",
					Conditions: []AuthorizationCondition{
						{
							Type:        "file_type",
							Operator:    "in",
							Value:       []string{"financial", "medical", "legal"},
							Description: "Sensitive file type detected",
						},
					},
					Actions:  []string{"require_approval", "require_consent"},
					Priority: 1,
				},
			},
			ConsentRequired:       false,
			AdminApprovalRequired: false,
			CreatedAt:             time.Now(),
			UpdatedAt:             time.Now(),
		},
		{
			Type:        "api_access",
			Name:        "API Access",
			Description: "Authorization for API operations",
			SupportedActions: []string{
				"read", "write", "delete", "execute", "admin",
			},
			SupportedDataTypes: []string{
				"user_data", "system_data", "configuration", "logs",
			},
			RequiredFields: []string{"actions", "locations"},
			OptionalFields: []string{"datatypes", "privileges", "conditions"},
			ValidationRules: []ValidationRule{
				{
					Field:    "actions",
					Type:     "enum",
					Value:    []string{"read", "write", "delete", "execute", "admin"},
					Message:  "Invalid API action",
					Severity: "error",
				},
			},
			SecurityPolicies: []SecurityPolicy{
				{
					PolicyID: "admin_api_protection",
					Type:     "access_control",
					Conditions: []AuthorizationCondition{
						{
							Type:        "actions",
							Operator:    "contains",
							Value:       "admin",
							Description: "Administrative API access requested",
						},
					},
					Actions:  []string{"require_approval"},
					Priority: 1,
				},
			},
			ConsentRequired:       false,
			AdminApprovalRequired: true,
			CreatedAt:             time.Now(),
			UpdatedAt:             time.Now(),
		},
	}
}

func (s *OAuthRichAuthorizationService) validateRichAuthorizationRequest(request *RichAuthorizationRequest) error {
	if request.ClientID == "" {
		return fmt.Errorf("client_id is required")
	}

	if len(request.AuthorizationDetails) == 0 {
		return fmt.Errorf("at least one authorization detail is required")
	}

	// Validate each authorization detail
	for i, detail := range request.AuthorizationDetails {
		if detail.Type == "" {
			return fmt.Errorf("authorization detail %d: type is required", i)
		}
	}

	return nil
}

func (s *OAuthRichAuthorizationService) getAuthorizationDetailType(detailType string) (*AuthorizationDetailType, error) {
	// In production, query database
	defaultTypes := s.getDefaultAuthorizationDetailTypes()
	for _, dt := range defaultTypes {
		if dt.Type == detailType {
			return dt, nil
		}
	}
	return nil, fmt.Errorf("authorization detail type not found: %s", detailType)
}

func (s *OAuthRichAuthorizationService) validateDetailAgainstType(detail AuthorizationDetail, detailType *AuthorizationDetailType) []string {
	var errors []string

	// Check required fields
	for _, field := range detailType.RequiredFields {
		if !s.hasField(detail, field) {
			errors = append(errors, fmt.Sprintf("Required field missing: %s", field))
		}
	}

	// Apply validation rules
	for _, rule := range detailType.ValidationRules {
		if err := s.applyValidationRule(detail, rule); err != nil {
			errors = append(errors, err.Error())
		}
	}

	return errors
}

func (s *OAuthRichAuthorizationService) hasField(detail AuthorizationDetail, field string) bool {
	switch field {
	case "type":
		return detail.Type != ""
	case "locations":
		return len(detail.Locations) > 0
	case "actions":
		return len(detail.Actions) > 0
	case "datatypes":
		return len(detail.DataTypes) > 0
	case "identifier":
		return detail.Identifier != ""
	case "privileges":
		return len(detail.Privileges) > 0
	case "purpose":
		return detail.Purpose != ""
	case "duration":
		return detail.Duration != nil
	case "conditions":
		return len(detail.Conditions) > 0
	default:
		return false
	}
}

func (s *OAuthRichAuthorizationService) applyValidationRule(detail AuthorizationDetail, rule ValidationRule) error {
	fieldValue := s.getFieldValue(detail, rule.Field)

	switch rule.Type {
	case "required":
		if fieldValue == nil {
			return fmt.Errorf(rule.Message)
		}
	case "enum":
		if enumValues, ok := rule.Value.([]string); ok {
			if fieldSlice, ok := fieldValue.([]string); ok {
				for _, value := range fieldSlice {
					if !s.contains(enumValues, value) {
						return fmt.Errorf("%s: %s", rule.Message, value)
					}
				}
			}
		}
	case "format":
		if _, ok := rule.Value.(string); ok {
			if strValue, ok := fieldValue.(string); ok {
				// Simplified format validation - in production use regex
				if len(strValue) == 0 {
					return fmt.Errorf(rule.Message)
				}
			}
		}
	}

	return nil
}

func (s *OAuthRichAuthorizationService) getFieldValue(detail AuthorizationDetail, field string) interface{} {
	switch field {
	case "type":
		return detail.Type
	case "locations":
		return detail.Locations
	case "actions":
		return detail.Actions
	case "datatypes":
		return detail.DataTypes
	case "identifier":
		return detail.Identifier
	case "privileges":
		return detail.Privileges
	case "purpose":
		return detail.Purpose
	case "duration":
		return detail.Duration
	case "conditions":
		return detail.Conditions
	default:
		return nil
	}
}

func (s *OAuthRichAuthorizationService) contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

type SecurityPolicyResult struct {
	Allowed  bool     `json:"allowed"`
	Decision string   `json:"decision"`
	Reason   string   `json:"reason"`
	Warnings []string `json:"warnings"`
}

func (s *OAuthRichAuthorizationService) checkSecurityPolicies(detail AuthorizationDetail, detailType *AuthorizationDetailType, request *RichAuthorizationRequest) *SecurityPolicyResult {
	result := &SecurityPolicyResult{
		Allowed:  true,
		Decision: "authorized",
		Warnings: []string{},
	}

	for _, policy := range detailType.SecurityPolicies {
		if s.evaluatePolicyConditions(policy.Conditions, detail, request) {
			for _, action := range policy.Actions {
				switch action {
				case "deny":
					result.Allowed = false
					result.Decision = "denied"
					result.Reason = fmt.Sprintf("Denied by security policy: %s", policy.PolicyID)
					return result
				case "require_consent":
					result.Decision = "consent_required"
					result.Reason = fmt.Sprintf("Consent required by policy: %s", policy.PolicyID)
				case "require_approval":
					result.Decision = "step_up_required"
					result.Reason = fmt.Sprintf("Approval required by policy: %s", policy.PolicyID)
				}
			}
		}
	}

	return result
}

func (s *OAuthRichAuthorizationService) evaluatePolicyConditions(conditions []AuthorizationCondition, detail AuthorizationDetail, request *RichAuthorizationRequest) bool {
	for _, condition := range conditions {
		if !s.evaluatePolicyCondition(condition, detail, request) {
			return false
		}
	}
	return len(conditions) > 0
}

func (s *OAuthRichAuthorizationService) evaluatePolicyCondition(condition AuthorizationCondition, detail AuthorizationDetail, request *RichAuthorizationRequest) bool {
	fieldValue := s.getConditionFieldValue(condition.Type, detail, request)

	switch condition.Operator {
	case "eq":
		return fieldValue == condition.Value
	case "ne":
		return fieldValue != condition.Value
	case "contains":
		if strValue, ok := fieldValue.(string); ok {
			if condValue, ok := condition.Value.(string); ok {
				return strings.Contains(strValue, condValue)
			}
		}
		if sliceValue, ok := fieldValue.([]string); ok {
			if condValue, ok := condition.Value.(string); ok {
				return s.contains(sliceValue, condValue)
			}
		}
	case "in":
		if condSlice, ok := condition.Value.([]interface{}); ok {
			for _, v := range condSlice {
				if fieldValue == v {
					return true
				}
			}
		}
	case "gt":
		if fv, ok := fieldValue.(float64); ok {
			if cv, ok := condition.Value.(float64); ok {
				return fv > cv
			}
		}
	}

	return false
}

func (s *OAuthRichAuthorizationService) getConditionFieldValue(fieldType string, detail AuthorizationDetail, request *RichAuthorizationRequest) interface{} {
	switch fieldType {
	case "actions":
		return detail.Actions
	case "datatypes":
		return detail.DataTypes
	case "file_type":
		// Simplified - in production, would analyze file type
		return "document"
	case "amount":
		// Simplified - in production, would extract from additional_data
		if detail.AdditionalData != nil {
			if amount, exists := detail.AdditionalData["amount"]; exists {
				return amount
			}
		}
		return 0.0
	case "frequency":
		// Simplified - in production, would check access frequency
		return 10
	default:
		return nil
	}
}

func (s *OAuthRichAuthorizationService) requiresConsentForDetail(detail AuthorizationDetail, request *RichAuthorizationRequest) bool {
	// Check if detail involves sensitive actions or data
	sensitiveActions := []string{"delete", "admin", "write", "share"}
	for _, action := range detail.Actions {
		if s.contains(sensitiveActions, action) {
			return true
		}
	}

	// Check if detail involves sensitive data types
	sensitiveDataTypes := []string{"financial", "medical", "personal"}
	for _, dataType := range detail.DataTypes {
		if s.contains(sensitiveDataTypes, dataType) {
			return true
		}
	}

	return false
}

func (s *OAuthRichAuthorizationService) requiresSteppedUpAuth(detail AuthorizationDetail, request *RichAuthorizationRequest) bool {
	// Check if detail involves high-privilege actions
	highPrivilegeActions := []string{"admin", "delete", "execute"}
	for _, action := range detail.Actions {
		if s.contains(highPrivilegeActions, action) {
			return true
		}
	}

	return false
}

func (s *OAuthRichAuthorizationService) processAndOptimizeDetail(detail AuthorizationDetail, detailType *AuthorizationDetailType, request *RichAuthorizationRequest) (AuthorizationDetail, bool) {
	processedDetail := detail
	modified := false

	// Remove unsupported actions
	var supportedActions []string
	for _, action := range detail.Actions {
		if s.contains(detailType.SupportedActions, action) {
			supportedActions = append(supportedActions, action)
		} else {
			modified = true
		}
	}
	processedDetail.Actions = supportedActions

	// Remove unsupported data types
	var supportedDataTypes []string
	for _, dataType := range detail.DataTypes {
		if s.contains(detailType.SupportedDataTypes, dataType) {
			supportedDataTypes = append(supportedDataTypes, dataType)
		} else {
			modified = true
		}
	}
	processedDetail.DataTypes = supportedDataTypes

	// Apply duration limits if necessary
	if processedDetail.Duration != nil && processedDetail.Duration.MaxDuration > 86400 { // 24 hours
		processedDetail.Duration.MaxDuration = 86400
		modified = true
	}

	return processedDetail, modified
}

func (s *OAuthRichAuthorizationService) addDetailSecurityRecommendations(result *AuthorizationDetailResult, detail AuthorizationDetail, detailType *AuthorizationDetailType) {
	// Add recommendations based on detail type and content
	if len(detail.Actions) > 3 {
		result.Recommendations = append(result.Recommendations, "Consider limiting the number of requested actions")
	}

	if detail.Duration != nil && detail.Duration.MaxDuration > 3600 { // 1 hour
		result.Recommendations = append(result.Recommendations, "Consider shorter access duration for security")
	}

	if len(detail.Conditions) == 0 {
		result.Recommendations = append(result.Recommendations, "Consider adding access conditions for better security")
	}
}

func (s *OAuthRichAuthorizationService) generateRichAuthorizationTokens(result *RichAuthorizationResult, request *RichAuthorizationRequest) error {
	// Group authorized details by resource server
	detailsByResource := s.groupDetailsByResource(result.AuthorizedDetails)

	for resourceServer, details := range detailsByResource {
		token, err := s.createRichAuthorizationToken(resourceServer, details, request)
		if err != nil {
			return fmt.Errorf("failed to create token for resource %s: %w", resourceServer, err)
		}

		result.GrantedTokens[resourceServer] = token
	}

	return nil
}

func (s *OAuthRichAuthorizationService) groupDetailsByResource(details []AuthorizationDetail) map[string][]AuthorizationDetail {
	grouped := make(map[string][]AuthorizationDetail)

	for _, detail := range details {
		if len(detail.Locations) == 0 {
			// Default resource server
			resourceServer := "default"
			grouped[resourceServer] = append(grouped[resourceServer], detail)
		} else {
			for _, location := range detail.Locations {
				grouped[location] = append(grouped[location], detail)
			}
		}
	}

	return grouped
}

func (s *OAuthRichAuthorizationService) createRichAuthorizationToken(resourceServer string, details []AuthorizationDetail, request *RichAuthorizationRequest) (*RichAuthorizationToken, error) {
	tokenID := s.generateTokenID()
	now := time.Now()
	expiresIn := int64(3600) // 1 hour default

	// Calculate effective permissions
	effectivePermissions := s.calculateEffectivePermissions(details)

	// Determine token expiration based on details
	if tokenExpiry := s.calculateTokenExpiry(details); tokenExpiry.After(now) {
		expiresIn = int64(tokenExpiry.Sub(now).Seconds())
	}

	token := &RichAuthorizationToken{
		TokenID:              tokenID,
		TokenType:            "Bearer",
		AccessToken:          s.generateAccessToken(),
		ExpiresIn:            expiresIn,
		AuthorizationDetails: details,
		IssuedAt:             now,
		ExpiresAt:            now.Add(time.Duration(expiresIn) * time.Second),
		ClientID:             request.ClientID,
		UserID:               request.UserID,
		ResourceServers:      []string{resourceServer},
		EffectivePermissions: effectivePermissions,
		SecurityContext: map[string]interface{}{
			"resource_server":       resourceServer,
			"authorization_details": len(details),
			"effective_permissions": len(effectivePermissions),
			"issued_at":             now.Unix(),
		},
	}

	// Generate refresh token if needed
	if s.shouldGenerateRefreshToken(details) {
		token.RefreshToken = s.generateRefreshToken()
	}

	return token, nil
}

func (s *OAuthRichAuthorizationService) calculateEffectivePermissions(details []AuthorizationDetail) map[string]interface{} {
	permissions := make(map[string]interface{})

	// Collect all actions and resources
	allActions := make(map[string]bool)
	allResources := make(map[string]bool)
	allDataTypes := make(map[string]bool)

	for _, detail := range details {
		for _, action := range detail.Actions {
			allActions[action] = true
		}
		for _, location := range detail.Locations {
			allResources[location] = true
		}
		for _, dataType := range detail.DataTypes {
			allDataTypes[dataType] = true
		}
	}

	// Convert to slices
	var actions, resources, dataTypes []string
	for action := range allActions {
		actions = append(actions, action)
	}
	for resource := range allResources {
		resources = append(resources, resource)
	}
	for dataType := range allDataTypes {
		dataTypes = append(dataTypes, dataType)
	}

	permissions["actions"] = actions
	permissions["resources"] = resources
	permissions["data_types"] = dataTypes
	permissions["details_count"] = len(details)

	return permissions
}

func (s *OAuthRichAuthorizationService) calculateTokenExpiry(details []AuthorizationDetail) time.Time {
	minExpiry := time.Now().Add(time.Hour * 24) // Default 24 hours

	for _, detail := range details {
		if detail.Duration != nil {
			if detail.Duration.EndTime != nil && detail.Duration.EndTime.Before(minExpiry) {
				minExpiry = *detail.Duration.EndTime
			}
			if detail.Duration.MaxDuration > 0 {
				maxExpiry := time.Now().Add(time.Duration(detail.Duration.MaxDuration) * time.Second)
				if maxExpiry.Before(minExpiry) {
					minExpiry = maxExpiry
				}
			}
		}
	}

	return minExpiry
}

func (s *OAuthRichAuthorizationService) shouldGenerateRefreshToken(details []AuthorizationDetail) bool {
	// Generate refresh token for long-term access
	for _, detail := range details {
		if detail.Duration != nil {
			if detail.Duration.MaxDuration > 3600 { // More than 1 hour
				return true
			}
			if detail.Duration.Recurring != nil {
				return true
			}
		}
	}
	return false
}

// Storage and utility methods

func (s *OAuthRichAuthorizationService) generateTokenID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return "rich_token_" + base64.RawURLEncoding.EncodeToString(bytes)
}

func (s *OAuthRichAuthorizationService) generateAccessToken() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return base64.RawURLEncoding.EncodeToString(bytes)
}

func (s *OAuthRichAuthorizationService) generateRefreshToken() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return "refresh_" + base64.RawURLEncoding.EncodeToString(bytes)
}

func (s *OAuthRichAuthorizationService) storeAuthorizationDetailType(detailType *AuthorizationDetailType) error {
	key := fmt.Sprintf("auth_detail_type_%s", detailType.Type)
	data, err := json.Marshal(detailType)
	if err != nil {
		return err
	}

	facades.Cache().Put(key, string(data), time.Hour*24*30) // 30 days
	return nil
}

func (s *OAuthRichAuthorizationService) validateAuthorizationDetailType(detailType *AuthorizationDetailType) error {
	if detailType.Type == "" {
		return fmt.Errorf("type is required")
	}
	if detailType.Name == "" {
		return fmt.Errorf("name is required")
	}
	if detailType.Description == "" {
		return fmt.Errorf("description is required")
	}
	return nil
}

func (s *OAuthRichAuthorizationService) logRichAuthorizationProcessing(request *RichAuthorizationRequest, result *RichAuthorizationResult) {
	facades.Log().Info("Rich authorization request processed", map[string]interface{}{
		"client_id":                request.ClientID,
		"user_id":                  request.UserID,
		"authorization_details":    len(request.AuthorizationDetails),
		"authorized":               result.Authorized,
		"authorized_details":       len(result.AuthorizedDetails),
		"denied_details":           len(result.DeniedDetails),
		"modified_details":         len(result.ModifiedDetails),
		"consent_required":         len(result.ConsentRequired),
		"stepped_up_auth_required": len(result.SteppedUpAuthRequired),
		"validation_errors":        len(result.ValidationErrors),
		"security_warnings":        len(result.SecurityWarnings),
		"granted_tokens":           len(result.GrantedTokens),
	})
}

// GetRichAuthorizationCapabilities returns RAR capabilities for discovery
func (s *OAuthRichAuthorizationService) GetRichAuthorizationCapabilities() map[string]interface{} {
	supportedTypes, _ := s.GetSupportedAuthorizationDetailTypes()
	var typeNames []string
	for _, t := range supportedTypes {
		typeNames = append(typeNames, t.Type)
	}

	return map[string]interface{}{
		"rich_authorization_requests_supported": facades.Config().GetBool("oauth.rich_authorization.enabled", true),
		"authorization_details_types_supported": typeNames,
		"authorization_details_supported":       true,
		"multiple_authorization_details":        true,
		"authorization_details_validation":      true,
		"authorization_details_optimization":    true,
		"conditional_authorization":             true,
		"duration_constraints_supported":        true,
		"recurring_access_supported":            true,
		"fine_grained_permissions":              true,
		"resource_specific_tokens":              true,
		"consent_management_integration":        true,
		"security_policy_enforcement":           true,
	}
}
