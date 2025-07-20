package requests

// CreateActivityLogRequest represents the request for creating an activity log
// @Description Request model for creating a new activity log entry
type CreateActivityLogRequest struct {
	// Log name for categorizing activities
	// @example user_management
	LogName string `json:"log_name" example:"user_management"`

	// Activity description
	// @example User created successfully
	Description string `json:"description" binding:"required" example:"User created successfully" validate:"required"`

	// Subject type (model type)
	// @example *models.User
	SubjectType string `json:"subject_type" example:"*models.User"`

	// Subject ID (model ID)
	// @example 01HXYZ123456789ABCDEFGHIJK
	SubjectID string `json:"subject_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Causer type (who performed the action)
	// @example *models.User
	CauserType string `json:"causer_type" example:"*models.User"`

	// Causer ID (who performed the action)
	// @example 01HXYZ123456789ABCDEFGHIJK
	CauserID string `json:"causer_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Additional properties (JSON)
	// @example {"ip_address": "192.168.1.1", "user_agent": "Mozilla/5.0..."}
	Properties map[string]interface{} `json:"properties" example:"{\"ip_address\": \"192.168.1.1\", \"user_agent\": \"Mozilla/5.0...\"}"`
}
