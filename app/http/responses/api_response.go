package responses

import (
	"time"
)

// APIResponse represents a standard API response
// @Description Standard API response format
type APIResponse struct {
	// Response status
	// @example success
	Status string `json:"status" example:"success"`

	// Response message
	// @example Operation completed successfully
	Message string `json:"message,omitempty" example:"Operation completed successfully"`

	// Response data
	Data interface{} `json:"data,omitempty"`

	// Error details (if any)
	Error interface{} `json:"error,omitempty"`

	// Response timestamp
	// @example 2024-01-15T10:30:00Z
	Timestamp time.Time `json:"timestamp" example:"2024-01-15T10:30:00Z"`
}

// PaginatedResponse represents a paginated API response
// @Description Paginated API response format
type PaginatedResponse struct {
	// Response status
	// @example success
	Status string `json:"status" example:"success"`

	// Response message
	// @example Data retrieved successfully
	Message string `json:"message,omitempty" example:"Data retrieved successfully"`

	// Response data
	Data interface{} `json:"data,omitempty"`

	// Pagination information
	Pagination PaginationInfo `json:"pagination"`

	// Response timestamp
	// @example 2024-01-15T10:30:00Z
	Timestamp time.Time `json:"timestamp" example:"2024-01-15T10:30:00Z"`
}

// PaginationInfo represents pagination metadata
// @Description Pagination metadata for list responses
type PaginationInfo struct {
	// Cursor for the next page
	// @example 01HXYZ123456789ABCDEFGHIJK
	NextCursor string `json:"next_cursor,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Cursor for the previous page
	// @example 01HXYZ123456789ABCDEFGHIJK
	PrevCursor string `json:"prev_cursor,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Whether there are more pages
	// @example true
	HasMore bool `json:"has_more" example:"true"`

	// Whether there are previous pages
	// @example false
	HasPrev bool `json:"has_prev" example:"false"`

	// Number of items in current page
	// @example 10
	Count int `json:"count" example:"10"`

	// Maximum number of items per page
	// @example 10
	Limit int `json:"limit" example:"10"`
}

// ErrorResponse represents an error response
// @Description Standard error response format
type ErrorResponse struct {
	// Response status
	// @example error
	Status string `json:"status" example:"error"`

	// Error message
	// @example Something went wrong
	Message string `json:"message" example:"Something went wrong"`

	// Error code
	// @example VALIDATION_ERROR
	Code string `json:"code,omitempty" example:"VALIDATION_ERROR"`

	// Detailed error information
	Details interface{} `json:"details,omitempty"`

	// Response timestamp
	// @example 2024-01-15T10:30:00Z
	Timestamp time.Time `json:"timestamp" example:"2024-01-15T10:30:00Z"`
}
