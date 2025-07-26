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
// @Description Paginated API response format with unified pagination support
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

// QueryBuilderResponse represents a response using QueryBuilder's unified pagination
// @Description Response format for QueryBuilder AutoPaginate results
type QueryBuilderResponse struct {
	// Response status
	// @example success
	Status string `json:"status" example:"success"`

	// Response message
	// @example Data retrieved successfully
	Message string `json:"message,omitempty" example:"Data retrieved successfully"`

	// Response data (embedded from UnifiedPaginationResult)
	Data interface{} `json:"data,omitempty"`

	// Pagination information (embedded from UnifiedPaginationResult)
	Pagination *PaginationInfo `json:"pagination,omitempty"`

	// Response timestamp
	// @example 2024-01-15T10:30:00Z
	Timestamp time.Time `json:"timestamp" example:"2024-01-15T10:30:00Z"`
}

// PaginationInfo represents pagination metadata
// @Description Unified pagination metadata supporting both offset and cursor pagination
type PaginationInfo struct {
	// Type of pagination used (offset, cursor, or simple)
	// @example offset
	Type string `json:"type" example:"offset"`

	// Number of items in current page
	// @example 20
	Count int `json:"count" example:"20"`

	// Maximum items per page
	// @example 20
	Limit int `json:"limit" example:"20"`

	// Whether there are more items after current page
	// @example true
	HasNext bool `json:"has_next" example:"true"`

	// Whether there are items before current page
	// @example false
	HasPrev bool `json:"has_prev" example:"false"`

	// Offset pagination fields
	// Current page number (offset pagination only)
	// @example 1
	CurrentPage *int `json:"current_page,omitempty" example:"1"`

	// Last page number (offset pagination only)
	// @example 5
	LastPage *int `json:"last_page,omitempty" example:"5"`

	// Items per page (offset pagination only)
	// @example 20
	PerPage *int `json:"per_page,omitempty" example:"20"`

	// Total number of items (offset pagination only)
	// @example 100
	Total *int64 `json:"total,omitempty" example:"100"`

	// Starting item number (offset pagination only)
	// @example 1
	From *int `json:"from,omitempty" example:"1"`

	// Ending item number (offset pagination only)
	// @example 20
	To *int `json:"to,omitempty" example:"20"`

	// Cursor pagination fields
	// Cursor for next page (cursor pagination only)
	// @example eyJpZCI6MTIzfQ==
	NextCursor *string `json:"next_cursor,omitempty" example:"eyJpZCI6MTIzfQ=="`

	// Cursor for previous page (cursor pagination only)
	// @example eyJpZCI6MTAwfQ==
	PrevCursor *string `json:"prev_cursor,omitempty" example:"eyJpZCI6MTAwfQ=="`

	// Legacy fields for backward compatibility
	// @deprecated Use HasNext instead
	HasMore bool `json:"has_more,omitempty" example:"true"`
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
