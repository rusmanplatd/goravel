package middleware

import (
	"fmt"
	"strings"
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/http/responses"
	"goravel/app/querybuilder"
)

// QueryBuilderMiddleware provides automatic validation and sanitization for query parameters
type QueryBuilderMiddleware struct {
	config *QueryBuilderMiddlewareConfig
}

// QueryBuilderMiddlewareConfig holds configuration for the middleware
type QueryBuilderMiddlewareConfig struct {
	MaxFilters         int
	MaxSorts           int
	MaxIncludes        int
	MaxFields          int
	EnableSanitization bool
	EnableValidation   bool
	LogInvalidRequests bool
}

// DefaultQueryBuilderMiddlewareConfig returns default middleware configuration
func DefaultQueryBuilderMiddlewareConfig() *QueryBuilderMiddlewareConfig {
	return &QueryBuilderMiddlewareConfig{
		MaxFilters:         20,
		MaxSorts:           10,
		MaxIncludes:        10,
		MaxFields:          50,
		EnableSanitization: true,
		EnableValidation:   true,
		LogInvalidRequests: true,
	}
}

// NewQueryBuilderMiddleware creates a new QueryBuilder middleware instance
func NewQueryBuilderMiddleware(config ...*QueryBuilderMiddlewareConfig) *QueryBuilderMiddleware {
	var cfg *QueryBuilderMiddlewareConfig
	if len(config) > 0 && config[0] != nil {
		cfg = config[0]
	} else {
		cfg = DefaultQueryBuilderMiddlewareConfig()
	}

	return &QueryBuilderMiddleware{
		config: cfg,
	}
}

// Handle processes the request through the QueryBuilder middleware
func (m *QueryBuilderMiddleware) Handle(ctx http.Context, request http.ContextRequest) http.Response {
	// Skip middleware for non-GET requests
	if request.Method() != "GET" {
		return nil
	}

	// Extract query parameters
	filterParams := m.extractFilterParameters(ctx)
	sortParam := ctx.Request().Input("sort", "")
	includeParam := ctx.Request().Input("include", "")
	fieldsParam := ctx.Request().Input("fields", "")

	// Validate parameter counts
	if err := m.validateParameterCounts(filterParams, sortParam, includeParam, fieldsParam); err != nil {
		if m.config.LogInvalidRequests {
			facades.Log().Warning(fmt.Sprintf("QueryBuilder middleware validation failed: %s", err.Error()))
		}
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   fmt.Sprintf("Invalid query parameters: %s", err.Error()),
			Timestamp: time.Now(),
		})
	}

	// Sanitize parameters if enabled
	if m.config.EnableSanitization {
		filterParams = m.sanitizeFilterParameters(filterParams)
		sortParam = m.sanitizeParameter(sortParam)
		includeParam = m.sanitizeParameter(includeParam)
		fieldsParam = m.sanitizeParameter(fieldsParam)
	}

	// Add performance monitoring headers
	m.addPerformanceHeaders(ctx)

	return nil
}

// extractFilterParameters extracts filter parameters from the request
func (m *QueryBuilderMiddleware) extractFilterParameters(ctx http.Context) map[string]interface{} {
	filters := make(map[string]interface{})

	// Extract filter[key]=value parameters
	allParams := ctx.Request().All()
	for key, value := range allParams {
		if strings.HasPrefix(key, "filter[") && strings.HasSuffix(key, "]") {
			filterName := key[7 : len(key)-1] // Remove "filter[" and "]"
			filters[filterName] = value
		}
	}

	return filters
}

// validateParameterCounts validates that parameter counts don't exceed limits
func (m *QueryBuilderMiddleware) validateParameterCounts(filters map[string]interface{}, sort, include, fields string) error {
	// Check filter count
	if len(filters) > m.config.MaxFilters {
		return fmt.Errorf("too many filters (max: %d, provided: %d)", m.config.MaxFilters, len(filters))
	}

	// Check sort count
	if sort != "" {
		sortCount := len(strings.Split(sort, ","))
		if sortCount > m.config.MaxSorts {
			return fmt.Errorf("too many sort fields (max: %d, provided: %d)", m.config.MaxSorts, sortCount)
		}
	}

	// Check include count
	if include != "" {
		includeCount := len(strings.Split(include, ","))
		if includeCount > m.config.MaxIncludes {
			return fmt.Errorf("too many includes (max: %d, provided: %d)", m.config.MaxIncludes, includeCount)
		}
	}

	// Check fields count
	if fields != "" {
		fieldsCount := len(strings.Split(fields, ","))
		if fieldsCount > m.config.MaxFields {
			return fmt.Errorf("too many fields (max: %d, provided: %d)", m.config.MaxFields, fieldsCount)
		}
	}

	return nil
}

// sanitizeFilterParameters sanitizes filter parameters
func (m *QueryBuilderMiddleware) sanitizeFilterParameters(filters map[string]interface{}) map[string]interface{} {
	sanitized := make(map[string]interface{})

	for key, value := range filters {
		sanitizedKey := querybuilder.SanitizeParameterName(key)
		sanitizedValue := querybuilder.SanitizeFilterValue(value)

		if sanitizedKey != "" { // Only include non-empty keys
			sanitized[sanitizedKey] = sanitizedValue
		}
	}

	return sanitized
}

// sanitizeParameter sanitizes a single parameter
func (m *QueryBuilderMiddleware) sanitizeParameter(param string) string {
	if param == "" {
		return ""
	}

	// Split by comma, sanitize each part, and rejoin
	parts := strings.Split(param, ",")
	sanitizedParts := make([]string, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			// Remove direction indicator for sorting, sanitize, then add back
			if strings.HasPrefix(part, "-") {
				sanitized := querybuilder.SanitizeParameterName(part[1:])
				if sanitized != "" {
					sanitizedParts = append(sanitizedParts, "-"+sanitized)
				}
			} else {
				sanitized := querybuilder.SanitizeParameterName(part)
				if sanitized != "" {
					sanitizedParts = append(sanitizedParts, sanitized)
				}
			}
		}
	}

	return strings.Join(sanitizedParts, ",")
}

// addPerformanceHeaders adds performance-related headers to the response
func (m *QueryBuilderMiddleware) addPerformanceHeaders(ctx http.Context) {
	// Add headers that might be useful for debugging and monitoring
	ctx.Response().Header("X-QueryBuilder-Middleware", "enabled")
	ctx.Response().Header("X-QueryBuilder-Version", "1.0")

	// Add timestamp for request processing
	ctx.Response().Header("X-Request-Timestamp", time.Now().UTC().Format(time.RFC3339))
}

// QueryBuilderValidationMiddleware provides validation-specific middleware
type QueryBuilderValidationMiddleware struct {
	config querybuilder.QueryConfig
}

// NewQueryBuilderValidationMiddleware creates validation middleware with specific query config
func NewQueryBuilderValidationMiddleware(config querybuilder.QueryConfig) *QueryBuilderValidationMiddleware {
	return &QueryBuilderValidationMiddleware{
		config: config,
	}
}

// Handle validates query parameters against the provided configuration
func (m *QueryBuilderValidationMiddleware) Handle(ctx http.Context, request http.ContextRequest) http.Response {
	// Skip middleware for non-GET requests
	if request.Method() != "GET" {
		return nil
	}

	// Extract parameters
	filters := make(map[string]interface{})
	allParams := ctx.Request().All()
	for key, value := range allParams {
		if strings.HasPrefix(key, "filter[") && strings.HasSuffix(key, "]") {
			filterName := key[7 : len(key)-1]
			filters[filterName] = value
		}
	}

	sortParam := ctx.Request().Input("sort", "")
	includeParam := ctx.Request().Input("include", "")
	fieldsParam := ctx.Request().Input("fields", "")

	// Validate parameters against configuration
	if err := querybuilder.ValidateQueryParameters(filters, sortParam, includeParam, fieldsParam, m.config); err != nil {
		facades.Log().Warning(fmt.Sprintf("QueryBuilder validation failed: %s", err.Error()))

		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   fmt.Sprintf("Invalid query parameters: %s", err.Error()),
			Timestamp: time.Now(),
		})
	}

	return nil
}

// Example usage documentation
/*
Usage in routes/api.go or similar:

import (
	"goravel/app/http/middleware"
	"goravel/app/querybuilder"
)

// Apply to specific routes
Route.Get("/api/v1/users", "UserController@Index").
	Middleware(middleware.NewQueryBuilderMiddleware()).
	Middleware(middleware.NewQueryBuilderValidationMiddleware(querybuilder.UserConfig()))

// Or register globally in app/http/kernel.go
*/
