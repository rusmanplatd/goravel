package querybuilder

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ValidationError represents a validation error
type ValidationError struct {
	Field   string
	Message string
	Value   interface{}
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("validation error for field '%s': %s (value: %v)", e.Field, e.Message, e.Value)
}

// Validator provides validation methods for query parameters
type Validator struct {
	errors []ValidationError
}

// NewValidator creates a new validator instance
func NewValidator() *Validator {
	return &Validator{
		errors: make([]ValidationError, 0),
	}
}

// AddError adds a validation error
func (v *Validator) AddError(field, message string, value interface{}) {
	v.errors = append(v.errors, ValidationError{
		Field:   field,
		Message: message,
		Value:   value,
	})
}

// HasErrors returns true if there are validation errors
func (v *Validator) HasErrors() bool {
	return len(v.errors) > 0
}

// GetErrors returns all validation errors
func (v *Validator) GetErrors() []ValidationError {
	return v.errors
}

// GetFirstError returns the first validation error
func (v *Validator) GetFirstError() error {
	if len(v.errors) > 0 {
		return v.errors[0]
	}
	return nil
}

// Clear clears all validation errors
func (v *Validator) Clear() {
	v.errors = make([]ValidationError, 0)
}

// ValidateFilterValue validates a filter value based on its type
func (v *Validator) ValidateFilterValue(filter AllowedFilter, value interface{}) bool {
	if value == nil {
		if !filter.Nullable {
			v.AddError(filter.Name, "value cannot be null", value)
			return false
		}
		return true
	}

	valueStr := fmt.Sprintf("%v", value)
	if valueStr == "" && !filter.Nullable {
		v.AddError(filter.Name, "value cannot be empty", value)
		return false
	}

	switch filter.Type {
	case FilterTypeGreaterThan, FilterTypeLessThan, FilterTypeGreaterEqual, FilterTypeLessEqual:
		return v.validateNumericValue(filter.Name, valueStr)
	case FilterTypeBetween:
		return v.validateBetweenValue(filter.Name, valueStr)
	case FilterTypeIn, FilterTypeNotIn:
		return v.validateArrayValue(filter.Name, valueStr)
	case FilterTypeDateRange:
		return v.validateDateRangeValue(filter.Name, valueStr)
	case FilterTypeRegex:
		return v.validateRegexValue(filter.Name, valueStr)
	case FilterTypePartial, FilterTypeExact, FilterTypeBeginsWith, FilterTypeEndsWith:
		return v.validateStringValue(filter.Name, valueStr)
	case FilterTypeJsonContains, FilterTypeJsonExtract:
		return v.validateJsonValue(filter.Name, valueStr)
	case FilterTypeGeoDistance:
		return v.validateGeoValue(filter.Name, valueStr)
	case FilterTypeArrayContains:
		return v.validateArrayContainsValue(filter.Name, valueStr)
	}

	return true
}

// ValidateSort validates a sort parameter
func (v *Validator) ValidateSort(sortParam string, allowedSorts []AllowedSort) bool {
	if sortParam == "" {
		return true
	}

	sorts := strings.Split(sortParam, ",")
	for _, sort := range sorts {
		sort = strings.TrimSpace(sort)
		if sort == "" {
			continue
		}

		// Remove direction prefix
		field := sort
		if strings.HasPrefix(sort, "-") || strings.HasPrefix(sort, "+") {
			field = sort[1:]
		}

		// Check if sort is allowed
		if !v.isSortAllowed(field, allowedSorts) {
			v.AddError("sort", fmt.Sprintf("sort field '%s' is not allowed", field), sort)
			return false
		}

		// Validate field name format
		if !v.isValidFieldName(field) {
			v.AddError("sort", fmt.Sprintf("invalid sort field name '%s'", field), sort)
			return false
		}
	}

	return true
}

// ValidateInclude validates an include parameter
func (v *Validator) ValidateInclude(includeParam string, allowedIncludes []AllowedInclude) bool {
	if includeParam == "" {
		return true
	}

	includes := strings.Split(includeParam, ",")
	for _, include := range includes {
		include = strings.TrimSpace(include)
		if include == "" {
			continue
		}

		// Handle count and exists suffixes
		baseName := include
		if strings.HasSuffix(include, "Count") {
			baseName = strings.TrimSuffix(include, "Count")
		} else if strings.HasSuffix(include, "Exists") {
			baseName = strings.TrimSuffix(include, "Exists")
		}

		// Check if include is allowed
		if !v.isIncludeAllowed(baseName, allowedIncludes) {
			v.AddError("include", fmt.Sprintf("include '%s' is not allowed", include), include)
			return false
		}

		// Validate relationship name format
		if !v.isValidRelationshipName(baseName) {
			v.AddError("include", fmt.Sprintf("invalid include name '%s'", include), include)
			return false
		}
	}

	return true
}

// ValidateFields validates a fields parameter
func (v *Validator) ValidateFields(fieldsParam string, allowedFields []AllowedField) bool {
	if fieldsParam == "" {
		return true
	}

	fields := strings.Split(fieldsParam, ",")
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}

		// Check if field is allowed
		if !v.isFieldAllowed(field, allowedFields) {
			v.AddError("fields", fmt.Sprintf("field '%s' is not allowed", field), field)
			return false
		}

		// Validate field name format
		if !v.isValidFieldName(field) {
			v.AddError("fields", fmt.Sprintf("invalid field name '%s'", field), field)
			return false
		}
	}

	return true
}

// ValidatePagination validates pagination parameters
func (v *Validator) ValidatePagination(page, limit int, maxLimit int) bool {
	if page < 1 {
		v.AddError("page", "page must be greater than 0", page)
		return false
	}

	if limit < 1 {
		v.AddError("limit", "limit must be greater than 0", limit)
		return false
	}

	if limit > maxLimit {
		v.AddError("limit", fmt.Sprintf("limit cannot exceed %d", maxLimit), limit)
		return false
	}

	return true
}

// ValidateQueryOptions validates query options for security
func (v *Validator) ValidateQueryOptions(options *QueryOptions) bool {
	if options == nil {
		return true
	}

	if options.MaxFilterDepth < 1 || options.MaxFilterDepth > 10 {
		v.AddError("options", "max filter depth must be between 1 and 10", options.MaxFilterDepth)
		return false
	}

	if options.MaxFilterConditions < 1 || options.MaxFilterConditions > 100 {
		v.AddError("options", "max filter conditions must be between 1 and 100", options.MaxFilterConditions)
		return false
	}

	if options.MaxJoinDepth < 1 || options.MaxJoinDepth > 5 {
		v.AddError("options", "max join depth must be between 1 and 5", options.MaxJoinDepth)
		return false
	}

	if options.MaxSubQueryDepth < 1 || options.MaxSubQueryDepth > 5 {
		v.AddError("options", "max subquery depth must be between 1 and 5", options.MaxSubQueryDepth)
		return false
	}

	if options.QueryTimeout < 1 || options.QueryTimeout > 300 {
		v.AddError("options", "query timeout must be between 1 and 300 seconds", options.QueryTimeout)
		return false
	}

	return true
}

// Private validation methods

// validateNumericValue validates numeric filter values
func (v *Validator) validateNumericValue(field, value string) bool {
	if _, err := strconv.ParseFloat(value, 64); err != nil {
		v.AddError(field, "value must be a valid number", value)
		return false
	}
	return true
}

// validateBetweenValue validates a between filter value (should be comma-separated)
func (v *Validator) validateBetweenValue(field, value string) bool {
	if !strings.Contains(value, ",") {
		v.AddError(field, "between value must contain comma-separated min and max values", value)
		return false
	}

	parts := strings.Split(value, ",")
	if len(parts) != 2 {
		v.AddError(field, "between value must contain exactly two comma-separated values", value)
		return false
	}

	// Validation - ensure it's not just commas
	for i, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			v.AddError(field, "between values cannot be empty", value)
			return false
		}

		// Validate that both parts are numeric
		if _, err := strconv.ParseFloat(part, 64); err != nil {
			v.AddError(field, fmt.Sprintf("between value part %d must be a valid number", i+1), part)
			return false
		}
	}

	return true
}

// validateArrayValue validates array filter values (comma-separated)
func (v *Validator) validateArrayValue(field, value string) bool {
	if value == "" {
		v.AddError(field, "array value cannot be empty", value)
		return false
	}

	parts := strings.Split(value, ",")
	if len(parts) == 0 {
		v.AddError(field, "array value must contain at least one item", value)
		return false
	}

	// Check for empty values
	for _, part := range parts {
		if strings.TrimSpace(part) == "" {
			v.AddError(field, "array values cannot contain empty items", value)
			return false
		}
	}

	// Limit array size for security
	if len(parts) > 100 {
		v.AddError(field, "array cannot contain more than 100 items", len(parts))
		return false
	}

	return true
}

// validateDateRangeValue validates date range filter values
func (v *Validator) validateDateRangeValue(field, value string) bool {
	if !strings.Contains(value, ",") {
		v.AddError(field, "date range must contain comma-separated start and end dates", value)
		return false
	}

	parts := strings.Split(value, ",")
	if len(parts) != 2 {
		v.AddError(field, "date range must contain exactly two comma-separated dates", value)
		return false
	}

	// Validate date formats
	for i, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			v.AddError(field, "date range values cannot be empty", value)
			return false
		}

		// Try common date formats
		dateFormats := []string{
			"2006-01-02",
			"2006-01-02 15:04:05",
			"2006-01-02T15:04:05Z",
			"2006-01-02T15:04:05-07:00",
		}

		validDate := false
		for _, format := range dateFormats {
			if _, err := time.Parse(format, part); err == nil {
				validDate = true
				break
			}
		}

		if !validDate {
			v.AddError(field, fmt.Sprintf("date range part %d has invalid date format", i+1), part)
			return false
		}
	}

	return true
}

// validateRegexValue validates regex filter values
func (v *Validator) validateRegexValue(field, value string) bool {
	if _, err := regexp.Compile(value); err != nil {
		v.AddError(field, fmt.Sprintf("invalid regular expression: %v", err), value)
		return false
	}

	// Security check - prevent potentially dangerous regex patterns
	dangerousPatterns := []string{
		`.*.*.*.*.*`, // Catastrophic backtracking
		`(.*){10,}`,  // Excessive repetition
		`(.+)+$`,     // Nested quantifiers
	}

	for _, pattern := range dangerousPatterns {
		if matched, _ := regexp.MatchString(pattern, value); matched {
			v.AddError(field, "regex pattern may cause performance issues", value)
			return false
		}
	}

	return true
}

// validateStringValue validates a string filter value
func (v *Validator) validateStringValue(field, value string) bool {
	// String validation - could be extended with length limits, etc.
	if len(value) > 1000 { // Example limit
		v.AddError(field, "string value too long (max 1000 characters)", value)
		return false
	}

	// Check for potentially malicious content
	if v.containsSqlInjection(value) {
		v.AddError(field, "value contains potentially malicious content", value)
		return false
	}

	return true
}

// validateJsonValue validates JSON filter values
func (v *Validator) validateJsonValue(field, value string) bool {
	if len(value) > 5000 {
		v.AddError(field, "JSON value too long (max 5000 characters)", value)
		return false
	}

	// Check for valid JSON structure (simplified)
	if !strings.HasPrefix(value, "{") && !strings.HasPrefix(value, "[") && !strings.HasPrefix(value, "\"") {
		v.AddError(field, "value must be valid JSON", value)
		return false
	}

	return true
}

// validateGeoValue validates geographic distance filter values
func (v *Validator) validateGeoValue(field, value string) bool {
	parts := strings.Split(value, ",")
	if len(parts) != 3 {
		v.AddError(field, "geo distance must contain latitude,longitude,distance", value)
		return false
	}

	// Validate latitude
	if lat, err := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64); err != nil {
		v.AddError(field, "invalid latitude value", parts[0])
		return false
	} else if lat < -90 || lat > 90 {
		v.AddError(field, "latitude must be between -90 and 90", lat)
		return false
	}

	// Validate longitude
	if lng, err := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64); err != nil {
		v.AddError(field, "invalid longitude value", parts[1])
		return false
	} else if lng < -180 || lng > 180 {
		v.AddError(field, "longitude must be between -180 and 180", lng)
		return false
	}

	// Validate distance
	if dist, err := strconv.ParseFloat(strings.TrimSpace(parts[2]), 64); err != nil {
		v.AddError(field, "invalid distance value", parts[2])
		return false
	} else if dist <= 0 || dist > 20000 { // Max ~half Earth circumference
		v.AddError(field, "distance must be between 0 and 20000 km", dist)
		return false
	}

	return true
}

// validateArrayContainsValue validates array contains filter values
func (v *Validator) validateArrayContainsValue(field, value string) bool {
	if len(value) > 1000 {
		v.AddError(field, "array contains value too long (max 1000 characters)", value)
		return false
	}

	// Check for potentially malicious content
	if v.containsSqlInjection(value) {
		v.AddError(field, "value contains potentially malicious content", value)
		return false
	}

	return true
}

// Helper methods

// isSortAllowed checks if a sort field is allowed
func (v *Validator) isSortAllowed(field string, allowedSorts []AllowedSort) bool {
	if len(allowedSorts) == 0 {
		return true // No restrictions
	}

	for _, sort := range allowedSorts {
		if sort.Name == field {
			return true
		}
	}
	return false
}

// isIncludeAllowed checks if an include is allowed
func (v *Validator) isIncludeAllowed(include string, allowedIncludes []AllowedInclude) bool {
	if len(allowedIncludes) == 0 {
		return true // No restrictions
	}

	for _, allowed := range allowedIncludes {
		if allowed.Name == include {
			return true
		}
	}
	return false
}

// isFieldAllowed checks if a field is allowed
func (v *Validator) isFieldAllowed(field string, allowedFields []AllowedField) bool {
	if len(allowedFields) == 0 {
		return true // No restrictions
	}

	for _, allowed := range allowedFields {
		if allowed.Name == field {
			return true
		}
	}
	return false
}

// isValidFieldName validates field name format
func (v *Validator) isValidFieldName(field string) bool {
	// Allow alphanumeric, underscore, and dot (for nested fields)
	matched, _ := regexp.MatchString(`^[a-zA-Z][a-zA-Z0-9_.]*$`, field)
	return matched && len(field) <= 100
}

// isValidRelationshipName validates relationship name format
func (v *Validator) isValidRelationshipName(name string) bool {
	// Allow alphanumeric, underscore, and dot (for nested relationships)
	matched, _ := regexp.MatchString(`^[a-zA-Z][a-zA-Z0-9_.]*$`, name)
	return matched && len(name) <= 100
}

// containsSqlInjection checks for potential SQL injection patterns
func (v *Validator) containsSqlInjection(value string) bool {
	lowerValue := strings.ToLower(value)

	// Common SQL injection patterns
	patterns := []string{
		"'", "\"", ";", "--", "/*", "*/",
		"union", "select", "insert", "update", "delete", "drop",
		"exec", "execute", "sp_", "xp_",
	}

	for _, pattern := range patterns {
		if strings.Contains(lowerValue, pattern) {
			return true
		}
	}

	return false
}

// ValidateQueryParameters validates all query parameters together
func ValidateQueryParameters(filters map[string]interface{}, sortParam, includeParam, fieldsParam string, config QueryConfig) error {
	validator := NewValidator()

	// Validate filters
	for name, value := range filters {
		var allowedFilter *AllowedFilter
		for _, filter := range config.AllowedFilters {
			if filter.Name == name {
				allowedFilter = &filter
				break
			}
		}

		if allowedFilter == nil {
			validator.AddError(name, "filter is not allowed", value)
			continue
		}

		validator.ValidateFilterValue(*allowedFilter, value)
	}

	// Validate sort
	validator.ValidateSort(sortParam, config.AllowedSorts)

	// Validate include
	validator.ValidateInclude(includeParam, config.AllowedIncludes)

	// Validate fields
	validator.ValidateFields(fieldsParam, config.AllowedFields)

	if validator.HasErrors() {
		return fmt.Errorf("validation failed: %v", validator.GetErrors())
	}

	return nil
}

// SanitizeFilterValue sanitizes a filter value
func SanitizeFilterValue(value interface{}) interface{} {
	if value == nil {
		return nil
	}

	valueStr, ok := value.(string)
	if !ok {
		return value
	}

	// Remove potentially dangerous characters
	valueStr = strings.ReplaceAll(valueStr, "'", "")
	valueStr = strings.ReplaceAll(valueStr, "\"", "")
	valueStr = strings.ReplaceAll(valueStr, ";", "")
	valueStr = strings.ReplaceAll(valueStr, "--", "")
	valueStr = strings.ReplaceAll(valueStr, "/*", "")
	valueStr = strings.ReplaceAll(valueStr, "*/", "")

	// Trim whitespace
	valueStr = strings.TrimSpace(valueStr)

	return valueStr
}

// SanitizeParameterName sanitizes a parameter name
func SanitizeParameterName(name string) string {
	// Allow only alphanumeric and underscore
	reg := regexp.MustCompile(`[^a-zA-Z0-9_]`)
	return reg.ReplaceAllString(name, "")
}
