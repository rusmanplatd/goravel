package services

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/goravel/framework/contracts/database/orm"
)

// ProjectFilterService provides GitHub Projects-style advanced filtering
type ProjectFilterService struct{}

func NewProjectFilterService() *ProjectFilterService {
	return &ProjectFilterService{}
}

// FilterExpression represents a parsed filter expression
type FilterExpression struct {
	Field    string
	Operator string
	Value    interface{}
	Negate   bool
}

// ApplyFilters applies GitHub Projects-style filters to a query
func (pfs *ProjectFilterService) ApplyFilters(query orm.Query, filterString string, model string) (orm.Query, error) {
	if filterString == "" {
		return query, nil
	}

	expressions, err := pfs.parseFilterString(filterString)
	if err != nil {
		return query, err
	}

	for _, expr := range expressions {
		query, err = pfs.applyFilterExpression(query, expr, model)
		if err != nil {
			return query, err
		}
	}

	return query, nil
}

// parseFilterString parses GitHub Projects-style filter syntax
func (pfs *ProjectFilterService) parseFilterString(filterString string) ([]FilterExpression, error) {
	var expressions []FilterExpression

	// Split by spaces but preserve quoted strings
	parts := pfs.splitFilterString(filterString)

	for _, part := range parts {
		if part == "" {
			continue
		}

		expr, err := pfs.parseFilterExpression(part)
		if err != nil {
			return nil, err
		}

		expressions = append(expressions, expr)
	}

	return expressions, nil
}

// splitFilterString splits filter string while preserving quoted values
func (pfs *ProjectFilterService) splitFilterString(input string) []string {
	var parts []string
	var current strings.Builder
	inQuotes := false
	quoteChar := byte(0)

	for i := 0; i < len(input); i++ {
		char := input[i]

		if !inQuotes && (char == '"' || char == '\'') {
			inQuotes = true
			quoteChar = char
			continue
		}

		if inQuotes && char == quoteChar {
			inQuotes = false
			quoteChar = 0
			continue
		}

		if !inQuotes && char == ' ' {
			if current.Len() > 0 {
				parts = append(parts, current.String())
				current.Reset()
			}
			continue
		}

		current.WriteByte(char)
	}

	if current.Len() > 0 {
		parts = append(parts, current.String())
	}

	return parts
}

// parseFilterExpression parses a single filter expression
func (pfs *ProjectFilterService) parseFilterExpression(expr string) (FilterExpression, error) {
	var filter FilterExpression

	// Check for negation
	if strings.HasPrefix(expr, "-") || strings.HasPrefix(expr, "!") {
		filter.Negate = true
		expr = expr[1:]
	}

	// Parse different filter patterns
	operators := []string{">=", "<=", "!=", "=", ">", "<", ":", "~"}

	for _, op := range operators {
		if idx := strings.Index(expr, op); idx != -1 {
			filter.Field = strings.TrimSpace(expr[:idx])
			filter.Operator = op
			filter.Value = strings.TrimSpace(expr[idx+len(op):])

			// Convert value to appropriate type
			filter.Value = pfs.convertValue(filter.Value, filter.Field)
			return filter, nil
		}
	}

	// If no operator found, treat as field existence check
	filter.Field = expr
	filter.Operator = "exists"
	return filter, nil
}

// convertValue converts string values to appropriate types
func (pfs *ProjectFilterService) convertValue(value interface{}, field string) interface{} {
	strValue, ok := value.(string)
	if !ok {
		return value
	}

	// Handle special values
	switch strings.ToLower(strValue) {
	case "true":
		return true
	case "false":
		return false
	case "null", "nil", "none":
		return nil
	case "today":
		return time.Now().Format("2006-01-02")
	case "yesterday":
		return time.Now().AddDate(0, 0, -1).Format("2006-01-02")
	case "tomorrow":
		return time.Now().AddDate(0, 0, 1).Format("2006-01-02")
	}

	// Handle relative dates
	if strings.HasPrefix(strValue, "@") {
		return pfs.parseRelativeDate(strValue[1:])
	}

	// Try to parse as number
	if intVal, err := strconv.Atoi(strValue); err == nil {
		return intVal
	}

	// Try to parse as float
	if floatVal, err := strconv.ParseFloat(strValue, 64); err == nil {
		return floatVal
	}

	// Try to parse as date
	if dateVal, err := time.Parse("2006-01-02", strValue); err == nil {
		return dateVal.Format("2006-01-02")
	}

	// Return as string
	return strValue
}

// parseRelativeDate parses relative date expressions
func (pfs *ProjectFilterService) parseRelativeDate(expr string) string {
	now := time.Now()

	// Handle patterns like "1d", "2w", "3m", "1y"
	re := regexp.MustCompile(`^(\d+)([dwmy])$`)
	matches := re.FindStringSubmatch(expr)

	if len(matches) == 3 {
		num, _ := strconv.Atoi(matches[1])
		unit := matches[2]

		switch unit {
		case "d":
			return now.AddDate(0, 0, num).Format("2006-01-02")
		case "w":
			return now.AddDate(0, 0, num*7).Format("2006-01-02")
		case "m":
			return now.AddDate(0, num, 0).Format("2006-01-02")
		case "y":
			return now.AddDate(num, 0, 0).Format("2006-01-02")
		}
	}

	return expr
}

// applyFilterExpression applies a single filter expression to the query
func (pfs *ProjectFilterService) applyFilterExpression(query orm.Query, expr FilterExpression, model string) (orm.Query, error) {
	field := pfs.mapFieldName(expr.Field, model)

	switch expr.Operator {
	case "=", ":":
		if expr.Negate {
			if expr.Value == nil {
				return query.WhereNotNull(field), nil
			}
			return query.Where(field+" != ?", expr.Value), nil
		}
		if expr.Value == nil {
			return query.WhereNull(field), nil
		}
		return query.Where(field+" = ?", expr.Value), nil

	case "!=":
		if expr.Negate {
			if expr.Value == nil {
				return query.WhereNull(field), nil
			}
			return query.Where(field+" = ?", expr.Value), nil
		}
		if expr.Value == nil {
			return query.WhereNotNull(field), nil
		}
		return query.Where(field+" != ?", expr.Value), nil

	case ">":
		if expr.Negate {
			return query.Where(field+" <= ?", expr.Value), nil
		}
		return query.Where(field+" > ?", expr.Value), nil

	case ">=":
		if expr.Negate {
			return query.Where(field+" < ?", expr.Value), nil
		}
		return query.Where(field+" >= ?", expr.Value), nil

	case "<":
		if expr.Negate {
			return query.Where(field+" >= ?", expr.Value), nil
		}
		return query.Where(field+" < ?", expr.Value), nil

	case "<=":
		if expr.Negate {
			return query.Where(field+" > ?", expr.Value), nil
		}
		return query.Where(field+" <= ?", expr.Value), nil

	case "~":
		if expr.Negate {
			return query.Where(field+" NOT LIKE ?", "%"+fmt.Sprintf("%v", expr.Value)+"%"), nil
		}
		return query.Where(field+" LIKE ?", "%"+fmt.Sprintf("%v", expr.Value)+"%"), nil

	case "exists":
		if expr.Negate {
			return query.WhereNull(field), nil
		}
		return query.WhereNotNull(field), nil

	default:
		return query, fmt.Errorf("unsupported operator: %s", expr.Operator)
	}
}

// mapFieldName maps GitHub Projects-style field names to database columns
func (pfs *ProjectFilterService) mapFieldName(field, model string) string {
	fieldMappings := map[string]map[string]string{
		"project": {
			"name":        "name",
			"title":       "name",
			"description": "description",
			"status":      "status",
			"state":       "state",
			"priority":    "priority",
			"visibility":  "visibility",
			"owner":       "owner_id",
			"manager":     "project_manager_id",
			"created":     "created_at",
			"updated":     "updated_at",
			"closed":      "closed_at",
			"archived":    "archived_at",
			"active":      "is_active",
			"template":    "is_template",
			"progress":    "progress",
			"budget":      "budget",
		},
		"task": {
			"title":       "title",
			"description": "description",
			"status":      "status",
			"priority":    "priority",
			"assignee":    "assignee_id",
			"created":     "created_at",
			"updated":     "updated_at",
			"due":         "due_date",
			"completed":   "completed_at",
			"progress":    "progress",
			"type":        "type",
			"milestone":   "milestone_id",
			"iteration":   "iteration_id",
		},
		"roadmap": {
			"title":       "title",
			"description": "description",
			"type":        "type",
			"status":      "status",
			"start":       "start_date",
			"target":      "target_date",
			"completed":   "completed_at",
			"progress":    "progress",
			"parent":      "parent_id",
			"position":    "position",
		},
	}

	if modelMappings, exists := fieldMappings[model]; exists {
		if dbField, exists := modelMappings[field]; exists {
			return dbField
		}
	}

	// Return the field as-is if no mapping found
	return field
}

// GetAvailableFilters returns available filters for a model
func (pfs *ProjectFilterService) GetAvailableFilters(model string) map[string]interface{} {
	filters := map[string]map[string]interface{}{
		"project": {
			"fields":    []string{"name", "title", "description", "status", "state", "priority", "visibility", "owner", "manager", "created", "updated", "closed", "archived", "active", "template", "progress", "budget"},
			"operators": []string{"=", "!=", ">", ">=", "<", "<=", "~", ":"},
			"examples": []string{
				"status:active",
				"state:open",
				"priority:high",
				"owner:@me",
				"created:@7d",
				"progress>50",
				"name~portal",
				"-archived:true",
			},
		},
		"task": {
			"fields":    []string{"title", "description", "status", "priority", "assignee", "created", "updated", "due", "completed", "progress", "type", "milestone", "iteration"},
			"operators": []string{"=", "!=", ">", ">=", "<", "<=", "~", ":"},
			"examples": []string{
				"status:todo",
				"priority:high",
				"assignee:@me",
				"due<@7d",
				"progress>=50",
				"title~bug",
				"-completed:null",
			},
		},
		"roadmap": {
			"fields":    []string{"title", "description", "type", "status", "start", "target", "completed", "progress", "parent", "position"},
			"operators": []string{"=", "!=", ">", ">=", "<", "<=", "~", ":"},
			"examples": []string{
				"type:milestone",
				"status:in_progress",
				"target<@30d",
				"progress>=75",
				"parent:null",
				"title~release",
			},
		},
	}

	if modelFilters, exists := filters[model]; exists {
		return modelFilters
	}

	return map[string]interface{}{
		"fields":    []string{},
		"operators": []string{"=", "!=", ">", ">=", "<", "<=", "~", ":"},
		"examples":  []string{},
	}
}

// ValidateFilterString validates a filter string syntax
func (pfs *ProjectFilterService) ValidateFilterString(filterString string) error {
	if filterString == "" {
		return nil
	}

	_, err := pfs.parseFilterString(filterString)
	return err
}

// BuildFilterSuggestions builds filter suggestions based on partial input
func (pfs *ProjectFilterService) BuildFilterSuggestions(partial string, model string) []map[string]interface{} {
	var suggestions []map[string]interface{}

	availableFilters := pfs.GetAvailableFilters(model)
	fields, _ := availableFilters["fields"].([]string)
	examples, _ := availableFilters["examples"].([]string)

	// If partial is empty, return common examples
	if partial == "" {
		for _, example := range examples {
			suggestions = append(suggestions, map[string]interface{}{
				"text":        example,
				"type":        "example",
				"description": "Example filter",
			})
		}
		return suggestions
	}

	// If partial contains a field name, suggest operators
	for _, field := range fields {
		if strings.HasPrefix(partial, field) {
			operators := []string{":", "=", "!=", ">", ">=", "<", "<=", "~"}
			for _, op := range operators {
				suggestions = append(suggestions, map[string]interface{}{
					"text":        field + op,
					"type":        "operator",
					"description": fmt.Sprintf("Filter by %s using %s", field, op),
				})
			}
			break
		}
	}

	// Suggest field names that match partial
	for _, field := range fields {
		if strings.HasPrefix(field, partial) {
			suggestions = append(suggestions, map[string]interface{}{
				"text":        field + ":",
				"type":        "field",
				"description": fmt.Sprintf("Filter by %s", field),
			})
		}
	}

	return suggestions
}
