package querybuilder

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/goravel/framework/contracts/database/orm"
	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"
)

// QueryBuilder provides a fluent interface for building database queries from HTTP requests
type QueryBuilder struct {
	query            orm.Query
	request          http.Context
	allowedFilters   []AllowedFilter
	allowedSorts     []AllowedSort
	allowedIncludes  []AllowedInclude
	allowedFields    []AllowedField
	defaultSorts     []DefaultSort
	config           *Config
	paginationConfig *PaginationConfig
	cache            *Cache

	// Extended features
	options          *QueryOptions
	aggregates       []AggregateField
	groupBy          *GroupByClause
	windowFunctions  []WindowFunction
	joins            []JoinClause
	subQueries       []SubQuery
	filters          []FilterGroup
	rawSelects       []string
	havingConditions []FilterCondition
}

// Config holds configuration options for the query builder
type Config struct {
	FilterParameter  string
	SortParameter    string
	IncludeParameter string
	FieldsParameter  string
	CountSuffix      string
	ExistsSuffix     string

	// Security options
	DisableInvalidFilterException  bool
	DisableInvalidSortException    bool
	DisableInvalidIncludeException bool
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	return &Config{
		FilterParameter:  "filter",
		SortParameter:    "sort",
		IncludeParameter: "include",
		FieldsParameter:  "fields",
		CountSuffix:      "Count",
		ExistsSuffix:     "Exists",

		DisableInvalidFilterException:  false,
		DisableInvalidSortException:    false,
		DisableInvalidIncludeException: false,
	}
}

// For creates a new QueryBuilder instance for the given model or query
func For(subject interface{}) *QueryBuilder {
	var query orm.Query

	switch v := subject.(type) {
	case orm.Query:
		query = v
	case string:
		// Model class name
		query = facades.Orm().Query().Model(subject)
	default:
		// Assume it's a model instance
		query = facades.Orm().Query().Model(subject)
	}

	return &QueryBuilder{
		query:           query,
		allowedFilters:  make([]AllowedFilter, 0),
		allowedSorts:    make([]AllowedSort, 0),
		allowedIncludes: make([]AllowedInclude, 0),
		allowedFields:   make([]AllowedField, 0),
		defaultSorts:    make([]DefaultSort, 0),
		config:          DefaultConfig(),

		// Initialize extended features
		options:          DefaultQueryOptions(),
		aggregates:       make([]AggregateField, 0),
		windowFunctions:  make([]WindowFunction, 0),
		joins:            make([]JoinClause, 0),
		subQueries:       make([]SubQuery, 0),
		filters:          make([]FilterGroup, 0),
		rawSelects:       make([]string, 0),
		havingConditions: make([]FilterCondition, 0),
	}
}

// WithRequest sets the HTTP request context for parsing query parameters
func (qb *QueryBuilder) WithRequest(ctx http.Context) *QueryBuilder {
	qb.request = ctx
	return qb
}

// WithConfig sets a custom configuration
func (qb *QueryBuilder) WithConfig(config *Config) *QueryBuilder {
	qb.config = config
	return qb
}

// WithPaginationConfig sets a custom pagination configuration
func (qb *QueryBuilder) WithPaginationConfig(config *PaginationConfig) *QueryBuilder {
	qb.paginationConfig = config
	return qb
}

// AllowedFilters specifies which filters are allowed
func (qb *QueryBuilder) AllowedFilters(filters ...interface{}) *QueryBuilder {
	for _, filter := range filters {
		switch f := filter.(type) {
		case string:
			// Convert string to partial filter by default
			qb.allowedFilters = append(qb.allowedFilters, AllowedFilter{
				Name:     f,
				Property: f,
				Type:     FilterTypePartial,
			})
		case AllowedFilter:
			qb.allowedFilters = append(qb.allowedFilters, f)
		}
	}
	return qb
}

// AllowedSorts specifies which sorts are allowed
func (qb *QueryBuilder) AllowedSorts(sorts ...interface{}) *QueryBuilder {
	for _, sort := range sorts {
		switch s := sort.(type) {
		case string:
			qb.allowedSorts = append(qb.allowedSorts, AllowedSort{
				Name:     s,
				Property: s,
			})
		case AllowedSort:
			qb.allowedSorts = append(qb.allowedSorts, s)
		}
	}
	return qb
}

// AllowedIncludes specifies which relationships can be included
func (qb *QueryBuilder) AllowedIncludes(includes ...interface{}) *QueryBuilder {
	for _, include := range includes {
		switch i := include.(type) {
		case string:
			qb.allowedIncludes = append(qb.allowedIncludes, AllowedInclude{
				Name:         i,
				Relationship: i,
			})
		case AllowedInclude:
			qb.allowedIncludes = append(qb.allowedIncludes, i)
		}
	}
	return qb
}

// AllowedFields specifies which fields can be selected
func (qb *QueryBuilder) AllowedFields(fields ...interface{}) *QueryBuilder {
	for _, field := range fields {
		switch f := field.(type) {
		case string:
			qb.allowedFields = append(qb.allowedFields, AllowedField{
				Name: f,
			})
		case AllowedField:
			qb.allowedFields = append(qb.allowedFields, f)
		case []string:
			for _, fieldName := range f {
				qb.allowedFields = append(qb.allowedFields, AllowedField{
					Name: fieldName,
				})
			}
		}
	}
	return qb
}

// DefaultSort sets default sorting when no sort is specified
func (qb *QueryBuilder) DefaultSort(sorts ...interface{}) *QueryBuilder {
	for _, sort := range sorts {
		switch s := sort.(type) {
		case string:
			direction := "asc"
			field := s
			if strings.HasPrefix(s, "-") {
				direction = "desc"
				field = s[1:]
			}
			qb.defaultSorts = append(qb.defaultSorts, DefaultSort{
				Field:     field,
				Direction: direction,
			})
		case DefaultSort:
			qb.defaultSorts = append(qb.defaultSorts, s)
		}
	}
	return qb
}

// Build applies all query parameters and returns the final query
func (qb *QueryBuilder) Build() orm.Query {
	if qb.request == nil {
		return qb.query
	}

	// Apply filters
	qb.applyFilters()

	// Apply sorts
	qb.applySorts()

	// Apply includes
	qb.applyIncludes()

	// Apply field selection
	qb.applyFields()

	return qb.query
}

// Get executes the query and returns results
func (qb *QueryBuilder) Get(dest interface{}) error {
	return qb.Build().Find(dest)
}

// First executes the query and returns the first result
func (qb *QueryBuilder) First(dest interface{}) error {
	return qb.Build().First(dest)
}

// Paginate applies pagination and returns paginated results (legacy method - use OffsetPaginate instead)
func (qb *QueryBuilder) Paginate(page, limit int, dest interface{}) error {
	offset := (page - 1) * limit
	return qb.Build().Offset(offset).Limit(limit).Find(dest)
}

// PaginateWithResult applies pagination and returns both results and pagination info
func (qb *QueryBuilder) PaginateWithResult(page, limit int, dest interface{}) (*OffsetPaginationResult, error) {
	config := qb.getPaginationConfig()

	// Apply constraints
	if page < 1 {
		page = 1
	}
	if limit <= 0 {
		limit = config.DefaultLimit
	}
	if limit > config.MaxLimit {
		limit = config.MaxLimit
	}

	// Get total count first
	countQuery := qb.Build()
	total, err := countQuery.Count()
	if err != nil {
		return nil, err
	}

	// Calculate pagination values
	offset := (page - 1) * limit
	lastPage := int((total + int64(limit) - 1) / int64(limit)) // Ceiling division
	if lastPage < 1 {
		lastPage = 1
	}

	// Build and execute paginated query
	query := qb.Build()
	query = query.Offset(offset).Limit(limit)
	err = query.Find(dest)
	if err != nil {
		return nil, err
	}

	// Calculate result metrics
	resultCount := qb.getResultCount(dest)
	from := 0
	to := 0
	if resultCount > 0 {
		from = offset + 1
		to = offset + resultCount
	}

	return &OffsetPaginationResult{
		Data: dest,
		Pagination: &PaginationInfo{
			Type:        "offset",
			Count:       resultCount,
			Limit:       limit,
			HasNext:     page < lastPage,
			HasPrev:     page > 1,
			CurrentPage: &page,
			LastPage:    &lastPage,
			PerPage:     &limit,
			Total:       &total,
			From:        &from,
			To:          &to,
		},
	}, nil
}

// Count returns the count of matching records
func (qb *QueryBuilder) Count() (int64, error) {
	return qb.Build().Count()
}

// applyFilters processes filter query parameters
func (qb *QueryBuilder) applyFilters() {
	if qb.request == nil {
		return
	}

	// Parse filter parameters
	filters := qb.parseFilters()

	for filterName, filterValue := range filters {
		allowedFilter := qb.findAllowedFilter(filterName)
		if allowedFilter == nil {
			if !qb.config.DisableInvalidFilterException {
				facades.Log().Warning(fmt.Sprintf("Filter '%s' is not allowed", filterName))
			}
			continue
		}

		qb.applyFilter(*allowedFilter, filterValue)
	}
}

// applySorts processes sort query parameters
func (qb *QueryBuilder) applySorts() {
	if qb.request == nil {
		// Apply default sorts if no request context
		qb.applyDefaultSorts()
		return
	}

	sortParam := qb.request.Request().Input(qb.config.SortParameter, "")
	if sortParam == "" {
		qb.applyDefaultSorts()
		return
	}

	sorts := strings.Split(sortParam, ",")
	appliedAnySort := false

	for _, sort := range sorts {
		sort = strings.TrimSpace(sort)
		if sort == "" {
			continue
		}

		direction := "asc"
		field := sort
		if strings.HasPrefix(sort, "-") {
			direction = "desc"
			field = sort[1:]
		}

		allowedSort := qb.findAllowedSort(field)
		if allowedSort == nil {
			if !qb.config.DisableInvalidSortException {
				facades.Log().Warning(fmt.Sprintf("Sort '%s' is not allowed", field))
			}
			continue
		}

		qb.query = qb.query.Order(fmt.Sprintf("%s %s", allowedSort.Property, direction))
		appliedAnySort = true
	}

	// Apply default sorts if no valid sorts were applied
	if !appliedAnySort {
		qb.applyDefaultSorts()
	}
}

// applyIncludes processes include query parameters
func (qb *QueryBuilder) applyIncludes() {
	if qb.request == nil {
		return
	}

	includeParam := qb.request.Request().Input(qb.config.IncludeParameter, "")
	if includeParam == "" {
		return
	}

	includes := strings.Split(includeParam, ",")

	for _, include := range includes {
		include = strings.TrimSpace(include)
		if include == "" {
			continue
		}

		// Handle count and exists suffixes - Note: WithCount not available in Goravel ORM
		if strings.HasSuffix(include, qb.config.CountSuffix) {
			relationName := strings.TrimSuffix(include, qb.config.CountSuffix)
			allowedInclude := qb.findAllowedInclude(relationName)
			if allowedInclude != nil {
				facades.Log().Warning(fmt.Sprintf("WithCount for '%s' not supported in current ORM version", relationName))
			}
			continue
		}

		if strings.HasSuffix(include, qb.config.ExistsSuffix) {
			relationName := strings.TrimSuffix(include, qb.config.ExistsSuffix)
			allowedInclude := qb.findAllowedInclude(relationName)
			if allowedInclude != nil {
				facades.Log().Warning(fmt.Sprintf("WithExists for '%s' not supported in current ORM version", relationName))
			}
			continue
		}

		allowedInclude := qb.findAllowedInclude(include)
		if allowedInclude == nil {
			if !qb.config.DisableInvalidIncludeException {
				facades.Log().Warning(fmt.Sprintf("Include '%s' is not allowed", include))
			}
			continue
		}

		if allowedInclude.Callback != nil {
			qb.query = allowedInclude.Callback(qb.query, include)
		} else {
			qb.query = qb.query.With(allowedInclude.Relationship)
		}
	}
}

// applyFields processes field selection query parameters
func (qb *QueryBuilder) applyFields() {
	if qb.request == nil {
		return
	}

	// Parse fields parameter - can be fields=field1,field2 or fields[table]=field1,field2
	fieldsParam := qb.request.Request().Input(qb.config.FieldsParameter, "")
	if fieldsParam == "" {
		return
	}

	// Simple field selection (not table-specific)
	if fieldsParam != "" {
		fields := strings.Split(fieldsParam, ",")
		allowedFieldNames := make([]string, 0)

		for _, field := range fields {
			field = strings.TrimSpace(field)
			if field == "" {
				continue
			}

			if qb.isFieldAllowed(field) {
				allowedFieldNames = append(allowedFieldNames, field)
			}
		}

		if len(allowedFieldNames) > 0 {
			qb.query = qb.query.Select(allowedFieldNames[0]) // ORM Select takes string, not slice
			for _, field := range allowedFieldNames[1:] {
				qb.query = qb.query.Select(field)
			}
		}
	}
}

// Helper methods

// parseFilters parses filter parameters from the request
func (qb *QueryBuilder) parseFilters() map[string]interface{} {
	filters := make(map[string]interface{})

	// Get all query parameters
	values := qb.request.Request().All()

	// Look for filter parameters
	for key, value := range values {
		if strings.HasPrefix(key, qb.config.FilterParameter+"[") && strings.HasSuffix(key, "]") {
			// Extract filter name from filter[name] format
			filterName := key[len(qb.config.FilterParameter)+1 : len(key)-1]
			filters[filterName] = value
		}
	}

	return filters
}

// applyFilter applies a specific filter to the query
func (qb *QueryBuilder) applyFilter(filter AllowedFilter, value interface{}) {
	if filter.Callback != nil {
		qb.query = filter.Callback(qb.query, value, filter.Name)
		return
	}

	// Handle ignored values
	if filter.IgnoredValues != nil {
		for _, ignored := range filter.IgnoredValues {
			if value == ignored {
				return
			}
		}
	}

	// Apply default value if value is nil/empty
	if (value == nil || value == "") && filter.DefaultValue != nil {
		value = filter.DefaultValue
	}

	// Handle nullable filters
	if filter.Nullable && (value == nil || value == "") {
		qb.query = qb.query.Where(fmt.Sprintf("%s IS NULL", filter.Property))
		return
	}

	valueStr := fmt.Sprintf("%v", value)
	if valueStr == "" {
		return
	}

	switch filter.Type {
	case FilterTypeExact:
		// Handle comma-separated values for IN clause
		if strings.Contains(valueStr, ",") {
			values := strings.Split(valueStr, ",")
			qb.query = qb.query.Where(fmt.Sprintf("%s IN ?", filter.Property), values)
		} else {
			qb.query = qb.query.Where(fmt.Sprintf("%s = ?", filter.Property), value)
		}
	case FilterTypePartial:
		qb.query = qb.query.Where(fmt.Sprintf("%s LIKE ?", filter.Property), "%"+valueStr+"%")
	case FilterTypeBeginsWith:
		qb.query = qb.query.Where(fmt.Sprintf("%s LIKE ?", filter.Property), valueStr+"%")
	case FilterTypeEndsWith:
		qb.query = qb.query.Where(fmt.Sprintf("%s LIKE ?", filter.Property), "%"+valueStr)
	case FilterTypeGreaterThan:
		qb.query = qb.query.Where(fmt.Sprintf("%s > ?", filter.Property), value)
	case FilterTypeLessThan:
		qb.query = qb.query.Where(fmt.Sprintf("%s < ?", filter.Property), value)
	case FilterTypeGreaterEqual:
		qb.query = qb.query.Where(fmt.Sprintf("%s >= ?", filter.Property), value)
	case FilterTypeLessEqual:
		qb.query = qb.query.Where(fmt.Sprintf("%s <= ?", filter.Property), value)
	case FilterTypeBetween:
		// Handle comma-separated values for BETWEEN clause
		if strings.Contains(valueStr, ",") {
			values := strings.Split(valueStr, ",")
			if len(values) == 2 {
				qb.query = qb.query.Where(fmt.Sprintf("%s BETWEEN ? AND ?", filter.Property), strings.TrimSpace(values[0]), strings.TrimSpace(values[1]))
			}
		}
	case FilterTypeIn:
		// Handle comma-separated values for IN clause
		if strings.Contains(valueStr, ",") {
			values := strings.Split(valueStr, ",")
			// Trim whitespace from values
			for i, v := range values {
				values[i] = strings.TrimSpace(v)
			}
			qb.query = qb.query.Where(fmt.Sprintf("%s IN ?", filter.Property), values)
		} else {
			qb.query = qb.query.Where(fmt.Sprintf("%s IN ?", filter.Property), []string{valueStr})
		}
	case FilterTypeNotIn:
		// Handle comma-separated values for NOT IN clause
		if strings.Contains(valueStr, ",") {
			values := strings.Split(valueStr, ",")
			// Trim whitespace from values
			for i, v := range values {
				values[i] = strings.TrimSpace(v)
			}
			qb.query = qb.query.Where(fmt.Sprintf("%s NOT IN ?", filter.Property), values)
		} else {
			qb.query = qb.query.Where(fmt.Sprintf("%s NOT IN ?", filter.Property), []string{valueStr})
		}
	case FilterTypeNull:
		qb.query = qb.query.Where(fmt.Sprintf("%s IS NULL", filter.Property))
	case FilterTypeNotNull:
		qb.query = qb.query.Where(fmt.Sprintf("%s IS NOT NULL", filter.Property))
	case FilterTypeDateRange:
		// Handle date range in format: start_date,end_date
		if strings.Contains(valueStr, ",") {
			dates := strings.Split(valueStr, ",")
			if len(dates) == 2 {
				startDate := strings.TrimSpace(dates[0])
				endDate := strings.TrimSpace(dates[1])
				qb.query = qb.query.Where(fmt.Sprintf("%s >= ? AND %s <= ?", filter.Property, filter.Property), startDate, endDate)
			}
		}
	case FilterTypeRegex:
		// Use database-specific regex operator
		qb.query = qb.query.Where(fmt.Sprintf("%s REGEXP ?", filter.Property), valueStr)
	case FilterTypeScope:
		// Handle scope filters - this would need to be implemented based on your model scopes
		facades.Log().Warning(fmt.Sprintf("Scope filter '%s' not implemented", filter.Name))
	}
}

// applyDefaultSorts applies default sorting
func (qb *QueryBuilder) applyDefaultSorts() {
	for _, sort := range qb.defaultSorts {
		qb.query = qb.query.Order(fmt.Sprintf("%s %s", sort.Field, sort.Direction))
	}
}

// findAllowedFilter finds an allowed filter by name
func (qb *QueryBuilder) findAllowedFilter(name string) *AllowedFilter {
	for _, filter := range qb.allowedFilters {
		if filter.Name == name {
			return &filter
		}
	}
	return nil
}

// findAllowedSort finds an allowed sort by name
func (qb *QueryBuilder) findAllowedSort(name string) *AllowedSort {
	for _, sort := range qb.allowedSorts {
		if sort.Name == name {
			return &sort
		}
	}
	return nil
}

// findAllowedInclude finds an allowed include by name
func (qb *QueryBuilder) findAllowedInclude(name string) *AllowedInclude {
	for _, include := range qb.allowedIncludes {
		if include.Name == name {
			return &include
		}
	}
	return nil
}

// isFieldAllowed checks if a field is allowed for selection
func (qb *QueryBuilder) isFieldAllowed(field string) bool {
	if len(qb.allowedFields) == 0 {
		return true // If no restrictions, allow all fields
	}

	for _, allowedField := range qb.allowedFields {
		if allowedField.Name == field {
			return true
		}
	}
	return false
}

// Chain methods to allow method chaining with the underlying query

// Where adds a where clause
func (qb *QueryBuilder) Where(column string, args ...interface{}) *QueryBuilder {
	qb.query = qb.query.Where(column, args...)
	return qb
}

// OrWhere adds an or where clause
func (qb *QueryBuilder) OrWhere(column string, args ...interface{}) *QueryBuilder {
	qb.query = qb.query.OrWhere(column, args...)
	return qb
}

// WithTrashed includes soft deleted records
func (qb *QueryBuilder) WithTrashed() *QueryBuilder {
	qb.query = qb.query.WithTrashed()
	return qb
}

// OnlyTrashed only includes soft deleted records - Note: Not available in current ORM version
func (qb *QueryBuilder) OnlyTrashed() *QueryBuilder {
	facades.Log().Warning("OnlyTrashed not supported in current ORM version, using manual where clause")
	qb.query = qb.query.Where("deleted_at IS NOT NULL")
	return qb
}

// Join adds a join clause
func (qb *QueryBuilder) Join(table string, args ...interface{}) *QueryBuilder {
	qb.query = qb.query.Join(table, args...)
	return qb
}

// LeftJoin adds a left join clause - Note: Not available in current ORM version
func (qb *QueryBuilder) LeftJoin(table string, args ...interface{}) *QueryBuilder {
	facades.Log().Warning("LeftJoin not supported in current ORM version")
	return qb
}

// RightJoin adds a right join clause - Note: Not available in current ORM version
func (qb *QueryBuilder) RightJoin(table string, args ...interface{}) *QueryBuilder {
	facades.Log().Warning("RightJoin not supported in current ORM version")
	return qb
}

// GroupBy adds a group by clause
func (qb *QueryBuilder) GroupBy(columns ...string) *QueryBuilder {
	qb.query = qb.query.Group(strings.Join(columns, ","))
	return qb
}

// Having adds a having clause
func (qb *QueryBuilder) Having(column string, args ...interface{}) *QueryBuilder {
	qb.query = qb.query.Having(column, args...)
	return qb
}

// Limit sets the limit
func (qb *QueryBuilder) Limit(limit int) *QueryBuilder {
	qb.query = qb.query.Limit(limit)
	return qb
}

// Offset sets the offset
func (qb *QueryBuilder) Offset(offset int) *QueryBuilder {
	qb.query = qb.query.Offset(offset)
	return qb
}

// Helper methods for pagination

// getPaginationConfig returns the pagination configuration (custom or default)
func (qb *QueryBuilder) getPaginationConfig() *PaginationConfig {
	if qb.paginationConfig != nil {
		return qb.paginationConfig
	}
	return DefaultPaginationConfig()
}

// applyCursorPagination applies cursor-based pagination to a query
func (qb *QueryBuilder) applyCursorPagination(query orm.Query, cursorStr string, limit int, cursorFields []CursorField, reverse bool) (orm.Query, error) {
	if cursorStr != "" {
		cursor, err := qb.decodeCursor(cursorStr)
		if err != nil {
			return query, err
		}

		if cursor != nil && len(cursor.Values) > 0 {
			// Build WHERE clause for cursor pagination
			whereConditions := make([]string, 0)
			whereValues := make([]interface{}, 0)

			for _, field := range cursorFields {
				if value, exists := cursor.Values[field.Name]; exists {
					operator := ">"
					if field.Direction == "desc" {
						operator = "<"
					}
					if reverse {
						// Reverse the operator for reverse pagination
						if operator == ">" {
							operator = "<"
						} else {
							operator = ">"
						}
					}

					whereConditions = append(whereConditions, fmt.Sprintf("%s %s ?", field.Name, operator))
					whereValues = append(whereValues, value)
				}
			}

			if len(whereConditions) > 0 {
				// For multiple cursor fields, we need a composite comparison
				if len(whereConditions) == 1 {
					query = query.Where(whereConditions[0], whereValues[0])
				} else {
					// Build composite WHERE clause: (field1, field2) > (value1, value2)
					fieldNames := make([]string, len(cursorFields))
					for i, field := range cursorFields {
						fieldNames[i] = field.Name
					}

					operator := ">"
					if cursorFields[0].Direction == "desc" {
						operator = "<"
					}
					if reverse {
						if operator == ">" {
							operator = "<"
						} else {
							operator = ">"
						}
					}

					compositeWhere := fmt.Sprintf("(%s) %s (%s)",
						strings.Join(fieldNames, ", "),
						operator,
						strings.Repeat("?,", len(whereValues)-1)+"?")
					query = query.Where(compositeWhere, whereValues...)
				}
			}
		}
	}

	// Apply ordering
	for _, field := range cursorFields {
		direction := field.Direction
		if reverse {
			// Reverse the direction for reverse pagination
			if direction == "asc" {
				direction = "desc"
			} else {
				direction = "asc"
			}
		}
		query = query.Order(fmt.Sprintf("%s %s", field.Name, direction))
	}

	return query, nil
}

// buildCursorPaginationResult builds the cursor pagination result
func (qb *QueryBuilder) buildCursorPaginationResult(dest interface{}, cursorStr string, limit int, cursorFields []CursorField, reverse bool) (*CursorPaginationResult, error) {
	resultCount := qb.getResultCount(dest)
	hasNext := resultCount > limit
	hasPrev := cursorStr != ""

	// Trim results to actual limit if we got extra
	actualCount := resultCount
	if hasNext {
		qb.trimResults(dest, limit)
		actualCount = limit
	}

	paginationInfo := &PaginationInfo{
		Type:    "cursor",
		Count:   actualCount,
		Limit:   limit,
		HasNext: hasNext,
		HasPrev: hasPrev,
	}

	// Generate next cursor if there are more results
	if hasNext && actualCount > 0 {
		lastItem := qb.getLastItem(dest)
		if lastItem != nil {
			nextCursor, err := qb.generateCursor(lastItem, cursorFields)
			if err == nil {
				paginationInfo.NextCursor = &nextCursor
			}
		}
	}

	// Set previous cursor
	if hasPrev {
		paginationInfo.PrevCursor = &cursorStr
	}

	result := &CursorPaginationResult{
		Data:       dest,
		Pagination: paginationInfo,
	}

	return result, nil
}

// getResultCount gets the count of results using reflection
func (qb *QueryBuilder) getResultCount(results interface{}) int {
	val := reflect.ValueOf(results)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}
	if val.Kind() == reflect.Slice {
		return val.Len()
	}
	return 0
}

// trimResults trims the results slice to the specified limit
func (qb *QueryBuilder) trimResults(results interface{}, limit int) {
	val := reflect.ValueOf(results)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}
	if val.Kind() == reflect.Slice && val.Len() > limit {
		// Trim the slice to the limit
		newSlice := val.Slice(0, limit)
		val.Set(newSlice)
	}
}

// getLastItem gets the last item from results
func (qb *QueryBuilder) getLastItem(results interface{}) interface{} {
	val := reflect.ValueOf(results)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}
	if val.Kind() == reflect.Slice && val.Len() > 0 {
		return val.Index(val.Len() - 1).Interface()
	}
	return nil
}

// generateCursor generates a cursor from an item and cursor fields
func (qb *QueryBuilder) generateCursor(item interface{}, cursorFields []CursorField) (string, error) {
	cursor := &Cursor{
		Values: make(map[string]interface{}),
	}

	val := reflect.ValueOf(item)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}

	for _, field := range cursorFields {
		fieldValue := val.FieldByName(qb.toCamelCase(field.Name))
		if fieldValue.IsValid() {
			cursor.Values[field.Name] = fieldValue.Interface()
		}
	}

	return qb.encodeCursor(cursor)
}

// encodeCursor encodes a cursor to a base64 string
func (qb *QueryBuilder) encodeCursor(cursor *Cursor) (string, error) {
	data, err := json.Marshal(cursor)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

// decodeCursor decodes a base64 string to a cursor
func (qb *QueryBuilder) decodeCursor(cursorStr string) (*Cursor, error) {
	if cursorStr == "" {
		return nil, nil
	}

	data, err := base64.StdEncoding.DecodeString(cursorStr)
	if err != nil {
		return nil, fmt.Errorf("invalid cursor format: %v", err)
	}

	var cursor Cursor
	err = json.Unmarshal(data, &cursor)
	if err != nil {
		return nil, fmt.Errorf("invalid cursor data: %v", err)
	}

	return &cursor, nil
}

// toCamelCase converts snake_case to CamelCase for struct field names
func (qb *QueryBuilder) toCamelCase(s string) string {
	parts := strings.Split(s, "_")
	for i, part := range parts {
		if len(part) > 0 {
			parts[i] = strings.ToUpper(part[:1]) + strings.ToLower(part[1:])
		}
	}
	return strings.Join(parts, "")
}

// Extended methods for QueryBuilder functionality

// WithAggregates adds aggregation functions
func (qb *QueryBuilder) WithAggregates(aggregates ...AggregateField) *QueryBuilder {
	qb.aggregates = append(qb.aggregates, aggregates...)
	return qb
}

// WithJoins adds join clauses
func (qb *QueryBuilder) WithJoins(joins ...JoinClause) *QueryBuilder {
	qb.joins = append(qb.joins, joins...)
	return qb
}

// WithWindowFunctions adds window functions
func (qb *QueryBuilder) WithWindowFunctions(functions ...WindowFunction) *QueryBuilder {
	qb.windowFunctions = append(qb.windowFunctions, functions...)
	return qb
}

// GetWithFullResult executes query and returns complete results
func (qb *QueryBuilder) GetWithFullResult(dest interface{}) (*QueryResult, error) {
	err := qb.Get(dest)
	if err != nil {
		return nil, err
	}

	// Build comprehensive result structure
	result := &QueryResult{
		Data: dest,
		Metadata: map[string]interface{}{
			"query_type": "full",
			"features_enabled": map[string]bool{
				"aggregates":       len(qb.aggregates) > 0,
				"joins":            len(qb.joins) > 0,
				"window_functions": len(qb.windowFunctions) > 0,
				"filters":          len(qb.filters) > 0,
			},
		},
	}

	return result, nil
}

// AutoPaginate automatically chooses pagination type based on query parameters
func (qb *QueryBuilder) AutoPaginate(dest interface{}, options ...PaginationOptions) (*UnifiedPaginationResult, error) {
	config := qb.getPaginationConfig()

	// Determine pagination type from query parameter
	paginationType := config.Type
	if qb.request != nil {
		typeParam := qb.request.Request().Input(config.TypeParameter, "")
		switch typeParam {
		case "cursor":
			paginationType = PaginationTypeCursor
		case "offset":
			paginationType = PaginationTypeOffset
		}
	}

	// Use the appropriate pagination method
	switch paginationType {
	case PaginationTypeCursor:
		result, err := qb.CursorPaginate(dest, options...)
		if err != nil {
			return nil, err
		}
		return &UnifiedPaginationResult{
			Data:       result.Data,
			Pagination: result.Pagination,
		}, nil
	default:
		result, err := qb.OffsetPaginate(dest)
		if err != nil {
			return nil, err
		}
		return &UnifiedPaginationResult{
			Data:       result.Data,
			Pagination: result.Pagination,
		}, nil
	}
}

// CursorPaginate applies cursor-based pagination and returns paginated results
func (qb *QueryBuilder) CursorPaginate(dest interface{}, options ...PaginationOptions) (*CursorPaginationResult, error) {
	config := qb.getPaginationConfig()

	// Parse pagination parameters from request
	var cursor string
	var limit int
	var reverse bool

	if qb.request != nil {
		cursor = qb.request.Request().Input(config.CursorParameter, "")
		limitStr := qb.request.Request().Input(config.LimitParameter, strconv.Itoa(config.DefaultLimit))
		limit, _ = strconv.Atoi(limitStr)
		reverse = qb.request.Request().Input("reverse", "false") == "true"
	} else {
		limit = config.DefaultLimit
	}

	// Apply limit constraints
	if limit <= 0 {
		limit = config.DefaultLimit
	}
	if limit > config.MaxLimit {
		limit = config.MaxLimit
	}

	// Get cursor fields from options or use default
	var cursorFields []CursorField
	if len(options) > 0 && len(options[0].CursorFields) > 0 {
		cursorFields = options[0].CursorFields
		if len(options) > 0 {
			reverse = options[0].Reverse
		}
	} else {
		// Default cursor fields: id and created_at
		cursorFields = []CursorField{
			{Name: "created_at", Direction: "desc"},
			{Name: "id", Direction: "desc"},
		}
	}

	// Build and execute query
	query := qb.Build()
	query, err := qb.applyCursorPagination(query, cursor, limit, cursorFields, reverse)
	if err != nil {
		return nil, err
	}

	// Execute query with limit + 1 to check for more results
	query = query.Limit(limit + 1)
	err = query.Find(dest)
	if err != nil {
		return nil, err
	}

	// Build pagination result
	return qb.buildCursorPaginationResult(dest, cursor, limit, cursorFields, reverse)
}

// OffsetPaginate applies offset-based pagination and returns paginated results
func (qb *QueryBuilder) OffsetPaginate(dest interface{}) (*OffsetPaginationResult, error) {
	config := qb.getPaginationConfig()

	// Parse pagination parameters from request
	var page int = 1
	var limit int = config.DefaultLimit

	if qb.request != nil {
		pageStr := qb.request.Request().Input(config.PageParameter, "1")
		page, _ = strconv.Atoi(pageStr)
		limitStr := qb.request.Request().Input(config.LimitParameter, strconv.Itoa(config.DefaultLimit))
		limit, _ = strconv.Atoi(limitStr)
	}

	// Apply constraints
	if page < 1 {
		page = 1
	}
	if limit <= 0 {
		limit = config.DefaultLimit
	}
	if limit > config.MaxLimit {
		limit = config.MaxLimit
	}

	// Get total count first
	countQuery := qb.Build()
	total, err := countQuery.Count()
	if err != nil {
		return nil, err
	}

	// Calculate pagination values
	offset := (page - 1) * limit
	lastPage := int((total + int64(limit) - 1) / int64(limit)) // Ceiling division
	if lastPage < 1 {
		lastPage = 1
	}

	// Build and execute paginated query
	query := qb.Build()
	query = query.Offset(offset).Limit(limit)
	err = query.Find(dest)
	if err != nil {
		return nil, err
	}

	// Calculate result metrics
	resultCount := qb.getResultCount(dest)
	from := 0
	to := 0
	if resultCount > 0 {
		from = offset + 1
		to = offset + resultCount
	}

	return &OffsetPaginationResult{
		Data: dest,
		Pagination: &PaginationInfo{
			Type:        "offset",
			Count:       resultCount,
			Limit:       limit,
			HasNext:     page < lastPage,
			HasPrev:     page > 1,
			CurrentPage: &page,
			LastPage:    &lastPage,
			PerPage:     &limit,
			Total:       &total,
			From:        &from,
			To:          &to,
		},
	}, nil
}

// SimplePaginate applies simple offset-based pagination (without total count)
func (qb *QueryBuilder) SimplePaginate(dest interface{}) (*OffsetPaginationResult, error) {
	config := qb.getPaginationConfig()

	// Parse pagination parameters from request
	var page int = 1
	var limit int = config.DefaultLimit

	if qb.request != nil {
		pageStr := qb.request.Request().Input(config.PageParameter, "1")
		page, _ = strconv.Atoi(pageStr)
		limitStr := qb.request.Request().Input(config.LimitParameter, strconv.Itoa(config.DefaultLimit))
		limit, _ = strconv.Atoi(limitStr)
	}

	// Apply constraints
	if page < 1 {
		page = 1
	}
	if limit <= 0 {
		limit = config.DefaultLimit
	}
	if limit > config.MaxLimit {
		limit = config.MaxLimit
	}

	// Calculate offset
	offset := (page - 1) * limit

	// Build and execute query with limit + 1 to check for more results
	query := qb.Build()
	query = query.Offset(offset).Limit(limit + 1)
	err := query.Find(dest)
	if err != nil {
		return nil, err
	}

	// Check if there are more results
	resultCount := qb.getResultCount(dest)
	hasNext := resultCount > limit

	// Trim results to actual limit if we got extra
	if hasNext {
		qb.trimResults(dest, limit)
		resultCount = limit
	}

	// Calculate result metrics
	from := 0
	to := 0
	if resultCount > 0 {
		from = offset + 1
		to = offset + resultCount
	}

	lastPage := -1
	total := int64(-1)

	return &OffsetPaginationResult{
		Data: dest,
		Pagination: &PaginationInfo{
			Type:        "simple",
			Count:       resultCount,
			Limit:       limit,
			HasNext:     hasNext,
			HasPrev:     page > 1,
			CurrentPage: &page,
			LastPage:    &lastPage,
			PerPage:     &limit,
			Total:       &total,
			From:        &from,
			To:          &to,
		},
	}, nil
}
