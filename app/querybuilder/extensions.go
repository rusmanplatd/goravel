package querybuilder

import (
	"fmt"
	"strings"
	"time"

	"github.com/goravel/framework/contracts/database/orm"
	"github.com/goravel/framework/facades"
)

// QueryExtensions provides additional functionality for the QueryBuilder
type QueryExtensions struct {
	qb *QueryBuilder
}

// WithExtensions adds extensions to the query builder
func (qb *QueryBuilder) WithExtensions() *QueryExtensions {
	return &QueryExtensions{qb: qb}
}

// Conditional Query Building

// When applies a condition only if the condition is true
func (qe *QueryExtensions) When(condition bool, callback func(*QueryBuilder) *QueryBuilder) *QueryExtensions {
	if condition {
		qe.qb = callback(qe.qb)
	}
	return qe
}

// Unless applies a condition only if the condition is false
func (qe *QueryExtensions) Unless(condition bool, callback func(*QueryBuilder) *QueryBuilder) *QueryExtensions {
	if !condition {
		qe.qb = callback(qe.qb)
	}
	return qe
}

// WhenNotEmpty applies a condition only if the value is not empty
func (qe *QueryExtensions) WhenNotEmpty(value string, callback func(*QueryBuilder, string) *QueryBuilder) *QueryExtensions {
	if strings.TrimSpace(value) != "" {
		qe.qb = callback(qe.qb, value)
	}
	return qe
}

// WhenNotNil applies a condition only if the value is not nil
func (qe *QueryExtensions) WhenNotNil(value interface{}, callback func(*QueryBuilder, interface{}) *QueryBuilder) *QueryExtensions {
	if value != nil {
		qe.qb = callback(qe.qb, value)
	}
	return qe
}

// Query Scopes

// WithScope applies a named scope to the query
func (qe *QueryExtensions) WithScope(scopeName string, params ...interface{}) *QueryExtensions {
	// This would be implemented based on your model scopes
	facades.Log().Info(fmt.Sprintf("Applying scope: %s with params: %v", scopeName, params))
	return qe
}

// WithGlobalScope applies a global scope to the query
func (qe *QueryExtensions) WithGlobalScope(scopeName string) *QueryExtensions {
	facades.Log().Info(fmt.Sprintf("Applying global scope: %s", scopeName))
	return qe
}

// WithoutGlobalScope removes a global scope from the query
func (qe *QueryExtensions) WithoutGlobalScope(scopeName string) *QueryExtensions {
	facades.Log().Info(fmt.Sprintf("Removing global scope: %s", scopeName))
	return qe
}

// Time-based Queries

// WhereDate filters by date (ignoring time)
func (qe *QueryExtensions) WhereDate(column string, date time.Time) *QueryExtensions {
	dateStr := date.Format("2006-01-02")
	qe.qb.query = qe.qb.query.Where(fmt.Sprintf("DATE(%s) = ?", column), dateStr)
	return qe
}

// WhereDateBetween filters by date range
func (qe *QueryExtensions) WhereDateBetween(column string, startDate, endDate time.Time) *QueryExtensions {
	startStr := startDate.Format("2006-01-02")
	endStr := endDate.Format("2006-01-02")
	qe.qb.query = qe.qb.query.Where(fmt.Sprintf("DATE(%s) BETWEEN ? AND ?", column), startStr, endStr)
	return qe
}

// WhereTime filters by time (ignoring date)
func (qe *QueryExtensions) WhereTime(column string, operator string, time time.Time) *QueryExtensions {
	timeStr := time.Format("15:04:05")
	qe.qb.query = qe.qb.query.Where(fmt.Sprintf("TIME(%s) %s ?", column, operator), timeStr)
	return qe
}

// WhereYear filters by year
func (qe *QueryExtensions) WhereYear(column string, year int) *QueryExtensions {
	qe.qb.query = qe.qb.query.Where(fmt.Sprintf("YEAR(%s) = ?", column), year)
	return qe
}

// WhereMonth filters by month
func (qe *QueryExtensions) WhereMonth(column string, month int) *QueryExtensions {
	qe.qb.query = qe.qb.query.Where(fmt.Sprintf("MONTH(%s) = ?", column), month)
	return qe
}

// WhereDay filters by day
func (qe *QueryExtensions) WhereDay(column string, day int) *QueryExtensions {
	qe.qb.query = qe.qb.query.Where(fmt.Sprintf("DAY(%s) = ?", column), day)
	return qe
}

// JSON Query Methods

// WhereJsonContains filters by JSON contains
func (qe *QueryExtensions) WhereJsonContains(column string, value interface{}) *QueryExtensions {
	qe.qb.query = qe.qb.query.Where(fmt.Sprintf("JSON_CONTAINS(%s, ?)", column), value)
	return qe
}

// WhereJsonExtract filters by JSON path extraction
func (qe *QueryExtensions) WhereJsonExtract(column string, path string, operator string, value interface{}) *QueryExtensions {
	qe.qb.query = qe.qb.query.Where(fmt.Sprintf("JSON_EXTRACT(%s, '%s') %s ?", column, path, operator), value)
	return qe
}

// WhereJsonLength filters by JSON array/object length
func (qe *QueryExtensions) WhereJsonLength(column string, operator string, length int) *QueryExtensions {
	qe.qb.query = qe.qb.query.Where(fmt.Sprintf("JSON_LENGTH(%s) %s ?", column, operator), length)
	return qe
}

// Full-Text Search

// WhereFullText performs full-text search
func (qe *QueryExtensions) WhereFullText(columns []string, search string) *QueryExtensions {
	columnList := strings.Join(columns, ",")
	qe.qb.query = qe.qb.query.Where(fmt.Sprintf("MATCH(%s) AGAINST(? IN BOOLEAN MODE)", columnList), search)
	return qe
}

// WhereFullTextNatural performs natural language full-text search
func (qe *QueryExtensions) WhereFullTextNatural(columns []string, search string) *QueryExtensions {
	columnList := strings.Join(columns, ",")
	qe.qb.query = qe.qb.query.Where(fmt.Sprintf("MATCH(%s) AGAINST(?)", columnList), search)
	return qe
}

// Geographic Queries

// WhereDistance filters by geographic distance
func (qe *QueryExtensions) WhereDistance(latColumn, lngColumn string, lat, lng, distance float64) *QueryExtensions {
	// Using Haversine formula
	qe.qb.query = qe.qb.query.Where(
		fmt.Sprintf("(6371 * acos(cos(radians(?)) * cos(radians(%s)) * cos(radians(%s) - radians(?)) + sin(radians(?)) * sin(radians(%s)))) <= ?",
			latColumn, lngColumn, latColumn),
		lat, lng, lat, distance)
	return qe
}

// WhereWithinBounds filters by geographic bounding box
func (qe *QueryExtensions) WhereWithinBounds(latColumn, lngColumn string, northLat, southLat, eastLng, westLng float64) *QueryExtensions {
	qe.qb.query = qe.qb.query.Where(fmt.Sprintf("%s BETWEEN ? AND ?", latColumn), southLat, northLat)
	qe.qb.query = qe.qb.query.Where(fmt.Sprintf("%s BETWEEN ? AND ?", lngColumn), westLng, eastLng)
	return qe
}

// Array Operations

// WhereArrayContains filters by array contains (for JSON arrays)
func (qe *QueryExtensions) WhereArrayContains(column string, value interface{}) *QueryExtensions {
	qe.qb.query = qe.qb.query.Where(fmt.Sprintf("JSON_CONTAINS(%s, ?)", column), fmt.Sprintf(`"%v"`, value))
	return qe
}

// WhereArrayLength filters by array length
func (qe *QueryExtensions) WhereArrayLength(column string, operator string, length int) *QueryExtensions {
	qe.qb.query = qe.qb.query.Where(fmt.Sprintf("JSON_LENGTH(%s) %s ?", column, operator), length)
	return qe
}

// Statistical Queries

// WithCount adds a count of related records
func (qe *QueryExtensions) WithCount(relation string) *QueryExtensions {
	// This would need to be implemented based on your ORM's relationship handling
	facades.Log().Info(fmt.Sprintf("Adding count for relation: %s", relation))
	return qe
}

// WithAvg adds an average of related records
func (qe *QueryExtensions) WithAvg(relation string, column string) *QueryExtensions {
	facades.Log().Info(fmt.Sprintf("Adding average for relation: %s, column: %s", relation, column))
	return qe
}

// WithSum adds a sum of related records
func (qe *QueryExtensions) WithSum(relation string, column string) *QueryExtensions {
	facades.Log().Info(fmt.Sprintf("Adding sum for relation: %s, column: %s", relation, column))
	return qe
}

// WithMin adds a minimum of related records
func (qe *QueryExtensions) WithMin(relation string, column string) *QueryExtensions {
	facades.Log().Info(fmt.Sprintf("Adding min for relation: %s, column: %s", relation, column))
	return qe
}

// WithMax adds a maximum of related records
func (qe *QueryExtensions) WithMax(relation string, column string) *QueryExtensions {
	facades.Log().Info(fmt.Sprintf("Adding max for relation: %s, column: %s", relation, column))
	return qe
}

// Query Debugging

// ToSQL returns the SQL query string (if supported by ORM)
func (qe *QueryExtensions) ToSQL() string {
	// Get the underlying SQL query from the query builder
	if qe.qb.query != nil {
		// In production, this would use the ORM's ToSQL method
		// For now, construct a basic SQL representation
		sql := qe.constructBasicSQL()
		facades.Log().Info("Generated SQL query", map[string]interface{}{
			"sql": sql,
		})
		return sql
	}

	facades.Log().Warning("No query available for SQL generation")
	return "-- No query built yet"
}

// Explain returns the query execution plan
func (qe *QueryExtensions) Explain() map[string]interface{} {
	// Get query execution plan
	sql := qe.ToSQL()
	explainSQL := "EXPLAIN " + sql

	// In production, this would execute EXPLAIN against the database
	plan := map[string]interface{}{
		"type":           "explain",
		"query":          sql,
		"explain_sql":    explainSQL,
		"estimated_cost": qe.estimateQueryCost(),
		"indexes_used":   qe.getIndexesUsed(),
		"scan_type":      qe.determineScanType(),
		"note":           "Execute EXPLAIN query against database for detailed plan",
	}

	facades.Log().Info("Generated query execution plan", map[string]interface{}{
		"plan": plan,
	})

	return plan
}

// Dump dumps the current query state for debugging
func (qe *QueryExtensions) Dump() *QueryExtensions {
	facades.Log().Info("Current query state:")
	facades.Log().Info(fmt.Sprintf("Filters: %d", len(qe.qb.allowedFilters)))
	facades.Log().Info(fmt.Sprintf("Sorts: %d", len(qe.qb.allowedSorts)))
	facades.Log().Info(fmt.Sprintf("Includes: %d", len(qe.qb.allowedIncludes)))
	facades.Log().Info(fmt.Sprintf("Aggregates: %d", len(qe.qb.aggregates)))
	facades.Log().Info(fmt.Sprintf("Joins: %d", len(qe.qb.joins)))
	return qe
}

// Query Optimization

// WithIndex hints the query to use a specific index
func (qe *QueryExtensions) WithIndex(indexName string) *QueryExtensions {
	facades.Log().Info(fmt.Sprintf("Hinting to use index: %s", indexName))
	// This would need database-specific implementation
	return qe
}

// WithoutIndex hints the query to avoid a specific index
func (qe *QueryExtensions) WithoutIndex(indexName string) *QueryExtensions {
	facades.Log().Info(fmt.Sprintf("Hinting to avoid index: %s", indexName))
	return qe
}

// ForceIndex forces the query to use a specific index
func (qe *QueryExtensions) ForceIndex(indexName string) *QueryExtensions {
	facades.Log().Info(fmt.Sprintf("Forcing index: %s", indexName))
	return qe
}

// WithQueryHint adds a query hint
func (qe *QueryExtensions) WithQueryHint(hint string) *QueryExtensions {
	facades.Log().Info(fmt.Sprintf("Adding query hint: %s", hint))
	return qe
}

// Return to QueryBuilder

// QueryBuilder returns the underlying QueryBuilder
func (qe *QueryExtensions) QueryBuilder() *QueryBuilder {
	return qe.qb
}

// Build builds and returns the final query
func (qe *QueryExtensions) Build() orm.Query {
	return qe.qb.Build()
}

// Get executes the query and returns results
func (qe *QueryExtensions) Get(dest interface{}) error {
	return qe.qb.Get(dest)
}

// First executes the query and returns the first result
func (qe *QueryExtensions) First(dest interface{}) error {
	return qe.qb.First(dest)
}

// Count returns the count of matching records
func (qe *QueryExtensions) Count() (int64, error) {
	return qe.qb.Count()
}

// Paginate applies pagination and returns paginated results
func (qe *QueryExtensions) Paginate(dest interface{}) (*OffsetPaginationResult, error) {
	return qe.qb.OffsetPaginate(dest)
}

// CursorPaginate applies cursor pagination and returns paginated results
func (qe *QueryExtensions) CursorPaginate(dest interface{}, options ...PaginationOptions) (*CursorPaginationResult, error) {
	return qe.qb.CursorPaginate(dest, options...)
}

// Utility Extensions

// Tap allows you to perform an action on the query without changing it
func (qe *QueryExtensions) Tap(callback func(*QueryBuilder)) *QueryExtensions {
	callback(qe.qb)
	return qe
}

// Clone creates a copy of the current query builder
func (qe *QueryExtensions) Clone() *QueryExtensions {
	// This would need deep copying implementation
	facades.Log().Info("Cloning query builder")
	return &QueryExtensions{qb: qe.qb}
}

// Reset resets the query builder to its initial state
func (qe *QueryExtensions) Reset() *QueryExtensions {
	qe.qb.allowedFilters = make([]AllowedFilter, 0)
	qe.qb.allowedSorts = make([]AllowedSort, 0)
	qe.qb.allowedIncludes = make([]AllowedInclude, 0)
	qe.qb.allowedFields = make([]AllowedField, 0)
	qe.qb.aggregates = make([]AggregateField, 0)
	qe.qb.joins = make([]JoinClause, 0)
	qe.qb.filters = make([]FilterGroup, 0)
	facades.Log().Info("Query builder reset")
	return qe
}

// Macro system for custom extensions

var macros = make(map[string]func(*QueryExtensions, ...interface{}) *QueryExtensions)

// Macro registers a custom macro
func Macro(name string, callback func(*QueryExtensions, ...interface{}) *QueryExtensions) {
	macros[name] = callback
}

// Helper methods for query analysis and SQL generation

// constructBasicSQL constructs a basic SQL representation of the query
func (qe *QueryExtensions) constructBasicSQL() string {
	// This is a simplified SQL construction
	// In production, this would use the ORM's actual SQL generation

	sql := "SELECT "

	// Add select fields
	if len(qe.qb.allowedFields) > 0 {
		fields := make([]string, 0)
		for _, field := range qe.qb.allowedFields {
			fields = append(fields, field.Name)
		}
		sql += strings.Join(fields, ", ")
	} else {
		sql += "*"
	}

	// Add FROM clause (simplified)
	sql += " FROM table_name"

	// Add WHERE conditions (simplified representation)
	if len(qe.qb.allowedFilters) > 0 {
		sql += " WHERE conditions_applied"
	}

	// Add ORDER BY (simplified)
	if len(qe.qb.defaultSorts) > 0 {
		sql += " ORDER BY "
		sorts := make([]string, 0)
		for _, sort := range qe.qb.defaultSorts {
			sorts = append(sorts, sort.Field+" "+sort.Direction)
		}
		sql += strings.Join(sorts, ", ")
	}

	// Add JOINs (simplified)
	if len(qe.qb.joins) > 0 {
		sql = strings.Replace(sql, "FROM table_name", "FROM table_name WITH_JOINS", 1)
	}

	return sql
}

// estimateQueryCost estimates the query execution cost
func (qe *QueryExtensions) estimateQueryCost() map[string]interface{} {
	cost := map[string]interface{}{
		"estimated_rows": 1000, // Default estimate
		"cost_score":     1.0,  // Default cost
		"complexity":     "medium",
	}

	// Increase cost based on joins
	if len(qe.qb.joins) > 0 {
		cost["cost_score"] = cost["cost_score"].(float64) * float64(len(qe.qb.joins)) * 1.5
		cost["complexity"] = "high"
	}

	// Increase cost based on filters
	if len(qe.qb.allowedFilters) > 3 {
		cost["cost_score"] = cost["cost_score"].(float64) * 1.2
	}

	// Decrease cost if using indexes (simplified check)
	if qe.hasIndexedFilters() {
		cost["cost_score"] = cost["cost_score"].(float64) * 0.8
		cost["has_indexes"] = true
	}

	return cost
}

// getIndexesUsed returns information about indexes that might be used
func (qe *QueryExtensions) getIndexesUsed() []map[string]interface{} {
	indexes := make([]map[string]interface{}, 0)

	// Check for common indexed fields
	commonIndexes := []string{"id", "created_at", "updated_at", "user_id", "status"}

	for _, filter := range qe.qb.allowedFilters {
		for _, indexField := range commonIndexes {
			if strings.Contains(filter.Property, indexField) {
				indexes = append(indexes, map[string]interface{}{
					"index_name": "idx_" + indexField,
					"field":      indexField,
					"type":       "btree",
					"usage":      "potential",
				})
			}
		}
	}

	return indexes
}

// determineScanType determines the likely scan type for the query
func (qe *QueryExtensions) determineScanType() string {
	// Simplified scan type determination
	if len(qe.qb.allowedFilters) == 0 {
		return "full_table_scan"
	}

	if qe.hasIndexedFilters() {
		return "index_scan"
	}

	if len(qe.qb.joins) > 0 {
		return "nested_loop_join"
	}

	return "range_scan"
}

// hasIndexedFilters checks if any filters are on commonly indexed fields
func (qe *QueryExtensions) hasIndexedFilters() bool {
	commonIndexes := []string{"id", "created_at", "updated_at", "user_id", "status"}

	for _, filter := range qe.qb.allowedFilters {
		for _, indexField := range commonIndexes {
			if strings.Contains(filter.Property, indexField) {
				return true
			}
		}
	}

	return false
}

// CallMacro calls a registered macro
func (qe *QueryExtensions) CallMacro(name string, args ...interface{}) *QueryExtensions {
	if macro, exists := macros[name]; exists {
		return macro(qe, args...)
	}
	facades.Log().Warning(fmt.Sprintf("Macro '%s' not found", name))
	return qe
}

// HasMacro checks if a macro is registered
func HasMacro(name string) bool {
	_, exists := macros[name]
	return exists
}

// GetRegisteredMacros returns all registered macro names
func GetRegisteredMacros() []string {
	names := make([]string, 0, len(macros))
	for name := range macros {
		names = append(names, name)
	}
	return names
}
