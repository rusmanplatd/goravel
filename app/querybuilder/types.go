package querybuilder

import (
	"fmt"
	"strings"
	"time"

	"github.com/goravel/framework/contracts/database/orm"
)

// FilterType defines the type of filter to apply
type FilterType string

const (
	FilterTypePartial       FilterType = "partial"
	FilterTypeExact         FilterType = "exact"
	FilterTypeBeginsWith    FilterType = "begins_with"
	FilterTypeEndsWith      FilterType = "ends_with"
	FilterTypeScope         FilterType = "scope"
	FilterTypeCallback      FilterType = "callback"
	FilterTypeTrashed       FilterType = "trashed"
	FilterTypeGreaterThan   FilterType = "greater_than"
	FilterTypeLessThan      FilterType = "less_than"
	FilterTypeGreaterEqual  FilterType = "greater_equal"
	FilterTypeLessEqual     FilterType = "less_equal"
	FilterTypeBetween       FilterType = "between"
	FilterTypeIn            FilterType = "in"
	FilterTypeNotIn         FilterType = "not_in"
	FilterTypeNull          FilterType = "null"
	FilterTypeNotNull       FilterType = "not_null"
	FilterTypeDateRange     FilterType = "date_range"
	FilterTypeRegex         FilterType = "regex"
	FilterTypeJsonContains  FilterType = "json_contains"
	FilterTypeJsonExtract   FilterType = "json_extract"
	FilterTypeFullText      FilterType = "fulltext"
	FilterTypeGeoDistance   FilterType = "geo_distance"
	FilterTypeArrayContains FilterType = "array_contains"
)

// LogicalOperator defines logical operators for filter groups
type LogicalOperator string

const (
	LogicalAnd LogicalOperator = "AND"
	LogicalOr  LogicalOperator = "OR"
	LogicalNot LogicalOperator = "NOT"
)

// ComparisonOperator defines comparison operators
type ComparisonOperator string

const (
	OpEqual              ComparisonOperator = "="
	OpNotEqual           ComparisonOperator = "!="
	OpGreaterThan        ComparisonOperator = ">"
	OpLessThan           ComparisonOperator = "<"
	OpGreaterThanOrEqual ComparisonOperator = ">="
	OpLessThanOrEqual    ComparisonOperator = "<="
	OpLike               ComparisonOperator = "LIKE"
	OpNotLike            ComparisonOperator = "NOT LIKE"
	OpIn                 ComparisonOperator = "IN"
	OpNotIn              ComparisonOperator = "NOT IN"
	OpBetween            ComparisonOperator = "BETWEEN"
	OpNotBetween         ComparisonOperator = "NOT BETWEEN"
	OpIsNull             ComparisonOperator = "IS NULL"
	OpIsNotNull          ComparisonOperator = "IS NOT NULL"
	OpRegex              ComparisonOperator = "REGEXP"
	OpExists             ComparisonOperator = "EXISTS"
	OpNotExists          ComparisonOperator = "NOT EXISTS"
)

// AggregateFunction defines aggregate functions
type AggregateFunction string

const (
	AggCount    AggregateFunction = "COUNT"
	AggSum      AggregateFunction = "SUM"
	AggAvg      AggregateFunction = "AVG"
	AggMin      AggregateFunction = "MIN"
	AggMax      AggregateFunction = "MAX"
	AggStdDev   AggregateFunction = "STDDEV"
	AggVariance AggregateFunction = "VARIANCE"
	AggFirst    AggregateFunction = "FIRST"
	AggLast     AggregateFunction = "LAST"
)

// JoinType defines join types
type JoinType string

const (
	JoinInner JoinType = "INNER"
	JoinLeft  JoinType = "LEFT"
	JoinRight JoinType = "RIGHT"
	JoinFull  JoinType = "FULL"
	JoinCross JoinType = "CROSS"
)

// FilterCallback defines the signature for custom filter callbacks
type FilterCallback func(query orm.Query, value interface{}, property string) orm.Query

// SortCallback defines the signature for custom sort callbacks
type SortCallback func(query orm.Query, direction string, property string) orm.Query

// IncludeCallback defines the signature for custom include callbacks
type IncludeCallback func(query orm.Query, include string) orm.Query

// Filter group structures

// FilterCondition represents a single filter condition
type FilterCondition struct {
	Field    string             `json:"field"`
	Operator ComparisonOperator `json:"operator"`
	Value    interface{}        `json:"value"`
	Values   []interface{}      `json:"values,omitempty"` // For IN, NOT IN, etc.
}

// FilterGroup represents a group of filter conditions with logical operators
type FilterGroup struct {
	Operator   LogicalOperator   `json:"operator"`
	Conditions []FilterCondition `json:"conditions,omitempty"`
	Groups     []FilterGroup     `json:"groups,omitempty"`
}

// ComplexFilter represents a complex filter with nested conditions
type ComplexFilter struct {
	Name     string      `json:"name"`
	Root     FilterGroup `json:"root"`
	Internal bool        `json:"internal,omitempty"`
}

// Aggregation structures

// AggregateField represents a field to aggregate
type AggregateField struct {
	Function AggregateFunction `json:"function"`
	Field    string            `json:"field"`
	Alias    string            `json:"alias,omitempty"`
	Distinct bool              `json:"distinct,omitempty"`
}

// GroupByClause represents GROUP BY configuration
type GroupByClause struct {
	Fields []string          `json:"fields"`
	Having []FilterCondition `json:"having,omitempty"`
}

// WindowFunction represents window function configuration
type WindowFunction struct {
	Function    string   `json:"function"`
	Field       string   `json:"field,omitempty"`
	Alias       string   `json:"alias"`
	PartitionBy []string `json:"partition_by,omitempty"`
	OrderBy     []string `json:"order_by,omitempty"`
	Frame       string   `json:"frame,omitempty"` // e.g., "ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW"
}

// Join structures

// JoinCondition represents a join condition
type JoinCondition struct {
	LeftField  string             `json:"left_field"`
	Operator   ComparisonOperator `json:"operator"`
	RightField string             `json:"right_field"`
	Value      interface{}        `json:"value,omitempty"` // For non-field comparisons
}

// JoinClause represents a join operation
type JoinClause struct {
	Type       JoinType        `json:"type"`
	Table      string          `json:"table"`
	Alias      string          `json:"alias,omitempty"`
	Conditions []JoinCondition `json:"conditions"`
	SubQuery   *SubQuery       `json:"subquery,omitempty"` // For joining with subqueries
}

// Subquery structures

// SubQueryType defines subquery types
type SubQueryType string

const (
	SubQueryExists SubQueryType = "EXISTS"
	SubQueryIn     SubQueryType = "IN"
	SubQueryScalar SubQueryType = "SCALAR"
)

// SubQuery represents a subquery
type SubQuery struct {
	Type        SubQueryType      `json:"type"`
	Field       string            `json:"field,omitempty"` // Field to compare with (for IN subqueries)
	SelectField string            `json:"select_field"`    // Field to select from subquery
	Table       string            `json:"table"`
	Alias       string            `json:"alias,omitempty"`
	Conditions  []FilterCondition `json:"conditions,omitempty"`
	Joins       []JoinClause      `json:"joins,omitempty"`
}

// Existing types (keeping them as they were)

// AllowedFilter represents a filter that can be applied to the query
type AllowedFilter struct {
	Name          string
	Property      string
	Type          FilterType
	Callback      FilterCallback
	IgnoredValues []interface{}
	DefaultValue  interface{}
	Nullable      bool
	Internal      bool
}

// AllowedSort represents a sort that can be applied to the query
type AllowedSort struct {
	Name     string
	Property string
	Callback SortCallback
	Internal bool
}

// AllowedInclude represents a relationship that can be included in the query
type AllowedInclude struct {
	Name         string
	Relationship string
	Callback     IncludeCallback
	Internal     bool
}

// AllowedField represents a field that can be selected in the query
type AllowedField struct {
	Name     string
	Internal bool
}

// DefaultSort represents a default sort to apply when no sort is specified
type DefaultSort struct {
	Field     string
	Direction string
}

// Query configuration

// QueryOptions holds query configuration options
type QueryOptions struct {
	// Filter options
	AllowFilterGroups   bool
	MaxFilterDepth      int
	MaxFilterConditions int

	// Aggregation
	AllowAggregation  bool
	AllowedAggregates []AggregateField
	AllowGroupBy      bool
	AllowHaving       bool

	// Joins
	AllowJoins   bool
	AllowedJoins []JoinClause
	MaxJoinDepth int

	// Subqueries
	AllowSubQueries  bool
	MaxSubQueryDepth int

	// Performance
	DefaultLimit    int
	MaxLimit        int
	QueryTimeout    int // seconds
	EnableQueryPlan bool

	// Security
	AllowRawSQL    bool
	SanitizeInputs bool
	ValidateSchema bool
}

// DefaultQueryOptions returns default query options
func DefaultQueryOptions() *QueryOptions {
	return &QueryOptions{
		AllowFilterGroups:   true,
		MaxFilterDepth:      5,
		MaxFilterConditions: 50,
		AllowAggregation:    true,
		AllowGroupBy:        true,
		AllowHaving:         true,
		AllowJoins:          true,
		MaxJoinDepth:        3,
		AllowSubQueries:     true,
		MaxSubQueryDepth:    3,
		DefaultLimit:        15,
		MaxLimit:            1000,
		QueryTimeout:        30,
		EnableQueryPlan:     false,
		AllowRawSQL:         false,
		SanitizeInputs:      true,
		ValidateSchema:      true,
	}
}

// Filter builders - similar to spatie/laravel-query-builder

// Partial creates a partial filter (LIKE %value%)
func Partial(name string, property ...string) AllowedFilter {
	prop := name
	if len(property) > 0 {
		prop = property[0]
	}
	return AllowedFilter{
		Name:     name,
		Property: prop,
		Type:     FilterTypePartial,
	}
}

// Exact creates an exact filter (= value or IN values)
func Exact(name string, property ...string) AllowedFilter {
	prop := name
	if len(property) > 0 {
		prop = property[0]
	}
	return AllowedFilter{
		Name:     name,
		Property: prop,
		Type:     FilterTypeExact,
	}
}

// BeginsWith creates a begins with filter (LIKE value%)
func BeginsWith(name string, property ...string) AllowedFilter {
	prop := name
	if len(property) > 0 {
		prop = property[0]
	}
	return AllowedFilter{
		Name:     name,
		Property: prop,
		Type:     FilterTypeBeginsWith,
	}
}

// EndsWith creates an ends with filter (LIKE %value)
func EndsWith(name string, property ...string) AllowedFilter {
	prop := name
	if len(property) > 0 {
		prop = property[0]
	}
	return AllowedFilter{
		Name:     name,
		Property: prop,
		Type:     FilterTypeEndsWith,
	}
}

// Scope creates a scope filter
func Scope(name string, scopeName ...string) AllowedFilter {
	scope := name
	if len(scopeName) > 0 {
		scope = scopeName[0]
	}
	return AllowedFilter{
		Name:     name,
		Property: scope,
		Type:     FilterTypeScope,
	}
}

// Callback creates a custom callback filter
func Callback(name string, callback FilterCallback) AllowedFilter {
	return AllowedFilter{
		Name:     name,
		Property: name,
		Type:     FilterTypeCallback,
		Callback: callback,
	}
}

// Trashed creates a trashed filter for soft deletes
func Trashed() AllowedFilter {
	return AllowedFilter{
		Name:     "trashed",
		Property: "trashed",
		Type:     FilterTypeTrashed,
		Callback: func(query orm.Query, value interface{}, property string) orm.Query {
			valueStr := ""
			if value != nil {
				valueStr = value.(string)
			}

			switch valueStr {
			case "with":
				return query.WithTrashed()
			case "only":
				// For "only" trashed, we need to add a where clause for deleted_at IS NOT NULL
				return query.Where("deleted_at IS NOT NULL")
			default:
				// Default behavior - exclude trashed
				return query
			}
		},
	}
}

// Extended filter builders

// JsonContains creates a JSON contains filter
func JsonContains(name string, property ...string) AllowedFilter {
	prop := name
	if len(property) > 0 {
		prop = property[0]
	}
	return AllowedFilter{
		Name:     name,
		Property: prop,
		Type:     FilterTypeJsonContains,
	}
}

// JsonExtract creates a JSON extract filter
func JsonExtract(name string, property string, path string) AllowedFilter {
	return AllowedFilter{
		Name:     name,
		Property: property,
		Type:     FilterTypeJsonExtract,
		Callback: func(query orm.Query, value interface{}, property string) orm.Query {
			return query.Where(fmt.Sprintf("JSON_EXTRACT(%s, '%s') = ?", property, path), value)
		},
	}
}

// FullText creates a full-text search filter
func FullText(name string, fields ...string) AllowedFilter {
	return AllowedFilter{
		Name:     name,
		Property: strings.Join(fields, ","),
		Type:     FilterTypeFullText,
		Callback: func(query orm.Query, value interface{}, property string) orm.Query {
			fields := strings.Split(property, ",")
			matchFields := strings.Join(fields, ",")
			return query.Where(fmt.Sprintf("MATCH(%s) AGAINST(? IN BOOLEAN MODE)", matchFields), value)
		},
	}
}

// GeoDistance creates a geographic distance filter
func GeoDistance(name string, latField, lngField string) AllowedFilter {
	return AllowedFilter{
		Name:     name,
		Property: fmt.Sprintf("%s,%s", latField, lngField),
		Type:     FilterTypeGeoDistance,
		Callback: func(query orm.Query, value interface{}, property string) orm.Query {
			// Expected value format: "lat,lng,distance_km"
			valueStr := fmt.Sprintf("%v", value)
			parts := strings.Split(valueStr, ",")
			if len(parts) != 3 {
				return query
			}

			fields := strings.Split(property, ",")
			if len(fields) != 2 {
				return query
			}

			latField, lngField := fields[0], fields[1]
			lat, lng, distance := parts[0], parts[1], parts[2]

			// Using Haversine formula for distance calculation
			return query.Where(
				fmt.Sprintf("(6371 * acos(cos(radians(?)) * cos(radians(%s)) * cos(radians(%s) - radians(?)) + sin(radians(?)) * sin(radians(%s)))) <= ?",
					latField, lngField, latField),
				lat, lng, lat, distance)
		},
	}
}

// ArrayContains creates an array contains filter
func ArrayContains(name string, property ...string) AllowedFilter {
	prop := name
	if len(property) > 0 {
		prop = property[0]
	}
	return AllowedFilter{
		Name:     name,
		Property: prop,
		Type:     FilterTypeArrayContains,
		Callback: func(query orm.Query, value interface{}, property string) orm.Query {
			return query.Where(fmt.Sprintf("JSON_CONTAINS(%s, ?)", property), fmt.Sprintf(`"%v"`, value))
		},
	}
}

// Filter methods for chaining

// Ignore sets values to ignore for this filter
func (f AllowedFilter) Ignore(values ...interface{}) AllowedFilter {
	f.IgnoredValues = append(f.IgnoredValues, values...)
	return f
}

// Default sets a default value for this filter
func (f AllowedFilter) Default(value interface{}) AllowedFilter {
	f.DefaultValue = value
	return f
}

// SetNullable marks this filter as nullable
func (f AllowedFilter) SetNullable(nullable bool) AllowedFilter {
	f.Nullable = nullable
	return f
}

// Sort builders

// Sort creates a simple sort
func Sort(name string, property ...string) AllowedSort {
	prop := name
	if len(property) > 0 {
		prop = property[0]
	}
	return AllowedSort{
		Name:     name,
		Property: prop,
	}
}

// CustomSort creates a custom callback sort
func CustomSort(name string, callback SortCallback) AllowedSort {
	return AllowedSort{
		Name:     name,
		Property: name,
		Callback: callback,
	}
}

// Include builders

// Include creates a simple include
func Include(name string, relationship ...string) AllowedInclude {
	rel := name
	if len(relationship) > 0 {
		rel = relationship[0]
	}
	return AllowedInclude{
		Name:         name,
		Relationship: rel,
	}
}

// CustomInclude creates a custom callback include
func CustomInclude(name string, callback IncludeCallback) AllowedInclude {
	return AllowedInclude{
		Name:     name,
		Callback: callback,
	}
}

// Field builders

// Field creates a simple field
func Field(name string) AllowedField {
	return AllowedField{
		Name: name,
	}
}

// Advanced filter builders

// GreaterThan creates a greater than filter (> value)
func GreaterThan(name string, property ...string) AllowedFilter {
	prop := name
	if len(property) > 0 {
		prop = property[0]
	}
	return AllowedFilter{
		Name:     name,
		Property: prop,
		Type:     FilterTypeGreaterThan,
	}
}

// LessThan creates a less than filter (< value)
func LessThan(name string, property ...string) AllowedFilter {
	prop := name
	if len(property) > 0 {
		prop = property[0]
	}
	return AllowedFilter{
		Name:     name,
		Property: prop,
		Type:     FilterTypeLessThan,
	}
}

// GreaterEqual creates a greater than or equal filter (>= value)
func GreaterEqual(name string, property ...string) AllowedFilter {
	prop := name
	if len(property) > 0 {
		prop = property[0]
	}
	return AllowedFilter{
		Name:     name,
		Property: prop,
		Type:     FilterTypeGreaterEqual,
	}
}

// LessEqual creates a less than or equal filter (<= value)
func LessEqual(name string, property ...string) AllowedFilter {
	prop := name
	if len(property) > 0 {
		prop = property[0]
	}
	return AllowedFilter{
		Name:     name,
		Property: prop,
		Type:     FilterTypeLessEqual,
	}
}

// Between creates a between filter (BETWEEN value1 AND value2)
func Between(name string, property ...string) AllowedFilter {
	prop := name
	if len(property) > 0 {
		prop = property[0]
	}
	return AllowedFilter{
		Name:     name,
		Property: prop,
		Type:     FilterTypeBetween,
	}
}

// In creates an IN filter (IN (value1, value2, ...))
func In(name string, property ...string) AllowedFilter {
	prop := name
	if len(property) > 0 {
		prop = property[0]
	}
	return AllowedFilter{
		Name:     name,
		Property: prop,
		Type:     FilterTypeIn,
	}
}

// NotIn creates a NOT IN filter (NOT IN (value1, value2, ...))
func NotIn(name string, property ...string) AllowedFilter {
	prop := name
	if len(property) > 0 {
		prop = property[0]
	}
	return AllowedFilter{
		Name:     name,
		Property: prop,
		Type:     FilterTypeNotIn,
	}
}

// IsNull creates a NULL filter (IS NULL)
func IsNull(name string, property ...string) AllowedFilter {
	prop := name
	if len(property) > 0 {
		prop = property[0]
	}
	return AllowedFilter{
		Name:     name,
		Property: prop,
		Type:     FilterTypeNull,
	}
}

// IsNotNull creates a NOT NULL filter (IS NOT NULL)
func IsNotNull(name string, property ...string) AllowedFilter {
	prop := name
	if len(property) > 0 {
		prop = property[0]
	}
	return AllowedFilter{
		Name:     name,
		Property: prop,
		Type:     FilterTypeNotNull,
	}
}

// DateRange creates a date range filter
func DateRange(name string, property ...string) AllowedFilter {
	prop := name
	if len(property) > 0 {
		prop = property[0]
	}
	return AllowedFilter{
		Name:     name,
		Property: prop,
		Type:     FilterTypeDateRange,
	}
}

// Regex creates a regex filter
func Regex(name string, property ...string) AllowedFilter {
	prop := name
	if len(property) > 0 {
		prop = property[0]
	}
	return AllowedFilter{
		Name:     name,
		Property: prop,
		Type:     FilterTypeRegex,
	}
}

// Pagination types and structures

// PaginationType defines the type of pagination
type PaginationType string

const (
	PaginationTypeOffset PaginationType = "offset"
	PaginationTypeCursor PaginationType = "cursor"
	PaginationTypeKeyset PaginationType = "keyset"
)

// PaginationConfig holds pagination configuration
type PaginationConfig struct {
	Type            PaginationType
	DefaultLimit    int
	MaxLimit        int
	PageParameter   string
	LimitParameter  string
	CursorParameter string
	TypeParameter   string // New parameter to specify pagination type dynamically
}

// DefaultPaginationConfig returns default pagination configuration
func DefaultPaginationConfig() *PaginationConfig {
	return &PaginationConfig{
		Type:            PaginationTypeOffset,
		DefaultLimit:    15,
		MaxLimit:        100,
		PageParameter:   "page",
		LimitParameter:  "limit",
		CursorParameter: "cursor",
		TypeParameter:   "pagination_type", // Can be "offset" or "cursor"
	}
}

// PaginationInfo contains all pagination metadata
type PaginationInfo struct {
	// Common fields for all pagination types
	Count   int    `json:"count"`
	Limit   int    `json:"limit"`
	HasNext bool   `json:"has_next"`
	HasPrev bool   `json:"has_prev"`
	Type    string `json:"type"` // "offset", "cursor", or "simple"

	// Offset pagination specific fields
	CurrentPage *int   `json:"current_page,omitempty"`
	LastPage    *int   `json:"last_page,omitempty"`
	PerPage     *int   `json:"per_page,omitempty"`
	Total       *int64 `json:"total,omitempty"`
	From        *int   `json:"from,omitempty"`
	To          *int   `json:"to,omitempty"`

	// Cursor pagination specific fields
	NextCursor *string `json:"next_cursor,omitempty"`
	PrevCursor *string `json:"prev_cursor,omitempty"`
}

// UnifiedPaginationResult represents a unified pagination result
type UnifiedPaginationResult struct {
	Data       interface{}     `json:"data"`
	Pagination *PaginationInfo `json:"pagination"`
}

// CursorPaginationResult represents the result of cursor-based pagination
type CursorPaginationResult struct {
	Data       interface{}     `json:"data"`
	Pagination *PaginationInfo `json:"pagination"`
}

// OffsetPaginationResult represents the result of offset-based pagination
type OffsetPaginationResult struct {
	Data       interface{}     `json:"data"`
	Pagination *PaginationInfo `json:"pagination"`
}

// Cursor represents a pagination cursor with flexible field support
type Cursor struct {
	Values map[string]interface{} `json:"values"`
}

// CursorField represents a field used for cursor pagination
type CursorField struct {
	Name      string
	Direction string // "asc" or "desc"
}

// PaginationOptions holds options for pagination
type PaginationOptions struct {
	CursorFields []CursorField
	Reverse      bool
}

// Advanced result structures

// AggregationResult represents the result of an aggregation query
type AggregationResult struct {
	Data       interface{}            `json:"data"`
	Aggregates map[string]interface{} `json:"aggregates"`
	GroupedBy  []string               `json:"grouped_by,omitempty"`
	Pagination *PaginationInfo        `json:"pagination,omitempty"`
}

// QueryResult represents a complete query result
type QueryResult struct {
	Data        interface{}            `json:"data"`
	Aggregates  map[string]interface{} `json:"aggregates,omitempty"`
	Pagination  *PaginationInfo        `json:"pagination,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	QueryPlan   *QueryPlan             `json:"query_plan,omitempty"`
	Performance *PerformanceMetrics    `json:"performance,omitempty"`
}

// QueryPlan represents a database query execution plan
type QueryPlan struct {
	EstimatedCost float64              `json:"estimated_cost"`
	EstimatedRows int64                `json:"estimated_rows"`
	Operations    []QueryPlanOperation `json:"operations"`
	IndexesUsed   []string             `json:"indexes_used"`
	Warnings      []string             `json:"warnings,omitempty"`
	Suggestions   []string             `json:"suggestions,omitempty"`
}

// QueryPlanOperation represents a single operation in the query plan
type QueryPlanOperation struct {
	Type        string  `json:"type"`
	Table       string  `json:"table,omitempty"`
	Index       string  `json:"index,omitempty"`
	Cost        float64 `json:"cost"`
	Rows        int64   `json:"rows"`
	Description string  `json:"description"`
}

// PerformanceMetrics represents query performance metrics
type PerformanceMetrics struct {
	ExecutionTime time.Duration `json:"execution_time"`
	ParseTime     time.Duration `json:"parse_time"`
	PlanTime      time.Duration `json:"plan_time"`
	RowsExamined  int64         `json:"rows_examined"`
	RowsReturned  int64         `json:"rows_returned"`
	IndexHits     int64         `json:"index_hits"`
	CacheHit      bool          `json:"cache_hit"`
	MemoryUsage   int64         `json:"memory_usage"` // bytes
}
