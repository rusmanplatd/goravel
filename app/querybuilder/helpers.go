package querybuilder

import (
	"fmt"

	"github.com/goravel/framework/contracts/database/orm"
	"github.com/goravel/framework/contracts/http"
)

// FromRequest creates a QueryBuilder from an HTTP request context
func FromRequest(ctx http.Context, subject interface{}) *QueryBuilder {
	return For(subject).WithRequest(ctx)
}

// ApplyQueryParameters applies query parameters from request to an existing query
func ApplyQueryParameters(query orm.Query, ctx http.Context, config QueryConfig) orm.Query {
	qb := &QueryBuilder{
		query:           query,
		request:         ctx,
		allowedFilters:  config.AllowedFilters,
		allowedSorts:    config.AllowedSorts,
		allowedIncludes: config.AllowedIncludes,
		allowedFields:   config.AllowedFields,
		defaultSorts:    config.DefaultSorts,
		config:          DefaultConfig(),
	}

	if config.Config != nil {
		qb.config = config.Config
	}

	return qb.Build()
}

// QueryConfig holds configuration for applying query parameters
type QueryConfig struct {
	AllowedFilters  []AllowedFilter
	AllowedSorts    []AllowedSort
	AllowedIncludes []AllowedInclude
	AllowedFields   []AllowedField
	DefaultSorts    []DefaultSort
	Config          *Config
}

// Common filter builders for convenience

// TextFilters creates common text filters (partial, exact, begins_with, ends_with)
func TextFilters(fields ...string) []AllowedFilter {
	filters := make([]AllowedFilter, 0)
	for _, field := range fields {
		filters = append(filters, Partial(field))
		filters = append(filters, Exact(field+"_exact", field))
		filters = append(filters, BeginsWith(field+"_starts", field))
		filters = append(filters, EndsWith(field+"_ends", field))
	}
	return filters
}

// ExactFilters creates exact filters for the given fields
func ExactFilters(fields ...string) []AllowedFilter {
	filters := make([]AllowedFilter, 0)
	for _, field := range fields {
		filters = append(filters, Exact(field))
	}
	return filters
}

// PartialFilters creates partial filters for the given fields
func PartialFilters(fields ...string) []AllowedFilter {
	filters := make([]AllowedFilter, 0)
	for _, field := range fields {
		filters = append(filters, Partial(field))
	}
	return filters
}

// CommonSorts creates common sorts for the given fields
func CommonSorts(fields ...string) []AllowedSort {
	sorts := make([]AllowedSort, 0)
	for _, field := range fields {
		sorts = append(sorts, Sort(field))
	}
	return sorts
}

// CommonIncludes creates common includes for the given relationships
func CommonIncludes(relationships ...string) []AllowedInclude {
	includes := make([]AllowedInclude, 0)
	for _, rel := range relationships {
		includes = append(includes, Include(rel))
	}
	return includes
}

// CommonFields creates common fields for the given field names
func CommonFields(fields ...string) []AllowedField {
	allowedFields := make([]AllowedField, 0)
	for _, field := range fields {
		allowedFields = append(allowedFields, Field(field))
	}
	return allowedFields
}

// Extended filter helpers

// NumericFilters creates numeric comparison filters for the given fields
func NumericFilters(fields ...string) []AllowedFilter {
	filters := make([]AllowedFilter, 0)
	for _, field := range fields {
		filters = append(filters, GreaterThan(field+"_gt", field))
		filters = append(filters, LessThan(field+"_lt", field))
		filters = append(filters, GreaterEqual(field+"_gte", field))
		filters = append(filters, LessEqual(field+"_lte", field))
		filters = append(filters, Between(field+"_between", field))
	}
	return filters
}

// DateFilters creates date-related filters for the given fields
func DateFilters(fields ...string) []AllowedFilter {
	filters := make([]AllowedFilter, 0)
	for _, field := range fields {
		filters = append(filters, DateRange(field+"_range", field))
		filters = append(filters, GreaterThan(field+"_after", field))
		filters = append(filters, LessThan(field+"_before", field))
		filters = append(filters, IsNull(field+"_null", field))
		filters = append(filters, IsNotNull(field+"_not_null", field))
	}
	return filters
}

// ArrayFilters creates array-related filters for the given fields
func ArrayFilters(fields ...string) []AllowedFilter {
	filters := make([]AllowedFilter, 0)
	for _, field := range fields {
		filters = append(filters, In(field+"_in", field))
		filters = append(filters, NotIn(field+"_not_in", field))
	}
	return filters
}

// NullabilityFilters creates null/not null filters for the given fields
func NullabilityFilters(fields ...string) []AllowedFilter {
	filters := make([]AllowedFilter, 0)
	for _, field := range fields {
		filters = append(filters, IsNull(field+"_null", field))
		filters = append(filters, IsNotNull(field+"_not_null", field))
	}
	return filters
}

// Extended filter builders for modern database features

// JsonFilters creates JSON-related filters for the given fields
func JsonFilters(fields ...string) []AllowedFilter {
	filters := make([]AllowedFilter, 0)
	for _, field := range fields {
		filters = append(filters, JsonContains(field+"_contains", field))
		filters = append(filters, ArrayContains(field+"_array_contains", field))
	}
	return filters
}

// FullTextFilters creates full-text search filters for the given fields
func FullTextFilters(name string, fields ...string) []AllowedFilter {
	return []AllowedFilter{
		FullText(name, fields...),
		FullText(name+"_boolean", fields...), // Boolean mode variant
	}
}

// GeoFilters creates geographic filters for location-based fields
func GeoFilters(name string, latField, lngField string) []AllowedFilter {
	return []AllowedFilter{
		GeoDistance(name+"_within", latField, lngField),
	}
}

// Complex filter builders

// Filter group builders

// AndGroup creates an AND filter group
func AndGroup(conditions ...FilterCondition) FilterGroup {
	return FilterGroup{
		Operator:   LogicalAnd,
		Conditions: conditions,
	}
}

// OrGroup creates an OR filter group
func OrGroup(conditions ...FilterCondition) FilterGroup {
	return FilterGroup{
		Operator:   LogicalOr,
		Conditions: conditions,
	}
}

// NotGroup creates a NOT filter group
func NotGroup(conditions ...FilterCondition) FilterGroup {
	return FilterGroup{
		Operator:   LogicalNot,
		Conditions: conditions,
	}
}

// Condition creates a filter condition
func Condition(field string, operator ComparisonOperator, value interface{}) FilterCondition {
	return FilterCondition{
		Field:    field,
		Operator: operator,
		Value:    value,
	}
}

// InCondition creates an IN condition with multiple values
func InCondition(field string, values ...interface{}) FilterCondition {
	return FilterCondition{
		Field:    field,
		Operator: OpIn,
		Values:   values,
	}
}

// BetweenCondition creates a BETWEEN condition
func BetweenCondition(field string, min, max interface{}) FilterCondition {
	return FilterCondition{
		Field:    field,
		Operator: OpBetween,
		Values:   []interface{}{min, max},
	}
}

// Aggregation helpers

// CommonAggregates creates common aggregate fields for the given fields
func CommonAggregates(fields ...string) []AggregateField {
	aggregates := make([]AggregateField, 0)
	for _, field := range fields {
		aggregates = append(aggregates, AggregateField{Function: AggCount, Field: field, Alias: field + "_count"})
		aggregates = append(aggregates, AggregateField{Function: AggSum, Field: field, Alias: field + "_sum"})
		aggregates = append(aggregates, AggregateField{Function: AggAvg, Field: field, Alias: field + "_avg"})
		aggregates = append(aggregates, AggregateField{Function: AggMin, Field: field, Alias: field + "_min"})
		aggregates = append(aggregates, AggregateField{Function: AggMax, Field: field, Alias: field + "_max"})
	}
	return aggregates
}

// StatisticalAggregates creates statistical aggregate fields
func StatisticalAggregates(fields ...string) []AggregateField {
	aggregates := make([]AggregateField, 0)
	for _, field := range fields {
		aggregates = append(aggregates,
			AggregateField{Function: AggStdDev, Field: field, Alias: field + "_stddev"},
			AggregateField{Function: AggVariance, Field: field, Alias: field + "_variance"},
		)
	}
	return aggregates
}

// Window function helpers

// RowNumberWindow creates a ROW_NUMBER window function
func RowNumberWindow(alias string, partitionBy []string, orderBy []string) WindowFunction {
	return WindowFunction{
		Function:    "ROW_NUMBER",
		Alias:       alias,
		PartitionBy: partitionBy,
		OrderBy:     orderBy,
	}
}

// RankWindow creates a RANK window function
func RankWindow(alias string, partitionBy []string, orderBy []string) WindowFunction {
	return WindowFunction{
		Function:    "RANK",
		Alias:       alias,
		PartitionBy: partitionBy,
		OrderBy:     orderBy,
	}
}

// DenseRankWindow creates a DENSE_RANK window function
func DenseRankWindow(alias string, partitionBy []string, orderBy []string) WindowFunction {
	return WindowFunction{
		Function:    "DENSE_RANK",
		Alias:       alias,
		PartitionBy: partitionBy,
		OrderBy:     orderBy,
	}
}

// LeadLagWindow creates LEAD or LAG window function
func LeadLagWindow(function, field, alias string, partitionBy []string, orderBy []string, offset int) WindowFunction {
	return WindowFunction{
		Function:    function,
		Field:       field,
		Alias:       alias,
		PartitionBy: partitionBy,
		OrderBy:     orderBy,
		Frame:       fmt.Sprintf("ROWS %d PRECEDING", offset),
	}
}

// CommonConfig provides a common configuration with typical filters and sorts
func CommonConfig(model string) QueryConfig {
	return QueryConfig{
		AllowedFilters: []AllowedFilter{
			Partial("search"),
			Exact("id"),
			Exact("status"),
			Exact("is_active"),
			Trashed(),
		},
		AllowedSorts: []AllowedSort{
			Sort("id"),
			Sort("created_at"),
			Sort("updated_at"),
			Sort("name"),
			Sort("title"),
		},
		DefaultSorts: []DefaultSort{
			{Field: "created_at", Direction: "desc"},
		},
	}
}

// ExtendedConfig provides a configuration with extended features
func ExtendedConfig(model string) QueryConfig {
	config := CommonConfig(model)

	// Add extended filters
	config.AllowedFilters = append(config.AllowedFilters,
		JsonContains("metadata_contains"),
		DateRange("created_between"),
		FullText("search_fulltext", "name", "description", "content"),
	)

	return config
}

// ReadOnlyConfig provides a configuration suitable for read-only endpoints
func ReadOnlyConfig() QueryConfig {
	return QueryConfig{
		AllowedFilters: []AllowedFilter{
			Partial("search"),
			Exact("id"),
			Exact("status"),
		},
		AllowedSorts: []AllowedSort{
			Sort("id"),
			Sort("created_at"),
			Sort("name"),
			Sort("title"),
		},
		DefaultSorts: []DefaultSort{
			{Field: "created_at", Direction: "desc"},
		},
	}
}

// UserConfig provides a configuration suitable for user-related endpoints
func UserConfig() QueryConfig {
	return QueryConfig{
		AllowedFilters: []AllowedFilter{
			Partial("name"),
			Partial("email"),
			Exact("id"),
			Exact("is_active"),
			Exact("email_verified_at"),
			Trashed(),
		},
		AllowedSorts: []AllowedSort{
			Sort("id"),
			Sort("name"),
			Sort("email"),
			Sort("created_at"),
			Sort("updated_at"),
		},
		AllowedIncludes: []AllowedInclude{
			Include("roles"),
			Include("organizations"),
			Include("permissions"),
		},
		AllowedFields: []AllowedField{
			Field("id"),
			Field("name"),
			Field("email"),
			Field("created_at"),
			Field("updated_at"),
			Field("is_active"),
		},
		DefaultSorts: []DefaultSort{
			{Field: "created_at", Direction: "desc"},
		},
	}
}

// AnalyticsConfig provides a configuration suitable for analytics endpoints
func AnalyticsConfig() QueryConfig {
	return QueryConfig{
		AllowedFilters: append(
			DateFilters("created_at", "updated_at"),
			NumericFilters("amount", "quantity", "price")...,
		),
		AllowedSorts: []AllowedSort{
			Sort("created_at"),
			Sort("amount"),
			Sort("quantity"),
		},
		DefaultSorts: []DefaultSort{
			{Field: "created_at", Direction: "desc"},
		},
	}
}

// E-commerce specific configurations

// ProductConfig provides configuration for product listings
func ProductConfig() QueryConfig {
	return QueryConfig{
		AllowedFilters: append(append(
			TextFilters("name", "description"),
			NumericFilters("price", "stock_quantity")...),
			Exact("category_id"),
			Exact("brand_id"),
			Exact("is_active"),
			Between("price_range", "price"),
			In("categories", "category_id"),
		),
		AllowedSorts: []AllowedSort{
			Sort("name"),
			Sort("price"),
			Sort("created_at"),
			Sort("stock_quantity"),
			CustomSort("popularity", func(query orm.Query, direction string, property string) orm.Query {
				return query.Order("view_count " + direction)
			}),
		},
		AllowedIncludes: []AllowedInclude{
			Include("category"),
			Include("brand"),
			Include("images"),
			Include("reviews"),
		},
		AllowedFields: []AllowedField{
			Field("id"),
			Field("name"),
			Field("description"),
			Field("price"),
			Field("stock_quantity"),
			Field("is_active"),
		},
		DefaultSorts: []DefaultSort{
			{Field: "created_at", Direction: "desc"},
		},
	}
}

// OrderConfig provides configuration for order management
func OrderConfig() QueryConfig {
	return QueryConfig{
		AllowedFilters: append(
			DateFilters("created_at", "shipped_at", "delivered_at"),
			append(NumericFilters("total_amount"),
				Exact("status"),
				Exact("customer_id"),
				Exact("payment_status"),
				Partial("order_number"),
			)...),
		AllowedSorts: []AllowedSort{
			Sort("created_at"),
			Sort("total_amount"),
			Sort("status"),
			Sort("order_number"),
		},
		AllowedIncludes: []AllowedInclude{
			Include("customer"),
			Include("items"),
			Include("payments"),
			Include("shipping_address"),
		},
		DefaultSorts: []DefaultSort{
			{Field: "created_at", Direction: "desc"},
		},
	}
}

// Content management configurations

// ArticleConfig provides configuration for article/blog management
func ArticleConfig() QueryConfig {
	return QueryConfig{
		AllowedFilters: append(append(
			TextFilters("title", "content"),
			DateFilters("published_at", "created_at")...),
			Exact("status"),
			Exact("author_id"),
			Exact("category_id"),
			In("tags", "tag_id"),
			FullText("search", "title", "content", "excerpt"),
		),
		AllowedSorts: []AllowedSort{
			Sort("title"),
			Sort("published_at"),
			Sort("created_at"),
			Sort("view_count"),
			CustomSort("relevance", func(query orm.Query, direction string, property string) orm.Query {
				return query.Order("view_count " + direction)
			}),
		},
		AllowedIncludes: []AllowedInclude{
			Include("author"),
			Include("category"),
			Include("tags"),
			Include("comments"),
		},
		AllowedFields: []AllowedField{
			Field("id"),
			Field("title"),
			Field("excerpt"),
			Field("published_at"),
			Field("view_count"),
			Field("status"),
		},
		DefaultSorts: []DefaultSort{
			{Field: "published_at", Direction: "desc"},
		},
	}
}

// Utility functions for filter group building

// BuildFilterGroup builds a filter group from conditions
func BuildFilterGroup(name string, root FilterGroup) FilterGroup {
	return root
}

// CombineFilterGroups combines multiple filter groups with an operator
func CombineFilterGroups(operator LogicalOperator, groups ...FilterGroup) FilterGroup {
	return FilterGroup{
		Operator: operator,
		Groups:   groups,
	}
}

// Quick condition builders for common patterns

// EqualCondition creates an equality condition
func EqualCondition(field string, value interface{}) FilterCondition {
	return Condition(field, OpEqual, value)
}

// LikeCondition creates a LIKE condition
func LikeCondition(field string, value interface{}) FilterCondition {
	return Condition(field, OpLike, value)
}

// GreaterThanCondition creates a greater than condition
func GreaterThanCondition(field string, value interface{}) FilterCondition {
	return Condition(field, OpGreaterThan, value)
}

// LessThanCondition creates a less than condition
func LessThanCondition(field string, value interface{}) FilterCondition {
	return Condition(field, OpLessThan, value)
}

// IsNullCondition creates an IS NULL condition
func IsNullCondition(field string) FilterCondition {
	return FilterCondition{
		Field:    field,
		Operator: OpIsNull,
	}
}

// IsNotNullCondition creates an IS NOT NULL condition
func IsNotNullCondition(field string) FilterCondition {
	return FilterCondition{
		Field:    field,
		Operator: OpIsNotNull,
	}
}
