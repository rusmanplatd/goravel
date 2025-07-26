package querybuilder

import (
	"fmt"
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"
)

// ExampleUsage demonstrates how to use the improved querybuilder
func ExampleUsage() {
	facades.Log().Info("QueryBuilder Usage Examples")

	// Example 1: Simple query building
	facades.Log().Info("=== Example 1: Simple Query Building ===")

	// Simulate a model for demonstration
	type User struct {
		ID        uint      `json:"id"`
		Name      string    `json:"name"`
		Email     string    `json:"email"`
		CreatedAt time.Time `json:"created_at"`
		IsActive  bool      `json:"is_active"`
	}

	// Create query builder
	qb := For(&User{}).
		AllowedFilters("name", "email", "is_active").
		AllowedSorts("name", "created_at").
		AllowedIncludes("roles", "profile").
		DefaultSort("-created_at")

	facades.Log().Info("Query builder created with filters, sorts, and includes")

	// Example 2: Using extensions
	facades.Log().Info("=== Example 2: Using Extensions ===")

	_ = qb.WithExtensions().
		When(true, func(qb *QueryBuilder) *QueryBuilder {
			return qb.Where("is_active", true)
		}).
		WhenNotEmpty("john", func(qb *QueryBuilder, value string) *QueryBuilder {
			return qb.Where("name LIKE ?", "%"+value+"%")
		})

	facades.Log().Info("Extensions applied with conditional logic")

	// Example 3: Performance monitoring
	facades.Log().Info("=== Example 3: Performance Monitoring ===")

	// Initialize performance monitoring
	perfConfig := DefaultPerformanceConfig()
	perfConfig.EnableOptimization = true
	InitPerformanceMonitoring(perfConfig)

	facades.Log().Info("Performance monitoring initialized")

	// Example 4: Caching
	facades.Log().Info("=== Example 4: Caching ===")

	cacheConfig := DefaultCacheConfig()
	cacheConfig.DefaultTTL = 10 * time.Minute

	_ = For(&User{}).WithCache(cacheConfig)
	facades.Log().Info("Query builder with caching enabled")

	// Example 5: Bulk operations
	facades.Log().Info("=== Example 5: Bulk Operations ===")

	_ = ForBulk(&User{}).
		WithBatchSize(100).
		WithTimeout(30 * time.Second).
		WithValidation(func(record interface{}) error {
			user := record.(*User)
			if user.Email == "" {
				return fmt.Errorf("email is required")
			}
			return nil
		})

	facades.Log().Info("Bulk operation configured with validation")

	// Example 6: Validation
	facades.Log().Info("=== Example 6: Validation ===")

	validator := NewValidator()
	filter := Partial("name")
	isValid := validator.ValidateFilterValue(filter, "john")

	if isValid {
		facades.Log().Info("Filter validation passed")
	} else {
		facades.Log().Warning("Filter validation failed")
	}

	// Example 7: Different pagination types
	facades.Log().Info("=== Example 7: Pagination ===")

	// Offset pagination
	users := make([]User, 0)
	if result, err := qb.OffsetPaginate(&users); err == nil {
		facades.Log().Info(fmt.Sprintf("Offset pagination: %d results", result.Pagination.Count))
	}

	// Cursor pagination
	cursorOptions := PaginationOptions{
		CursorFields: []CursorField{
			{Name: "created_at", Direction: "desc"},
			{Name: "id", Direction: "desc"},
		},
	}
	if result, err := qb.CursorPaginate(&users, cursorOptions); err == nil {
		facades.Log().Info(fmt.Sprintf("Cursor pagination: %d results", result.Pagination.Count))
	}

	// Example 8: Filter groups
	facades.Log().Info("=== Example 8: Filter Groups ===")

	// Create filter conditions
	nameCondition := EqualCondition("name", "John")
	emailCondition := LikeCondition("email", "%@example.com")

	// Create filter group
	filterGroup := OrGroup(nameCondition, emailCondition)
	facades.Log().Info(fmt.Sprintf("Created filter group with %d conditions", len(filterGroup.Conditions)))

	// Example 9: Using helper configurations
	facades.Log().Info("=== Example 9: Helper Configurations ===")

	// Use predefined configurations
	userConfig := UserConfig()
	facades.Log().Info(fmt.Sprintf("User config: %d filters, %d sorts", len(userConfig.AllowedFilters), len(userConfig.AllowedSorts)))

	productConfig := ProductConfig()
	facades.Log().Info(fmt.Sprintf("Product config: %d filters, %d sorts", len(productConfig.AllowedFilters), len(productConfig.AllowedSorts)))

	// Example 10: Query optimization
	facades.Log().Info("=== Example 10: Query Optimization ===")

	// Get optimization suggestions
	optimizations := GetOptimizations()
	facades.Log().Info(fmt.Sprintf("Found %d optimization suggestions", len(optimizations)))

	// Get performance metrics
	metrics := GetMetrics()
	facades.Log().Info(fmt.Sprintf("Performance metrics - Total queries: %d, Cache hits: %d",
		metrics.TotalQueries, metrics.CacheHits))

	facades.Log().Info("QueryBuilder examples completed successfully!")
}

// ExampleWithRequest demonstrates usage with HTTP request context
func ExampleWithRequest(ctx http.Context) {
	facades.Log().Info("=== QueryBuilder with HTTP Request ===")

	type Product struct {
		ID         uint      `json:"id"`
		Name       string    `json:"name"`
		Price      float64   `json:"price"`
		CategoryID uint      `json:"category_id"`
		IsActive   bool      `json:"is_active"`
		CreatedAt  time.Time `json:"created_at"`
	}

	// Create query builder with request context
	qb := For(&Product{}).
		WithRequest(ctx).
		AllowedFilters(
			Partial("name"),
			Exact("category_id"),
			Between("price_range", "price"),
			Exact("is_active"),
		).
		AllowedSorts("name", "price", "created_at").
		AllowedIncludes("category", "reviews").
		DefaultSort("-created_at")

	// Execute with extensions
	products := make([]Product, 0)
	err := qb.WithExtensions().
		When(ctx.Request().Input("featured", "") == "true", func(qb *QueryBuilder) *QueryBuilder {
			return qb.Where("is_featured", true)
		}).
		WhenNotEmpty(ctx.Request().Input("search", ""), func(qb *QueryBuilder, search string) *QueryBuilder {
			return qb.Where("name LIKE ? OR description LIKE ?", "%"+search+"%", "%"+search+"%")
		}).
		Get(&products)

	if err != nil {
		facades.Log().Error(fmt.Sprintf("Query failed: %v", err))
	} else {
		facades.Log().Info(fmt.Sprintf("Found %d products", len(products)))
	}
}

// ExampleBulkOperations demonstrates bulk operations
func ExampleBulkOperations() {
	facades.Log().Info("=== Bulk Operations Example ===")

	type User struct {
		ID    uint   `json:"id"`
		Name  string `json:"name"`
		Email string `json:"email"`
	}

	// Sample data
	users := []User{
		{Name: "John Doe", Email: "john@example.com"},
		{Name: "Jane Smith", Email: "jane@example.com"},
		{Name: "Bob Johnson", Email: "bob@example.com"},
	}

	// Create bulk operation
	bulkOp := ForBulk(&User{}).
		WithBatchSize(2).
		WithValidation(func(record interface{}) error {
			user := record.(User)
			if user.Email == "" {
				return fmt.Errorf("email is required")
			}
			return nil
		}).
		WithProgress(func(processed, total int) {
			facades.Log().Info(fmt.Sprintf("Progress: %d/%d", processed, total))
		})

	// Execute bulk insert
	result, err := bulkOp.BulkInsert(users)
	if err != nil {
		facades.Log().Error(fmt.Sprintf("Bulk insert failed: %v", err))
	} else {
		facades.Log().Info(fmt.Sprintf("Bulk insert completed: %d successful, %d failed",
			result.SuccessfulRecords, result.FailedRecords))
	}

	// Bulk update example
	updates := map[string]interface{}{
		"is_active":  true,
		"updated_at": time.Now(),
	}
	conditions := map[string]interface{}{
		"email": "john@example.com",
	}

	updateResult, err := bulkOp.BulkUpdate(updates, conditions)
	if err != nil {
		facades.Log().Error(fmt.Sprintf("Bulk update failed: %v", err))
	} else {
		facades.Log().Info(fmt.Sprintf("Bulk update completed: %d records updated",
			updateResult.SuccessfulRecords))
	}
}

// ExampleValidation demonstrates validation features
func ExampleValidation() {
	facades.Log().Info("=== Validation Example ===")

	validator := NewValidator()

	// Test filter validation
	filters := map[string]interface{}{
		"name":      "John",
		"age_gt":    "25",
		"email":     "john@example.com",
		"is_active": "true",
	}

	config := UserConfig()

	// Validate query parameters
	err := ValidateQueryParameters(filters, "name,-created_at", "roles,profile", "id,name,email", config)
	if err != nil {
		facades.Log().Error(fmt.Sprintf("Validation failed: %v", err))
	} else {
		facades.Log().Info("All query parameters are valid")
	}

	// Test individual validations
	validator.ValidatePagination(1, 20, 100)
	if validator.HasErrors() {
		facades.Log().Warning("Pagination validation failed")
		for _, err := range validator.GetErrors() {
			facades.Log().Warning(err.Error())
		}
	} else {
		facades.Log().Info("Pagination validation passed")
	}

	// Test input sanitization
	unsafeInput := "'; DROP TABLE users; --"
	safeInput := SanitizeFilterValue(unsafeInput)
	facades.Log().Info(fmt.Sprintf("Sanitized input: '%s' -> '%s'", unsafeInput, safeInput))
}

// ExamplePerformanceMonitoring demonstrates performance features
func ExamplePerformanceMonitoring() {
	facades.Log().Info("=== Performance Monitoring Example ===")

	// Initialize performance monitoring
	config := DefaultPerformanceConfig()
	config.EnableOptimization = true
	config.SlowQueryThreshold = 100 * time.Millisecond
	InitPerformanceMonitoring(config)

	type User struct {
		ID   uint   `json:"id"`
		Name string `json:"name"`
	}

	// Execute query with metrics
	qb := For(&User{})
	users := make([]User, 0)

	err := qb.QueryWithMetrics(&users)
	if err != nil {
		facades.Log().Error(fmt.Sprintf("Query with metrics failed: %v", err))
	}

	// Get performance metrics
	metrics := GetMetrics()
	facades.Log().Info(fmt.Sprintf("Total queries: %d", metrics.TotalQueries))
	facades.Log().Info(fmt.Sprintf("Cache hits: %d", metrics.CacheHits))
	facades.Log().Info(fmt.Sprintf("Slow queries: %d", metrics.SlowQueries))
	facades.Log().Info(fmt.Sprintf("Average query time: %v", metrics.AverageQueryTime))

	// Get optimization suggestions
	optimizations := GetOptimizations()
	for hash, opt := range optimizations {
		facades.Log().Info(fmt.Sprintf("Optimization for %s: %v (estimated gain: %v)",
			hash, opt.Suggestions, opt.EstimatedGain))
	}

	// Reset metrics for clean slate
	ResetMetrics()
	facades.Log().Info("Performance metrics reset")
}
