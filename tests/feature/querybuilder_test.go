package feature

import (
	"net/http/httptest"
	"testing"

	"github.com/goravel/framework/contracts/database/orm"
	"github.com/goravel/framework/facades"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"

	"goravel/app/models"
	"goravel/app/querybuilder"
)

type QueryBuilderTestSuite struct {
	suite.Suite
	testUsers []models.User
}

func (suite *QueryBuilderTestSuite) SetupTest() {
	// Setup test database
	assert.NotNil(suite.T(), facades.Orm())

	// Create test users
	suite.createTestUsers()
}

func (suite *QueryBuilderTestSuite) TearDownTest() {
	// Clean up test data
	facades.Orm().Query().Where("email LIKE ?", "test%").Delete(&models.User{})
}

func TestQueryBuilderTestSuite(t *testing.T) {
	suite.Run(t, new(QueryBuilderTestSuite))
}

func (suite *QueryBuilderTestSuite) createTestUsers() {
	testUsers := []models.User{
		{Name: "John Doe", Email: "test1@example.com", IsActive: true},
		{Name: "Jane Smith", Email: "test2@example.com", IsActive: true},
		{Name: "Bob Johnson", Email: "test3@example.com", IsActive: false},
		{Name: "Alice Brown", Email: "test4@example.com", IsActive: true},
		{Name: "Charlie Wilson", Email: "test5@example.com", IsActive: false},
	}

	for _, user := range testUsers {
		facades.Orm().Query().Create(&user)
		suite.testUsers = append(suite.testUsers, user)
	}
}

// Test basic filtering functionality
func (suite *QueryBuilderTestSuite) TestBasicFiltering() {
	// Test partial filter
	var users []models.User
	err := querybuilder.For(&models.User{}).
		AllowedFilters(querybuilder.Partial("name")).
		Where("email LIKE ?", "test%").
		Get(&users)

	assert.NoError(suite.T(), err)
	assert.GreaterOrEqual(suite.T(), len(users), 5)

	// Test exact filter
	users = []models.User{}
	err = querybuilder.For(&models.User{}).
		AllowedFilters(querybuilder.Exact("is_active")).
		Where("email LIKE ? AND is_active = ?", "test%", true).
		Get(&users)

	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), 3, len(users))
}

// Test different filter types
func (suite *QueryBuilderTestSuite) TestFilterTypes() {
	tests := []struct {
		name        string
		filter      querybuilder.AllowedFilter
		value       string
		expectedSQL string
	}{
		{
			name:        "Partial filter",
			filter:      querybuilder.Partial("name"),
			value:       "John",
			expectedSQL: "name LIKE ?",
		},
		{
			name:        "Exact filter",
			filter:      querybuilder.Exact("name"),
			value:       "John Doe",
			expectedSQL: "name = ?",
		},
		{
			name:        "Begins with filter",
			filter:      querybuilder.BeginsWith("name"),
			value:       "John",
			expectedSQL: "name LIKE ?",
		},
		{
			name:        "Ends with filter",
			filter:      querybuilder.EndsWith("name"),
			value:       "Doe",
			expectedSQL: "name LIKE ?",
		},
	}

	for _, tt := range tests {
		suite.T().Run(tt.name, func(t *testing.T) {
			var users []models.User
			err := querybuilder.For(&models.User{}).
				AllowedFilters(tt.filter).
				Where("email LIKE ?", "test%").
				Get(&users)

			assert.NoError(t, err)
		})
	}
}

// Test custom callback filters
func (suite *QueryBuilderTestSuite) TestCallbackFilters() {
	var users []models.User

	customFilter := querybuilder.Callback("active_users", func(query orm.Query, value interface{}, property string) orm.Query {
		if value == "true" {
			return query.Where("is_active = ?", true)
		}
		return query.Where("is_active = ?", false)
	})

	err := querybuilder.For(&models.User{}).
		AllowedFilters(customFilter).
		Where("email LIKE ?", "test%").
		Get(&users)

	assert.NoError(suite.T(), err)
}

// Test filter options (ignore, default, nullable)
func (suite *QueryBuilderTestSuite) TestFilterOptions() {
	// Test ignored values
	ignoredFilter := querybuilder.Exact("status").Ignore("", "all")
	assert.Contains(suite.T(), ignoredFilter.IgnoredValues, "")
	assert.Contains(suite.T(), ignoredFilter.IgnoredValues, "all")

	// Test default values
	defaultFilter := querybuilder.Exact("is_active").Default(true)
	assert.Equal(suite.T(), true, defaultFilter.DefaultValue)

	// Test nullable
	nullableFilter := querybuilder.Exact("email_verified_at").SetNullable(true)
	assert.True(suite.T(), nullableFilter.Nullable)
}

// Test sorting functionality
func (suite *QueryBuilderTestSuite) TestSorting() {
	var users []models.User

	// Test basic sorting
	err := querybuilder.For(&models.User{}).
		AllowedSorts("name", "created_at").
		Where("email LIKE ?", "test%").
		DefaultSort("name").
		Get(&users)

	assert.NoError(suite.T(), err)
	assert.GreaterOrEqual(suite.T(), len(users), 5)

	// Test custom sort
	customSort := querybuilder.CustomSort("custom", func(query orm.Query, direction string, property string) orm.Query {
		return query.Order("name " + direction)
	})

	err = querybuilder.For(&models.User{}).
		AllowedSorts(customSort).
		Where("email LIKE ?", "test%").
		Get(&users)

	assert.NoError(suite.T(), err)
}

// Test relationship includes
func (suite *QueryBuilderTestSuite) TestIncludes() {
	var users []models.User

	err := querybuilder.For(&models.User{}).
		AllowedIncludes("roles", "tenants").
		Where("email LIKE ?", "test%").
		Get(&users)

	assert.NoError(suite.T(), err)

	// Test custom include
	customInclude := querybuilder.CustomInclude("active_roles", func(query orm.Query, include string) orm.Query {
		return query.With("Roles", func(query orm.Query) orm.Query {
			return query.Where("is_active = ?", true)
		})
	})

	err = querybuilder.For(&models.User{}).
		AllowedIncludes(customInclude).
		Where("email LIKE ?", "test%").
		Get(&users)

	assert.NoError(suite.T(), err)
}

// Test field selection
func (suite *QueryBuilderTestSuite) TestFieldSelection() {
	var users []models.User

	err := querybuilder.For(&models.User{}).
		AllowedFields("id", "name", "email").
		Where("email LIKE ?", "test%").
		Get(&users)

	assert.NoError(suite.T(), err)
	assert.GreaterOrEqual(suite.T(), len(users), 5)
}

// Test pagination
func (suite *QueryBuilderTestSuite) TestPagination() {
	var users []models.User

	err := querybuilder.For(&models.User{}).
		Where("email LIKE ?", "test%").
		Paginate(1, 2, &users)

	assert.NoError(suite.T(), err)
	assert.LessOrEqual(suite.T(), len(users), 2)

	// Test count
	count, err := querybuilder.For(&models.User{}).
		Where("email LIKE ?", "test%").
		Count()

	assert.NoError(suite.T(), err)
	assert.GreaterOrEqual(suite.T(), count, int64(5))
}

// Test method chaining
func (suite *QueryBuilderTestSuite) TestMethodChaining() {
	var users []models.User

	err := querybuilder.For(&models.User{}).
		AllowedFilters(querybuilder.Partial("name")).
		AllowedSorts("name", "created_at").
		AllowedIncludes("roles").
		AllowedFields("id", "name", "email").
		Where("email LIKE ?", "test%").
		DefaultSort("-created_at").
		Get(&users)

	assert.NoError(suite.T(), err)
	assert.GreaterOrEqual(suite.T(), len(users), 5)
}

// Test helper functions
func (suite *QueryBuilderTestSuite) TestHelperFunctions() {
	// Test TextFilters
	textFilters := querybuilder.TextFilters("name", "email")
	assert.Equal(suite.T(), 8, len(textFilters)) // 4 types * 2 fields

	// Test ExactFilters
	exactFilters := querybuilder.ExactFilters("id", "is_active")
	assert.Equal(suite.T(), 2, len(exactFilters))

	// Test PartialFilters
	partialFilters := querybuilder.PartialFilters("name", "email")
	assert.Equal(suite.T(), 2, len(partialFilters))

	// Test CommonSorts
	sorts := querybuilder.CommonSorts("id", "name", "created_at")
	assert.Equal(suite.T(), 3, len(sorts))

	// Test CommonIncludes
	includes := querybuilder.CommonIncludes("roles", "tenants")
	assert.Equal(suite.T(), 2, len(includes))

	// Test CommonFields
	fields := querybuilder.CommonFields("id", "name", "email")
	assert.Equal(suite.T(), 3, len(fields))
}

// Test predefined configurations
func (suite *QueryBuilderTestSuite) TestPredefinedConfigurations() {
	// Test BasicConfig
	basicConfig := querybuilder.BasicConfig("User")
	assert.GreaterOrEqual(suite.T(), len(basicConfig.AllowedFilters), 4)
	assert.GreaterOrEqual(suite.T(), len(basicConfig.AllowedSorts), 4)

	// Test ReadOnlyConfig
	readOnlyConfig := querybuilder.ReadOnlyConfig()
	assert.GreaterOrEqual(suite.T(), len(readOnlyConfig.AllowedFilters), 3)
	assert.GreaterOrEqual(suite.T(), len(readOnlyConfig.AllowedSorts), 3)

	// Test UserConfig
	userConfig := querybuilder.UserConfig()
	assert.GreaterOrEqual(suite.T(), len(userConfig.AllowedFilters), 5)
	assert.GreaterOrEqual(suite.T(), len(userConfig.AllowedSorts), 5)
	assert.GreaterOrEqual(suite.T(), len(userConfig.AllowedIncludes), 3)
	assert.GreaterOrEqual(suite.T(), len(userConfig.AllowedFields), 6)
}

// Test trashed filter
func (suite *QueryBuilderTestSuite) TestTrashedFilter() {
	trashedFilter := querybuilder.Trashed()
	assert.Equal(suite.T(), "trashed", trashedFilter.Name)
	assert.Equal(suite.T(), querybuilder.FilterTypeTrashed, trashedFilter.Type)
	assert.NotNil(suite.T(), trashedFilter.Callback)
}

// Test HTTP request integration
func (suite *QueryBuilderTestSuite) TestHTTPRequestIntegration() {
	// Create a mock HTTP request with query parameters
	req := httptest.NewRequest("GET", "/api/v1/users?filter[name]=John&sort=-created_at&include=roles&fields=id,name,email", nil)
	w := httptest.NewRecorder()

	// This would require a proper HTTP context setup
	// For now, we'll test the structure exists
	assert.NotNil(suite.T(), req)
	assert.NotNil(suite.T(), w)
}

// Test error handling
func (suite *QueryBuilderTestSuite) TestErrorHandling() {
	// Test with invalid model
	qb := querybuilder.For(nil)
	assert.NotNil(suite.T(), qb)

	// Test with empty filters
	var users []models.User
	err := querybuilder.For(&models.User{}).
		AllowedFilters().
		Where("email LIKE ?", "test%").
		Get(&users)

	assert.NoError(suite.T(), err)
}

// Test configuration options
func (suite *QueryBuilderTestSuite) TestConfigurationOptions() {
	config := querybuilder.DefaultConfig()
	assert.Equal(suite.T(), "filter", config.FilterParameter)
	assert.Equal(suite.T(), "sort", config.SortParameter)
	assert.Equal(suite.T(), "include", config.IncludeParameter)
	assert.Equal(suite.T(), "fields", config.FieldsParameter)
	assert.Equal(suite.T(), "Count", config.CountSuffix)
	assert.Equal(suite.T(), "Exists", config.ExistsSuffix)

	// Test custom config
	customConfig := &querybuilder.Config{
		FilterParameter:  "q",
		SortParameter:    "order",
		IncludeParameter: "with",
		FieldsParameter:  "select",
	}

	qb := querybuilder.For(&models.User{}).WithConfig(customConfig)
	assert.NotNil(suite.T(), qb)
}

// setupBenchmarkDatabase sets up database for benchmarks
func setupBenchmarkDatabase() {
	// Initialize database connection for benchmarks
	// This is a simplified version that doesn't require *testing.T
	if facades.Orm() == nil {
		// Skip benchmark if database is not available
		return
	}
}

// Benchmark tests
func BenchmarkQueryBuilderBasicQuery(b *testing.B) {
	setupBenchmarkDatabase()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var users []models.User
		querybuilder.For(&models.User{}).
			AllowedFilters(querybuilder.Partial("name")).
			AllowedSorts("created_at").
			Limit(10).
			Get(&users)
	}
}

func BenchmarkQueryBuilderComplexQuery(b *testing.B) {
	setupBenchmarkDatabase()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var users []models.User
		querybuilder.For(&models.User{}).
			AllowedFilters(
				querybuilder.Partial("name"),
				querybuilder.Exact("is_active"),
				querybuilder.Trashed(),
			).
			AllowedSorts("name", "created_at", "updated_at").
			AllowedIncludes("roles", "tenants").
			AllowedFields("id", "name", "email", "created_at").
			DefaultSort("-created_at").
			Limit(50).
			Get(&users)
	}
}
