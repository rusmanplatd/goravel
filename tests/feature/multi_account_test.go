package feature

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/goravel/framework/testing/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"

	"goravel/app/models"
	"goravel/app/services"
)

type MultiAccountTestSuite struct {
	suite.Suite
	service *services.MultiAccountService
	mockCtx *mock.Context
}

func TestMultiAccountTestSuite(t *testing.T) {
	suite.Run(t, new(MultiAccountTestSuite))
}

func (s *MultiAccountTestSuite) SetupTest() {
	s.service = services.NewMultiAccountService()
	s.mockCtx = &mock.Context{}

	// Setup mock session
	mockSession := &mock.Session{}
	mockRequest := &mock.Request{}
	mockRequest.On("Session").Return(mockSession)
	mockRequest.On("Ip").Return("127.0.0.1")
	mockRequest.On("Header", "User-Agent", "").Return("Test Agent")
	mockRequest.On("Method").Return("POST")
	mockRequest.On("Path").Return("/test")
	mockRequest.On("Header", "Referer", "").Return("")

	s.mockCtx.On("Request").Return(mockRequest)
	s.mockCtx.On("Value", "user_id").Return("user123")

	// Setup initial empty session
	mockSession.On("Get", "multi_account_session").Return(nil)
	mockSession.On("Put", "multi_account_session", mock.Anything).Return()
	mockSession.On("Put", "user_id", mock.Anything).Return()
	mockSession.On("Put", "user_email", mock.Anything).Return()
	mockSession.On("GetID").Return("session123")
}

func (s *MultiAccountTestSuite) TestNewMultiAccountSession() {
	session, err := s.service.GetMultiAccountSession(s.mockCtx)

	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), session)
	assert.Empty(s.T(), session.Accounts)
	assert.Equal(s.T(), "", session.ActiveAccount)
	assert.Equal(s.T(), 0, session.SwitchCount)
}

func (s *MultiAccountTestSuite) TestAddAccount() {
	user := &models.User{
		BaseModel: models.BaseModel{ID: "user123"},
		Email:     "test@example.com",
		Name:      "Test User",
		Avatar:    "avatar.jpg",
		IsActive:  true,
	}

	err := s.service.AddAccount(s.mockCtx, user, "password")

	assert.NoError(s.T(), err)

	// Verify account was added
	session, err := s.service.GetMultiAccountSession(s.mockCtx)
	assert.NoError(s.T(), err)
	assert.Len(s.T(), session.Accounts, 1)
	assert.Equal(s.T(), user.ID, session.ActiveAccount)
	assert.Equal(s.T(), user.Email, session.Accounts[0].Email)
	assert.Equal(s.T(), "password", session.Accounts[0].LoginMethod)
}

func (s *MultiAccountTestSuite) TestAddMultipleAccounts() {
	users := []*models.User{
		{BaseModel: models.BaseModel{ID: "user1"}, Email: "user1@example.com", Name: "User 1", IsActive: true},
		{BaseModel: models.BaseModel{ID: "user2"}, Email: "user2@example.com", Name: "User 2", IsActive: true},
		{BaseModel: models.BaseModel{ID: "user3"}, Email: "user3@example.com", Name: "User 3", IsActive: true},
	}

	// Add multiple accounts
	for i, user := range users {
		err := s.service.AddAccount(s.mockCtx, user, "password")
		assert.NoError(s.T(), err)

		// Verify account count
		count := s.service.GetAccountCount(s.mockCtx)
		assert.Equal(s.T(), i+1, count)
	}

	// Verify all accounts are present
	accounts, err := s.service.GetAllAccounts(s.mockCtx)
	assert.NoError(s.T(), err)
	assert.Len(s.T(), accounts, 3)

	// Verify last added account is active
	session, err := s.service.GetMultiAccountSession(s.mockCtx)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "user3", session.ActiveAccount)
}

func (s *MultiAccountTestSuite) TestAccountLimit() {
	// Add maximum number of accounts
	for i := 0; i < services.MaxAccountsPerSession+2; i++ {
		user := &models.User{
			BaseModel: models.BaseModel{ID: fmt.Sprintf("user%d", i)},
			Email:     fmt.Sprintf("user%d@example.com", i),
			Name:      fmt.Sprintf("User %d", i),
			IsActive:  true,
		}

		err := s.service.AddAccount(s.mockCtx, user, "password")
		assert.NoError(s.T(), err)
	}

	// Verify account limit is enforced
	count := s.service.GetAccountCount(s.mockCtx)
	assert.Equal(s.T(), services.MaxAccountsPerSession, count)
}

func (s *MultiAccountTestSuite) TestSwitchAccount() {
	// Add two accounts
	user1 := &models.User{BaseModel: models.BaseModel{ID: "user1"}, Email: "user1@example.com", Name: "User 1", IsActive: true}
	user2 := &models.User{BaseModel: models.BaseModel{ID: "user2"}, Email: "user2@example.com", Name: "User 2", IsActive: true}

	s.service.AddAccount(s.mockCtx, user1, "password")
	s.service.AddAccount(s.mockCtx, user2, "password")

	// Switch to first account
	err := s.service.SwitchAccount(s.mockCtx, "user1")
	assert.NoError(s.T(), err)

	// Verify active account changed
	activeAccount, err := s.service.GetActiveAccount(s.mockCtx)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "user1", activeAccount.UserID)
}

func (s *MultiAccountTestSuite) TestSwitchAccountNotFound() {
	user := &models.User{BaseModel: models.BaseModel{ID: "user1"}, Email: "user1@example.com", Name: "User 1", IsActive: true}
	s.service.AddAccount(s.mockCtx, user, "password")

	// Try to switch to non-existent account
	err := s.service.SwitchAccount(s.mockCtx, "nonexistent")
	assert.Error(s.T(), err)
	assert.Contains(s.T(), err.Error(), "account not found in session")
}

func (s *MultiAccountTestSuite) TestRemoveAccount() {
	// Add two accounts
	user1 := &models.User{BaseModel: models.BaseModel{ID: "user1"}, Email: "user1@example.com", Name: "User 1", IsActive: true}
	user2 := &models.User{BaseModel: models.BaseModel{ID: "user2"}, Email: "user2@example.com", Name: "User 2", IsActive: true}

	s.service.AddAccount(s.mockCtx, user1, "password")
	s.service.AddAccount(s.mockCtx, user2, "password")

	// Remove first account
	err := s.service.RemoveAccount(s.mockCtx, "user1")
	assert.NoError(s.T(), err)

	// Verify account was removed
	count := s.service.GetAccountCount(s.mockCtx)
	assert.Equal(s.T(), 1, count)

	// Verify remaining account
	accounts, err := s.service.GetAllAccounts(s.mockCtx)
	assert.NoError(s.T(), err)
	assert.Len(s.T(), accounts, 1)
	assert.Equal(s.T(), "user2", accounts[0].UserID)
}

func (s *MultiAccountTestSuite) TestAccountExpiration() {
	user := &models.User{BaseModel: models.BaseModel{ID: "user1"}, Email: "user1@example.com", Name: "User 1", IsActive: true}
	s.service.AddAccount(s.mockCtx, user, "password")

	// Manually expire the account
	session, _ := s.service.GetMultiAccountSession(s.mockCtx)
	session.Accounts[0].ExpiresAt = time.Now().Add(-1 * time.Hour)

	// Mock session data with expired account
	sessionBytes, _ := json.Marshal(session)
	mockSession := &mock.Session{}
	mockSession.On("Get", "multi_account_session").Return(string(sessionBytes))
	mockRequest := s.mockCtx.Request().(*mock.Request)
	mockRequest.On("Session").Return(mockSession)

	// Try to switch to expired account
	err := s.service.SwitchAccount(s.mockCtx, "user1")
	assert.Error(s.T(), err)
	assert.Contains(s.T(), err.Error(), "session has expired")
}

func (s *MultiAccountTestSuite) TestRateLimit() {
	user := &models.User{BaseModel: models.BaseModel{ID: "user1"}, Email: "user1@example.com", Name: "User 1", IsActive: true}
	s.service.AddAccount(s.mockCtx, user, "password")

	// Simulate rapid switching by manipulating session data
	session, _ := s.service.GetMultiAccountSession(s.mockCtx)
	session.SwitchCount = services.MaxSwitchesPerHour
	session.LastSwitchAt = time.Now().Add(-30 * time.Minute) // Within rate limit window

	sessionBytes, _ := json.Marshal(session)
	mockSession := &mock.Session{}
	mockSession.On("Get", "multi_account_session").Return(string(sessionBytes))
	mockRequest := s.mockCtx.Request().(*mock.Request)
	mockRequest.On("Session").Return(mockSession)

	// Try to switch account (should be rate limited)
	err := s.service.SwitchAccount(s.mockCtx, "user1")
	assert.Error(s.T(), err)
	assert.Contains(s.T(), err.Error(), "too many account switches")
}

func (s *MultiAccountTestSuite) TestExtendSession() {
	user := &models.User{BaseModel: models.BaseModel{ID: "user1"}, Email: "user1@example.com", Name: "User 1", IsActive: true}
	s.service.AddAccount(s.mockCtx, user, "password")

	// Get original expiration
	session, _ := s.service.GetMultiAccountSession(s.mockCtx)
	originalExpiration := session.Accounts[0].ExpiresAt

	// Wait a moment to ensure time difference
	time.Sleep(10 * time.Millisecond)

	// Extend session
	err := s.service.ExtendAccountSession(s.mockCtx, "user1")
	assert.NoError(s.T(), err)

	// Verify expiration was extended
	session, _ = s.service.GetMultiAccountSession(s.mockCtx)
	assert.True(s.T(), session.Accounts[0].ExpiresAt.After(originalExpiration))
}

func (s *MultiAccountTestSuite) TestValidateAccountAccess() {
	user := &models.User{BaseModel: models.BaseModel{ID: "user1"}, Email: "user1@example.com", Name: "User 1", IsActive: true}
	s.service.AddAccount(s.mockCtx, user, "password")

	// Validate existing account
	err := s.service.ValidateAccountAccess(s.mockCtx, "user1")
	assert.NoError(s.T(), err)

	// Validate non-existent account
	err = s.service.ValidateAccountAccess(s.mockCtx, "nonexistent")
	assert.Error(s.T(), err)
	assert.Contains(s.T(), err.Error(), "account not found in session")
}

func (s *MultiAccountTestSuite) TestGetSessionStatistics() {
	user := &models.User{BaseModel: models.BaseModel{ID: "user1"}, Email: "user1@example.com", Name: "User 1", IsActive: true}
	s.service.AddAccount(s.mockCtx, user, "password")

	stats, err := s.service.GetSessionStatistics(s.mockCtx)
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), stats)

	assert.Equal(s.T(), 1, stats["total_accounts"])
	assert.Equal(s.T(), services.MaxAccountsPerSession, stats["max_accounts"])
	assert.Equal(s.T(), "user1", stats["active_account_id"])
	assert.Contains(s.T(), stats, "session_age_hours")
	assert.Contains(s.T(), stats, "login_methods")
}

func (s *MultiAccountTestSuite) TestClearAllAccounts() {
	// Add multiple accounts
	for i := 0; i < 3; i++ {
		user := &models.User{
			BaseModel: models.BaseModel{ID: fmt.Sprintf("user%d", i)},
			Email:     fmt.Sprintf("user%d@example.com", i),
			Name:      fmt.Sprintf("User %d", i),
			IsActive:  true,
		}
		s.service.AddAccount(s.mockCtx, user, "password")
	}

	// Verify accounts exist
	count := s.service.GetAccountCount(s.mockCtx)
	assert.Equal(s.T(), 3, count)

	// Clear all accounts
	mockSession := s.mockCtx.Request().(*mock.Request).Session().(*mock.Session)
	mockSession.On("Forget", "multi_account_session").Return()
	mockSession.On("Forget", "user_id").Return()
	mockSession.On("Forget", "user_email").Return()

	err := s.service.ClearAllAccounts(s.mockCtx)
	assert.NoError(s.T(), err)

	// Verify session methods were called
	mockSession.AssertCalled(s.T(), "Forget", "multi_account_session")
	mockSession.AssertCalled(s.T(), "Forget", "user_id")
	mockSession.AssertCalled(s.T(), "Forget", "user_email")
}

func (s *MultiAccountTestSuite) TestIsAccountInSession() {
	user := &models.User{BaseModel: models.BaseModel{ID: "user1"}, Email: "user1@example.com", Name: "User 1", IsActive: true}
	s.service.AddAccount(s.mockCtx, user, "password")

	// Check existing account
	exists := s.service.IsAccountInSession(s.mockCtx, "user1")
	assert.True(s.T(), exists)

	// Check non-existent account
	exists = s.service.IsAccountInSession(s.mockCtx, "nonexistent")
	assert.False(s.T(), exists)
}

func (s *MultiAccountTestSuite) TestCleanupExpiredAccounts() {
	// Add account with past expiration
	user := &models.User{BaseModel: models.BaseModel{ID: "user1"}, Email: "user1@example.com", Name: "User 1", IsActive: true}
	s.service.AddAccount(s.mockCtx, user, "password")

	// Manually expire the account
	session, _ := s.service.GetMultiAccountSession(s.mockCtx)
	session.Accounts[0].ExpiresAt = time.Now().Add(-1 * time.Hour)
	s.service.SaveMultiAccountSession(s.mockCtx, session)

	// Get session again (should trigger cleanup)
	session, err := s.service.GetMultiAccountSession(s.mockCtx)
	assert.NoError(s.T(), err)
	assert.Empty(s.T(), session.Accounts) // Expired account should be removed
}

// Benchmark tests for performance
func (s *MultiAccountTestSuite) TestAccountSwitchingPerformance() {
	// Add multiple accounts
	for i := 0; i < 5; i++ {
		user := &models.User{
			BaseModel: models.BaseModel{ID: fmt.Sprintf("user%d", i)},
			Email:     fmt.Sprintf("user%d@example.com", i),
			Name:      fmt.Sprintf("User %d", i),
			IsActive:  true,
		}
		s.service.AddAccount(s.mockCtx, user, "password")
	}

	// Measure switching performance
	start := time.Now()
	for i := 0; i < 10; i++ {
		userID := fmt.Sprintf("user%d", i%5)
		s.service.SwitchAccount(s.mockCtx, userID)
	}
	duration := time.Since(start)

	// Should complete quickly (less than 100ms for 10 switches)
	assert.Less(s.T(), duration, 100*time.Millisecond)
}

func (s *MultiAccountTestSuite) TearDownTest() {
	// Clean up any resources if needed
}
