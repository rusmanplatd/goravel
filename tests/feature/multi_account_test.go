package feature

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"
	testingHttp "github.com/goravel/framework/testing/http"
	"github.com/stretchr/testify/suite"

	"goravel/app/models"
	"goravel/app/services"
	"goravel/tests"
)

type MultiAccountTestSuite struct {
	suite.Suite
	multiAccountService *services.MultiAccountService
	jwtService          *services.JWTService
	authService         *services.AuthService
	testUsers           []models.User
}

func TestMultiAccountTestSuite(t *testing.T) {
	suite.Run(t, &MultiAccountTestSuite{})
}

func (s *MultiAccountTestSuite) SetupSuite() {
	tests.TestCase{}.SetupSuite()

	// Initialize services
	var err error
	s.multiAccountService, err = services.NewMultiAccountService()
	s.Require().NoError(err, "Failed to initialize multi-account service")

	s.jwtService, err = services.NewJWTService()
	s.Require().NoError(err, "Failed to initialize JWT service")

	s.authService, err = services.NewAuthService()
	s.Require().NoError(err, "Failed to initialize auth service")
}

func (s *MultiAccountTestSuite) SetupTest() {
	tests.TestCase{}.SetupTest()

	// Create test users
	s.testUsers = []models.User{
		{
			Name:     "John Doe",
			Email:    "john@example.com",
			Password: "password123",
		},
		{
			Name:     "Jane Smith",
			Email:    "jane@example.com",
			Password: "password456",
		},
		{
			Name:     "Bob Wilson",
			Email:    "bob@example.com",
			Password: "password789",
		},
	}

	// Hash passwords and create users
	for i := range s.testUsers {
		hashedPassword, err := facades.Hash().Make(s.testUsers[i].Password)
		s.Require().NoError(err)
		s.testUsers[i].Password = hashedPassword

		err = facades.Orm().Query().Create(&s.testUsers[i])
		s.Require().NoError(err)
	}
}

func (s *MultiAccountTestSuite) TearDownTest() {
	// Clean up test data
	for _, user := range s.testUsers {
		facades.Orm().Query().Where("id", user.ID).Delete(&models.User{})
	}
	tests.TestCase{}.TearDownTest()
}

func (s *MultiAccountTestSuite) TestCreateMultiAccountSession() {
	// Test creating a new multi-account session
	req := testingHttp.NewRequest("POST", "/api/auth/multi-account/create")
	req.Header("Content-Type", "application/json")

	// Create session for first user
	token, err := s.jwtService.GenerateToken(s.testUsers[0].ID, "access")
	s.Require().NoError(err)

	req.Header("Authorization", "Bearer "+token)

	resp := req.Call()
	s.Equal(http.StatusOK, resp.Status())

	var response map[string]interface{}
	err = json.Unmarshal(resp.Body(), &response)
	s.Require().NoError(err)

	s.Equal("success", response["status"])
	s.Contains(response, "session_id")
	s.Contains(response, "accounts")
}

func (s *MultiAccountTestSuite) TestAddAccountToSession() {
	// Create initial session
	session, err := s.multiAccountService.CreateMultiAccountSession(s.testUsers[0].ID)
	s.Require().NoError(err)

	// Add second account
	err = s.multiAccountService.AddAccountToSession(session.SessionID, s.testUsers[1].ID)
	s.Require().NoError(err)

	// Verify account was added
	updatedSession, err := s.multiAccountService.GetMultiAccountSessionByID(session.SessionID)
	s.Require().NoError(err)
	s.Len(updatedSession.Accounts, 2)

	// Check that both users are in the session
	userIDs := make(map[string]bool)
	for _, account := range updatedSession.Accounts {
		userIDs[account.UserID] = true
	}
	s.True(userIDs[s.testUsers[0].ID])
	s.True(userIDs[s.testUsers[1].ID])
}

func (s *MultiAccountTestSuite) TestSwitchAccount() {
	// Create session with multiple accounts
	session, err := s.multiAccountService.CreateMultiAccountSession(s.testUsers[0].ID)
	s.Require().NoError(err)

	err = s.multiAccountService.AddAccountToSession(session.SessionID, s.testUsers[1].ID)
	s.Require().NoError(err)

	// Switch to second account
	switchResult, err := s.multiAccountService.SwitchAccount(session.SessionID, s.testUsers[1].ID)
	s.Require().NoError(err)
	s.NotNil(switchResult)
	s.Equal(s.testUsers[1].ID, switchResult.CurrentUserID)

	// Verify session was updated
	updatedSession, err := s.multiAccountService.GetMultiAccountSessionByID(session.SessionID)
	s.Require().NoError(err)
	s.Equal(s.testUsers[1].ID, updatedSession.CurrentUserID)
}

func (s *MultiAccountTestSuite) TestRemoveAccountFromSession() {
	// Create session with multiple accounts
	session, err := s.multiAccountService.CreateMultiAccountSession(s.testUsers[0].ID)
	s.Require().NoError(err)

	err = s.multiAccountService.AddAccountToSession(session.SessionID, s.testUsers[1].ID)
	s.Require().NoError(err)

	err = s.multiAccountService.AddAccountToSession(session.SessionID, s.testUsers[2].ID)
	s.Require().NoError(err)

	// Remove middle account
	err = s.multiAccountService.RemoveAccountFromSession(session.SessionID, s.testUsers[1].ID)
	s.Require().NoError(err)

	// Verify account was removed
	updatedSession, err := s.multiAccountService.GetMultiAccountSessionByID(session.SessionID)
	s.Require().NoError(err)
	s.Len(updatedSession.Accounts, 2)

	// Check that correct accounts remain
	userIDs := make(map[string]bool)
	for _, account := range updatedSession.Accounts {
		userIDs[account.UserID] = true
	}
	s.True(userIDs[s.testUsers[0].ID])
	s.False(userIDs[s.testUsers[1].ID]) // Should be removed
	s.True(userIDs[s.testUsers[2].ID])
}

func (s *MultiAccountTestSuite) TestSessionExpiration() {
	// Create session
	session, err := s.multiAccountService.CreateMultiAccountSession(s.testUsers[0].ID)
	s.Require().NoError(err)

	// Check that session is initially active
	s.False(s.multiAccountService.IsSessionExpired(session))

	// Test session validation
	isValid := s.multiAccountService.ValidateSession(session.SessionID)
	s.True(isValid)
}

func (s *MultiAccountTestSuite) TestGetUserAccounts() {
	// Create sessions for the same user
	session1, err := s.multiAccountService.CreateMultiAccountSession(s.testUsers[0].ID)
	s.Require().NoError(err)

	session2, err := s.multiAccountService.CreateMultiAccountSession(s.testUsers[0].ID)
	s.Require().NoError(err)

	// Add different accounts to each session
	err = s.multiAccountService.AddAccountToSession(session1.SessionID, s.testUsers[1].ID)
	s.Require().NoError(err)

	err = s.multiAccountService.AddAccountToSession(session2.SessionID, s.testUsers[2].ID)
	s.Require().NoError(err)

	// Get all accounts for user
	accounts, err := s.multiAccountService.GetUserAccounts(s.testUsers[0].ID)
	s.Require().NoError(err)
	s.GreaterOrEqual(len(accounts), 2) // Should have at least the accounts we added
}

func (s *MultiAccountTestSuite) TestSessionSecurity() {
	// Create session
	session, err := s.multiAccountService.CreateMultiAccountSession(s.testUsers[0].ID)
	s.Require().NoError(err)

	// Test that we can't add the same account twice
	err = s.multiAccountService.AddAccountToSession(session.SessionID, s.testUsers[0].ID)
	s.Error(err, "Should not allow adding the same account twice")

	// Test that we can't switch to an account not in the session
	_, err = s.multiAccountService.SwitchAccount(session.SessionID, s.testUsers[2].ID)
	s.Error(err, "Should not allow switching to account not in session")

	// Test that we can't remove the last account
	err = s.multiAccountService.RemoveAccountFromSession(session.SessionID, s.testUsers[0].ID)
	s.Error(err, "Should not allow removing the last account from session")
}

func (s *MultiAccountTestSuite) TestHTTPEndpoints() {
	// Test multi-account HTTP endpoints
	token, err := s.jwtService.GenerateToken(s.testUsers[0].ID, "access")
	s.Require().NoError(err)

	// Test create session endpoint
	req := testingHttp.NewRequest("POST", "/api/auth/multi-account/create")
	req.Header("Authorization", "Bearer "+token)
	req.Header("Content-Type", "application/json")

	resp := req.Call()
	s.Equal(http.StatusOK, resp.Status())

	var createResponse map[string]interface{}
	err = json.Unmarshal(resp.Body(), &createResponse)
	s.Require().NoError(err)

	sessionID := createResponse["session_id"].(string)

	// Test add account endpoint
	addReq := testingHttp.NewRequest("POST", "/api/auth/multi-account/add")
	addReq.Header("Authorization", "Bearer "+token)
	addReq.Header("Content-Type", "application/json")
	addReq.Json(map[string]interface{}{
		"session_id": sessionID,
		"email":      s.testUsers[1].Email,
		"password":   "password456", // Use the original password before hashing
	})

	addResp := addReq.Call()
	s.Equal(http.StatusOK, addResp.Status())

	// Test switch account endpoint
	switchReq := testingHttp.NewRequest("POST", "/api/auth/multi-account/switch")
	switchReq.Header("Authorization", "Bearer "+token)
	switchReq.Header("Content-Type", "application/json")
	switchReq.Json(map[string]interface{}{
		"session_id": sessionID,
		"user_id":    s.testUsers[1].ID,
	})

	switchResp := switchReq.Call()
	s.Equal(http.StatusOK, switchResp.Status())

	var switchResponse map[string]interface{}
	err = json.Unmarshal(switchResp.Body(), &switchResponse)
	s.Require().NoError(err)
	s.Contains(switchResponse, "access_token")
	s.Contains(switchResponse, "user")
}

func (s *MultiAccountTestSuite) TestConcurrentSessions() {
	// Test that a user can have multiple concurrent sessions
	session1, err := s.multiAccountService.CreateMultiAccountSession(s.testUsers[0].ID)
	s.Require().NoError(err)

	session2, err := s.multiAccountService.CreateMultiAccountSession(s.testUsers[0].ID)
	s.Require().NoError(err)

	// Sessions should have different IDs
	s.NotEqual(session1.SessionID, session2.SessionID)

	// Both sessions should be valid
	s.True(s.multiAccountService.ValidateSession(session1.SessionID))
	s.True(s.multiAccountService.ValidateSession(session2.SessionID))

	// Add different accounts to each session
	err = s.multiAccountService.AddAccountToSession(session1.SessionID, s.testUsers[1].ID)
	s.Require().NoError(err)

	err = s.multiAccountService.AddAccountToSession(session2.SessionID, s.testUsers[2].ID)
	s.Require().NoError(err)

	// Verify sessions are independent
	session1Updated, err := s.multiAccountService.GetMultiAccountSessionByID(session1.SessionID)
	s.Require().NoError(err)
	s.Len(session1Updated.Accounts, 2)

	session2Updated, err := s.multiAccountService.GetMultiAccountSessionByID(session2.SessionID)
	s.Require().NoError(err)
	s.Len(session2Updated.Accounts, 2)
}
