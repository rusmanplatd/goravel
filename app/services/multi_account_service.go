package services

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/models"
)

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type MultiAccountService struct {
	jwtService   *JWTService
	auditService *AuditService
}

type AccountSession struct {
	UserID       string    `json:"user_id"`
	Email        string    `json:"email"`
	Name         string    `json:"name"`
	Avatar       string    `json:"avatar,omitempty"`
	LoginTime    time.Time `json:"login_time"`
	LastAccessed time.Time `json:"last_accessed"`
	LoginMethod  string    `json:"login_method"` // password, webauthn, google_oauth, etc.
	IsActive     bool      `json:"is_active"`
	ExpiresAt    time.Time `json:"expires_at"` // Account session expiration
	IPAddress    string    `json:"ip_address"` // IP address when account was added
	UserAgent    string    `json:"user_agent"` // User agent when account was added
}

type MultiAccountSession struct {
	Accounts      []AccountSession `json:"accounts"`
	ActiveAccount string           `json:"active_account"` // UserID of currently active account
	CreatedAt     time.Time        `json:"created_at"`
	UpdatedAt     time.Time        `json:"updated_at"`
	LastSwitchAt  time.Time        `json:"last_switch_at"` // Last time account was switched
	SwitchCount   int              `json:"switch_count"`   // Number of switches in current session
}

const (
	MaxAccountsPerSession = 5
	AccountSessionTTL     = 7 * 24 * time.Hour // 7 days
	MaxSwitchesPerHour    = 20                 // Rate limit for account switching
)

func NewMultiAccountService() *MultiAccountService {
	return &MultiAccountService{
		jwtService:   NewJWTService(),
		auditService: NewAuditService(),
	}
}

// GetMultiAccountSession retrieves the multi-account session from the session storage
func (s *MultiAccountService) GetMultiAccountSession(ctx http.Context) (*MultiAccountSession, error) {
	facades.Log().Info("GetMultiAccountSession: Starting")

	// Check if session is available
	session := ctx.Request().Session()
	if session == nil {
		facades.Log().Info("GetMultiAccountSession: No session available, returning empty session")
		return &MultiAccountSession{
			Accounts:     []AccountSession{},
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
			LastSwitchAt: time.Now(),
			SwitchCount:  0,
		}, nil
	}

	sessionData := session.Get("multi_account_session")
	facades.Log().Info("GetMultiAccountSession: Raw session data", map[string]interface{}{
		"session_data": sessionData,
		"data_type":    fmt.Sprintf("%T", sessionData),
	})

	if sessionData == nil {
		facades.Log().Info("GetMultiAccountSession: No multi_account_session data, returning empty session")
		return &MultiAccountSession{
			Accounts:     []AccountSession{},
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
			LastSwitchAt: time.Now(),
			SwitchCount:  0,
		}, nil
	}

	var multiSession MultiAccountSession
	sessionBytes, ok := sessionData.(string)
	if !ok {
		facades.Log().Error("GetMultiAccountSession: Invalid session data format", map[string]interface{}{
			"data_type": fmt.Sprintf("%T", sessionData),
		})
		return nil, fmt.Errorf("invalid session data format")
	}

	facades.Log().Info("GetMultiAccountSession: Session bytes", map[string]interface{}{
		"session_bytes_length":  len(sessionBytes),
		"session_bytes_preview": sessionBytes[:min(200, len(sessionBytes))],
	})

	err := json.Unmarshal([]byte(sessionBytes), &multiSession)
	if err != nil {
		facades.Log().Error("GetMultiAccountSession: Failed to unmarshal session data", map[string]interface{}{
			"error":         err.Error(),
			"session_bytes": sessionBytes,
		})
		return nil, fmt.Errorf("failed to unmarshal session data: %v", err)
	}

	facades.Log().Info("GetMultiAccountSession: Successfully unmarshaled", map[string]interface{}{
		"active_account": multiSession.ActiveAccount,
		"account_count":  len(multiSession.Accounts),
	})

	// Clean up expired accounts
	multiSession = s.cleanupExpiredAccounts(multiSession)

	return &multiSession, nil
}

// cleanupExpiredAccounts removes expired account sessions
func (s *MultiAccountService) cleanupExpiredAccounts(multiSession MultiAccountSession) MultiAccountSession {
	now := time.Now()
	validAccounts := []AccountSession{}

	for _, account := range multiSession.Accounts {
		if account.ExpiresAt.After(now) {
			validAccounts = append(validAccounts, account)
		} else {
			facades.Log().Info("Removed expired account session", map[string]interface{}{
				"user_id":    account.UserID,
				"email":      account.Email,
				"expired_at": account.ExpiresAt,
			})
		}
	}

	multiSession.Accounts = validAccounts

	// If active account was expired, switch to first available
	if multiSession.ActiveAccount != "" {
		activeFound := false
		for _, account := range validAccounts {
			if account.UserID == multiSession.ActiveAccount {
				activeFound = true
				break
			}
		}

		if !activeFound {
			if len(validAccounts) > 0 {
				multiSession.ActiveAccount = validAccounts[0].UserID
			} else {
				multiSession.ActiveAccount = ""
			}
		}
	}

	return multiSession
}

// SaveMultiAccountSession saves the multi-account session to session storage
func (s *MultiAccountService) SaveMultiAccountSession(ctx http.Context, multiSession *MultiAccountSession) error {
	// Check if session is available
	session := ctx.Request().Session()
	if session == nil {
		// Session not available, skip saving
		return nil
	}

	multiSession.UpdatedAt = time.Now()

	sessionBytes, err := json.Marshal(multiSession)
	if err != nil {
		return fmt.Errorf("failed to marshal session data: %v", err)
	}

	session.Put("multi_account_session", string(sessionBytes))
	return nil
}

// AddAccount adds a new account to the multi-account session
func (s *MultiAccountService) AddAccount(ctx http.Context, user *models.User, loginMethod string) error {
	multiSession, err := s.GetMultiAccountSession(ctx)
	if err != nil {
		return err
	}

	// Get client information
	ipAddress := ctx.Request().Ip()
	userAgent := ctx.Request().Header("User-Agent", "")

	// Check if account already exists
	for i, account := range multiSession.Accounts {
		if account.UserID == user.ID {
			// Update existing account
			multiSession.Accounts[i].LastAccessed = time.Now()
			multiSession.Accounts[i].LoginMethod = loginMethod
			multiSession.Accounts[i].IsActive = user.IsActive
			multiSession.Accounts[i].ExpiresAt = time.Now().Add(AccountSessionTTL)
			multiSession.Accounts[i].IPAddress = ipAddress
			multiSession.Accounts[i].UserAgent = userAgent
			multiSession.ActiveAccount = user.ID

			// Log account update
			s.auditService.LogMultiAccountActivity(ctx, "account_updated", map[string]interface{}{
				"user_id":      user.ID,
				"email":        user.Email,
				"login_method": loginMethod,
				"action":       "existing_account_updated",
			})

			return s.SaveMultiAccountSession(ctx, multiSession)
		}
	}

	// Check account limit
	if len(multiSession.Accounts) >= MaxAccountsPerSession {
		// Remove oldest account to make room
		removedAccount := multiSession.Accounts[0]
		multiSession.Accounts = multiSession.Accounts[1:]

		// Log account removal due to limit
		s.auditService.LogMultiAccountActivity(ctx, "account_removed", map[string]interface{}{
			"removed_user_id": removedAccount.UserID,
			"removed_email":   removedAccount.Email,
			"reason":          "account_limit_exceeded",
			"max_accounts":    MaxAccountsPerSession,
		})
	}

	// Add new account
	newAccount := AccountSession{
		UserID:       user.ID,
		Email:        user.Email,
		Name:         user.Name,
		Avatar:       user.Avatar,
		LoginTime:    time.Now(),
		LastAccessed: time.Now(),
		LoginMethod:  loginMethod,
		IsActive:     user.IsActive,
		ExpiresAt:    time.Now().Add(AccountSessionTTL),
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
	}

	multiSession.Accounts = append(multiSession.Accounts, newAccount)
	multiSession.ActiveAccount = user.ID

	// Log new account addition
	s.auditService.LogMultiAccountActivity(ctx, "account_added", map[string]interface{}{
		"user_id":         user.ID,
		"email":           user.Email,
		"name":            user.Name,
		"login_method":    loginMethod,
		"total_accounts":  len(multiSession.Accounts),
		"session_expires": newAccount.ExpiresAt,
	})

	return s.SaveMultiAccountSession(ctx, multiSession)
}

// SwitchAccount switches the active account in the session
func (s *MultiAccountService) SwitchAccount(ctx http.Context, userID string) error {
	multiSession, err := s.GetMultiAccountSession(ctx)
	if err != nil {
		return err
	}

	// Rate limiting check
	if err := s.checkSwitchRateLimit(multiSession); err != nil {
		// Log rate limit exceeded
		s.auditService.LogMultiAccountActivity(ctx, "rate_limit_exceeded", map[string]interface{}{
			"target_user_id": userID,
			"switch_count":   multiSession.SwitchCount,
			"last_switch":    multiSession.LastSwitchAt,
		})

		// Log security event for rapid switching
		s.auditService.LogMultiAccountSecurityEvent(ctx, "rapid_account_switching", "medium", map[string]interface{}{
			"target_user_id": userID,
			"switch_count":   multiSession.SwitchCount,
			"time_window":    "1 hour",
		})

		return err
	}

	// Store previous active account for logging
	previousActiveAccount := multiSession.ActiveAccount

	// Check if the account exists in the session
	accountFound := false
	var targetAccount *AccountSession
	for i, account := range multiSession.Accounts {
		if account.UserID == userID {
			// Check if account session is expired
			if account.ExpiresAt.Before(time.Now()) {
				// Log session expiration
				s.auditService.LogMultiAccountActivity(ctx, "session_expired", map[string]interface{}{
					"expired_user_id": userID,
					"expired_email":   account.Email,
					"expired_at":      account.ExpiresAt,
				})
				return fmt.Errorf("account session has expired, please log in again")
			}

			// Verify the user is still active
			var user models.User
			err := facades.Orm().Query().Where("id", userID).First(&user)
			if err != nil {
				// Log user not found
				s.auditService.LogMultiAccountActivity(ctx, "validation_failed", map[string]interface{}{
					"target_user_id": userID,
					"reason":         "user_not_found_in_database",
				})
				return fmt.Errorf("user not found")
			}

			if !user.IsActive {
				// Log inactive user attempt
				s.auditService.LogMultiAccountActivity(ctx, "validation_failed", map[string]interface{}{
					"target_user_id": userID,
					"target_email":   user.Email,
					"reason":         "user_account_deactivated",
				})
				return fmt.Errorf("user account is deactivated")
			}

			// Update account info and set as active
			multiSession.Accounts[i].LastAccessed = time.Now()
			multiSession.Accounts[i].IsActive = user.IsActive
			multiSession.Accounts[i].Name = user.Name     // Update in case name changed
			multiSession.Accounts[i].Avatar = user.Avatar // Update avatar
			multiSession.ActiveAccount = userID
			targetAccount = &multiSession.Accounts[i]
			accountFound = true
			break
		}
	}

	if !accountFound {
		// Log account not found
		s.auditService.LogMultiAccountActivity(ctx, "validation_failed", map[string]interface{}{
			"target_user_id": userID,
			"reason":         "account_not_found_in_session",
		})
		return fmt.Errorf("account not found in session")
	}

	// Update switch tracking
	multiSession.LastSwitchAt = time.Now()
	multiSession.SwitchCount++

	// Update legacy session values for backward compatibility
	session := ctx.Request().Session()
	if session != nil {
		session.Put("user_id", userID)
		session.Put("user_email", targetAccount.Email)
	}

	// Log successful account switch
	s.auditService.LogMultiAccountActivity(ctx, "account_switched", map[string]interface{}{
		"switched_from":     previousActiveAccount,
		"switched_to":       userID,
		"switched_to_email": targetAccount.Email,
		"switched_to_name":  targetAccount.Name,
		"login_method":      targetAccount.LoginMethod,
		"switch_count":      multiSession.SwitchCount,
		"session_age_hours": time.Since(multiSession.CreatedAt).Hours(),
	})

	return s.SaveMultiAccountSession(ctx, multiSession)
}

// checkSwitchRateLimit checks if the user is switching accounts too frequently
func (s *MultiAccountService) checkSwitchRateLimit(multiSession *MultiAccountSession) error {
	now := time.Now()
	oneHourAgo := now.Add(-1 * time.Hour)

	// Reset counter if last switch was more than an hour ago
	if multiSession.LastSwitchAt.Before(oneHourAgo) {
		multiSession.SwitchCount = 0
		return nil
	}

	// Check if user has exceeded the rate limit
	if multiSession.SwitchCount >= MaxSwitchesPerHour {
		return fmt.Errorf("too many account switches. Please wait before switching again")
	}

	return nil
}

// RemoveAccount removes an account from the multi-account session
func (s *MultiAccountService) RemoveAccount(ctx http.Context, userID string) error {
	multiSession, err := s.GetMultiAccountSession(ctx)
	if err != nil {
		return err
	}

	// Find the account to be removed for logging
	var removedAccount *AccountSession
	for _, account := range multiSession.Accounts {
		if account.UserID == userID {
			removedAccount = &account
			break
		}
	}

	if removedAccount == nil {
		// Log account not found
		s.auditService.LogMultiAccountActivity(ctx, "validation_failed", map[string]interface{}{
			"target_user_id": userID,
			"reason":         "account_not_found_for_removal",
		})
		return fmt.Errorf("account not found in session")
	}

	// Find and remove the account
	newAccounts := []AccountSession{}
	for _, account := range multiSession.Accounts {
		if account.UserID != userID {
			newAccounts = append(newAccounts, account)
		}
	}

	multiSession.Accounts = newAccounts

	// If the removed account was active, switch to the first available account
	if multiSession.ActiveAccount == userID {
		if len(multiSession.Accounts) > 0 {
			multiSession.ActiveAccount = multiSession.Accounts[0].UserID
			// Update legacy session values
			session := ctx.Request().Session()
			if session != nil {
				session.Put("user_id", multiSession.ActiveAccount)
				session.Put("user_email", multiSession.Accounts[0].Email)
			}
		} else {
			// No accounts left, clear session
			multiSession.ActiveAccount = ""
			session := ctx.Request().Session()
			if session != nil {
				session.Forget("user_id")
				session.Forget("user_email")
			}
		}
	}

	// Log account removal
	s.auditService.LogMultiAccountActivity(ctx, "account_removed", map[string]interface{}{
		"removed_user_id":    userID,
		"removed_email":      removedAccount.Email,
		"removed_name":       removedAccount.Name,
		"was_active":         multiSession.ActiveAccount == userID,
		"remaining_accounts": len(multiSession.Accounts),
		"new_active_account": multiSession.ActiveAccount,
	})

	return s.SaveMultiAccountSession(ctx, multiSession)
}

// GetActiveAccount returns the currently active account
func (s *MultiAccountService) GetActiveAccount(ctx http.Context) (*AccountSession, error) {
	facades.Log().Info("GetActiveAccount: Starting")

	// Debug: Check if session exists
	session := ctx.Request().Session()
	if session == nil {
		facades.Log().Error("GetActiveAccount: No session available")
		return nil, fmt.Errorf("no session available")
	}

	facades.Log().Info("GetActiveAccount: Session ID", map[string]interface{}{
		"session_id": session.GetID(),
	})

	multiSession, err := s.GetMultiAccountSession(ctx)
	if err != nil {
		facades.Log().Error("GetActiveAccount: Failed to get multi-account session", map[string]interface{}{
			"error": err.Error(),
		})
		return nil, err
	}

	facades.Log().Info("GetActiveAccount: Session retrieved", map[string]interface{}{
		"active_account": multiSession.ActiveAccount,
		"account_count":  len(multiSession.Accounts),
		"accounts":       multiSession.Accounts,
	})

	if multiSession.ActiveAccount == "" {
		facades.Log().Info("GetActiveAccount: No active account set")
		return nil, fmt.Errorf("no active account")
	}

	for _, account := range multiSession.Accounts {
		if account.UserID == multiSession.ActiveAccount {
			facades.Log().Info("GetActiveAccount: Found active account", map[string]interface{}{
				"user_id": account.UserID,
				"email":   account.Email,
			})
			return &account, nil
		}
	}

	facades.Log().Warning("GetActiveAccount: Active account not found in session accounts")
	return nil, fmt.Errorf("active account not found in session")
}

// GetAllAccounts returns all accounts in the session
func (s *MultiAccountService) GetAllAccounts(ctx http.Context) ([]AccountSession, error) {
	multiSession, err := s.GetMultiAccountSession(ctx)
	if err != nil {
		return nil, err
	}

	return multiSession.Accounts, nil
}

// IsAccountInSession checks if a user account is already in the session
func (s *MultiAccountService) IsAccountInSession(ctx http.Context, userID string) bool {
	multiSession, err := s.GetMultiAccountSession(ctx)
	if err != nil {
		return false
	}

	for _, account := range multiSession.Accounts {
		if account.UserID == userID {
			return true
		}
	}

	return false
}

// ClearAllAccounts clears all accounts from the session
func (s *MultiAccountService) ClearAllAccounts(ctx http.Context) error {
	multiSession, err := s.GetMultiAccountSession(ctx)
	if err != nil {
		return err
	}

	// Log the clearing of all accounts
	s.auditService.LogMultiAccountActivity(ctx, "all_accounts_cleared", map[string]interface{}{
		"cleared_count":    len(multiSession.Accounts),
		"session_duration": time.Since(multiSession.CreatedAt).Hours(),
		"total_switches":   multiSession.SwitchCount,
	})

	session := ctx.Request().Session()
	if session != nil {
		session.Forget("multi_account_session")
		session.Forget("user_id")
		session.Forget("user_email")
	}
	return nil
}

// GetAccountCount returns the number of accounts in the session
func (s *MultiAccountService) GetAccountCount(ctx http.Context) int {
	multiSession, err := s.GetMultiAccountSession(ctx)
	if err != nil {
		return 0
	}

	return len(multiSession.Accounts)
}

// ValidateAccountAccess checks if the current session can access a specific account
func (s *MultiAccountService) ValidateAccountAccess(ctx http.Context, userID string) error {
	multiSession, err := s.GetMultiAccountSession(ctx)
	if err != nil {
		return fmt.Errorf("failed to get session: %v", err)
	}

	// Check if account exists in session
	for _, account := range multiSession.Accounts {
		if account.UserID == userID {
			// Check if account session is expired
			if account.ExpiresAt.Before(time.Now()) {
				return fmt.Errorf("account session has expired")
			}

			// Verify user is still active in database
			var user models.User
			err := facades.Orm().Query().Where("id", userID).First(&user)
			if err != nil {
				return fmt.Errorf("user not found in database")
			}

			if !user.IsActive {
				return fmt.Errorf("user account is deactivated")
			}

			return nil
		}
	}

	return fmt.Errorf("account not found in session")
}

// GetAccountByID returns a specific account from the session
func (s *MultiAccountService) GetAccountByID(ctx http.Context, userID string) (*AccountSession, error) {
	multiSession, err := s.GetMultiAccountSession(ctx)
	if err != nil {
		return nil, err
	}

	for _, account := range multiSession.Accounts {
		if account.UserID == userID {
			return &account, nil
		}
	}

	return nil, fmt.Errorf("account not found")
}

// RefreshAccountData updates account information from the database
func (s *MultiAccountService) RefreshAccountData(ctx http.Context, userID string) error {
	multiSession, err := s.GetMultiAccountSession(ctx)
	if err != nil {
		return err
	}

	// Find the account in session
	accountIndex := -1
	var oldAccountData AccountSession
	for i, account := range multiSession.Accounts {
		if account.UserID == userID {
			accountIndex = i
			oldAccountData = account
			break
		}
	}

	if accountIndex == -1 {
		// Log account not found
		s.auditService.LogMultiAccountActivity(ctx, "validation_failed", map[string]interface{}{
			"target_user_id": userID,
			"reason":         "account_not_found_for_refresh",
		})
		return fmt.Errorf("account not found in session")
	}

	// Get fresh user data from database
	var user models.User
	err = facades.Orm().Query().Where("id", userID).First(&user)
	if err != nil {
		// Log refresh failure
		s.auditService.LogMultiAccountActivity(ctx, "account_refresh_failed", map[string]interface{}{
			"user_id": userID,
			"error":   err.Error(),
		})
		return fmt.Errorf("failed to fetch user data: %v", err)
	}

	// Track changes
	changes := make(map[string]interface{})
	if oldAccountData.Name != user.Name {
		changes["name"] = map[string]string{"old": oldAccountData.Name, "new": user.Name}
	}
	if oldAccountData.Email != user.Email {
		changes["email"] = map[string]string{"old": oldAccountData.Email, "new": user.Email}
	}
	if oldAccountData.Avatar != user.Avatar {
		changes["avatar"] = map[string]string{"old": oldAccountData.Avatar, "new": user.Avatar}
	}
	if oldAccountData.IsActive != user.IsActive {
		changes["is_active"] = map[string]bool{"old": oldAccountData.IsActive, "new": user.IsActive}
	}

	// Update account information
	multiSession.Accounts[accountIndex].Name = user.Name
	multiSession.Accounts[accountIndex].Email = user.Email
	multiSession.Accounts[accountIndex].Avatar = user.Avatar
	multiSession.Accounts[accountIndex].IsActive = user.IsActive
	multiSession.Accounts[accountIndex].LastAccessed = time.Now()

	// Log account refresh
	s.auditService.LogMultiAccountActivity(ctx, "account_refreshed", map[string]interface{}{
		"user_id":     userID,
		"email":       user.Email,
		"changes":     changes,
		"has_changes": len(changes) > 0,
	})

	return s.SaveMultiAccountSession(ctx, multiSession)
}

// GetSessionStatistics returns statistics about the multi-account session
func (s *MultiAccountService) GetSessionStatistics(ctx http.Context) (map[string]interface{}, error) {
	multiSession, err := s.GetMultiAccountSession(ctx)
	if err != nil {
		return nil, err
	}

	activeAccount, _ := s.GetActiveAccount(ctx)

	stats := map[string]interface{}{
		"total_accounts":    len(multiSession.Accounts),
		"max_accounts":      MaxAccountsPerSession,
		"active_account_id": multiSession.ActiveAccount,
		"created_at":        multiSession.CreatedAt,
		"last_updated":      multiSession.UpdatedAt,
		"last_switch_at":    multiSession.LastSwitchAt,
		"switch_count":      multiSession.SwitchCount,
		"session_age_hours": time.Since(multiSession.CreatedAt).Hours(),
	}

	if activeAccount != nil {
		stats["active_account_email"] = activeAccount.Email
		stats["active_account_name"] = activeAccount.Name
		stats["active_login_method"] = activeAccount.LoginMethod
		stats["active_session_expires"] = activeAccount.ExpiresAt
	}

	// Calculate account distribution by login method
	loginMethods := make(map[string]int)
	for _, account := range multiSession.Accounts {
		loginMethods[account.LoginMethod]++
	}
	stats["login_methods"] = loginMethods

	return stats, nil
}

// CleanupInactiveSessions removes accounts that haven't been accessed recently
func (s *MultiAccountService) CleanupInactiveSessions(ctx http.Context, inactivityThreshold time.Duration) error {
	multiSession, err := s.GetMultiAccountSession(ctx)
	if err != nil {
		return err
	}

	cutoffTime := time.Now().Add(-inactivityThreshold)
	activeAccounts := []AccountSession{}
	removedCount := 0

	for _, account := range multiSession.Accounts {
		if account.LastAccessed.After(cutoffTime) {
			activeAccounts = append(activeAccounts, account)
		} else {
			removedCount++
			facades.Log().Info("Removed inactive account session", map[string]interface{}{
				"user_id":       account.UserID,
				"email":         account.Email,
				"last_accessed": account.LastAccessed,
				"threshold":     inactivityThreshold.String(),
			})
		}
	}

	if removedCount > 0 {
		multiSession.Accounts = activeAccounts

		// If active account was removed, switch to first available
		if multiSession.ActiveAccount != "" {
			activeFound := false
			for _, account := range activeAccounts {
				if account.UserID == multiSession.ActiveAccount {
					activeFound = true
					break
				}
			}

			if !activeFound {
				if len(activeAccounts) > 0 {
					multiSession.ActiveAccount = activeAccounts[0].UserID
					session := ctx.Request().Session()
					if session != nil {
						session.Put("user_id", activeAccounts[0].UserID)
						session.Put("user_email", activeAccounts[0].Email)
					}
				} else {
					multiSession.ActiveAccount = ""
					session := ctx.Request().Session()
					if session != nil {
						session.Forget("user_id")
						session.Forget("user_email")
					}
				}
			}
		}

		return s.SaveMultiAccountSession(ctx, multiSession)
	}

	return nil
}

// ExtendAccountSession extends the expiration time for a specific account
func (s *MultiAccountService) ExtendAccountSession(ctx http.Context, userID string) error {
	multiSession, err := s.GetMultiAccountSession(ctx)
	if err != nil {
		return err
	}

	for i, account := range multiSession.Accounts {
		if account.UserID == userID {
			oldExpiration := multiSession.Accounts[i].ExpiresAt
			multiSession.Accounts[i].ExpiresAt = time.Now().Add(AccountSessionTTL)
			multiSession.Accounts[i].LastAccessed = time.Now()

			// Log session extension
			s.auditService.LogMultiAccountActivity(ctx, "session_extended", map[string]interface{}{
				"user_id":         userID,
				"email":           account.Email,
				"old_expires_at":  oldExpiration,
				"new_expires_at":  multiSession.Accounts[i].ExpiresAt,
				"extension_hours": AccountSessionTTL.Hours(),
			})

			return s.SaveMultiAccountSession(ctx, multiSession)
		}
	}

	// Log account not found for extension
	s.auditService.LogMultiAccountActivity(ctx, "validation_failed", map[string]interface{}{
		"target_user_id": userID,
		"reason":         "account_not_found_for_extension",
	})

	return fmt.Errorf("account not found in session")
}
