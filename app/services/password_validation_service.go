package services

import (
	"crypto/rand"
	"fmt"
	"strings"
	"unicode"

	"github.com/goravel/framework/facades"
)

type PasswordValidationService struct{}

// NewPasswordValidationService creates a new password validation service
func NewPasswordValidationService() *PasswordValidationService {
	return &PasswordValidationService{}
}

// PasswordStrength represents the strength of a password
type PasswordStrength struct {
	Score       int      `json:"score"`       // 0-100
	Level       string   `json:"level"`       // weak, fair, good, strong, very_strong
	Suggestions []string `json:"suggestions"` // Improvement suggestions
	IsValid     bool     `json:"is_valid"`    // Whether password meets minimum requirements
}

// PasswordRequirements defines password policy requirements
type PasswordRequirements struct {
	MinLength              int  `json:"min_length"`
	MaxLength              int  `json:"max_length"`
	RequireUppercase       bool `json:"require_uppercase"`
	RequireLowercase       bool `json:"require_lowercase"`
	RequireNumbers         bool `json:"require_numbers"`
	RequireSpecialChars    bool `json:"require_special_chars"`
	PreventCommonPasswords bool `json:"prevent_common_passwords"`
}

// DefaultRequirements returns default password requirements
func (s *PasswordValidationService) DefaultRequirements() *PasswordRequirements {
	return &PasswordRequirements{
		MinLength:              8,
		MaxLength:              128,
		RequireUppercase:       true,
		RequireLowercase:       true,
		RequireNumbers:         true,
		RequireSpecialChars:    true,
		PreventCommonPasswords: true,
	}
}

// ValidatePassword validates a password against requirements
func (s *PasswordValidationService) ValidatePassword(password string, requirements *PasswordRequirements) (*PasswordStrength, error) {
	if requirements == nil {
		requirements = s.DefaultRequirements()
	}

	strength := &PasswordStrength{
		Score:       0,
		Level:       "weak",
		Suggestions: []string{},
		IsValid:     true,
	}

	// Check minimum length
	if len(password) < requirements.MinLength {
		strength.IsValid = false
		strength.Suggestions = append(strength.Suggestions,
			fmt.Sprintf("Password must be at least %d characters long", requirements.MinLength))
	}

	// Check maximum length
	if len(password) > requirements.MaxLength {
		strength.IsValid = false
		strength.Suggestions = append(strength.Suggestions,
			fmt.Sprintf("Password must be no more than %d characters long", requirements.MaxLength))
	}

	// Check character requirements
	var hasUpper, hasLower, hasNumber, hasSpecial bool
	var charScore int

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
			charScore += 2
		case unicode.IsLower(char):
			hasLower = true
			charScore += 2
		case unicode.IsNumber(char):
			hasNumber = true
			charScore += 2
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
			charScore += 3
		default:
			charScore += 1
		}
	}

	// Check requirements
	if requirements.RequireUppercase && !hasUpper {
		strength.IsValid = false
		strength.Suggestions = append(strength.Suggestions, "Include at least one uppercase letter")
	}

	if requirements.RequireLowercase && !hasLower {
		strength.IsValid = false
		strength.Suggestions = append(strength.Suggestions, "Include at least one lowercase letter")
	}

	if requirements.RequireNumbers && !hasNumber {
		strength.IsValid = false
		strength.Suggestions = append(strength.Suggestions, "Include at least one number")
	}

	if requirements.RequireSpecialChars && !hasSpecial {
		strength.IsValid = false
		strength.Suggestions = append(strength.Suggestions, "Include at least one special character")
	}

	// Check for common passwords
	if requirements.PreventCommonPasswords && s.isCommonPassword(password) {
		strength.IsValid = false
		strength.Suggestions = append(strength.Suggestions, "Avoid common passwords")
	}

	// Calculate strength score
	strength.Score = s.calculateStrengthScore(password, charScore, hasUpper, hasLower, hasNumber, hasSpecial)
	strength.Level = s.getStrengthLevel(strength.Score)

	// Add improvement suggestions
	strength.Suggestions = append(strength.Suggestions, s.getImprovementSuggestions(password, strength.Score)...)

	return strength, nil
}

// ValidatePasswordChange validates a password change request
func (s *PasswordValidationService) ValidatePasswordChange(currentPassword, newPassword string, requirements *PasswordRequirements) (*PasswordStrength, error) {
	// Validate new password
	strength, err := s.ValidatePassword(newPassword, requirements)
	if err != nil {
		return nil, err
	}

	// Check if new password is different from current
	if currentPassword == newPassword {
		strength.IsValid = false
		strength.Suggestions = append(strength.Suggestions, "New password must be different from current password")
	}

	// Check for similarity (optional - could be configurable)
	if s.calculateSimilarity(currentPassword, newPassword) > 0.7 {
		strength.Suggestions = append(strength.Suggestions, "New password should be significantly different from current password")
	}

	return strength, nil
}

// Helper methods

func (s *PasswordValidationService) calculateStrengthScore(password string, charScore int, hasUpper, hasLower, hasNumber, hasSpecial bool) int {
	score := 0

	// Base score from character variety
	score += charScore

	// Length bonus
	length := len(password)
	if length >= 12 {
		score += 20
	} else if length >= 10 {
		score += 15
	} else if length >= 8 {
		score += 10
	}

	// Character variety bonus
	if hasUpper && hasLower && hasNumber && hasSpecial {
		score += 20
	} else if hasUpper && hasLower && hasNumber {
		score += 15
	} else if hasUpper && hasLower {
		score += 10
	}

	// Penalty for repetitive patterns
	if s.hasRepetitivePattern(password) {
		score -= 10
	}

	// Penalty for sequential characters
	if s.hasSequentialChars(password) {
		score -= 15
	}

	// Bonus for mixed case
	if hasUpper && hasLower {
		score += 5
	}

	// Ensure score is within bounds
	if score < 0 {
		score = 0
	} else if score > 100 {
		score = 100
	}

	return score
}

func (s *PasswordValidationService) getStrengthLevel(score int) string {
	switch {
	case score >= 90:
		return "very_strong"
	case score >= 70:
		return "strong"
	case score >= 50:
		return "good"
	case score >= 30:
		return "fair"
	default:
		return "weak"
	}
}

func (s *PasswordValidationService) getImprovementSuggestions(password string, score int) []string {
	var suggestions []string

	if score < 50 {
		suggestions = append(suggestions, "Make your password longer")
		suggestions = append(suggestions, "Use a mix of letters, numbers, and symbols")
	}

	if score < 70 {
		suggestions = append(suggestions, "Avoid common words and patterns")
		suggestions = append(suggestions, "Consider using a passphrase")
	}

	if len(password) < 12 {
		suggestions = append(suggestions, "Use at least 12 characters for better security")
	}

	return suggestions
}

func (s *PasswordValidationService) isCommonPassword(password string) bool {
	commonPasswords := []string{
		"password", "123456", "123456789", "qwerty", "abc123",
		"password123", "admin", "letmein", "welcome", "monkey",
		"dragon", "master", "sunshine", "princess", "qwerty123",
		"football", "baseball", "superman", "trustno1", "butterfly",
		"dolphin", "jordan", "michael", "michelle", "charlie",
		"andrew", "matthew", "access", "shadow", "michael",
		"ginger", "blowme", "test", "jordan", "hunter",
		"michelle", "charlie", "andrew", "love", "2000",
		"robert", "orange", "joshua", "type", "1234567890",
		"654321", "superman", "121212", "buster", "butter",
		"dragon", "jordan", "michael", "michelle", "charlie",
		"andrew", "matthew", "access", "shadow", "michael",
		"ginger", "blowme", "test", "jordan", "hunter",
		"michelle", "charlie", "andrew", "love", "2000",
		"robert", "orange", "joshua", "type", "1234567890",
	}

	passwordLower := strings.ToLower(password)
	for _, common := range commonPasswords {
		if passwordLower == common {
			return true
		}
	}

	return false
}

func (s *PasswordValidationService) hasRepetitivePattern(password string) bool {
	if len(password) < 4 {
		return false
	}

	// Check for repeated characters
	for i := 0; i < len(password)-2; i++ {
		if password[i] == password[i+1] && password[i] == password[i+2] {
			return true
		}
	}

	// Check for repeated patterns
	for i := 0; i < len(password)-3; i++ {
		pattern := password[i : i+2]
		if strings.Count(password, pattern) > 2 {
			return true
		}
	}

	return false
}

func (s *PasswordValidationService) hasSequentialChars(password string) bool {
	if len(password) < 3 {
		return false
	}

	// Check for sequential numbers
	sequentialNumbers := []string{"123", "234", "345", "456", "567", "678", "789", "890", "012"}
	for _, seq := range sequentialNumbers {
		if strings.Contains(password, seq) {
			return true
		}
	}

	// Check for sequential letters
	sequentialLetters := []string{"abc", "bcd", "cde", "def", "efg", "fgh", "ghi", "hij", "ijk", "jkl", "klm", "lmn", "mno", "nop", "opq", "pqr", "qrs", "rst", "stu", "tuv", "uvw", "vwx", "wxy", "xyz"}
	for _, seq := range sequentialLetters {
		if strings.Contains(strings.ToLower(password), seq) {
			return true
		}
	}

	return false
}

func (s *PasswordValidationService) calculateSimilarity(str1, str2 string) float64 {
	if str1 == str2 {
		return 1.0
	}

	if len(str1) == 0 || len(str2) == 0 {
		return 0.0
	}

	// Simple similarity calculation using longest common subsequence
	lcs := s.longestCommonSubsequence(str1, str2)
	maxLen := len(str1)
	if len(str2) > maxLen {
		maxLen = len(str2)
	}

	return float64(lcs) / float64(maxLen)
}

func (s *PasswordValidationService) longestCommonSubsequence(str1, str2 string) int {
	m, n := len(str1), len(str2)
	dp := make([][]int, m+1)
	for i := range dp {
		dp[i] = make([]int, n+1)
	}

	for i := 1; i <= m; i++ {
		for j := 1; j <= n; j++ {
			if str1[i-1] == str2[j-1] {
				dp[i][j] = dp[i-1][j-1] + 1
			} else {
				if dp[i-1][j] > dp[i][j-1] {
					dp[i][j] = dp[i-1][j]
				} else {
					dp[i][j] = dp[i][j-1]
				}
			}
		}
	}

	return dp[m][n]
}

// GenerateStrongPassword generates a strong password
func (s *PasswordValidationService) GenerateStrongPassword(length int) string {
	if length < 8 {
		length = 12
	}

	const (
		lowercase = "abcdefghijklmnopqrstuvwxyz"
		uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		numbers   = "0123456789"
		symbols   = "!@#$%^&*()_+-=[]{}|;:,.<>?"
	)

	allChars := lowercase + uppercase + numbers + symbols
	password := make([]byte, length)

	// Ensure at least one character from each category
	password[0] = lowercase[s.getRandomIndex(len(lowercase))]
	password[1] = uppercase[s.getRandomIndex(len(uppercase))]
	password[2] = numbers[s.getRandomIndex(len(numbers))]
	password[3] = symbols[s.getRandomIndex(len(symbols))]

	// Fill the rest randomly
	for i := 4; i < length; i++ {
		password[i] = allChars[s.getRandomIndex(len(allChars))]
	}

	// Shuffle the password to avoid predictable patterns
	s.shuffleBytes(password)

	return string(password)
}

// getRandomIndex returns a cryptographically secure random index
func (s *PasswordValidationService) getRandomIndex(max int) int {
	if max <= 0 {
		return 0
	}

	// Use crypto/rand for cryptographically secure random numbers
	bytes := make([]byte, 4)
	_, err := rand.Read(bytes)
	if err != nil {
		// Do not fallback to insecure math/rand - return error instead
		facades.Log().Error("Failed to generate secure random number", map[string]interface{}{
			"error": err.Error(),
		})
		return 0 // Return 0 instead of insecure random
	}

	// Convert bytes to int and mod by max
	randomInt := int(bytes[0])<<24 | int(bytes[1])<<16 | int(bytes[2])<<8 | int(bytes[3])
	if randomInt < 0 {
		randomInt = -randomInt
	}

	return randomInt % max
}

// shuffleBytes shuffles a byte slice using Fisher-Yates algorithm
func (s *PasswordValidationService) shuffleBytes(slice []byte) {
	for i := len(slice) - 1; i > 0; i-- {
		j := s.getRandomIndex(i + 1)
		slice[i], slice[j] = slice[j], slice[i]
	}
}
