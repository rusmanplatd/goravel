package requests

// LoginRequest represents the request for user login
// @Description Request model for user authentication
type LoginRequest struct {
	// User's email address
	// @example john.doe@example.com
	Email string `json:"email" binding:"required,email" example:"john.doe@example.com" validate:"required,email"`

	// User's password
	// @example password123
	Password string `json:"password" binding:"required" example:"password123" validate:"required"`

	// Whether to remember the user
	// @example false
	Remember bool `json:"remember" example:"false"`

	// MFA code if enabled
	// @example 123456
	MfaCode string `json:"mfa_code,omitempty" example:"123456"`

	// WebAuthn assertion if using WebAuthn
	// @example {"id":"abc123","response":{"authenticatorData":"...","clientDataJSON":"...","signature":"..."}}
	WebauthnAssertion map[string]interface{} `json:"webauthn_assertion,omitempty" example:"{\"id\":\"abc123\",\"response\":{\"authenticatorData\":\"...\",\"clientDataJSON\":\"...\",\"signature\":\"...\"}}"`
}

// RegisterRequest represents the request for user registration
// @Description Request model for user registration
type RegisterRequest struct {
	// User's full name
	// @example John Doe
	Name string `json:"name" binding:"required" example:"John Doe" validate:"required"`

	// User's email address
	// @example john.doe@example.com
	Email string `json:"email" binding:"required,email" example:"john.doe@example.com" validate:"required,email"`

	// User's password
	// @example password123
	// @minLength 8
	Password string `json:"password" binding:"required,min=8" example:"password123" validate:"required,min=8"`

	// Password confirmation
	// @example password123
	PasswordConfirmation string `json:"password_confirmation" binding:"required,eqfield=Password" example:"password123" validate:"required,eqfield=Password"`

	// Whether to accept terms
	// @example true
	AcceptTerms bool `json:"accept_terms" binding:"required" example:"true" validate:"required"`
}

// ForgotPasswordRequest represents the request for password reset
// @Description Request model for initiating password reset
type ForgotPasswordRequest struct {
	// User's email address
	// @example john.doe@example.com
	Email string `json:"email" binding:"required,email" example:"john.doe@example.com" validate:"required,email"`
}

// ResetPasswordRequest represents the request for password reset confirmation
// @Description Request model for confirming password reset
type ResetPasswordRequest struct {
	// Reset token
	// @example abc123def456
	Token string `json:"token" binding:"required" example:"abc123def456" validate:"required"`

	// User's email address
	// @example john.doe@example.com
	Email string `json:"email" binding:"required,email" example:"john.doe@example.com" validate:"required,email"`

	// New password
	// @example newpassword123
	// @minLength 8
	Password string `json:"password" binding:"required,min=8" example:"newpassword123" validate:"required,min=8"`

	// Password confirmation
	// @example newpassword123
	PasswordConfirmation string `json:"password_confirmation" binding:"required,eqfield=Password" example:"newpassword123" validate:"required,eqfield=Password"`
}

// EnableMfaRequest represents the request for enabling MFA
// @Description Request model for enabling two-factor authentication
type EnableMfaRequest struct {
	// MFA secret (for manual entry)
	// @example ABCDEFGHIJKLMNOP
	Secret string `json:"secret,omitempty" example:"ABCDEFGHIJKLMNOP"`

	// QR code data (for QR code scanning)
	// @example otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example
	QrCode string `json:"qr_code,omitempty" example:"otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"`

	// Verification code
	// @example 123456
	Code string `json:"code" binding:"required" example:"123456" validate:"required"`
}

// DisableMfaRequest represents the request for disabling MFA
// @Description Request model for disabling two-factor authentication
type DisableMfaRequest struct {
	// Current password for verification
	// @example password123
	Password string `json:"password" binding:"required" example:"password123" validate:"required"`

	// MFA code for verification
	// @example 123456
	Code string `json:"code" binding:"required" example:"123456" validate:"required"`
}

// VerifyMfaRequest represents the request for MFA verification
// @Description Request model for MFA code verification
type VerifyMfaRequest struct {
	// MFA code
	// @example 123456
	Code string `json:"code" binding:"required" example:"123456" validate:"required"`
}

// WebauthnRegisterRequest represents the request for WebAuthn registration
// @Description Request model for WebAuthn credential registration
type WebauthnRegisterRequest struct {
	// Credential name
	// @example My Security Key
	Name string `json:"name" binding:"required" example:"My Security Key" validate:"required"`

	// WebAuthn attestation response
	// @example {"id":"abc123","response":{"attestationObject":"...","clientDataJSON":"..."}}
	AttestationResponse map[string]interface{} `json:"attestation_response" binding:"required" example:"{\"id\":\"abc123\",\"response\":{\"attestationObject\":\"...\",\"clientDataJSON\":\"...\"}}" validate:"required"`
}

// WebauthnAuthenticateRequest represents the request for WebAuthn authentication
// @Description Request model for WebAuthn authentication
type WebauthnAuthenticateRequest struct {
	// WebAuthn assertion response
	// @example {"id":"abc123","response":{"authenticatorData":"...","clientDataJSON":"...","signature":"..."}}
	AssertionResponse map[string]interface{} `json:"assertion_response" binding:"required" example:"{\"id\":\"abc123\",\"response\":{\"authenticatorData\":\"...\",\"clientDataJSON\":\"...\",\"signature\":\"...\"}}" validate:"required"`
}

// ChangePasswordRequest represents the request for changing password
// @Description Request model for changing user password
type ChangePasswordRequest struct {
	// Current password
	// @example oldpassword123
	CurrentPassword string `json:"current_password" binding:"required" example:"oldpassword123" validate:"required"`

	// New password
	// @example newpassword123
	// @minLength 8
	NewPassword string `json:"new_password" binding:"required,min=8" example:"newpassword123" validate:"required,min=8"`

	// New password confirmation
	// @example newpassword123
	NewPasswordConfirmation string `json:"new_password_confirmation" binding:"required,eqfield=NewPassword" example:"newpassword123" validate:"required,eqfield=NewPassword"`
}

// RefreshTokenRequest represents the request for refreshing JWT token
// @Description Request model for refreshing authentication token
type RefreshTokenRequest struct {
	// Refresh token
	// @example abc123def456
	RefreshToken string `json:"refresh_token" binding:"required" example:"abc123def456" validate:"required"`
}
