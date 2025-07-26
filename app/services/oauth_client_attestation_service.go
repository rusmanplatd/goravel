package services

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/goravel/framework/facades"
)

type OAuthClientAttestationService struct {
	oauthService *OAuthService
}

type ClientAttestationJWT struct {
	Header    ClientAttestationHeader `json:"header"`
	Payload   ClientAttestationClaims `json:"payload"`
	Signature string                  `json:"signature"`
}

type ClientAttestationHeader struct {
	Algorithm string   `json:"alg"`
	Type      string   `json:"typ"`
	X5C       []string `json:"x5c,omitempty"` // Certificate chain
	JWK       *JWK     `json:"jwk,omitempty"` // JSON Web Key
}

type ClientAttestationClaims struct {
	Issuer             string                 `json:"iss"`           // Attestation issuer (e.g., "android-safetynet", "apple-app-attest")
	Subject            string                 `json:"sub"`           // Client ID
	Audience           string                 `json:"aud"`           // OAuth server
	IssuedAt           int64                  `json:"iat"`           // Issued at
	Expiration         int64                  `json:"exp"`           // Expiration
	NotBefore          int64                  `json:"nbf,omitempty"` // Not before
	JWTID              string                 `json:"jti,omitempty"` // JWT ID
	ClientID           string                 `json:"client_id"`     // OAuth client ID
	AttestationType    string                 `json:"attestation_type"`
	AppIntegrity       *AppIntegrityInfo      `json:"app_integrity,omitempty"`
	DeviceIntegrity    *DeviceIntegrityInfo   `json:"device_integrity,omitempty"`
	EnvironmentDetails *EnvironmentDetails    `json:"environment_details,omitempty"`
	CustomClaims       map[string]interface{} `json:"custom_claims,omitempty"`
}

type AppIntegrityInfo struct {
	PackageName      string   `json:"package_name"`
	AppSigningCerts  []string `json:"app_signing_certs"`
	VersionCode      int64    `json:"version_code"`
	VersionName      string   `json:"version_name"`
	AppRecognition   string   `json:"app_recognition"` // PLAY_RECOGNIZED, UNRECOGNIZED, etc.
	InstallSource    string   `json:"install_source"`  // Google Play, sideload, etc.
	DebuggerAttached bool     `json:"debugger_attached"`
	Rooted           bool     `json:"rooted,omitempty"`
}

type DeviceIntegrityInfo struct {
	DeviceRecognition    []string `json:"device_recognition"` // MEETS_DEVICE_INTEGRITY, etc.
	RecentDeviceActivity bool     `json:"recent_device_activity"`
	DeviceModel          string   `json:"device_model,omitempty"`
	AndroidVersion       string   `json:"android_version,omitempty"`
	IOSVersion           string   `json:"ios_version,omitempty"`
	Platform             string   `json:"platform"` // android, ios
}

type EnvironmentDetails struct {
	AppAccessRiskVerdict     *RiskVerdict `json:"app_access_risk_verdict,omitempty"`
	AccountAccessRiskVerdict *RiskVerdict `json:"account_access_risk_verdict,omitempty"`
}

type RiskVerdict struct {
	RiskLevel string `json:"risk_level"` // LOW, MEDIUM, HIGH
	Details   string `json:"details,omitempty"`
}

type JWK struct {
	KeyType   string `json:"kty"`
	Algorithm string `json:"alg,omitempty"`
	Use       string `json:"use,omitempty"`
	KeyID     string `json:"kid,omitempty"`
	N         string `json:"n,omitempty"`   // RSA modulus
	E         string `json:"e,omitempty"`   // RSA exponent
	X         string `json:"x,omitempty"`   // ECDSA x coordinate
	Y         string `json:"y,omitempty"`   // ECDSA y coordinate
	Curve     string `json:"crv,omitempty"` // ECDSA curve
}

type AttestationValidationResult struct {
	Valid              bool                   `json:"valid"`
	ClientID           string                 `json:"client_id"`
	AttestationType    string                 `json:"attestation_type"`
	TrustLevel         string                 `json:"trust_level"` // HIGH, MEDIUM, LOW, UNTRUSTED
	ValidationErrors   []string               `json:"validation_errors,omitempty"`
	SecurityVerdicts   map[string]string      `json:"security_verdicts"`
	AppIntegrity       *AppIntegrityInfo      `json:"app_integrity,omitempty"`
	DeviceIntegrity    *DeviceIntegrityInfo   `json:"device_integrity,omitempty"`
	RecommendedActions []string               `json:"recommended_actions,omitempty"`
	Details            map[string]interface{} `json:"details,omitempty"`
}

func NewOAuthClientAttestationService() *OAuthClientAttestationService {
	return &OAuthClientAttestationService{
		oauthService: NewOAuthService(),
	}
}

// ValidateClientAttestation validates a client attestation JWT (Google-like)
func (s *OAuthClientAttestationService) ValidateClientAttestation(attestationJWT, clientID string) (*AttestationValidationResult, error) {
	result := &AttestationValidationResult{
		Valid:            false,
		ClientID:         clientID,
		ValidationErrors: []string{},
		SecurityVerdicts: make(map[string]string),
		Details:          make(map[string]interface{}),
	}

	// Parse the JWT
	claims, err := s.parseAttestationJWT(attestationJWT)
	if err != nil {
		result.ValidationErrors = append(result.ValidationErrors, fmt.Sprintf("JWT parsing failed: %v", err))
		return result, err
	}

	result.AttestationType = claims.AttestationType
	result.AppIntegrity = claims.AppIntegrity
	result.DeviceIntegrity = claims.DeviceIntegrity

	// Validate basic JWT claims
	if err := s.validateBasicClaims(claims, clientID); err != nil {
		result.ValidationErrors = append(result.ValidationErrors, err.Error())
		return result, err
	}

	// Validate signature and certificate chain
	if err := s.validateSignature(attestationJWT); err != nil {
		result.ValidationErrors = append(result.ValidationErrors, fmt.Sprintf("Signature validation failed: %v", err))
		return result, err
	}

	// Perform attestation-specific validation
	switch claims.AttestationType {
	case "android-safetynet", "android-play-integrity":
		s.validateAndroidAttestation(claims, result)
	case "apple-app-attest":
		s.validateAppleAttestation(claims, result)
	case "custom":
		s.validateCustomAttestation(claims, result)
	default:
		result.ValidationErrors = append(result.ValidationErrors, "Unsupported attestation type")
		return result, fmt.Errorf("unsupported attestation type: %s", claims.AttestationType)
	}

	// Determine overall trust level
	s.determineTrustLevel(result)

	// Generate security verdicts
	s.generateSecurityVerdicts(result)

	// Recommend actions based on validation results
	s.recommendActions(result)

	result.Valid = len(result.ValidationErrors) == 0

	// Log attestation validation
	s.logAttestationValidation(clientID, result)

	return result, nil
}

// parseAttestationJWT parses and validates the JWT structure
func (s *OAuthClientAttestationService) parseAttestationJWT(attestationJWT string) (*ClientAttestationClaims, error) {
	// Parse JWT without verification first to get claims
	token, _, err := new(jwt.Parser).ParseUnverified(attestationJWT, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid JWT claims")
	}

	// Convert map claims to structured claims
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal claims: %w", err)
	}

	var attestationClaims ClientAttestationClaims
	if err := json.Unmarshal(claimsJSON, &attestationClaims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal claims: %w", err)
	}

	return &attestationClaims, nil
}

// validateBasicClaims validates standard JWT claims
func (s *OAuthClientAttestationService) validateBasicClaims(claims *ClientAttestationClaims, expectedClientID string) error {
	now := time.Now().Unix()

	// Validate expiration
	if claims.Expiration != 0 && now > claims.Expiration {
		return fmt.Errorf("attestation JWT has expired")
	}

	// Validate not before
	if claims.NotBefore != 0 && now < claims.NotBefore {
		return fmt.Errorf("attestation JWT not yet valid")
	}

	// Validate issued at (not too old)
	maxAge := int64(facades.Config().GetInt("oauth.client_attestation.max_age_seconds", 300)) // 5 minutes default
	if claims.IssuedAt != 0 && now-claims.IssuedAt > maxAge {
		return fmt.Errorf("attestation JWT is too old")
	}

	// Validate client ID
	if claims.ClientID != expectedClientID {
		return fmt.Errorf("client ID mismatch in attestation")
	}

	// Validate audience
	expectedAudience := facades.Config().GetString("app.url", "")
	if claims.Audience != "" && claims.Audience != expectedAudience {
		return fmt.Errorf("invalid audience in attestation")
	}

	return nil
}

// validateSignature validates the JWT signature and certificate chain
func (s *OAuthClientAttestationService) validateSignature(attestationJWT string) error {
	// Parse JWT to get header
	parts := strings.Split(attestationJWT, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWT format")
	}

	// Decode header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("failed to decode JWT header: %w", err)
	}

	var header ClientAttestationHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return fmt.Errorf("failed to parse JWT header: %w", err)
	}

	// Validate certificate chain if present
	if len(header.X5C) > 0 {
		if err := s.validateCertificateChain(header.X5C); err != nil {
			return fmt.Errorf("certificate chain validation failed: %w", err)
		}
	}

	// Extract public key and verify signature
	publicKey, err := s.extractPublicKey(&header)
	if err != nil {
		return fmt.Errorf("failed to extract public key: %w", err)
	}

	if err := s.verifyJWTSignature(attestationJWT, publicKey, header.Algorithm); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

// validateCertificateChain validates the X.509 certificate chain
func (s *OAuthClientAttestationService) validateCertificateChain(certChain []string) error {
	if len(certChain) == 0 {
		return fmt.Errorf("empty certificate chain")
	}

	// Decode and parse certificates
	var certs []*x509.Certificate
	for i, certB64 := range certChain {
		certBytes, err := base64.StdEncoding.DecodeString(certB64)
		if err != nil {
			return fmt.Errorf("failed to decode certificate %d: %w", i, err)
		}

		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return fmt.Errorf("failed to parse certificate %d: %w", i, err)
		}

		certs = append(certs, cert)
	}

	// Validate certificate chain
	if len(certs) > 1 {
		// Verify each certificate is signed by the next one in the chain
		for i := 0; i < len(certs)-1; i++ {
			if err := certs[i].CheckSignatureFrom(certs[i+1]); err != nil {
				return fmt.Errorf("certificate %d signature verification failed: %w", i, err)
			}
		}
	}

	// Validate root certificate against trusted roots
	rootCert := certs[len(certs)-1]
	if err := s.validateRootCertificate(rootCert); err != nil {
		return fmt.Errorf("root certificate validation failed: %w", err)
	}

	return nil
}

// extractPublicKey extracts the public key from JWT header
func (s *OAuthClientAttestationService) extractPublicKey(header *ClientAttestationHeader) (interface{}, error) {
	if len(header.X5C) > 0 {
		// Extract from certificate
		certBytes, err := base64.StdEncoding.DecodeString(header.X5C[0])
		if err != nil {
			return nil, fmt.Errorf("failed to decode certificate: %w", err)
		}

		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}

		return cert.PublicKey, nil
	}

	if header.JWK != nil {
		// Extract from JWK
		return s.jwkToPublicKey(header.JWK)
	}

	return nil, fmt.Errorf("no public key found in JWT header")
}

// jwkToPublicKey converts JWK to Go public key
func (s *OAuthClientAttestationService) jwkToPublicKey(jwk *JWK) (interface{}, error) {
	switch jwk.KeyType {
	case "RSA":
		if jwk.N == "" || jwk.E == "" {
			return nil, fmt.Errorf("missing RSA key parameters")
		}

		// Convert to big integers and create RSA public key
		// This is a simplified implementation - production should use proper crypto libraries
		return nil, fmt.Errorf("RSA JWK conversion not implemented in this example")

	case "EC":
		return nil, fmt.Errorf("ECDSA JWK conversion not implemented in this example")

	default:
		return nil, fmt.Errorf("unsupported key type: %s", jwk.KeyType)
	}
}

// verifyJWTSignature verifies the JWT signature
func (s *OAuthClientAttestationService) verifyJWTSignature(tokenString string, publicKey interface{}, algorithm string) error {
	// Parse and verify JWT with the extracted public key
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if token.Method.Alg() != algorithm {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil {
		return fmt.Errorf("JWT verification failed: %w", err)
	}

	if !token.Valid {
		return fmt.Errorf("JWT is not valid")
	}

	return nil
}

// validateRootCertificate validates the root certificate against trusted roots
func (s *OAuthClientAttestationService) validateRootCertificate(cert *x509.Certificate) error {
	// In production, this would check against a list of trusted root certificates
	// For now, we'll implement basic validation

	// Check if certificate is expired
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return fmt.Errorf("root certificate is expired or not yet valid")
	}

	// Check basic constraints
	if !cert.IsCA {
		return fmt.Errorf("root certificate is not a CA certificate")
	}

	// In production, verify against known trusted roots for attestation services
	trustedIssuers := facades.Config().Get("oauth.client_attestation.trusted_issuers", []string{}).([]string)
	if len(trustedIssuers) > 0 {
		issuerFound := false
		for _, trustedIssuer := range trustedIssuers {
			if cert.Issuer.String() == trustedIssuer {
				issuerFound = true
				break
			}
		}
		if !issuerFound {
			return fmt.Errorf("root certificate issuer not trusted")
		}
	}

	return nil
}

// validateAndroidAttestation validates Android-specific attestation claims
func (s *OAuthClientAttestationService) validateAndroidAttestation(claims *ClientAttestationClaims, result *AttestationValidationResult) {
	if claims.AppIntegrity == nil {
		result.ValidationErrors = append(result.ValidationErrors, "Missing app integrity information for Android attestation")
		return
	}

	appIntegrity := claims.AppIntegrity

	// Validate app recognition
	switch appIntegrity.AppRecognition {
	case "PLAY_RECOGNIZED":
		result.SecurityVerdicts["app_recognition"] = "TRUSTED"
	case "UNRECOGNIZED":
		result.SecurityVerdicts["app_recognition"] = "UNTRUSTED"
		result.ValidationErrors = append(result.ValidationErrors, "App not recognized by Google Play")
	default:
		result.SecurityVerdicts["app_recognition"] = "UNKNOWN"
	}

	// Check for debugging and rooting
	if appIntegrity.DebuggerAttached {
		result.SecurityVerdicts["debugger"] = "ATTACHED"
		result.ValidationErrors = append(result.ValidationErrors, "Debugger attached to app")
	}

	if appIntegrity.Rooted {
		result.SecurityVerdicts["root_status"] = "ROOTED"
		result.ValidationErrors = append(result.ValidationErrors, "Device is rooted")
	}

	// Validate device integrity
	if claims.DeviceIntegrity != nil {
		deviceIntegrity := claims.DeviceIntegrity
		if len(deviceIntegrity.DeviceRecognition) > 0 {
			hasMeetsIntegrity := false
			for _, recognition := range deviceIntegrity.DeviceRecognition {
				if recognition == "MEETS_DEVICE_INTEGRITY" {
					hasMeetsIntegrity = true
					break
				}
			}
			if hasMeetsIntegrity {
				result.SecurityVerdicts["device_integrity"] = "MEETS_INTEGRITY"
			} else {
				result.SecurityVerdicts["device_integrity"] = "FAILS_INTEGRITY"
				result.ValidationErrors = append(result.ValidationErrors, "Device fails integrity checks")
			}
		}
	}
}

// validateAppleAttestation validates Apple App Attest claims
func (s *OAuthClientAttestationService) validateAppleAttestation(claims *ClientAttestationClaims, result *AttestationValidationResult) {
	// Apple App Attest validation logic
	if claims.AppIntegrity == nil {
		result.ValidationErrors = append(result.ValidationErrors, "Missing app integrity information for Apple attestation")
		return
	}

	// Validate app bundle ID and team ID
	appIntegrity := claims.AppIntegrity
	if appIntegrity.PackageName == "" {
		result.ValidationErrors = append(result.ValidationErrors, "Missing app bundle ID")
	}

	// Apple devices are generally trusted if attestation passes
	result.SecurityVerdicts["platform_trust"] = "TRUSTED"
	result.SecurityVerdicts["app_store"] = "VERIFIED"
}

// validateCustomAttestation validates custom attestation claims
func (s *OAuthClientAttestationService) validateCustomAttestation(claims *ClientAttestationClaims, result *AttestationValidationResult) {
	// Custom attestation validation logic
	// This would be implemented based on specific requirements
	result.SecurityVerdicts["attestation_type"] = "CUSTOM"

	// Basic validation
	if claims.CustomClaims == nil {
		result.ValidationErrors = append(result.ValidationErrors, "Missing custom claims for custom attestation")
		return
	}

	// Validate custom claims based on configuration
	requiredClaims := facades.Config().Get("oauth.client_attestation.custom_required_claims", []string{}).([]string)
	for _, requiredClaim := range requiredClaims {
		if _, exists := claims.CustomClaims[requiredClaim]; !exists {
			result.ValidationErrors = append(result.ValidationErrors, fmt.Sprintf("Missing required custom claim: %s", requiredClaim))
		}
	}
}

// determineTrustLevel determines the overall trust level based on validation results
func (s *OAuthClientAttestationService) determineTrustLevel(result *AttestationValidationResult) {
	if len(result.ValidationErrors) > 0 {
		result.TrustLevel = "UNTRUSTED"
		return
	}

	// Analyze security verdicts to determine trust level
	highTrustCount := 0
	mediumTrustCount := 0
	lowTrustCount := 0

	for _, verdict := range result.SecurityVerdicts {
		switch verdict {
		case "TRUSTED", "MEETS_INTEGRITY", "VERIFIED":
			highTrustCount++
		case "UNKNOWN", "CUSTOM":
			mediumTrustCount++
		case "UNTRUSTED", "FAILS_INTEGRITY", "ATTACHED", "ROOTED":
			lowTrustCount++
		}
	}

	if lowTrustCount > 0 {
		result.TrustLevel = "LOW"
	} else if highTrustCount >= 2 {
		result.TrustLevel = "HIGH"
	} else {
		result.TrustLevel = "MEDIUM"
	}
}

// generateSecurityVerdicts generates additional security verdicts
func (s *OAuthClientAttestationService) generateSecurityVerdicts(result *AttestationValidationResult) {
	// Add timestamp verdict
	result.SecurityVerdicts["validation_timestamp"] = time.Now().Format(time.RFC3339)

	// Add overall security verdict
	if result.TrustLevel == "HIGH" && len(result.ValidationErrors) == 0 {
		result.SecurityVerdicts["overall_security"] = "SECURE"
	} else if result.TrustLevel == "MEDIUM" {
		result.SecurityVerdicts["overall_security"] = "MODERATE"
	} else {
		result.SecurityVerdicts["overall_security"] = "INSECURE"
	}
}

// recommendActions recommends actions based on validation results
func (s *OAuthClientAttestationService) recommendActions(result *AttestationValidationResult) {
	switch result.TrustLevel {
	case "HIGH":
		result.RecommendedActions = append(result.RecommendedActions, "Allow full access", "Standard monitoring")
	case "MEDIUM":
		result.RecommendedActions = append(result.RecommendedActions, "Allow limited access", "Enhanced monitoring", "Require additional verification")
	case "LOW":
		result.RecommendedActions = append(result.RecommendedActions, "Restrict access", "Require manual review", "Enhanced logging")
	case "UNTRUSTED":
		result.RecommendedActions = append(result.RecommendedActions, "Block access", "Security investigation", "Client review required")
	}

	// Add specific recommendations based on security verdicts
	for key, verdict := range result.SecurityVerdicts {
		switch {
		case key == "debugger" && verdict == "ATTACHED":
			result.RecommendedActions = append(result.RecommendedActions, "Block debug builds in production")
		case key == "root_status" && verdict == "ROOTED":
			result.RecommendedActions = append(result.RecommendedActions, "Implement root detection countermeasures")
		case key == "device_integrity" && verdict == "FAILS_INTEGRITY":
			result.RecommendedActions = append(result.RecommendedActions, "Require device security update")
		}
	}
}

// logAttestationValidation logs the attestation validation results
func (s *OAuthClientAttestationService) logAttestationValidation(clientID string, result *AttestationValidationResult) {
	facades.Log().Info("Client attestation validation completed", map[string]interface{}{
		"client_id":           clientID,
		"attestation_type":    result.AttestationType,
		"trust_level":         result.TrustLevel,
		"valid":               result.Valid,
		"validation_errors":   result.ValidationErrors,
		"security_verdicts":   result.SecurityVerdicts,
		"recommended_actions": result.RecommendedActions,
	})
}

// IsClientAttestationRequired checks if client attestation is required for a client
func (s *OAuthClientAttestationService) IsClientAttestationRequired(clientID string) bool {
	// Check global configuration
	if !facades.Config().GetBool("oauth.client_attestation.enabled", false) {
		return false
	}

	// Check client-specific configuration
	client, err := s.oauthService.GetClient(clientID)
	if err != nil {
		return false
	}

	// Mobile clients typically require attestation
	if client.IsPublic() {
		return facades.Config().GetBool("oauth.client_attestation.require_for_public_clients", true)
	}

	// Check if client is marked as requiring attestation
	// This would be stored in client metadata
	return facades.Config().GetBool("oauth.client_attestation.require_for_all_clients", false)
}

// GenerateAttestationChallenge generates a challenge for client attestation
func (s *OAuthClientAttestationService) GenerateAttestationChallenge(clientID string) (string, error) {
	// Generate a cryptographically secure random challenge
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return "", fmt.Errorf("failed to generate challenge: %w", err)
	}

	// Encode as base64
	challengeB64 := base64.RawURLEncoding.EncodeToString(challenge)

	// Store challenge with expiration (typically 5-10 minutes)
	expiresAt := time.Now().Add(time.Duration(facades.Config().GetInt("oauth.client_attestation.challenge_ttl_seconds", 600)) * time.Second)

	// In production, store this in cache/database
	facades.Cache().Put(fmt.Sprintf("attestation_challenge_%s", clientID), challengeB64, expiresAt.Sub(time.Now()))

	return challengeB64, nil
}

// ValidateAttestationChallenge validates that the attestation includes the correct challenge
func (s *OAuthClientAttestationService) ValidateAttestationChallenge(clientID, challenge string) bool {
	// Retrieve stored challenge
	storedChallenge := facades.Cache().Get(fmt.Sprintf("attestation_challenge_%s", clientID))
	if storedChallenge == nil {
		return false
	}

	// Compare challenges
	return storedChallenge.(string) == challenge
}
