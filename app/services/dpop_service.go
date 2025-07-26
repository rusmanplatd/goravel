package services

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/goravel/framework/facades"
)

type DPoPService struct{}

type DPoPProof struct {
	Header DPoPHeader `json:"header"`
	Claims DPoPClaims `json:"claims"`
}

type DPoPHeader struct {
	Type      string                 `json:"typ"`
	Algorithm string                 `json:"alg"`
	JWK       map[string]interface{} `json:"jwk"`
}

type DPoPClaims struct {
	JTI             string `json:"jti"`           // Unique identifier for the JWT
	HTTPMethod      string `json:"htm"`           // HTTP method
	HTTPURI         string `json:"htu"`           // HTTP URI
	IssuedAt        int64  `json:"iat"`           // Issued at time
	AccessTokenHash string `json:"ath,omitempty"` // Access token hash (for resource server)
}

type DPoPKeyPair struct {
	PrivateKey interface{}            `json:"-"`
	PublicKey  interface{}            `json:"-"`
	JWK        map[string]interface{} `json:"jwk"`
	KeyID      string                 `json:"kid"`
	Algorithm  string                 `json:"alg"`
}

func NewDPoPService() *DPoPService {
	return &DPoPService{}
}

// ValidateDPoPProof validates a DPoP proof JWT
func (s *DPoPService) ValidateDPoPProof(dpopProof, httpMethod, httpURI string, accessToken ...string) (*DPoPProof, error) {
	if !facades.Config().GetBool("oauth.dpop.enabled", false) {
		return nil, fmt.Errorf("DPoP is not enabled")
	}

	// Parse the JWT without verification first to get the JWK
	token, err := jwt.Parse(dpopProof, func(token *jwt.Token) (interface{}, error) {
		// Validate the algorithm
		if !s.isValidDPoPAlgorithm(token.Header["alg"].(string)) {
			return nil, fmt.Errorf("invalid DPoP algorithm: %v", token.Header["alg"])
		}

		// Extract JWK from header
		jwkInterface, ok := token.Header["jwk"]
		if !ok {
			return nil, fmt.Errorf("missing jwk in DPoP proof header")
		}

		jwk, ok := jwkInterface.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("invalid jwk format in DPoP proof header")
		}

		// Convert JWK to public key
		return s.jwkToPublicKey(jwk)
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse DPoP proof: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid DPoP proof token")
	}

	// Validate claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid DPoP proof claims")
	}

	// Validate required claims
	if err := s.validateDPoPClaims(claims, httpMethod, httpURI); err != nil {
		return nil, fmt.Errorf("invalid DPoP claims: %w", err)
	}

	// Validate access token hash if provided
	if len(accessToken) > 0 && accessToken[0] != "" {
		if err := s.validateAccessTokenHash(claims, accessToken[0]); err != nil {
			return nil, fmt.Errorf("invalid access token hash: %w", err)
		}
	}

	// Check for replay attacks
	if err := s.checkDPoPReplay(claims["jti"].(string)); err != nil {
		return nil, fmt.Errorf("DPoP replay detected: %w", err)
	}

	// Store JTI to prevent replay
	s.storeDPoPJTI(claims["jti"].(string))

	// Build DPoP proof structure
	proof := &DPoPProof{
		Header: DPoPHeader{
			Type:      token.Header["typ"].(string),
			Algorithm: token.Header["alg"].(string),
			JWK:       token.Header["jwk"].(map[string]interface{}),
		},
		Claims: DPoPClaims{
			JTI:        claims["jti"].(string),
			HTTPMethod: claims["htm"].(string),
			HTTPURI:    claims["htu"].(string),
			IssuedAt:   int64(claims["iat"].(float64)),
		},
	}

	if ath, ok := claims["ath"].(string); ok {
		proof.Claims.AccessTokenHash = ath
	}

	return proof, nil
}

// GenerateDPoPKeyPair generates a new key pair for DPoP
func (s *DPoPService) GenerateDPoPKeyPair(algorithm string) (*DPoPKeyPair, error) {
	switch algorithm {
	case "ES256":
		return s.generateECDSAKeyPair()
	case "RS256":
		return s.generateRSAKeyPair()
	default:
		return nil, fmt.Errorf("unsupported DPoP algorithm: %s", algorithm)
	}
}

// CreateDPoPProof creates a DPoP proof JWT
func (s *DPoPService) CreateDPoPProof(keyPair *DPoPKeyPair, httpMethod, httpURI string, accessToken ...string) (string, error) {
	// Create claims
	claims := jwt.MapClaims{
		"jti": s.generateJTI(),
		"htm": httpMethod,
		"htu": httpURI,
		"iat": time.Now().Unix(),
	}

	// Add access token hash if provided
	if len(accessToken) > 0 && accessToken[0] != "" {
		claims["ath"] = s.calculateAccessTokenHash(accessToken[0])
	}

	// Create token
	token := jwt.NewWithClaims(s.getSigningMethod(keyPair.Algorithm), claims)

	// Set header
	token.Header["typ"] = "dpop+jwt"
	token.Header["jwk"] = keyPair.JWK

	// Sign token
	return token.SignedString(keyPair.PrivateKey)
}

// BindAccessTokenToDPoP binds an access token to a DPoP key
func (s *DPoPService) BindAccessTokenToDPoP(accessToken string, dpopProof *DPoPProof) error {
	// Calculate JWK thumbprint
	thumbprint, err := s.calculateJWKThumbprint(dpopProof.Header.JWK)
	if err != nil {
		return fmt.Errorf("failed to calculate JWK thumbprint: %w", err)
	}

	// Store binding in cache/database
	key := fmt.Sprintf("dpop_binding:%s", accessToken)
	bindingData := map[string]interface{}{
		"jwk_thumbprint": thumbprint,
		"bound_at":       time.Now().Unix(),
		"jti":            dpopProof.Claims.JTI,
	}

	bindingJSON, _ := json.Marshal(bindingData)

	// Store with token TTL
	ttl := facades.Config().GetInt("oauth.access_token_ttl", 3600)
	facades.Cache().Put(key, string(bindingJSON), time.Duration(ttl)*time.Second)

	return nil
}

// ValidateTokenBinding validates that an access token is properly bound to a DPoP key
func (s *DPoPService) ValidateTokenBinding(accessToken string, dpopProof *DPoPProof) error {
	// Get binding data
	key := fmt.Sprintf("dpop_binding:%s", accessToken)
	bindingJSON := facades.Cache().Get(key)
	if bindingJSON == nil {
		return fmt.Errorf("access token is not bound to any DPoP key")
	}

	var bindingData map[string]interface{}
	if err := json.Unmarshal([]byte(bindingJSON.(string)), &bindingData); err != nil {
		return fmt.Errorf("failed to parse binding data: %w", err)
	}

	// Calculate current JWK thumbprint
	currentThumbprint, err := s.calculateJWKThumbprint(dpopProof.Header.JWK)
	if err != nil {
		return fmt.Errorf("failed to calculate current JWK thumbprint: %w", err)
	}

	// Compare thumbprints
	boundThumbprint, ok := bindingData["jwk_thumbprint"].(string)
	if !ok || boundThumbprint != currentThumbprint {
		return fmt.Errorf("access token is bound to a different DPoP key")
	}

	return nil
}

// isValidDPoPAlgorithm checks if the algorithm is supported for DPoP
func (s *DPoPService) isValidDPoPAlgorithm(alg string) bool {
	supportedAlgs := facades.Config().Get("oauth.dpop.supported_algorithms").([]string)
	for _, supported := range supportedAlgs {
		if alg == supported {
			return true
		}
	}
	return false
}

// jwkToPublicKey converts a JWK to a public key
func (s *DPoPService) jwkToPublicKey(jwk map[string]interface{}) (interface{}, error) {
	kty, ok := jwk["kty"].(string)
	if !ok {
		return nil, fmt.Errorf("missing kty in JWK")
	}

	switch kty {
	case "RSA":
		return s.jwkToRSAPublicKey(jwk)
	case "EC":
		return s.jwkToECDSAPublicKey(jwk)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", kty)
	}
}

// jwkToRSAPublicKey converts a JWK to an RSA public key
func (s *DPoPService) jwkToRSAPublicKey(jwk map[string]interface{}) (*rsa.PublicKey, error) {
	nStr, ok := jwk["n"].(string)
	if !ok {
		return nil, fmt.Errorf("missing n in RSA JWK")
	}

	eStr, ok := jwk["e"].(string)
	if !ok {
		return nil, fmt.Errorf("missing e in RSA JWK")
	}

	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode n: %w", err)
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode e: %w", err)
	}

	// Convert bytes to big integers
	n := new(big.Int)
	n.SetBytes(nBytes)

	// Convert e bytes to int (usually 65537)
	var e int
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	return &rsa.PublicKey{
		N: n,
		E: e,
	}, nil
}

// jwkToECDSAPublicKey converts a JWK to an ECDSA public key
func (s *DPoPService) jwkToECDSAPublicKey(jwk map[string]interface{}) (*ecdsa.PublicKey, error) {
	curve, ok := jwk["crv"].(string)
	if !ok {
		return nil, fmt.Errorf("missing crv in EC JWK")
	}

	xStr, ok := jwk["x"].(string)
	if !ok {
		return nil, fmt.Errorf("missing x in EC JWK")
	}

	yStr, ok := jwk["y"].(string)
	if !ok {
		return nil, fmt.Errorf("missing y in EC JWK")
	}

	// Get the curve
	var ellipticCurve elliptic.Curve
	switch curve {
	case "P-256":
		ellipticCurve = elliptic.P256()
	case "P-384":
		ellipticCurve = elliptic.P384()
	case "P-521":
		ellipticCurve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported curve: %s", curve)
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(xStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode x: %w", err)
	}

	yBytes, err := base64.RawURLEncoding.DecodeString(yStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode y: %w", err)
	}

	// Convert bytes to big integers
	x := new(big.Int)
	x.SetBytes(xBytes)

	y := new(big.Int)
	y.SetBytes(yBytes)

	return &ecdsa.PublicKey{
		Curve: ellipticCurve,
		X:     x,
		Y:     y,
	}, nil
}

// validateDPoPClaims validates the DPoP claims
func (s *DPoPService) validateDPoPClaims(claims jwt.MapClaims, httpMethod, httpURI string) error {
	// Validate JTI
	jti, ok := claims["jti"].(string)
	if !ok || jti == "" {
		return fmt.Errorf("missing or empty jti claim")
	}

	// Validate HTM
	htm, ok := claims["htm"].(string)
	if !ok || htm != httpMethod {
		return fmt.Errorf("invalid htm claim: expected %s, got %s", httpMethod, htm)
	}

	// Validate HTU
	htu, ok := claims["htu"].(string)
	if !ok {
		return fmt.Errorf("missing htu claim")
	}

	// Parse and normalize URIs
	expectedURI, err := url.Parse(httpURI)
	if err != nil {
		return fmt.Errorf("invalid expected URI: %w", err)
	}

	actualURI, err := url.Parse(htu)
	if err != nil {
		return fmt.Errorf("invalid htu claim URI: %w", err)
	}

	// Compare normalized URIs (without query parameters for security)
	if expectedURI.Scheme != actualURI.Scheme ||
		expectedURI.Host != actualURI.Host ||
		expectedURI.Path != actualURI.Path {
		return fmt.Errorf("htu claim does not match request URI")
	}

	// Validate IAT
	iat, ok := claims["iat"].(float64)
	if !ok {
		return fmt.Errorf("missing iat claim")
	}

	now := time.Now().Unix()
	maxAge := int64(facades.Config().GetInt("oauth.dpop.max_age", 60)) // 60 seconds default

	if now-int64(iat) > maxAge {
		return fmt.Errorf("DPoP proof is too old")
	}

	if int64(iat) > now+60 { // Allow 60 seconds clock skew
		return fmt.Errorf("DPoP proof is from the future")
	}

	return nil
}

// validateAccessTokenHash validates the access token hash in DPoP proof
func (s *DPoPService) validateAccessTokenHash(claims jwt.MapClaims, accessToken string) error {
	ath, ok := claims["ath"].(string)
	if !ok {
		return fmt.Errorf("missing ath claim for access token validation")
	}

	expectedHash := s.calculateAccessTokenHash(accessToken)
	if ath != expectedHash {
		return fmt.Errorf("access token hash mismatch")
	}

	return nil
}

// checkDPoPReplay checks for replay attacks using JTI
func (s *DPoPService) checkDPoPReplay(jti string) error {
	key := fmt.Sprintf("dpop_jti:%s", jti)
	if facades.Cache().Has(key) {
		return fmt.Errorf("DPoP proof replay detected")
	}
	return nil
}

// storeDPoPJTI stores a JTI to prevent replay attacks
func (s *DPoPService) storeDPoPJTI(jti string) {
	key := fmt.Sprintf("dpop_jti:%s", jti)
	maxAge := facades.Config().GetInt("oauth.dpop.max_age", 60)
	facades.Cache().Put(key, "used", time.Duration(maxAge+60)*time.Second) // Store for max_age + buffer
}

// generateJTI generates a unique identifier for DPoP proof
func (s *DPoPService) generateJTI() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return base64.RawURLEncoding.EncodeToString(bytes)
}

// calculateAccessTokenHash calculates the hash of an access token
func (s *DPoPService) calculateAccessTokenHash(accessToken string) string {
	hash := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// calculateJWKThumbprint calculates the JWK thumbprint
func (s *DPoPService) calculateJWKThumbprint(jwk map[string]interface{}) (string, error) {
	// Create canonical JWK for thumbprint calculation
	canonical := make(map[string]interface{})

	// Required fields for thumbprint calculation
	requiredFields := []string{"kty", "use", "key_ops", "alg", "kid"}

	// Add key-specific fields
	if kty, ok := jwk["kty"].(string); ok {
		canonical["kty"] = kty
		switch kty {
		case "RSA":
			if n, ok := jwk["n"]; ok {
				canonical["n"] = n
			}
			if e, ok := jwk["e"]; ok {
				canonical["e"] = e
			}
		case "EC":
			if crv, ok := jwk["crv"]; ok {
				canonical["crv"] = crv
			}
			if x, ok := jwk["x"]; ok {
				canonical["x"] = x
			}
			if y, ok := jwk["y"]; ok {
				canonical["y"] = y
			}
		}
	}

	// Add other fields if present
	for _, field := range requiredFields {
		if value, ok := jwk[field]; ok {
			canonical[field] = value
		}
	}

	// Convert to JSON and hash
	jsonBytes, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(jsonBytes)
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

// generateECDSAKeyPair generates an ECDSA key pair for DPoP
func (s *DPoPService) generateECDSAKeyPair() (*DPoPKeyPair, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// Create JWK
	jwk := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(privateKey.X.Bytes()),
		"y":   base64.RawURLEncoding.EncodeToString(privateKey.Y.Bytes()),
		"use": "sig",
	}

	return &DPoPKeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		JWK:        jwk,
		Algorithm:  "ES256",
	}, nil
}

// generateRSAKeyPair generates an RSA key pair for DPoP
func (s *DPoPService) generateRSAKeyPair() (*DPoPKeyPair, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	// Create JWK
	jwk := map[string]interface{}{
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}), // 65537
		"use": "sig",
	}

	return &DPoPKeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		JWK:        jwk,
		Algorithm:  "RS256",
	}, nil
}

// getSigningMethod returns the appropriate signing method for the algorithm
func (s *DPoPService) getSigningMethod(algorithm string) jwt.SigningMethod {
	switch algorithm {
	case "ES256":
		return jwt.SigningMethodES256
	case "RS256":
		return jwt.SigningMethodRS256
	default:
		return jwt.SigningMethodES256 // Default fallback
	}
}
