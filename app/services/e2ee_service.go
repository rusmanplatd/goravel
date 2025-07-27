package services

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/crypto/pbkdf2"

	"goravel/app/models"

	"github.com/goravel/framework/facades"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// E2EEService handles end-to-end encryption for chat messages
type E2EEService struct {
	keyStorage *SecureKeyStorage
}

// NewE2EEService creates a new E2EE service instance
func NewE2EEService() *E2EEService {
	keyStorage, err := NewSecureKeyStorage()
	if err != nil {
		facades.Log().Error("Failed to initialize secure key storage", map[string]interface{}{
			"error": err.Error(),
		})
		// Fallback to basic service without secure storage
		return &E2EEService{keyStorage: nil}
	}

	return &E2EEService{
		keyStorage: keyStorage,
	}
}

// KeyPair represents a public/private key pair
type KeyPair struct {
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

// EncryptedMessage represents an encrypted message with metadata
type EncryptedMessage struct {
	Content   string            `json:"content"`
	KeyID     string            `json:"key_id"`
	Algorithm string            `json:"algorithm"`
	Version   int               `json:"version"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	Timestamp time.Time         `json:"timestamp"`
	Signature string            `json:"signature,omitempty"`
}

// PrekeyBundle represents a bundle of keys for Perfect Forward Secrecy
type PrekeyBundle struct {
	IdentityKey    string           `json:"identity_key"`
	SignedPrekey   *SignedPrekey    `json:"signed_prekey"`
	OneTimePrekeys []*OneTimePrekey `json:"one_time_prekeys"`
	RegistrationID int              `json:"registration_id"`
	DeviceID       int              `json:"device_id"`
}

// SignedPrekey represents a signed prekey for PFS
type SignedPrekey struct {
	KeyID     int    `json:"key_id"`
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
	Timestamp int64  `json:"timestamp"`
}

// OneTimePrekey represents a one-time prekey for PFS
type OneTimePrekey struct {
	KeyID     int    `json:"key_id"`
	PublicKey string `json:"public_key"`
}

// EncryptedFile represents an encrypted file with metadata
type EncryptedFile struct {
	ID            string            `json:"id"`
	FileName      string            `json:"file_name"`
	FileSize      int64             `json:"file_size"`
	MimeType      string            `json:"mime_type"`
	EncryptedData string            `json:"encrypted_data"`
	KeyID         string            `json:"key_id"`
	Algorithm     string            `json:"algorithm"`
	Version       int               `json:"version"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	Timestamp     time.Time         `json:"timestamp"`
	Signature     string            `json:"signature,omitempty"`
}

// RoomKey represents a decrypted room key for group chat encryption
type RoomKey struct {
	KeyID   string `json:"key_id"`
	RoomID  string `json:"room_id"`
	Key     []byte `json:"key"`
	Version int    `json:"version"`
}

// SearchableMessage represents a message with searchable encrypted content
type SearchableMessage struct {
	MessageID   string    `json:"message_id"`
	RoomID      string    `json:"room_id"`
	SenderID    string    `json:"sender_id"`
	SearchHash  string    `json:"search_hash"`
	ContentHash string    `json:"content_hash"`
	Timestamp   time.Time `json:"timestamp"`
	MatchScore  float64   `json:"match_score,omitempty"` // Relevance score for search results
}

// SecureKeyStorage provides secure storage for encryption keys
type SecureKeyStorage struct {
	masterKey []byte
}

// NewSecureKeyStorage creates a new secure key storage instance
func NewSecureKeyStorage() (*SecureKeyStorage, error) {
	// Get master key from environment or generate one
	masterKeyEnv := facades.Config().GetString("app.master_key", "")
	var masterKey []byte

	if masterKeyEnv != "" {
		// Use provided master key
		var err error
		masterKey, err = base64.StdEncoding.DecodeString(masterKeyEnv)
		if err != nil {
			return nil, fmt.Errorf("invalid master key format: %v", err)
		}
		if len(masterKey) != 32 {
			return nil, fmt.Errorf("master key must be 32 bytes (256 bits)")
		}
	} else {
		// Generate a new master key (for development only)
		facades.Log().Warning("No master key found in environment, generating temporary key", nil)
		masterKey = make([]byte, 32)
		if _, err := rand.Read(masterKey); err != nil {
			return nil, fmt.Errorf("failed to generate master key: %v", err)
		}

		// Log the generated key for development (remove TODO: In production)
		encodedKey := base64.StdEncoding.EncodeToString(masterKey)
		facades.Log().Info("Generated master key (store this in APP_MASTER_KEY environment variable)", map[string]interface{}{
			"master_key": encodedKey,
		})
	}

	return &SecureKeyStorage{
		masterKey: masterKey,
	}, nil
}

// EncryptForStorage encrypts data for secure storage
func (s *SecureKeyStorage) EncryptForStorage(data []byte) (string, error) {
	// Generate a random nonce
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %v", err)
	}

	// Encrypt with AES-256-GCM
	block, err := aes.NewCipher(s.masterKey)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %v", err)
	}

	ciphertext := aesGCM.Seal(nil, nonce, data, nil)

	// Combine nonce and ciphertext
	encryptedData := append(nonce, ciphertext...)
	return base64.StdEncoding.EncodeToString(encryptedData), nil
}

// DecryptFromStorage decrypts data from secure storage
func (s *SecureKeyStorage) DecryptFromStorage(encryptedData string) ([]byte, error) {
	// Decode base64
	data, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted data: %v", err)
	}

	// Extract nonce and ciphertext
	if len(data) < 12 {
		return nil, fmt.Errorf("invalid encrypted data: too short")
	}
	nonce := data[:12]
	ciphertext := data[12:]

	// Decrypt with AES-256-GCM
	block, err := aes.NewCipher(s.masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %v", err)
	}

	return plaintext, nil
}

// GenerateKeyPair generates a new RSA key pair for a user
func (s *E2EEService) GenerateKeyPair() (*KeyPair, error) {
	s.recordKeyGeneration()

	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		s.recordError()
		return nil, fmt.Errorf("failed to generate RSA key pair: %v", err)
	}

	// Encode private key
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	privateKeyStr := string(pem.EncodeToMemory(privateKeyPEM))

	// Encode public key
	publicKeyPEM := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&privateKey.PublicKey),
	}
	publicKeyStr := string(pem.EncodeToMemory(publicKeyPEM))

	return &KeyPair{
		PublicKey:  publicKeyStr,
		PrivateKey: privateKeyStr,
	}, nil
}

// EncryptMessage encrypts a message using AES-256-GCM with a random key
func (s *E2EEService) EncryptMessage(message string, recipientPublicKeys []string) (*EncryptedMessage, error) {
	startTime := time.Now()
	defer func() {
		duration := time.Since(startTime)
		s.recordEncryption(duration)
	}()

	// Security audit log
	facades.Log().Info("E2EE message encryption initiated", map[string]interface{}{
		"recipients_count": len(recipientPublicKeys),
		"message_size":     len(message),
		"timestamp":        time.Now().Unix(),
	})

	// Input validation
	if len(message) == 0 {
		s.recordError()
		facades.Log().Warning("E2EE encryption failed: empty message", map[string]interface{}{
			"error": "message cannot be empty",
		})
		return nil, fmt.Errorf("message cannot be empty")
	}
	if len(message) > 64*1024 { // 64KB limit
		s.recordError()
		facades.Log().Warning("E2EE encryption failed: message too large", map[string]interface{}{
			"message_size": len(message),
			"max_size":     64 * 1024,
		})
		return nil, fmt.Errorf("message too large: maximum size is 64KB")
	}
	if len(recipientPublicKeys) == 0 {
		facades.Log().Warning("E2EE encryption failed: no recipients", map[string]interface{}{
			"error": "no recipients provided",
		})
		return nil, fmt.Errorf("at least one recipient public key is required")
	}
	if len(recipientPublicKeys) > 100 { // Reasonable limit
		facades.Log().Warning("E2EE encryption failed: too many recipients", map[string]interface{}{
			"recipients_count": len(recipientPublicKeys),
			"max_recipients":   100,
		})
		return nil, fmt.Errorf("too many recipients: maximum is 100")
	}

	// Validate all public keys before proceeding
	for i, publicKeyStr := range recipientPublicKeys {
		if len(strings.TrimSpace(publicKeyStr)) == 0 {
			facades.Log().Warning("E2EE encryption failed: empty public key", map[string]interface{}{
				"recipient_index": i,
			})
			return nil, fmt.Errorf("recipient public key %d is empty", i)
		}
		// Validate key format
		if err := s.ValidatePublicKey(publicKeyStr); err != nil {
			facades.Log().Warning("E2EE encryption failed: invalid public key", map[string]interface{}{
				"recipient_index": i,
				"error":           err.Error(),
			})
			return nil, fmt.Errorf("invalid public key for recipient %d: %v", i, err)
		}
	}

	// Generate a random AES key
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return nil, fmt.Errorf("failed to generate AES key: %v", err)
	}

	// Generate a random nonce
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	// Encrypt the message with AES-256-GCM
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	ciphertext := aesGCM.Seal(nil, nonce, []byte(message), nil)

	// Combine nonce and ciphertext
	encryptedData := append(nonce, ciphertext...)
	encryptedContent := base64.StdEncoding.EncodeToString(encryptedData)

	// Encrypt the AES key for each recipient
	encryptedKeys := make(map[string]string)
	successfulEncryptions := 0

	for i, publicKeyStr := range recipientPublicKeys {
		encryptedKey, err := s.encryptAESKeyWithRSA(aesKey, publicKeyStr)
		if err != nil {
			facades.Log().Error("Failed to encrypt AES key for recipient", map[string]interface{}{
				"recipient_index": i,
				"error":           err.Error(),
			})
			continue
		}
		encryptedKeys[fmt.Sprintf("recipient_%d", i)] = encryptedKey
		successfulEncryptions++
	}

	if successfulEncryptions == 0 {
		facades.Log().Error("E2EE encryption failed: no successful recipient encryptions", map[string]interface{}{
			"total_recipients": len(recipientPublicKeys),
		})
		return nil, fmt.Errorf("failed to encrypt message for any recipient")
	}

	// Create encrypted message
	encryptedMsg := &EncryptedMessage{
		Content:   encryptedContent,
		Algorithm: "AES-256-GCM",
		Version:   1,
		Metadata:  encryptedKeys,
		Timestamp: time.Now(),
	}

	// Add message authentication (HMAC signature)
	signature, err := s.generateMessageSignature(encryptedMsg, aesKey)
	if err != nil {
		facades.Log().Error("E2EE signature generation failed", map[string]interface{}{
			"error": err.Error(),
		})
		return nil, fmt.Errorf("failed to generate message signature: %v", err)
	}
	encryptedMsg.Signature = signature

	// Security audit log for successful encryption
	facades.Log().Info("E2EE message encryption completed successfully", map[string]interface{}{
		"successful_recipients": successfulEncryptions,
		"total_recipients":      len(recipientPublicKeys),
		"has_signature":         encryptedMsg.Signature != "",
		"algorithm":             encryptedMsg.Algorithm,
		"version":               encryptedMsg.Version,
	})

	return encryptedMsg, nil
}

// DecryptMessage decrypts a message using the user's private key
func (s *E2EEService) DecryptMessage(encryptedMsg *EncryptedMessage, userPrivateKey string) (string, error) {
	startTime := time.Now()
	defer func() {
		duration := time.Since(startTime)
		s.recordDecryption(duration)
	}()

	// Security audit log
	facades.Log().Info("E2EE message decryption initiated", map[string]interface{}{
		"algorithm":     encryptedMsg.Algorithm,
		"version":       encryptedMsg.Version,
		"has_signature": encryptedMsg.Signature != "",
		"timestamp":     time.Now().Unix(),
	})

	// Decode the encrypted content
	encryptedData, err := base64.StdEncoding.DecodeString(encryptedMsg.Content)
	if err != nil {
		facades.Log().Warning("E2EE decryption failed: invalid base64 content", map[string]interface{}{
			"error": err.Error(),
		})
		return "", fmt.Errorf("failed to decode encrypted content: %v", err)
	}

	// Extract nonce and ciphertext
	if len(encryptedData) < 12 {
		facades.Log().Warning("E2EE decryption failed: invalid data length", map[string]interface{}{
			"data_length": len(encryptedData),
			"min_length":  12,
		})
		return "", fmt.Errorf("invalid encrypted data length")
	}
	nonce := encryptedData[:12]
	ciphertext := encryptedData[12:]

	// Find the encrypted AES key for this user
	// Try all encrypted keys until one works with this user's private key
	var aesKey []byte
	var decryptionError error

	for _, encryptedKey := range encryptedMsg.Metadata {
		aesKey, decryptionError = s.decryptAESKeyWithRSA(encryptedKey, userPrivateKey)
		if decryptionError == nil {
			// Successfully decrypted with this key
			break
		}
	}

	if decryptionError != nil {
		facades.Log().Warning("E2EE decryption failed: no valid encrypted key found", map[string]interface{}{
			"available_keys": len(encryptedMsg.Metadata),
			"error":          decryptionError.Error(),
		})
		return "", fmt.Errorf("failed to decrypt AES key with any available encrypted keys: %v", decryptionError)
	}

	// Verify message signature if present
	if encryptedMsg.Signature != "" {
		if err := s.verifyMessageSignature(encryptedMsg, aesKey, encryptedMsg.Signature); err != nil {
			facades.Log().Error("E2EE message integrity verification failed", map[string]interface{}{
				"error": err.Error(),
			})
			return "", fmt.Errorf("message integrity verification failed: %v", err)
		}
		facades.Log().Info("E2EE message signature verified successfully", nil)
	}

	// Decrypt the message
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %v", err)
	}

	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		facades.Log().Error("E2EE decryption failed: GCM decryption error", map[string]interface{}{
			"error": err.Error(),
		})
		return "", fmt.Errorf("failed to decrypt message: %v", err)
	}

	// Security audit log for successful decryption
	facades.Log().Info("E2EE message decryption completed successfully", map[string]interface{}{
		"message_length": len(plaintext),
		"algorithm":      encryptedMsg.Algorithm,
		"version":        encryptedMsg.Version,
	})

	return string(plaintext), nil
}

// EncryptFile encrypts a file using AES-256-GCM
func (s *E2EEService) EncryptFile(fileData []byte, fileName, mimeType string, recipientPublicKeys []string) (*EncryptedFile, error) {
	// Generate a random AES key
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return nil, fmt.Errorf("failed to generate AES key: %v", err)
	}

	// Generate a random nonce
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	// Encrypt the file data with AES-256-GCM
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	ciphertext := aesGCM.Seal(nil, nonce, fileData, nil)

	// Combine nonce and ciphertext
	encryptedData := append(nonce, ciphertext...)
	encryptedDataStr := base64.StdEncoding.EncodeToString(encryptedData)

	// Encrypt the AES key for each recipient
	encryptedKeys := make(map[string]string)
	for i, publicKeyStr := range recipientPublicKeys {
		encryptedKey, err := s.encryptAESKeyWithRSA(aesKey, publicKeyStr)
		if err != nil {
			facades.Log().Error("Failed to encrypt AES key for recipient", map[string]interface{}{
				"recipient_index": i,
				"error":           err.Error(),
			})
			continue
		}
		encryptedKeys[fmt.Sprintf("recipient_%d", i)] = encryptedKey
	}

	// Generate file ID
	fileID := s.generateFileID()

	// Create encrypted file
	encryptedFile := &EncryptedFile{
		ID:            fileID,
		FileName:      fileName,
		FileSize:      int64(len(fileData)),
		MimeType:      mimeType,
		EncryptedData: encryptedDataStr,
		Algorithm:     "AES-256-GCM",
		Version:       1,
		Metadata:      encryptedKeys,
		Timestamp:     time.Now(),
	}

	// Add message authentication (HMAC signature)
	signature, err := s.generateMessageSignature(encryptedFile, aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate file signature: %v", err)
	}
	encryptedFile.Signature = signature

	return encryptedFile, nil
}

// DecryptFile decrypts a file using the user's private key
func (s *E2EEService) DecryptFile(encryptedFile *EncryptedFile, userPrivateKey string) ([]byte, error) {
	// Decode the encrypted data
	encryptedData, err := base64.StdEncoding.DecodeString(encryptedFile.EncryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted data: %v", err)
	}

	// Extract nonce and ciphertext
	if len(encryptedData) < 12 {
		return nil, fmt.Errorf("invalid encrypted data length")
	}
	nonce := encryptedData[:12]
	ciphertext := encryptedData[12:]

	// Find the encrypted AES key for this user
	var encryptedAESKey string
	for _, encryptedKey := range encryptedFile.Metadata {
		encryptedAESKey = encryptedKey
		break // For simplicity, we'll use the first key
	}

	if encryptedAESKey == "" {
		return nil, fmt.Errorf("no encrypted AES key found")
	}

	// Decrypt the AES key using RSA
	aesKey, err := s.decryptAESKeyWithRSA(encryptedAESKey, userPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt AES key: %v", err)
	}

	// Decrypt the file data
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt file: %v", err)
	}

	return plaintext, nil
}

// encryptAESKeyWithRSA encrypts an AES key using RSA public key
func (s *E2EEService) encryptAESKeyWithRSA(aesKey []byte, publicKeyStr string) (string, error) {
	// Decode public key
	block, _ := pem.Decode([]byte(publicKeyStr))
	if block == nil {
		return "", fmt.Errorf("failed to decode public key")
	}

	publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse public key: %v", err)
	}

	// Encrypt AES key with RSA
	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, aesKey, nil)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt AES key: %v", err)
	}

	return base64.StdEncoding.EncodeToString(encryptedKey), nil
}

// decryptAESKeyWithRSA decrypts an AES key using RSA private key
func (s *E2EEService) decryptAESKeyWithRSA(encryptedKeyStr string, privateKeyStr string) ([]byte, error) {
	// Decode encrypted key
	encryptedKey, err := base64.StdEncoding.DecodeString(encryptedKeyStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted key: %v", err)
	}

	// Decode private key
	block, _ := pem.Decode([]byte(privateKeyStr))
	if block == nil {
		return nil, fmt.Errorf("failed to decode private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	// Decrypt AES key with RSA
	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, encryptedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt AES key: %v", err)
	}

	return aesKey, nil
}

// EncryptPrivateKey encrypts a private key with a passphrase for secure storage
func (s *E2EEService) EncryptPrivateKey(privateKeyPEM string, passphrase string) (string, error) {
	// Generate a random salt
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %v", err)
	}

	// Derive key from passphrase using PBKDF2
	key := s.deriveKeyFromPassphrase(passphrase, salt, 100000) // 100k iterations

	// Generate a random nonce
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %v", err)
	}

	// Encrypt the private key with AES-256-GCM
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %v", err)
	}

	ciphertext := aesGCM.Seal(nil, nonce, []byte(privateKeyPEM), nil)

	// Combine salt, nonce, and ciphertext
	encryptedData := append(salt, append(nonce, ciphertext...)...)
	return base64.StdEncoding.EncodeToString(encryptedData), nil
}

// DecryptPrivateKey decrypts a private key using a passphrase
func (s *E2EEService) DecryptPrivateKey(encryptedPrivateKey string, passphrase string) (string, error) {
	// Decode the encrypted data
	encryptedData, err := base64.StdEncoding.DecodeString(encryptedPrivateKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode encrypted private key: %v", err)
	}

	// Extract salt (first 16 bytes)
	if len(encryptedData) < 16 {
		return "", fmt.Errorf("invalid encrypted data: too short")
	}
	salt := encryptedData[:16]

	// Extract nonce (next 12 bytes)
	if len(encryptedData) < 28 {
		return "", fmt.Errorf("invalid encrypted data: missing nonce")
	}
	nonce := encryptedData[16:28]

	// Extract ciphertext (remaining bytes)
	ciphertext := encryptedData[28:]

	// Derive key from passphrase
	key := s.deriveKeyFromPassphrase(passphrase, salt, 100000)

	// Decrypt the private key
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %v", err)
	}

	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt private key: %v", err)
	}

	return string(plaintext), nil
}

// deriveKeyFromPassphrase derives a key from a passphrase using PBKDF2
func (s *E2EEService) deriveKeyFromPassphrase(passphrase string, salt []byte, iterations int) []byte {
	// Use proper PBKDF2 with SHA-256
	return pbkdf2.Key([]byte(passphrase), salt, iterations, 32, sha256.New)
}

// GenerateRoomKey generates a new room key for group chats
func (s *E2EEService) GenerateRoomKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate room key: %v", err)
	}
	return key, nil
}

// EncryptRoomKey encrypts a room key for a specific user
func (s *E2EEService) EncryptRoomKey(roomKey []byte, userPublicKey string) (string, error) {
	return s.encryptAESKeyWithRSA(roomKey, userPublicKey)
}

// DecryptRoomKey decrypts a room key using user's private key
func (s *E2EEService) DecryptRoomKey(encryptedRoomKey string, userPrivateKey string) ([]byte, error) {
	return s.decryptAESKeyWithRSA(encryptedRoomKey, userPrivateKey)
}

// EncryptWithRoomKey encrypts a message using a room key
func (s *E2EEService) EncryptWithRoomKey(message string, roomKey []byte) (string, error) {
	// Use ChaCha20-Poly1305 for room key encryption
	aead, err := chacha20poly1305.New(roomKey)
	if err != nil {
		return "", fmt.Errorf("failed to create AEAD: %v", err)
	}

	// Generate nonce
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %v", err)
	}

	// Encrypt message
	ciphertext := aead.Seal(nil, nonce, []byte(message), nil)

	// Combine nonce and ciphertext
	encryptedData := append(nonce, ciphertext...)
	return base64.StdEncoding.EncodeToString(encryptedData), nil
}

// DecryptWithRoomKey decrypts a message using a room key
func (s *E2EEService) DecryptWithRoomKey(encryptedMessage string, roomKey []byte) (string, error) {
	// Decode encrypted data
	encryptedData, err := base64.StdEncoding.DecodeString(encryptedMessage)
	if err != nil {
		return "", fmt.Errorf("failed to decode encrypted message: %v", err)
	}

	// Use ChaCha20-Poly1305 for room key decryption
	aead, err := chacha20poly1305.New(roomKey)
	if err != nil {
		return "", fmt.Errorf("failed to create AEAD: %v", err)
	}

	// Extract nonce and ciphertext
	if len(encryptedData) < aead.NonceSize() {
		return "", fmt.Errorf("invalid encrypted data length")
	}
	nonce := encryptedData[:aead.NonceSize()]
	ciphertext := encryptedData[aead.NonceSize():]

	// Decrypt message
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt message: %v", err)
	}

	return string(plaintext), nil
}

// SignMessage signs a message with user's private key
func (s *E2EEService) SignMessage(message string, privateKeyStr string) (string, error) {
	// Decode private key
	block, _ := pem.Decode([]byte(privateKeyStr))
	if block == nil {
		return "", fmt.Errorf("failed to decode private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %v", err)
	}

	// Create message hash
	hash := sha256.Sum256([]byte(message))

	// Sign the hash
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign message: %v", err)
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}

// VerifySignature verifies a message signature with user's public key
func (s *E2EEService) VerifySignature(message string, signature string, publicKeyStr string) (bool, error) {
	// Decode signature
	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, fmt.Errorf("failed to decode signature: %v", err)
	}

	// Decode public key
	block, _ := pem.Decode([]byte(publicKeyStr))
	if block == nil {
		return false, fmt.Errorf("failed to decode public key")
	}

	publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("failed to parse public key: %v", err)
	}

	// Create message hash
	hash := sha256.Sum256([]byte(message))

	// Verify signature
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], sigBytes)
	if err != nil {
		return false, nil
	}

	return true, nil
}

// GetUserKeys retrieves all keys for a user
func (s *E2EEService) GetUserKeys(userID string) ([]models.UserKey, error) {
	var keys []models.UserKey
	err := facades.Orm().Query().Where("user_id", userID).Where("is_active", true).Find(&keys)
	return keys, err
}

// GetRoomKeys retrieves all keys for a chat room
func (s *E2EEService) GetRoomKeys(roomID string) ([]models.ChatRoomKey, error) {
	var keys []models.ChatRoomKey
	err := facades.Orm().Query().Where("chat_room_id", roomID).Where("is_active", true).Find(&keys)
	return keys, err
}

// SaveUserKey saves a user key to the database
func (s *E2EEService) SaveUserKey(userKey *models.UserKey) error {
	return facades.Orm().Query().Create(userKey)
}

// SaveRoomKey saves a room key to the database
func (s *E2EEService) SaveRoomKey(roomKey *models.ChatRoomKey) error {
	return facades.Orm().Query().Create(roomKey)
}

// RotateRoomKey rotates the encryption key for a chat room
func (s *E2EEService) RotateRoomKey(roomID string) error {
	s.recordKeyRotation()

	// Start transaction for atomic key rotation
	tx, err := facades.Orm().Query().Begin()
	if err != nil {
		s.recordError()
		return fmt.Errorf("failed to start transaction: %v", err)
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Get current active key version
	var currentKey models.ChatRoomKey
	err = tx.Where("chat_room_id", roomID).
		Where("is_active", true).
		Where("key_type", "room_key").
		First(&currentKey)

	nextVersion := 1
	if err == nil {
		nextVersion = currentKey.Version + 1
	}

	// Generate new room key
	newRoomKey, err := s.GenerateRoomKey()
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to generate new room key: %v", err)
	}

	// Get room members with their public keys
	var members []models.ChatRoomMember
	err = tx.Where("chat_room_id", roomID).
		Where("is_active", true).
		Find(&members)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to get room members: %v", err)
	}

	if len(members) == 0 {
		tx.Rollback()
		return fmt.Errorf("no active members found for room")
	}

	// Deactivate old keys (keep them for decrypting old messages)
	_, err = tx.Model(&models.ChatRoomKey{}).
		Where("chat_room_id", roomID).
		Where("is_active", true).
		Update("is_active", false)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to deactivate old keys: %v", err)
	}

	// Encrypt new room key for each member
	now := time.Now()
	successfulKeys := 0

	for _, member := range members {
		if member.PublicKey == "" {
			facades.Log().Warning("Member has no public key, skipping", map[string]interface{}{
				"member_id": member.UserID,
				"room_id":   roomID,
			})
			continue
		}

		// Encrypt room key for this member
		encryptedKey, err := s.EncryptRoomKey(newRoomKey, member.PublicKey)
		if err != nil {
			facades.Log().Error("Failed to encrypt room key for member", map[string]interface{}{
				"member_id": member.UserID,
				"room_id":   roomID,
				"error":     err.Error(),
			})
			continue
		}

		// Create new room key record for this member
		roomKey := &models.ChatRoomKey{
			ChatRoomID:   roomID,
			KeyType:      "room_key",
			EncryptedKey: encryptedKey,
			Version:      nextVersion,
			IsActive:     true,
			RotatedAt:    &now,
		}

		err = tx.Create(roomKey)
		if err != nil {
			facades.Log().Error("Failed to save room key for member", map[string]interface{}{
				"member_id": member.UserID,
				"room_id":   roomID,
				"error":     err.Error(),
			})
			continue
		}

		successfulKeys++
	}

	if successfulKeys == 0 {
		tx.Rollback()
		return fmt.Errorf("failed to create new room key for any member")
	}

	// Commit transaction
	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("failed to commit key rotation transaction: %v", err)
	}

	facades.Log().Info("Room key rotated successfully", map[string]interface{}{
		"room_id":         roomID,
		"new_version":     nextVersion,
		"members_updated": successfulKeys,
	})

	return nil
}

// GeneratePrekeyBundle generates a complete prekey bundle for PFS
func (s *E2EEService) GeneratePrekeyBundle(userID string, deviceID int) (*PrekeyBundle, error) {
	facades.Log().Info("Generating prekey bundle for PFS", map[string]interface{}{
		"user_id":   userID,
		"device_id": deviceID,
	})

	// Generate identity key
	identityKeyPair, err := s.GenerateKeyPair()
	if err != nil {
		facades.Log().Error("Failed to generate identity key for prekey bundle", map[string]interface{}{
			"user_id": userID,
			"error":   err.Error(),
		})
		return nil, fmt.Errorf("failed to generate identity key: %v", err)
	}

	// Generate signed prekey
	signedPrekey, err := s.GenerateSignedPrekey(identityKeyPair.PrivateKey)
	if err != nil {
		facades.Log().Error("Failed to generate signed prekey", map[string]interface{}{
			"user_id": userID,
			"error":   err.Error(),
		})
		return nil, fmt.Errorf("failed to generate signed prekey: %v", err)
	}

	// Generate one-time prekeys (100 keys for better forward secrecy)
	oneTimePrekeys := make([]*OneTimePrekey, 0, 100)
	for i := 0; i < 100; i++ {
		prekey, err := s.GenerateOneTimePrekey()
		if err != nil {
			facades.Log().Warning("Failed to generate one-time prekey", map[string]interface{}{
				"user_id": userID,
				"index":   i,
				"error":   err.Error(),
			})
			continue
		}
		oneTimePrekeys = append(oneTimePrekeys, prekey)
	}

	if len(oneTimePrekeys) < 50 {
		facades.Log().Error("Insufficient one-time prekeys generated", map[string]interface{}{
			"user_id":   userID,
			"generated": len(oneTimePrekeys),
			"minimum":   50,
		})
		return nil, fmt.Errorf("failed to generate sufficient one-time prekeys")
	}

	// Generate registration ID
	registrationID := s.generateRegistrationID()

	bundle := &PrekeyBundle{
		IdentityKey:    identityKeyPair.PublicKey,
		SignedPrekey:   signedPrekey,
		OneTimePrekeys: oneTimePrekeys,
		RegistrationID: registrationID,
		DeviceID:       deviceID,
	}

	// TODO: Implement StorePrekeyBundle method
	// Store the prekey bundle in database
	// if err := s.StorePrekeyBundle(userID, bundle, identityKeyPair.PrivateKey); err != nil {
	//	facades.Log().Error("Failed to store prekey bundle", map[string]interface{}{
	//		"user_id": userID,
	//		"error":   err.Error(),
	//	})
	//	return nil, fmt.Errorf("failed to store prekey bundle: %v", err)
	// }

	facades.Log().Info("Prekey bundle generated successfully", map[string]interface{}{
		"user_id":          userID,
		"device_id":        deviceID,
		"registration_id":  registrationID,
		"one_time_prekeys": len(oneTimePrekeys),
	})

	return bundle, nil
}

// GenerateSignedPrekey generates a signed prekey for PFS
func (s *E2EEService) GenerateSignedPrekey(identityPrivateKey string) (*SignedPrekey, error) {
	// Generate a new key pair for the signed prekey
	prekeyPair, err := s.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate prekey pair: %v", err)
	}

	// Create signature data
	timestamp := time.Now().Unix()
	keyID := s.generateKeyID()
	signatureData := fmt.Sprintf("%d|%s|%d", keyID, prekeyPair.PublicKey, timestamp)

	// Sign with identity private key
	signature, err := s.SignMessage(signatureData, identityPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign prekey: %v", err)
	}

	return &SignedPrekey{
		KeyID:     keyID,
		PublicKey: prekeyPair.PublicKey,
		Signature: signature,
		Timestamp: timestamp,
	}, nil
}

// GenerateOneTimePrekey generates a one-time prekey for PFS
func (s *E2EEService) GenerateOneTimePrekey() (*OneTimePrekey, error) {
	// Generate a new key pair
	prekeyPair, err := s.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate one-time prekey pair: %v", err)
	}

	return &OneTimePrekey{
		KeyID:     s.generateKeyID(),
		PublicKey: prekeyPair.PublicKey,
	}, nil
}

// generateKeyID generates a unique key ID
func (s *E2EEService) generateKeyID() int {
	// Generate a random key ID (TODO: In production, use a proper ID generation strategy)
	keyIDBytes := make([]byte, 4)
	rand.Read(keyIDBytes)
	return int(keyIDBytes[0])<<24 | int(keyIDBytes[1])<<16 | int(keyIDBytes[2])<<8 | int(keyIDBytes[3])
}

// generateRegistrationID generates a unique registration ID
func (s *E2EEService) generateRegistrationID() int {
	// Generate a random registration ID
	regIDBytes := make([]byte, 4)
	rand.Read(regIDBytes)
	return int(regIDBytes[0])<<24 | int(regIDBytes[1])<<16 | int(regIDBytes[2])<<8 | int(regIDBytes[3])
}

// generateFileID generates a unique file ID
func (s *E2EEService) generateFileID() string {
	// Generate a random 16-byte ID
	fileIDBytes := make([]byte, 16)
	rand.Read(fileIDBytes)
	return base64.StdEncoding.EncodeToString(fileIDBytes)
}

// GenerateSearchHash generates a searchable hash for encrypted content
func (s *E2EEService) GenerateSearchHash(encryptedContent string, searchTerms []string) (string, error) {
	// Create a deterministic hash from encrypted content and search terms
	hashInput := encryptedContent
	for _, term := range searchTerms {
		hashInput += "|" + term
	}

	// Generate SHA-256 hash
	hash := sha256.Sum256([]byte(hashInput))
	return base64.StdEncoding.EncodeToString(hash[:]), nil
}

// GenerateContentHash generates a hash of the encrypted content
func (s *E2EEService) GenerateContentHash(encryptedContent string) string {
	hash := sha256.Sum256([]byte(encryptedContent))
	return base64.StdEncoding.EncodeToString(hash[:])
}

// SearchMessages searches for messages using enhanced encrypted search
func (s *E2EEService) SearchMessages(userID string, searchTerms []string, roomIDs []string) ([]SearchableMessage, error) {
	// Enhanced encrypted search using searchable symmetric encryption (SSE) concepts
	// This implementation provides better security while maintaining search functionality

	// Input validation
	if userID == "" {
		return nil, fmt.Errorf("user ID cannot be empty")
	}
	if len(searchTerms) == 0 {
		return nil, fmt.Errorf("search terms cannot be empty")
	}
	if len(searchTerms) > 10 {
		return nil, fmt.Errorf("too many search terms (max 10)")
	}

	// Sanitize and validate search terms
	var validTerms []string
	for _, term := range searchTerms {
		term = strings.TrimSpace(strings.ToLower(term))
		if len(term) >= 2 && len(term) <= 100 {
			validTerms = append(validTerms, term)
		}
	}
	if len(validTerms) == 0 {
		return nil, fmt.Errorf("no valid search terms provided")
	}

	// Check cache for recent search results
	cacheKey := s.generateSearchCacheKey(userID, validTerms, roomIDs)
	var cachedResults []SearchableMessage
	if err := facades.Cache().Get(cacheKey, &cachedResults); err == nil {
		facades.Log().Debug("Returning cached search results", map[string]interface{}{
			"user_id":      userID,
			"cache_key":    cacheKey,
			"result_count": len(cachedResults),
		})
		return cachedResults, nil
	}

	// Step 1: Generate search tokens for the query terms
	searchTokens, err := s.generateSearchTokens(userID, validTerms)
	if err != nil {
		return nil, fmt.Errorf("failed to generate search tokens: %w", err)
	}

	// Step 2: Query messages that the user has access to with optimized query
	messages, err := s.getSearchableMessages(userID, roomIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to query messages: %w", err)
	}

	// Step 3: Build search index for matching (with caching)
	searchIndex, err := s.buildSearchIndexCached(messages, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to build search index: %w", err)
	}

	// Step 4: Perform encrypted search matching
	matchingMessages := s.performEncryptedSearch(searchIndex, searchTokens)

	// Cache results for 5 minutes
	facades.Cache().Put(cacheKey, matchingMessages, 5*time.Minute)

	facades.Log().Info("Encrypted search completed", map[string]interface{}{
		"user_id":           userID,
		"search_terms":      len(validTerms),
		"total_messages":    len(messages),
		"matching_messages": len(matchingMessages),
		"cache_key":         cacheKey,
	})

	return matchingMessages, nil
}

// generateSearchCacheKey creates a cache key for search results
func (s *E2EEService) generateSearchCacheKey(userID string, searchTerms []string, roomIDs []string) string {
	// Create a deterministic cache key
	keyData := fmt.Sprintf("search:%s:%s:%s", userID, strings.Join(searchTerms, ","), strings.Join(roomIDs, ","))
	hash := sha256.Sum256([]byte(keyData))
	return fmt.Sprintf("e2ee_search:%s", base64.URLEncoding.EncodeToString(hash[:16]))
}

// getSearchableMessages retrieves messages with optimized query
func (s *E2EEService) getSearchableMessages(userID string, roomIDs []string) ([]models.ChatMessage, error) {
	var messages []models.ChatMessage
	query := facades.Orm().Query().Select("id", "chat_room_id", "sender_id", "encrypted_content", "created_at")

	// Optimize query based on room access
	if len(roomIDs) > 0 {
		// Search in specific rooms where user is a member
		query = query.Where("chat_room_id IN ? AND (sender_id = ? OR chat_room_id IN (SELECT chat_room_id FROM chat_room_members WHERE user_id = ?))",
			roomIDs, userID, userID)
	} else {
		// Search all messages user has access to
		query = query.Where("sender_id = ? OR chat_room_id IN (SELECT chat_room_id FROM chat_room_members WHERE user_id = ?)",
			userID, userID)
	}

	// Add time-based filtering for performance (last 30 days by default)
	thirtyDaysAgo := time.Now().AddDate(0, 0, -30)
	query = query.Where("created_at > ?", thirtyDaysAgo)

	err := query.Order("created_at DESC").Limit(1000).Find(&messages) // Limit for performance
	if err != nil {
		return nil, fmt.Errorf("failed to query messages: %w", err)
	}

	return messages, nil
}

// buildSearchIndexCached builds search index with caching
func (s *E2EEService) buildSearchIndexCached(messages []models.ChatMessage, userID string) ([]SearchIndexEntry, error) {
	var index []SearchIndexEntry

	// Get user's search key (cached)
	searchKey, err := s.getUserSearchKeyCached(userID)
	if err != nil {
		return nil, err
	}

	// Process messages in batches for better performance
	batchSize := 100
	for i := 0; i < len(messages); i += batchSize {
		end := i + batchSize
		if end > len(messages) {
			end = len(messages)
		}

		batch := messages[i:end]
		batchIndex, err := s.processBatch(batch, userID, searchKey)
		if err != nil {
			facades.Log().Warning("Failed to process message batch", map[string]interface{}{
				"user_id":     userID,
				"batch_start": i,
				"batch_end":   end,
				"error":       err.Error(),
			})
			continue
		}

		index = append(index, batchIndex...)
	}

	return index, nil
}

// getUserSearchKeyCached gets user search key with caching
func (s *E2EEService) getUserSearchKeyCached(userID string) ([]byte, error) {
	cacheKey := fmt.Sprintf("user_search_key:%s", userID)

	var cachedKey []byte
	if err := facades.Cache().Get(cacheKey, &cachedKey); err == nil {
		return cachedKey, nil
	}

	// Generate key if not cached
	searchKey, err := s.getUserSearchKey(userID)
	if err != nil {
		return nil, err
	}

	// Cache for 1 hour
	facades.Cache().Put(cacheKey, searchKey, time.Hour)

	return searchKey, nil
}

// processBatch processes a batch of messages for indexing
func (s *E2EEService) processBatch(messages []models.ChatMessage, userID string, searchKey []byte) ([]SearchIndexEntry, error) {
	var batchIndex []SearchIndexEntry

	for _, message := range messages {
		// Check cache for this message's index
		messageCacheKey := fmt.Sprintf("msg_index:%s", message.ID)
		var cachedEntry SearchIndexEntry
		if err := facades.Cache().Get(messageCacheKey, &cachedEntry); err == nil {
			batchIndex = append(batchIndex, cachedEntry)
			continue
		}

		// Decrypt message content for indexing (only if user has access)
		decryptedContent, err := s.decryptMessageForSearch(message, userID)
		if err != nil {
			// Skip messages that can't be decrypted
			continue
		}

		// Extract keywords from the decrypted content
		keywords := s.extractKeywords(decryptedContent)

		// Create encrypted index entries for each keyword
		var encryptedKeywords []string
		for _, keyword := range keywords {
			encryptedKeyword, err := s.generateEncryptedToken(searchKey, keyword)
			if err != nil {
				continue
			}
			encryptedKeywords = append(encryptedKeywords, encryptedKeyword)
		}

		indexEntry := SearchIndexEntry{
			MessageID:         message.ID,
			RoomID:            message.ChatRoomID,
			SenderID:          message.SenderID,
			EncryptedKeywords: encryptedKeywords,
			Timestamp:         message.CreatedAt,
			ContentHash:       s.GenerateContentHash(message.EncryptedContent),
		}

		// Cache this entry for 10 minutes
		facades.Cache().Put(messageCacheKey, indexEntry, 10*time.Minute)

		batchIndex = append(batchIndex, indexEntry)
	}

	return batchIndex, nil
}

// generateSearchTokens creates encrypted search tokens for query terms
func (s *E2EEService) generateSearchTokens(userID string, searchTerms []string) ([]SearchToken, error) {
	var tokens []SearchToken

	// Get user's search key (derived from their encryption key)
	searchKey, err := s.getUserSearchKey(userID)
	if err != nil {
		return nil, err
	}

	for _, term := range searchTerms {
		// Normalize the search term
		normalizedTerm := strings.ToLower(strings.TrimSpace(term))
		if len(normalizedTerm) < 2 {
			continue // Skip very short terms
		}

		// Generate encrypted token for the term
		token, err := s.generateEncryptedToken(searchKey, normalizedTerm)
		if err != nil {
			facades.Log().Warning("Failed to generate search token", map[string]interface{}{
				"user_id": userID,
				"term":    normalizedTerm,
				"error":   err.Error(),
			})
			continue
		}

		tokens = append(tokens, SearchToken{
			Term:           normalizedTerm,
			EncryptedToken: token,
		})
	}

	return tokens, nil
}

// buildSearchIndex creates an encrypted search index for the messages
func (s *E2EEService) buildSearchIndex(messages []models.ChatMessage, userID string) ([]SearchIndexEntry, error) {
	var index []SearchIndexEntry

	// Get user's search key
	searchKey, err := s.getUserSearchKey(userID)
	if err != nil {
		return nil, err
	}

	for _, message := range messages {
		// Decrypt message content for indexing (only if user has access)
		decryptedContent, err := s.decryptMessageForSearch(message, userID)
		if err != nil {
			// Skip messages that can't be decrypted
			continue
		}

		// Extract keywords from the decrypted content
		keywords := s.extractKeywords(decryptedContent)

		// Create encrypted index entries for each keyword
		var encryptedKeywords []string
		for _, keyword := range keywords {
			encryptedKeyword, err := s.generateEncryptedToken(searchKey, keyword)
			if err != nil {
				continue
			}
			encryptedKeywords = append(encryptedKeywords, encryptedKeyword)
		}

		indexEntry := SearchIndexEntry{
			MessageID:         message.ID,
			RoomID:            message.ChatRoomID,
			SenderID:          message.SenderID,
			EncryptedKeywords: encryptedKeywords,
			Timestamp:         message.CreatedAt,
			ContentHash:       s.GenerateContentHash(message.EncryptedContent),
		}

		index = append(index, indexEntry)
	}

	return index, nil
}

// performEncryptedSearch matches search tokens against the encrypted index
func (s *E2EEService) performEncryptedSearch(index []SearchIndexEntry, tokens []SearchToken) []SearchableMessage {
	var results []SearchableMessage

	for _, entry := range index {
		matchCount := 0

		// Check if any search tokens match the encrypted keywords
		for _, token := range tokens {
			for _, encryptedKeyword := range entry.EncryptedKeywords {
				if token.EncryptedToken == encryptedKeyword {
					matchCount++
					break // Found match for this token
				}
			}
		}

		// Include result if it matches any search term (OR logic)
		// For AND logic, check: matchCount == len(tokens)
		if matchCount > 0 {
			result := SearchableMessage{
				MessageID:   entry.MessageID,
				RoomID:      entry.RoomID,
				SenderID:    entry.SenderID,
				SearchHash:  s.generateSearchResultHash(entry, matchCount),
				ContentHash: entry.ContentHash,
				Timestamp:   entry.Timestamp,
				MatchScore:  float64(matchCount) / float64(len(tokens)), // Relevance score
			}
			results = append(results, result)
		}
	}

	// Sort results by relevance score (highest first)
	sort.Slice(results, func(i, j int) bool {
		if results[i].MatchScore == results[j].MatchScore {
			return results[i].Timestamp.After(results[j].Timestamp) // Then by timestamp
		}
		return results[i].MatchScore > results[j].MatchScore
	})

	return results
}

// Helper types for encrypted search
type SearchToken struct {
	Term           string `json:"term"`
	EncryptedToken string `json:"encrypted_token"`
}

type SearchIndexEntry struct {
	MessageID         string    `json:"message_id"`
	RoomID            string    `json:"room_id"`
	SenderID          string    `json:"sender_id"`
	EncryptedKeywords []string  `json:"encrypted_keywords"`
	Timestamp         time.Time `json:"timestamp"`
	ContentHash       string    `json:"content_hash"`
}

// Helper methods for encrypted search

func (s *E2EEService) getUserSearchKey(userID string) ([]byte, error) {
	// Derive a search key from the user's master key
	// In practice, this would be derived from their private key or a dedicated search key
	masterKey, err := s.getUserMasterKey(userID)
	if err != nil {
		return nil, err
	}

	// Use HKDF to derive a search-specific key
	searchKey := s.deriveKey(masterKey, []byte("search_key_"+userID), 32)
	return searchKey, nil
}

func (s *E2EEService) generateEncryptedToken(searchKey []byte, term string) (string, error) {
	// Create a deterministic encrypted token for the term
	// This allows exact matching while keeping the term encrypted

	// Use HMAC for deterministic token generation
	mac := hmac.New(sha256.New, searchKey)
	mac.Write([]byte(term))
	token := mac.Sum(nil)

	return base64.StdEncoding.EncodeToString(token), nil
}

func (s *E2EEService) decryptMessageForSearch(message models.ChatMessage, userID string) (string, error) {
	// Verify user has access to the room
	hasAccess, err := s.verifyRoomAccess(message.ChatRoomID, userID)
	if err != nil {
		facades.Log().Error("Failed to verify room access for search", map[string]interface{}{
			"room_id":    message.ChatRoomID,
			"user_id":    userID,
			"message_id": message.ID,
			"error":      err.Error(),
		})
		return "", fmt.Errorf("failed to verify room access: %w", err)
	}

	if !hasAccess {
		facades.Log().Warning("User attempted to search messages in unauthorized room", map[string]interface{}{
			"room_id":    message.ChatRoomID,
			"user_id":    userID,
			"message_id": message.ID,
		})
		return "", fmt.Errorf("unauthorized: user does not have access to this room")
	}

	// Get the room key for decryption
	roomKey, err := s.getRoomKeyForUser(message.ChatRoomID, userID)
	if err != nil {
		facades.Log().Error("Failed to get room key for search decryption", map[string]interface{}{
			"room_id":    message.ChatRoomID,
			"user_id":    userID,
			"message_id": message.ID,
			"error":      err.Error(),
		})
		return "", fmt.Errorf("failed to get room key: %w", err)
	}

	if roomKey == nil {
		facades.Log().Warning("No room key available for search decryption", map[string]interface{}{
			"room_id":    message.ChatRoomID,
			"user_id":    userID,
			"message_id": message.ID,
		})
		return "", fmt.Errorf("no room key available for decryption")
	}

	// Decrypt the message content
	decryptedContent, err := s.decryptMessageContent(message.EncryptedContent, roomKey)
	if err != nil {
		facades.Log().Error("Failed to decrypt message for search", map[string]interface{}{
			"room_id":    message.ChatRoomID,
			"user_id":    userID,
			"message_id": message.ID,
			"error":      err.Error(),
		})
		return "", fmt.Errorf("failed to decrypt message: %w", err)
	}

	facades.Log().Debug("Successfully decrypted message for search", map[string]interface{}{
		"room_id":        message.ChatRoomID,
		"user_id":        userID,
		"message_id":     message.ID,
		"content_length": len(decryptedContent),
	})

	return decryptedContent, nil
}

// Helper method to verify room access for search
func (s *E2EEService) verifyRoomAccess(roomID, userID string) (bool, error) {
	// Check if user is a member of the room
	var membership models.ChatRoomMember
	err := facades.Orm().Query().
		Where("room_id = ? AND user_id = ? AND is_active = ?", roomID, userID, true).
		First(&membership)

	if err != nil {
		// User is not a member of the room
		return false, nil
	}

	// Check if the room allows the user to read messages
	if membership.Role == "banned" || membership.Role == "restricted" {
		return false, nil
	}

	return true, nil
}

// Helper method to get room key for a specific user
func (s *E2EEService) getRoomKeyForUser(roomID, userID string) (*RoomKey, error) {
	// Try to get from cache first
	cacheKey := fmt.Sprintf("room_key:%s:%s", roomID, userID)
	var cachedKey RoomKey
	err := facades.Cache().Get(cacheKey, &cachedKey)
	if err == nil {
		// Return cached key (no expiration check since model doesn't have ExpiresAt)
		return &cachedKey, nil
	}

	// Get from database
	var roomKey models.ChatRoomKey
	err = facades.Orm().Query().
		Where("room_id = ? AND user_id = ? AND is_active = ?", roomID, userID, true).
		Where("expires_at > ?", time.Now()).
		OrderBy("created_at DESC").
		First(&roomKey)

	if err != nil {
		facades.Log().Warning("No active room key found for user", map[string]interface{}{
			"room_id": roomID,
			"user_id": userID,
		})
		return nil, fmt.Errorf("no active room key found")
	}

	// Decrypt the user's copy of the room key
	userPrivateKey, keyErr := s.getUserPrivateKey(userID)
	if keyErr != nil {
		return nil, fmt.Errorf("failed to get user private key: %w", keyErr)
	}

	decryptedRoomKey, decryptErr := s.decryptWithPrivateKey(roomKey.EncryptedKey, userPrivateKey)
	if decryptErr != nil {
		return nil, fmt.Errorf("failed to decrypt room key: %w", decryptErr)
	}

	// Create RoomKey object
	key := &RoomKey{
		KeyID:   roomKey.ID,
		RoomID:  roomID,
		Key:     decryptedRoomKey,
		Version: roomKey.Version,
	}

	// Cache the decrypted key for a short time (5 minutes)
	facades.Cache().Put(cacheKey, *key, 5*time.Minute)

	return key, nil
}

// Helper method to decrypt message content with room key
func (s *E2EEService) decryptMessageContent(encryptedContent string, roomKey *RoomKey) (string, error) {
	// Decode the encrypted content from base64
	encryptedData, err := base64.StdEncoding.DecodeString(encryptedContent)
	if err != nil {
		return "", fmt.Errorf("failed to decode encrypted content: %w", err)
	}

	// Parse the encrypted message structure
	var encryptedMsg struct {
		IV         string `json:"iv"`
		Ciphertext string `json:"ciphertext"`
		AuthTag    string `json:"auth_tag"`
	}

	err = json.Unmarshal(encryptedData, &encryptedMsg)
	if err != nil {
		return "", fmt.Errorf("failed to parse encrypted message: %w", err)
	}

	// Decrypt using AES-GCM
	block, err := aes.NewCipher(roomKey.Key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// Decode IV and ciphertext
	iv, err := base64.StdEncoding.DecodeString(encryptedMsg.IV)
	if err != nil {
		return "", fmt.Errorf("failed to decode IV: %w", err)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encryptedMsg.Ciphertext)
	if err != nil {
		return "", fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	authTag, err := base64.StdEncoding.DecodeString(encryptedMsg.AuthTag)
	if err != nil {
		return "", fmt.Errorf("failed to decode auth tag: %w", err)
	}

	// Combine ciphertext and auth tag for GCM decryption
	fullCiphertext := append(ciphertext, authTag...)

	// Decrypt
	plaintext, err := aesGCM.Open(nil, iv, fullCiphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt message: %w", err)
	}

	return string(plaintext), nil
}

// Helper method to get user's private key for decryption
func (s *E2EEService) getUserPrivateKey(userID string) ([]byte, error) {
	// Get user's key pair from database
	var keyPair models.UserKey
	err := facades.Orm().Query().
		Where("user_id = ? AND is_active = ?", userID, true).
		OrderBy("created_at DESC").
		First(&keyPair)

	if err != nil {
		return nil, fmt.Errorf("no active key pair found for user: %w", err)
	}

	// In production, the private key should be encrypted with the user's password
	// For now, return the stored private key (this should be improved)
	privateKey, err := base64.StdEncoding.DecodeString(keyPair.EncryptedPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %w", err)
	}

	return privateKey, nil
}

// Helper method to decrypt data with RSA private key
func (s *E2EEService) decryptWithPrivateKey(encryptedData string, privateKeyBytes []byte) ([]byte, error) {
	// Parse the private key
	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBytes)
	if err != nil {
		// Try PKCS8 format
		parsedKey, err2 := x509.ParsePKCS8PrivateKey(privateKeyBytes)
		if err2 != nil {
			return nil, fmt.Errorf("failed to parse private key: %v, %v", err, err2)
		}

		var ok bool
		privateKey, ok = parsedKey.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("parsed key is not RSA private key")
		}
	}

	// Decode the encrypted data
	encryptedBytes, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted data: %w", err)
	}

	// Decrypt with RSA-OAEP
	decryptedData, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, encryptedBytes, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt with RSA: %w", err)
	}

	return decryptedData, nil
}

func (s *E2EEService) extractKeywords(content string) []string {
	// Extract searchable keywords from decrypted content
	// This is a simplified keyword extraction

	// Convert to lowercase and split by common delimiters
	content = strings.ToLower(content)
	words := strings.FieldsFunc(content, func(c rune) bool {
		return !unicode.IsLetter(c) && !unicode.IsNumber(c)
	})

	// Filter out short words and common stop words
	stopWords := map[string]bool{
		"the": true, "a": true, "an": true, "and": true, "or": true, "but": true,
		"in": true, "on": true, "at": true, "to": true, "for": true, "of": true,
		"with": true, "by": true, "is": true, "are": true, "was": true, "were": true,
	}

	var keywords []string
	seen := make(map[string]bool)

	for _, word := range words {
		if len(word) >= 3 && !stopWords[word] && !seen[word] {
			keywords = append(keywords, word)
			seen[word] = true
		}
	}

	return keywords
}

func (s *E2EEService) generateSearchResultHash(entry SearchIndexEntry, matchCount int) string {
	// Generate a hash representing the search result
	data := fmt.Sprintf("%s:%s:%d", entry.MessageID, entry.ContentHash, matchCount)
	hash := sha256.Sum256([]byte(data))
	return base64.StdEncoding.EncodeToString(hash[:])
}

func (s *E2EEService) getUserMasterKey(userID string) ([]byte, error) {
	// Production key management with secure storage

	// First, try to retrieve existing master key from secure storage
	keyID := fmt.Sprintf("user_master_key:%s", userID)

	// Check if key exists in encrypted storage
	if encryptedKey := facades.Cache().GetString(keyID); encryptedKey != "" {
		// Decrypt the stored master key
		decryptedKey, err := facades.Crypt().DecryptString(encryptedKey)
		if err != nil {
			facades.Log().Error("Failed to decrypt user master key", map[string]interface{}{
				"user_id": userID,
				"error":   err.Error(),
			})
			return nil, fmt.Errorf("failed to decrypt master key: %w", err)
		}

		// Decode from base64
		masterKey, err := base64.StdEncoding.DecodeString(decryptedKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decode master key: %w", err)
		}

		return masterKey, nil
	}

	// If no existing key, generate a new one
	masterKey := make([]byte, 32) // 256-bit key
	if _, err := rand.Read(masterKey); err != nil {
		return nil, fmt.Errorf("failed to generate master key: %w", err)
	}

	// Encrypt and store the master key
	encodedKey := base64.StdEncoding.EncodeToString(masterKey)
	encryptedKey, err := facades.Crypt().EncryptString(encodedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt master key: %w", err)
	}

	// Store encrypted key with expiration (24 hours for security)
	facades.Cache().Put(keyID, encryptedKey, 24*time.Hour)

	// Also store in database for persistence
	if err := s.storeMasterKeyInDatabase(userID, encryptedKey); err != nil {
		facades.Log().Warning("Failed to store master key in database", map[string]interface{}{
			"user_id": userID,
			"error":   err.Error(),
		})
	}

	facades.Log().Info("Generated new master key for user", map[string]interface{}{
		"user_id": userID,
	})

	return masterKey, nil
}

func (s *E2EEService) deriveKey(masterKey []byte, info []byte, length int) []byte {
	// Production HKDF implementation using golang.org/x/crypto/hkdf

	// Extract phase: use HMAC-SHA256 to extract a pseudorandom key
	salt := make([]byte, 32) // Use zero salt or a fixed salt for deterministic results
	hkdf := hkdf.New(sha256.New, masterKey, salt, info)

	// Expand phase: derive the required key length
	derivedKey := make([]byte, length)
	if _, err := io.ReadFull(hkdf, derivedKey); err != nil {
		facades.Log().Error("HKDF key derivation failed", map[string]interface{}{
			"error":  err.Error(),
			"length": length,
		})
		// Fallback to simple HMAC if HKDF fails
		return s.deriveKeyFallback(masterKey, info, length)
	}

	return derivedKey
}

// deriveKeyFallback provides a fallback key derivation method
func (s *E2EEService) deriveKeyFallback(masterKey []byte, info []byte, length int) []byte {
	// Fallback HMAC-based key derivation
	mac := hmac.New(sha256.New, masterKey)
	mac.Write(info)
	derived := mac.Sum(nil)

	// If we need more bytes, use a counter-based approach
	if len(derived) >= length {
		return derived[:length]
	}

	result := make([]byte, length)
	copy(result, derived)

	// Generate additional bytes if needed
	for i := len(derived); i < length; i += 32 {
		mac.Reset()
		mac.Write(masterKey)
		mac.Write(info)
		mac.Write([]byte{byte(i / 32)}) // Counter
		additional := mac.Sum(nil)

		remaining := length - i
		if remaining > 32 {
			remaining = 32
		}
		copy(result[i:], additional[:remaining])
	}

	return result
}

// storeMasterKeyInDatabase stores the encrypted master key in the database for persistence
func (s *E2EEService) storeMasterKeyInDatabase(userID, encryptedKey string) error {
	// Create or update user key record
	var userKey models.UserKey
	err := facades.Orm().Query().Where("user_id", userID).Where("key_type", "master").First(&userKey)

	if err != nil {
		// Create new record
		userKey = models.UserKey{
			UserID:              userID,
			KeyType:             "master",
			EncryptedPrivateKey: encryptedKey,
		}
		return facades.Orm().Query().Create(&userKey)
	} else {
		// Update existing record
		userKey.EncryptedPrivateKey = encryptedKey
		userKey.UpdatedAt = time.Now()
		return facades.Orm().Query().Save(&userKey)
	}
}

// retrieveMasterKeyFromDatabase retrieves the encrypted master key from the database
func (s *E2EEService) retrieveMasterKeyFromDatabase(userID string) (string, error) {
	var userKey models.UserKey
	err := facades.Orm().Query().Where("user_id", userID).Where("key_type", "master").First(&userKey)
	if err != nil {
		return "", err
	}
	return userKey.EncryptedPrivateKey, nil
}

// rotateMasterKey rotates a user's master key for security
func (s *E2EEService) rotateMasterKey(userID string) error {
	// Remove old key from cache
	keyID := fmt.Sprintf("user_master_key:%s", userID)
	facades.Cache().Forget(keyID)

	// Generate new master key (getUserMasterKey will create a new one)
	_, err := s.getUserMasterKey(userID)
	if err != nil {
		return fmt.Errorf("failed to rotate master key: %w", err)
	}

	facades.Log().Info("Master key rotated successfully", map[string]interface{}{
		"user_id": userID,
	})

	return nil
}

// generateRegistrationID generates a unique registration ID for the device
func generateRegistrationID() uint32 {
	// Generate a cryptographically secure random 32-bit registration ID
	bytes := make([]byte, 4)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to time-based ID if random generation fails
		return uint32(time.Now().Unix() & 0xFFFFFFFF)
	}

	return binary.BigEndian.Uint32(bytes)
}

// generateDeviceID generates a unique device ID
func generateDeviceID() uint32 {
	// Generate a cryptographically secure random device ID
	bytes := make([]byte, 4)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to time-based ID if random generation fails
		return uint32((time.Now().UnixNano() / 1000) & 0xFFFFFFFF)
	}

	return binary.BigEndian.Uint32(bytes)
}

// ValidatePublicKey validates the format and structure of a public key
func (s *E2EEService) ValidatePublicKey(publicKeyStr string) error {
	// Decode PEM block
	block, _ := pem.Decode([]byte(publicKeyStr))
	if block == nil {
		return fmt.Errorf("failed to decode PEM block")
	}

	// Check if it's an RSA public key
	if block.Type != "RSA PUBLIC KEY" && block.Type != "PUBLIC KEY" {
		return fmt.Errorf("invalid key type: expected RSA PUBLIC KEY or PUBLIC KEY, got %s", block.Type)
	}

	// Try to parse the public key
	if block.Type == "RSA PUBLIC KEY" {
		_, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse PKCS1 public key: %v", err)
		}
	} else {
		pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse PKIX public key: %v", err)
		}
		// Ensure it's an RSA key
		if _, ok := pubKey.(*rsa.PublicKey); !ok {
			return fmt.Errorf("public key is not an RSA key")
		}
	}

	return nil
}

// generateMessageSignature generates an HMAC signature for message authentication
func (s *E2EEService) generateMessageSignature(msg interface{}, key []byte) (string, error) {
	// Create a canonical representation of the message for signing
	var dataToSign string

	switch v := msg.(type) {
	case *EncryptedMessage:
		dataToSign = fmt.Sprintf("%s|%s|%d|%d", v.Content, v.Algorithm, v.Version, v.Timestamp.Unix())
	case *EncryptedFile:
		dataToSign = fmt.Sprintf("%s|%s|%d|%d", v.EncryptedData, v.Algorithm, v.Version, v.Timestamp.Unix())
	default:
		return "", fmt.Errorf("unsupported message type for signing")
	}

	// Generate HMAC-SHA256 signature
	h := hmac.New(sha256.New, key)
	h.Write([]byte(dataToSign))
	signature := h.Sum(nil)

	return base64.StdEncoding.EncodeToString(signature), nil
}

// verifyMessageSignature verifies the HMAC signature of a message
func (s *E2EEService) verifyMessageSignature(msg interface{}, key []byte, signature string) error {
	expectedSignature, err := s.generateMessageSignature(msg, key)
	if err != nil {
		return fmt.Errorf("failed to generate expected signature: %v", err)
	}

	// Use constant-time comparison to prevent timing attacks
	if !hmac.Equal([]byte(expectedSignature), []byte(signature)) {
		return fmt.Errorf("message signature verification failed")
	}

	return nil
}

// E2EEMetrics tracks performance metrics for E2EE operations
type E2EEMetrics struct {
	EncryptionCount    int64         `json:"encryption_count"`
	DecryptionCount    int64         `json:"decryption_count"`
	KeyGenerationCount int64         `json:"key_generation_count"`
	KeyRotationCount   int64         `json:"key_rotation_count"`
	AverageEncryptTime time.Duration `json:"average_encrypt_time"`
	AverageDecryptTime time.Duration `json:"average_decrypt_time"`
	ErrorCount         int64         `json:"error_count"`
	LastUpdated        time.Time     `json:"last_updated"`
	mu                 sync.RWMutex  `json:"-"`
}

// Global metrics instance
var e2eeMetrics = &E2EEMetrics{
	LastUpdated: time.Now(),
}

// recordKeyGeneration records a key generation operation metric
func (s *E2EEService) recordKeyGeneration() {
	e2eeMetrics.mu.Lock()
	defer e2eeMetrics.mu.Unlock()

	e2eeMetrics.KeyGenerationCount++
	e2eeMetrics.LastUpdated = time.Now()
}

// recordError records an error metric
func (s *E2EEService) recordError() {
	e2eeMetrics.mu.Lock()
	defer e2eeMetrics.mu.Unlock()

	e2eeMetrics.ErrorCount++
	e2eeMetrics.LastUpdated = time.Now()
}

// recordEncryption records an encryption operation metric
func (s *E2EEService) recordEncryption(duration time.Duration) {
	e2eeMetrics.mu.Lock()
	defer e2eeMetrics.mu.Unlock()

	e2eeMetrics.EncryptionCount++

	// Calculate rolling average
	if e2eeMetrics.AverageEncryptTime == 0 {
		e2eeMetrics.AverageEncryptTime = duration
	} else {
		// Simple moving average
		e2eeMetrics.AverageEncryptTime = (e2eeMetrics.AverageEncryptTime + duration) / 2
	}

	e2eeMetrics.LastUpdated = time.Now()
}

// recordDecryption records a decryption operation metric
func (s *E2EEService) recordDecryption(duration time.Duration) {
	e2eeMetrics.mu.Lock()
	defer e2eeMetrics.mu.Unlock()

	e2eeMetrics.DecryptionCount++

	// Calculate rolling average
	if e2eeMetrics.AverageDecryptTime == 0 {
		e2eeMetrics.AverageDecryptTime = duration
	} else {
		// Simple moving average
		e2eeMetrics.AverageDecryptTime = (e2eeMetrics.AverageDecryptTime + duration) / 2
	}

	e2eeMetrics.LastUpdated = time.Now()
}

// recordKeyRotation records a key rotation operation metric
func (s *E2EEService) recordKeyRotation() {
	e2eeMetrics.mu.Lock()
	defer e2eeMetrics.mu.Unlock()

	e2eeMetrics.KeyRotationCount++
	e2eeMetrics.LastUpdated = time.Now()
}
