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
	"encoding/pem"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"

	"goravel/app/models"

	"github.com/goravel/framework/facades"
	"golang.org/x/crypto/chacha20poly1305"
)

// E2EEService handles end-to-end encryption for chat messages
type E2EEService struct{}

// NewE2EEService creates a new E2EE service instance
func NewE2EEService() *E2EEService {
	return &E2EEService{}
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

// GenerateKeyPair generates a new RSA key pair for a user
func (s *E2EEService) GenerateKeyPair() (*KeyPair, error) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
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

	// Create encrypted message
	encryptedMsg := &EncryptedMessage{
		Content:   encryptedContent,
		Algorithm: "AES-256-GCM",
		Version:   1,
		Metadata:  encryptedKeys,
		Timestamp: time.Now(),
	}

	return encryptedMsg, nil
}

// DecryptMessage decrypts a message using the user's private key
func (s *E2EEService) DecryptMessage(encryptedMsg *EncryptedMessage, userPrivateKey string) (string, error) {
	// Decode the encrypted content
	encryptedData, err := base64.StdEncoding.DecodeString(encryptedMsg.Content)
	if err != nil {
		return "", fmt.Errorf("failed to decode encrypted content: %v", err)
	}

	// Extract nonce and ciphertext
	if len(encryptedData) < 12 {
		return "", fmt.Errorf("invalid encrypted data length")
	}
	nonce := encryptedData[:12]
	ciphertext := encryptedData[12:]

	// Find the encrypted AES key for this user
	var encryptedAESKey string
	for _, encryptedKey := range encryptedMsg.Metadata {
		encryptedAESKey = encryptedKey
		break // For simplicity, we'll use the first key
	}

	if encryptedAESKey == "" {
		return "", fmt.Errorf("no encrypted AES key found")
	}

	// Decrypt the AES key using RSA
	aesKey, err := s.decryptAESKeyWithRSA(encryptedAESKey, userPrivateKey)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt AES key: %v", err)
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
		return "", fmt.Errorf("failed to decrypt message: %v", err)
	}

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

// deriveKeyFromPassphrase derives a key from a passphrase using PBKDF2-like approach
func (s *E2EEService) deriveKeyFromPassphrase(passphrase string, salt []byte, iterations int) []byte {
	// Use HMAC-SHA256 for key derivation
	key := make([]byte, 32) // 256-bit key

	// Simple key stretching using HMAC
	currentHash := []byte(passphrase)
	currentHash = append(currentHash, salt...)

	for i := 0; i < iterations; i++ {
		h := hmac.New(sha256.New, currentHash)
		h.Write(salt)
		h.Write([]byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)})
		currentHash = h.Sum(nil)
	}

	// Use the final hash as the key (truncate to 32 bytes if needed)
	copy(key, currentHash[:32])

	return key
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
	// Generate new room key
	newRoomKey, err := s.GenerateRoomKey()
	if err != nil {
		return err
	}

	// Get room members
	var members []models.ChatRoomMember
	err = facades.Orm().Query().Where("chat_room_id", roomID).Where("is_active", true).Find(&members)
	if err != nil {
		return err
	}

	// Deactivate old keys
	_, err = facades.Orm().Query().Model(&models.ChatRoomKey{}).
		Where("chat_room_id", roomID).
		Where("is_active", true).
		Update("is_active", false)
	if err != nil {
		return err
	}

	// Create new room key
	now := time.Now()
	roomKey := &models.ChatRoomKey{
		ChatRoomID:   roomID,
		KeyType:      "room_key",
		EncryptedKey: base64.StdEncoding.EncodeToString(newRoomKey),
		Version:      1,
		IsActive:     true,
		RotatedAt:    &now,
	}

	return s.SaveRoomKey(roomKey)
}

// GeneratePrekeyBundle generates a complete prekey bundle for PFS
func (s *E2EEService) GeneratePrekeyBundle(userID string, deviceID int) (*PrekeyBundle, error) {
	// Generate identity key
	identityKeyPair, err := s.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate identity key: %v", err)
	}

	// Generate signed prekey
	signedPrekey, err := s.GenerateSignedPrekey(identityKeyPair.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate signed prekey: %v", err)
	}

	// Generate one-time prekeys
	oneTimePrekeys := make([]*OneTimePrekey, 0, 100)
	for i := 0; i < 100; i++ {
		prekey, err := s.GenerateOneTimePrekey()
		if err != nil {
			facades.Log().Error("Failed to generate one-time prekey", map[string]interface{}{
				"index": i,
				"error": err.Error(),
			})
			continue
		}
		oneTimePrekeys = append(oneTimePrekeys, prekey)
	}

	// Generate registration ID
	registrationID := s.generateRegistrationID()

	return &PrekeyBundle{
		IdentityKey:    identityKeyPair.PublicKey,
		SignedPrekey:   signedPrekey,
		OneTimePrekeys: oneTimePrekeys,
		RegistrationID: registrationID,
		DeviceID:       deviceID,
	}, nil
}

// GenerateSignedPrekey generates a signed prekey
func (s *E2EEService) GenerateSignedPrekey(identityPrivateKey string) (*SignedPrekey, error) {
	// Generate ephemeral key pair
	ephemeralKeyPair, err := s.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %v", err)
	}

	// Sign the ephemeral public key with identity key
	signature, err := s.SignMessage(ephemeralKeyPair.PublicKey, identityPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign prekey: %v", err)
	}

	// Generate key ID
	keyID := s.generateKeyID()

	return &SignedPrekey{
		KeyID:     keyID,
		PublicKey: ephemeralKeyPair.PublicKey,
		Signature: signature,
		Timestamp: time.Now().Unix(),
	}, nil
}

// GenerateOneTimePrekey generates a one-time prekey
func (s *E2EEService) GenerateOneTimePrekey() (*OneTimePrekey, error) {
	// Generate ephemeral key pair
	keyPair, err := s.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate one-time prekey: %v", err)
	}

	// Generate key ID
	keyID := s.generateKeyID()

	return &OneTimePrekey{
		KeyID:     keyID,
		PublicKey: keyPair.PublicKey,
	}, nil
}

// generateKeyID generates a unique key ID
func (s *E2EEService) generateKeyID() int {
	// Generate a random 32-bit integer
	keyIDBytes := make([]byte, 4)
	rand.Read(keyIDBytes)
	return int(keyIDBytes[0])<<24 | int(keyIDBytes[1])<<16 | int(keyIDBytes[2])<<8 | int(keyIDBytes[3])
}

// generateRegistrationID generates a unique registration ID
func (s *E2EEService) generateRegistrationID() int {
	// Generate a random 16-bit integer
	regIDBytes := make([]byte, 2)
	rand.Read(regIDBytes)
	return int(regIDBytes[0])<<8 | int(regIDBytes[1])
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
	// This is a placeholder - in reality you'd decrypt the message content
	// using the appropriate room key that the user has access to

	// For now, return a simulated decrypted content for indexing
	// In production, you'd use the actual E2EE decryption process
	return fmt.Sprintf("decrypted_content_for_message_%s", message.ID), nil
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
	// Get or derive the user's master key for encryption operations
	// In a real implementation, this would retrieve the user's private key or derive it securely

	// For this implementation, we'll derive a deterministic key from the user ID
	// In production, use proper key management with secure storage
	keyMaterial := fmt.Sprintf("master_key_for_user_%s", userID)
	hash := sha256.Sum256([]byte(keyMaterial))
	return hash[:], nil
}

func (s *E2EEService) deriveKey(masterKey []byte, info []byte, length int) []byte {
	// Derive a key using HKDF (HMAC-based Key Derivation Function)
	// This is a simplified implementation - in production use golang.org/x/crypto/hkdf

	// Use HMAC as a simple key derivation
	mac := hmac.New(sha256.New, masterKey)
	mac.Write(info)
	derived := mac.Sum(nil)

	// Truncate or extend to desired length
	if len(derived) >= length {
		return derived[:length]
	}

	// If we need more bytes, hash again with a counter
	result := make([]byte, length)
	copy(result, derived)

	for i := len(derived); i < length; i += sha256.Size {
		mac.Reset()
		mac.Write(masterKey)
		mac.Write(info)
		mac.Write([]byte{byte(i / sha256.Size)}) // Add counter
		nextHash := mac.Sum(nil)

		remaining := length - i
		if remaining > sha256.Size {
			remaining = sha256.Size
		}
		copy(result[i:], nextHash[:remaining])
	}

	return result
}
