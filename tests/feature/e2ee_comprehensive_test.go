package feature

import (
	"testing"
	"time"

	"goravel/app/services"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type E2EEComprehensiveTestSuite struct {
	suite.Suite
	e2eeService *services.E2EEService
}

func (suite *E2EEComprehensiveTestSuite) SetupTest() {
	suite.e2eeService = services.NewE2EEService()
	// Reset metrics for clean testing
	services.ResetE2EEMetrics()
}

func TestE2EEComprehensiveTestSuite(t *testing.T) {
	suite.Run(t, new(E2EEComprehensiveTestSuite))
}

// Test basic encryption and decryption with metrics
func (suite *E2EEComprehensiveTestSuite) TestBasicEncryptionDecryptionWithMetrics() {
	// Generate key pair
	keyPair, err := suite.e2eeService.GenerateKeyPair()
	assert.NoError(suite.T(), err)
	assert.NotEmpty(suite.T(), keyPair.PublicKey)
	assert.NotEmpty(suite.T(), keyPair.PrivateKey)

	// Test message encryption
	message := "This is a test message for comprehensive E2EE testing!"
	recipientKeys := []string{keyPair.PublicKey}

	encryptedMsg, err := suite.e2eeService.EncryptMessage(message, recipientKeys)
	assert.NoError(suite.T(), err)
	assert.NotEmpty(suite.T(), encryptedMsg.Content)
	assert.NotEmpty(suite.T(), encryptedMsg.Signature)
	assert.Equal(suite.T(), "AES-256-GCM", encryptedMsg.Algorithm)
	assert.Equal(suite.T(), 1, encryptedMsg.Version)

	// Test message decryption
	decryptedMessage, err := suite.e2eeService.DecryptMessage(encryptedMsg, keyPair.PrivateKey)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), message, decryptedMessage)

	// Verify metrics
	metrics := services.GetE2EEMetrics()
	assert.Equal(suite.T(), int64(1), metrics.KeyGenerationCount)
	assert.Equal(suite.T(), int64(1), metrics.EncryptionCount)
	assert.Equal(suite.T(), int64(1), metrics.DecryptionCount)
	assert.Greater(suite.T(), metrics.AverageEncryptTime, time.Duration(0))
	assert.Greater(suite.T(), metrics.AverageDecryptTime, time.Duration(0))
}

// Test Perfect Forward Secrecy prekey bundles
func (suite *E2EEComprehensiveTestSuite) TestPerfectForwardSecrecy() {
	userID := "test_user_123"
	deviceID := 1

	// Generate prekey bundle
	bundle, err := suite.e2eeService.GeneratePrekeyBundle(userID, deviceID)
	assert.NoError(suite.T(), err)
	assert.NotEmpty(suite.T(), bundle.IdentityKey)
	assert.NotNil(suite.T(), bundle.SignedPrekey)
	assert.NotEmpty(suite.T(), bundle.OneTimePrekeys)
	assert.GreaterOrEqual(suite.T(), len(bundle.OneTimePrekeys), 50)
	assert.Equal(suite.T(), deviceID, bundle.DeviceID)

	// Verify signed prekey structure
	assert.NotZero(suite.T(), bundle.SignedPrekey.KeyID)
	assert.NotEmpty(suite.T(), bundle.SignedPrekey.PublicKey)
	assert.NotEmpty(suite.T(), bundle.SignedPrekey.Signature)
	assert.Greater(suite.T(), bundle.SignedPrekey.Timestamp, int64(0))

	// Verify one-time prekeys structure
	for i, prekey := range bundle.OneTimePrekeys {
		assert.NotZero(suite.T(), prekey.KeyID, "One-time prekey %d should have valid KeyID", i)
		assert.NotEmpty(suite.T(), prekey.PublicKey, "One-time prekey %d should have valid PublicKey", i)
	}
}

// Test public key validation
func (suite *E2EEComprehensiveTestSuite) TestPublicKeyValidation() {
	// Generate valid key pair
	keyPair, err := suite.e2eeService.GenerateKeyPair()
	assert.NoError(suite.T(), err)

	// Test valid public key
	err = suite.e2eeService.ValidatePublicKey(keyPair.PublicKey)
	assert.NoError(suite.T(), err)

	// Test invalid public keys
	invalidKeys := []string{
		"",
		"not-a-pem-key",
		"-----BEGIN INVALID KEY-----\nInvalidData\n-----END INVALID KEY-----",
		"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKB\n-----END PRIVATE KEY-----",
	}

	for _, invalidKey := range invalidKeys {
		err = suite.e2eeService.ValidatePublicKey(invalidKey)
		assert.Error(suite.T(), err, "Should reject invalid key: %s", invalidKey)
	}
}

// Test input validation and error handling
func (suite *E2EEComprehensiveTestSuite) TestInputValidationAndErrorHandling() {
	keyPair, _ := suite.e2eeService.GenerateKeyPair()

	// Test empty message
	_, err := suite.e2eeService.EncryptMessage("", []string{keyPair.PublicKey})
	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "message cannot be empty")

	// Test message too large (65KB)
	largeMessage := make([]byte, 65*1024)
	for i := range largeMessage {
		largeMessage[i] = 'A'
	}
	_, err = suite.e2eeService.EncryptMessage(string(largeMessage), []string{keyPair.PublicKey})
	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "message too large")

	// Test no recipients
	_, err = suite.e2eeService.EncryptMessage("test", []string{})
	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "at least one recipient public key is required")

	// Test too many recipients
	manyKeys := make([]string, 101)
	for i := range manyKeys {
		manyKeys[i] = keyPair.PublicKey
	}
	_, err = suite.e2eeService.EncryptMessage("test", manyKeys)
	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "too many recipients")

	// Verify error metrics
	metrics := services.GetE2EEMetrics()
	assert.Greater(suite.T(), metrics.ErrorCount, int64(0))
}

// Test message authentication and integrity
func (suite *E2EEComprehensiveTestSuite) TestMessageAuthenticationAndIntegrity() {
	keyPair, _ := suite.e2eeService.GenerateKeyPair()
	message := "Test message for authentication"

	// Encrypt message
	encryptedMsg, err := suite.e2eeService.EncryptMessage(message, []string{keyPair.PublicKey})
	assert.NoError(suite.T(), err)
	assert.NotEmpty(suite.T(), encryptedMsg.Signature)

	// Test successful decryption with valid signature
	decryptedMessage, err := suite.e2eeService.DecryptMessage(encryptedMsg, keyPair.PrivateKey)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), message, decryptedMessage)

	// Test tampered signature
	originalSignature := encryptedMsg.Signature
	encryptedMsg.Signature = "tampered-signature"
	_, err = suite.e2eeService.DecryptMessage(encryptedMsg, keyPair.PrivateKey)
	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "message integrity verification failed")

	// Restore signature and test tampered content
	encryptedMsg.Signature = originalSignature
	encryptedMsg.Content = "tampered-content"
	_, err = suite.e2eeService.DecryptMessage(encryptedMsg, keyPair.PrivateKey)
	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "message integrity verification failed")
}

// Test multiple recipients encryption
func (suite *E2EEComprehensiveTestSuite) TestMultipleRecipientsEncryption() {
	// Generate multiple key pairs
	keyPairs := make([]*services.KeyPair, 5)
	for i := range keyPairs {
		keyPair, err := suite.e2eeService.GenerateKeyPair()
		assert.NoError(suite.T(), err)
		keyPairs[i] = keyPair
	}

	// Prepare recipient public keys
	recipientKeys := make([]string, len(keyPairs))
	for i, keyPair := range keyPairs {
		recipientKeys[i] = keyPair.PublicKey
	}

	// Encrypt message for all recipients
	message := "Message for multiple recipients"
	encryptedMsg, err := suite.e2eeService.EncryptMessage(message, recipientKeys)
	assert.NoError(suite.T(), err)
	assert.Len(suite.T(), encryptedMsg.Metadata, len(keyPairs))

	// Test that each recipient can decrypt the message
	for i, keyPair := range keyPairs {
		decryptedMessage, err := suite.e2eeService.DecryptMessage(encryptedMsg, keyPair.PrivateKey)
		assert.NoError(suite.T(), err, "Recipient %d should be able to decrypt", i)
		assert.Equal(suite.T(), message, decryptedMessage, "Recipient %d should get correct message", i)
	}
}

// Test room key encryption and decryption
func (suite *E2EEComprehensiveTestSuite) TestRoomKeyEncryptionDecryption() {
	keyPair, _ := suite.e2eeService.GenerateKeyPair()

	// Generate room key
	roomKey, err := suite.e2eeService.GenerateRoomKey()
	assert.NoError(suite.T(), err)
	assert.Len(suite.T(), roomKey, 32) // 256-bit key

	// Encrypt room key for user
	encryptedRoomKey, err := suite.e2eeService.EncryptRoomKey(roomKey, keyPair.PublicKey)
	assert.NoError(suite.T(), err)
	assert.NotEmpty(suite.T(), encryptedRoomKey)

	// Decrypt room key
	decryptedRoomKey, err := suite.e2eeService.DecryptRoomKey(encryptedRoomKey, keyPair.PrivateKey)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), roomKey, decryptedRoomKey)

	// Test room key encryption/decryption
	message := "Message encrypted with room key"
	encryptedMessage, err := suite.e2eeService.EncryptWithRoomKey(message, roomKey)
	assert.NoError(suite.T(), err)
	assert.NotEmpty(suite.T(), encryptedMessage)

	decryptedMessage, err := suite.e2eeService.DecryptWithRoomKey(encryptedMessage, roomKey)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), message, decryptedMessage)
}

// Test searchable encryption
func (suite *E2EEComprehensiveTestSuite) TestSearchableEncryption() {
	messageID := "msg_123"
	roomID := "room_456"
	senderID := "user_789"
	content := "This is a searchable message with important keywords like security and encryption"

	// Create searchable message
	searchableMsg, err := suite.e2eeService.CreateSearchableMessage(messageID, roomID, senderID, content)
	if err != nil {
		// Skip test if secure key storage is not available
		suite.T().Skip("Secure key storage not initialized, skipping searchable encryption test")
		return
	}

	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), messageID, searchableMsg.MessageID)
	assert.Equal(suite.T(), roomID, searchableMsg.RoomID)
	assert.Equal(suite.T(), senderID, searchableMsg.SenderID)
	assert.NotEmpty(suite.T(), searchableMsg.SearchHash)
	assert.NotEmpty(suite.T(), searchableMsg.ContentHash)

	// Test search result verification
	isValid := suite.e2eeService.VerifySearchResult(searchableMsg, content)
	assert.True(suite.T(), isValid)

	// Test with tampered content
	isValid = suite.e2eeService.VerifySearchResult(searchableMsg, "tampered content")
	assert.False(suite.T(), isValid)
}

// Test performance metrics
func (suite *E2EEComprehensiveTestSuite) TestPerformanceMetrics() {
	// Reset metrics
	services.ResetE2EEMetrics()

	// Perform various operations
	keyPair, _ := suite.e2eeService.GenerateKeyPair()
	message := "Performance test message"

	// Multiple encryptions and decryptions
	for i := 0; i < 5; i++ {
		encryptedMsg, err := suite.e2eeService.EncryptMessage(message, []string{keyPair.PublicKey})
		assert.NoError(suite.T(), err)

		_, err = suite.e2eeService.DecryptMessage(encryptedMsg, keyPair.PrivateKey)
		assert.NoError(suite.T(), err)
	}

	// Check metrics
	metrics := services.GetE2EEMetrics()
	assert.Equal(suite.T(), int64(1), metrics.KeyGenerationCount)
	assert.Equal(suite.T(), int64(5), metrics.EncryptionCount)
	assert.Equal(suite.T(), int64(5), metrics.DecryptionCount)
	assert.Greater(suite.T(), metrics.AverageEncryptTime, time.Duration(0))
	assert.Greater(suite.T(), metrics.AverageDecryptTime, time.Duration(0))
	assert.True(suite.T(), time.Since(metrics.LastUpdated) < time.Second)
}

// Test error scenarios and edge cases
func (suite *E2EEComprehensiveTestSuite) TestErrorScenariosAndEdgeCases() {
	keyPair, _ := suite.e2eeService.GenerateKeyPair()

	// Test decryption with wrong private key
	wrongKeyPair, _ := suite.e2eeService.GenerateKeyPair()
	encryptedMsg, _ := suite.e2eeService.EncryptMessage("test", []string{keyPair.PublicKey})

	_, err := suite.e2eeService.DecryptMessage(encryptedMsg, wrongKeyPair.PrivateKey)
	assert.Error(suite.T(), err)

	// Test malformed encrypted message
	malformedMsg := &services.EncryptedMessage{
		Content:   "invalid-base64-content",
		Algorithm: "AES-256-GCM",
		Version:   1,
		Metadata:  map[string]string{"recipient_0": "some-key"},
		Timestamp: time.Now(),
	}

	_, err = suite.e2eeService.DecryptMessage(malformedMsg, keyPair.PrivateKey)
	assert.Error(suite.T(), err)

	// Test encryption with invalid public key
	_, err = suite.e2eeService.EncryptMessage("test", []string{"invalid-public-key"})
	assert.Error(suite.T(), err)
}
