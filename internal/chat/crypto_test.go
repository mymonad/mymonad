package chat

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// TestDeriveKey_Deterministic verifies that same inputs produce same key.
func TestDeriveKey_Deterministic(t *testing.T) {
	// Generate a shared secret
	sharedSecret := make([]byte, 32)
	if _, err := rand.Read(sharedSecret); err != nil {
		t.Fatalf("failed to generate shared secret: %v", err)
	}

	// Generate a session ID
	sessionID := make([]byte, 16)
	if _, err := rand.Read(sessionID); err != nil {
		t.Fatalf("failed to generate session ID: %v", err)
	}

	// Derive key twice with same inputs
	key1, err := DeriveKey(sharedSecret, sessionID)
	if err != nil {
		t.Fatalf("first DeriveKey failed: %v", err)
	}

	key2, err := DeriveKey(sharedSecret, sessionID)
	if err != nil {
		t.Fatalf("second DeriveKey failed: %v", err)
	}

	// Keys must be identical
	if !bytes.Equal(key1, key2) {
		t.Error("DeriveKey is not deterministic: same inputs produced different keys")
	}

	// Key must be correct length
	if len(key1) != ChatKeyLength {
		t.Errorf("DeriveKey returned wrong key length: got %d, want %d", len(key1), ChatKeyLength)
	}
}

// TestDeriveKey_SessionBinding verifies that different sessions produce different keys.
func TestDeriveKey_SessionBinding(t *testing.T) {
	// Generate a shared secret
	sharedSecret := make([]byte, 32)
	if _, err := rand.Read(sharedSecret); err != nil {
		t.Fatalf("failed to generate shared secret: %v", err)
	}

	// Generate two different session IDs
	sessionID1 := make([]byte, 16)
	sessionID2 := make([]byte, 16)
	if _, err := rand.Read(sessionID1); err != nil {
		t.Fatalf("failed to generate session ID 1: %v", err)
	}
	if _, err := rand.Read(sessionID2); err != nil {
		t.Fatalf("failed to generate session ID 2: %v", err)
	}

	// Derive keys with different session IDs
	key1, err := DeriveKey(sharedSecret, sessionID1)
	if err != nil {
		t.Fatalf("first DeriveKey failed: %v", err)
	}

	key2, err := DeriveKey(sharedSecret, sessionID2)
	if err != nil {
		t.Fatalf("second DeriveKey failed: %v", err)
	}

	// Keys must be different
	if bytes.Equal(key1, key2) {
		t.Error("DeriveKey produced same key for different sessions")
	}
}

// TestDeriveKey_SecretBinding verifies that different shared secrets produce different keys.
func TestDeriveKey_SecretBinding(t *testing.T) {
	// Generate two different shared secrets
	sharedSecret1 := make([]byte, 32)
	sharedSecret2 := make([]byte, 32)
	if _, err := rand.Read(sharedSecret1); err != nil {
		t.Fatalf("failed to generate shared secret 1: %v", err)
	}
	if _, err := rand.Read(sharedSecret2); err != nil {
		t.Fatalf("failed to generate shared secret 2: %v", err)
	}

	// Same session ID
	sessionID := make([]byte, 16)
	if _, err := rand.Read(sessionID); err != nil {
		t.Fatalf("failed to generate session ID: %v", err)
	}

	// Derive keys with different shared secrets
	key1, err := DeriveKey(sharedSecret1, sessionID)
	if err != nil {
		t.Fatalf("first DeriveKey failed: %v", err)
	}

	key2, err := DeriveKey(sharedSecret2, sessionID)
	if err != nil {
		t.Fatalf("second DeriveKey failed: %v", err)
	}

	// Keys must be different
	if bytes.Equal(key1, key2) {
		t.Error("DeriveKey produced same key for different shared secrets")
	}
}

// TestDeriveKey_InvalidInputs verifies error handling for invalid inputs.
func TestDeriveKey_InvalidInputs(t *testing.T) {
	validSecret := make([]byte, 32)
	validSession := make([]byte, 16)
	rand.Read(validSecret)
	rand.Read(validSession)

	tests := []struct {
		name         string
		sharedSecret []byte
		sessionID    []byte
		wantErr      bool
	}{
		{
			name:         "nil shared secret",
			sharedSecret: nil,
			sessionID:    validSession,
			wantErr:      true,
		},
		{
			name:         "empty shared secret",
			sharedSecret: []byte{},
			sessionID:    validSession,
			wantErr:      true,
		},
		{
			name:         "nil session ID",
			sharedSecret: validSecret,
			sessionID:    nil,
			wantErr:      true,
		},
		{
			name:         "empty session ID",
			sharedSecret: validSecret,
			sessionID:    []byte{},
			wantErr:      true,
		},
		{
			name:         "valid inputs",
			sharedSecret: validSecret,
			sessionID:    validSession,
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DeriveKey(tt.sharedSecret, tt.sessionID)
			if (err != nil) != tt.wantErr {
				t.Errorf("DeriveKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestEncryptDecrypt_RoundTrip verifies that encrypt then decrypt recovers plaintext.
func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	// Generate a key
	key := make([]byte, ChatKeyLength)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	testCases := []struct {
		name      string
		plaintext []byte
	}{
		{"empty message", []byte{}},
		{"short message", []byte("hello")},
		{"longer message", []byte("This is a longer test message for encryption")},
		{"binary data", []byte{0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd}},
		{"unicode message", []byte("Hello, World")},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ciphertext, err := Encrypt(key, tc.plaintext)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}

			decrypted, err := Decrypt(key, ciphertext)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}

			if !bytes.Equal(decrypted, tc.plaintext) {
				t.Errorf("round-trip failed: got %v, want %v", decrypted, tc.plaintext)
			}
		})
	}
}

// TestEncrypt_NonceUniqueness verifies that each encryption produces unique ciphertext.
func TestEncrypt_NonceUniqueness(t *testing.T) {
	key := make([]byte, ChatKeyLength)
	rand.Read(key)

	plaintext := []byte("same message")

	// Encrypt same message twice
	ciphertext1, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("first Encrypt failed: %v", err)
	}

	ciphertext2, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("second Encrypt failed: %v", err)
	}

	// Ciphertexts should be different (due to random nonce)
	if bytes.Equal(ciphertext1, ciphertext2) {
		t.Error("Encrypt produced identical ciphertext for same plaintext (nonce reuse)")
	}
}

// TestDecrypt_TamperedCiphertext verifies that tampered ciphertext fails decryption.
func TestDecrypt_TamperedCiphertext(t *testing.T) {
	key := make([]byte, ChatKeyLength)
	rand.Read(key)

	plaintext := []byte("secret message")
	ciphertext, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Tamper with different parts of the ciphertext
	tests := []struct {
		name    string
		tamper  func([]byte) []byte
	}{
		{
			name: "flip bit in nonce",
			tamper: func(ct []byte) []byte {
				tampered := make([]byte, len(ct))
				copy(tampered, ct)
				tampered[0] ^= 0x01
				return tampered
			},
		},
		{
			name: "flip bit in ciphertext body",
			tamper: func(ct []byte) []byte {
				tampered := make([]byte, len(ct))
				copy(tampered, ct)
				// Tamper with byte after nonce
				tampered[NonceLength] ^= 0x01
				return tampered
			},
		},
		{
			name: "flip bit in auth tag",
			tamper: func(ct []byte) []byte {
				tampered := make([]byte, len(ct))
				copy(tampered, ct)
				// Tamper with last byte (part of auth tag)
				tampered[len(tampered)-1] ^= 0x01
				return tampered
			},
		},
		{
			name: "truncate ciphertext",
			tamper: func(ct []byte) []byte {
				return ct[:len(ct)-5]
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tampered := tt.tamper(ciphertext)
			_, err := Decrypt(key, tampered)
			if err == nil {
				t.Error("Decrypt should fail on tampered ciphertext")
			}
		})
	}
}

// TestDecrypt_WrongKey verifies that wrong key fails decryption.
func TestDecrypt_WrongKey(t *testing.T) {
	key1 := make([]byte, ChatKeyLength)
	key2 := make([]byte, ChatKeyLength)
	rand.Read(key1)
	rand.Read(key2)

	plaintext := []byte("secret message")
	ciphertext, err := Encrypt(key1, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Try to decrypt with wrong key
	_, err = Decrypt(key2, ciphertext)
	if err == nil {
		t.Error("Decrypt should fail with wrong key")
	}
}

// TestDecrypt_WrongNonce verifies that wrong nonce fails decryption.
func TestDecrypt_WrongNonce(t *testing.T) {
	key := make([]byte, ChatKeyLength)
	rand.Read(key)

	plaintext := []byte("secret message")
	ciphertext, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Corrupt the nonce (first NonceLength bytes)
	corrupted := make([]byte, len(ciphertext))
	copy(corrupted, ciphertext)
	for i := 0; i < NonceLength; i++ {
		corrupted[i] = 0xFF
	}

	_, err = Decrypt(key, corrupted)
	if err == nil {
		t.Error("Decrypt should fail with wrong nonce")
	}
}

// TestDecrypt_InvalidInputs verifies error handling for invalid inputs.
func TestDecrypt_InvalidInputs(t *testing.T) {
	validKey := make([]byte, ChatKeyLength)
	rand.Read(validKey)

	tests := []struct {
		name       string
		key        []byte
		ciphertext []byte
		wantErr    bool
	}{
		{
			name:       "nil key",
			key:        nil,
			ciphertext: make([]byte, NonceLength+16),
			wantErr:    true,
		},
		{
			name:       "wrong key length",
			key:        make([]byte, 16),
			ciphertext: make([]byte, NonceLength+16),
			wantErr:    true,
		},
		{
			name:       "nil ciphertext",
			key:        validKey,
			ciphertext: nil,
			wantErr:    true,
		},
		{
			name:       "ciphertext too short for nonce",
			key:        validKey,
			ciphertext: make([]byte, NonceLength-1),
			wantErr:    true,
		},
		{
			name:       "ciphertext too short for auth tag",
			key:        validKey,
			ciphertext: make([]byte, NonceLength+15), // GCM tag is 16 bytes
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Decrypt(tt.key, tt.ciphertext)
			if (err != nil) != tt.wantErr {
				t.Errorf("Decrypt() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestEncrypt_InvalidInputs verifies error handling for invalid inputs.
func TestEncrypt_InvalidInputs(t *testing.T) {
	validKey := make([]byte, ChatKeyLength)
	rand.Read(validKey)

	tests := []struct {
		name      string
		key       []byte
		plaintext []byte
		wantErr   bool
	}{
		{
			name:      "nil key",
			key:       nil,
			plaintext: []byte("hello"),
			wantErr:   true,
		},
		{
			name:      "wrong key length",
			key:       make([]byte, 16),
			plaintext: []byte("hello"),
			wantErr:   true,
		},
		{
			name:      "message too large",
			key:       validKey,
			plaintext: make([]byte, MaxMessageSize+1),
			wantErr:   true,
		},
		{
			name:      "valid empty message",
			key:       validKey,
			plaintext: []byte{},
			wantErr:   false,
		},
		{
			name:      "valid max size message",
			key:       validKey,
			plaintext: make([]byte, MaxMessageSize),
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Encrypt(tt.key, tt.plaintext)
			if (err != nil) != tt.wantErr {
				t.Errorf("Encrypt() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestCiphertextFormat verifies the ciphertext structure.
func TestCiphertextFormat(t *testing.T) {
	key := make([]byte, ChatKeyLength)
	rand.Read(key)

	plaintext := []byte("test")
	ciphertext, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Ciphertext format: nonce (12 bytes) + encrypted data + auth tag (16 bytes)
	// Expected length: NonceLength + len(plaintext) + 16 (GCM tag)
	expectedLen := NonceLength + len(plaintext) + 16
	if len(ciphertext) != expectedLen {
		t.Errorf("ciphertext length: got %d, want %d", len(ciphertext), expectedLen)
	}
}
