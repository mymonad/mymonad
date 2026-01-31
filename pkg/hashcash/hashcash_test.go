// Package hashcash provides Proof-of-Work challenge generation and verification
// for spam prevention in the MyMonad P2P protocol.
package hashcash

import (
	"encoding/base64"
	"sync"
	"testing"
	"time"
)

func TestNewChallenge(t *testing.T) {
	resource := "did:monad:abc123"
	bits := 20
	expiration := 5 * time.Minute

	c := NewChallenge(resource, bits, expiration)

	if c == nil {
		t.Fatal("NewChallenge returned nil")
	}
	if c.Version != 1 {
		t.Errorf("Version should be 1, got %d", c.Version)
	}
	if c.Bits != bits {
		t.Errorf("Bits should be %d, got %d", bits, c.Bits)
	}
	if c.Resource != resource {
		t.Errorf("Resource should be %q, got %q", resource, c.Resource)
	}
	if c.Expiration != expiration {
		t.Errorf("Expiration should be %v, got %v", expiration, c.Expiration)
	}
	if c.Rand == "" {
		t.Error("Rand should not be empty")
	}

	// Verify timestamp is recent (within last second)
	if time.Since(c.Timestamp) > time.Second {
		t.Errorf("Timestamp should be recent, got %v", c.Timestamp)
	}
}

func TestNewChallengeRandIsBase64(t *testing.T) {
	c := NewChallenge("test-resource", 20, 5*time.Minute)

	// Rand should be valid base64
	_, err := base64.StdEncoding.DecodeString(c.Rand)
	if err != nil {
		t.Errorf("Rand should be valid base64, got error: %v", err)
	}
}

func TestNewChallengeRandIsUnique(t *testing.T) {
	c1 := NewChallenge("test-resource", 20, 5*time.Minute)
	c2 := NewChallenge("test-resource", 20, 5*time.Minute)

	if c1.Rand == c2.Rand {
		t.Error("Two challenges should have different random components")
	}
}

func TestChallengeString(t *testing.T) {
	c := &Challenge{
		Version:    1,
		Bits:       20,
		Timestamp:  time.Unix(1706745600, 0).UTC(),
		Resource:   "did:monad:abc123",
		Rand:       "MTIzNDU2",
		Expiration: 5 * time.Minute,
	}

	s := c.String()

	// Format: version:bits:timestamp:resource:rand
	// Note: resource can contain colons, so we can't simply count parts
	expected := "1:20:1706745600:did:monad:abc123:MTIzNDU2"
	if s != expected {
		t.Errorf("String() = %q, want %q", s, expected)
	}

	// Verify we can parse it back
	parsed, err := ParseChallenge(s)
	if err != nil {
		t.Fatalf("ParseChallenge failed: %v", err)
	}
	if parsed.Version != c.Version {
		t.Errorf("Version mismatch: got %d, want %d", parsed.Version, c.Version)
	}
	if parsed.Resource != c.Resource {
		t.Errorf("Resource mismatch: got %q, want %q", parsed.Resource, c.Resource)
	}
}

func TestParseChallenge(t *testing.T) {
	input := "1:20:1706745600:did:monad:abc123:MTIzNDU2"

	c, err := ParseChallenge(input)
	if err != nil {
		t.Fatalf("ParseChallenge failed: %v", err)
	}

	if c.Version != 1 {
		t.Errorf("Version should be 1, got %d", c.Version)
	}
	if c.Bits != 20 {
		t.Errorf("Bits should be 20, got %d", c.Bits)
	}
	if c.Timestamp.Unix() != 1706745600 {
		t.Errorf("Timestamp should be 1706745600, got %d", c.Timestamp.Unix())
	}
	if c.Resource != "did:monad:abc123" {
		t.Errorf("Resource should be 'did:monad:abc123', got %q", c.Resource)
	}
	if c.Rand != "MTIzNDU2" {
		t.Errorf("Rand should be 'MTIzNDU2', got %q", c.Rand)
	}
}

func TestParseChallengeInvalidFormat(t *testing.T) {
	testCases := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"too few parts", "1:20:1706745600"},
		{"too few parts 2", "1:20:1706745600:resource"},
		// Note: "too many parts" is valid because resource can contain colons
		// e.g., "1:20:1706745600:resource:rand:extra" parses as resource="resource:rand", rand="extra"
		{"invalid version", "abc:20:1706745600:resource:rand"},
		{"invalid bits", "1:abc:1706745600:resource:rand"},
		{"invalid timestamp", "1:20:abc:resource:rand"},
		{"negative version", "-1:20:1706745600:resource:rand"},
		{"negative bits", "1:-20:1706745600:resource:rand"},
		{"zero bits", "1:0:1706745600:resource:rand"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseChallenge(tc.input)
			if err == nil {
				t.Errorf("ParseChallenge(%q) should return error", tc.input)
			}
		})
	}
}

func TestParseChallengeUnsupportedVersion(t *testing.T) {
	// Only version 1 is supported
	_, err := ParseChallenge("2:20:1706745600:resource:rand")
	if err == nil {
		t.Error("ParseChallenge should return error for unsupported version")
	}
	if err != ErrUnsupportedVersion {
		t.Errorf("Expected ErrUnsupportedVersion, got %v", err)
	}
}

func TestChallengeRoundTrip(t *testing.T) {
	original := NewChallenge("did:monad:test123", 20, 5*time.Minute)

	// Convert to string and back
	s := original.String()
	parsed, err := ParseChallenge(s)
	if err != nil {
		t.Fatalf("ParseChallenge failed: %v", err)
	}

	if parsed.Version != original.Version {
		t.Errorf("Version mismatch: got %d, want %d", parsed.Version, original.Version)
	}
	if parsed.Bits != original.Bits {
		t.Errorf("Bits mismatch: got %d, want %d", parsed.Bits, original.Bits)
	}
	if parsed.Timestamp.Unix() != original.Timestamp.Unix() {
		t.Errorf("Timestamp mismatch: got %d, want %d", parsed.Timestamp.Unix(), original.Timestamp.Unix())
	}
	if parsed.Resource != original.Resource {
		t.Errorf("Resource mismatch: got %q, want %q", parsed.Resource, original.Resource)
	}
	if parsed.Rand != original.Rand {
		t.Errorf("Rand mismatch: got %q, want %q", parsed.Rand, original.Rand)
	}
}

func TestChallengeIsExpired(t *testing.T) {
	// Create a challenge with 1 second expiration
	c := NewChallenge("test-resource", 20, 1*time.Second)

	// Should not be expired immediately
	if c.IsExpired() {
		t.Error("Challenge should not be expired immediately after creation")
	}

	// Wait for expiration
	time.Sleep(1100 * time.Millisecond)

	if !c.IsExpired() {
		t.Error("Challenge should be expired after waiting past expiration duration")
	}
}

func TestChallengeIsExpiredWithOldTimestamp(t *testing.T) {
	c := &Challenge{
		Version:    1,
		Bits:       20,
		Timestamp:  time.Now().Add(-10 * time.Minute),
		Resource:   "test-resource",
		Rand:       "dGVzdA==",
		Expiration: 5 * time.Minute,
	}

	if !c.IsExpired() {
		t.Error("Challenge with old timestamp should be expired")
	}
}

func TestChallengeIsExpiredWithFutureTimestamp(t *testing.T) {
	// Edge case: challenge with future timestamp
	c := &Challenge{
		Version:    1,
		Bits:       20,
		Timestamp:  time.Now().Add(1 * time.Minute), // Future
		Resource:   "test-resource",
		Rand:       "dGVzdA==",
		Expiration: 5 * time.Minute,
	}

	// Future timestamps should not be expired yet
	if c.IsExpired() {
		t.Error("Challenge with future timestamp should not be expired")
	}
}

func TestNewChallengeConcurrent(t *testing.T) {
	var wg sync.WaitGroup
	numGoroutines := 100
	challenges := make([]*Challenge, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			challenges[idx] = NewChallenge("concurrent-test", 20, 5*time.Minute)
		}(i)
	}

	wg.Wait()

	// All challenges should be valid and unique
	randValues := make(map[string]bool)
	for i, c := range challenges {
		if c == nil {
			t.Errorf("Challenge %d is nil", i)
			continue
		}
		if c.Version != 1 {
			t.Errorf("Challenge %d has wrong version: %d", i, c.Version)
		}
		if randValues[c.Rand] {
			t.Errorf("Challenge %d has duplicate Rand value", i)
		}
		randValues[c.Rand] = true
	}
}

func TestDefaultDifficulty(t *testing.T) {
	// Default difficulty should be 20 bits
	if DefaultBits != 20 {
		t.Errorf("DefaultBits should be 20, got %d", DefaultBits)
	}
}

func TestDefaultExpiration(t *testing.T) {
	// Default expiration should be 5 minutes
	if DefaultExpiration != 5*time.Minute {
		t.Errorf("DefaultExpiration should be 5m, got %v", DefaultExpiration)
	}
}

func TestNewDefaultChallenge(t *testing.T) {
	c := NewDefaultChallenge("test-resource")

	if c.Bits != DefaultBits {
		t.Errorf("Bits should be %d, got %d", DefaultBits, c.Bits)
	}
	if c.Expiration != DefaultExpiration {
		t.Errorf("Expiration should be %v, got %v", DefaultExpiration, c.Expiration)
	}
}

func TestChallengeEmptyResource(t *testing.T) {
	// Empty resource should be allowed (though unusual)
	c := NewChallenge("", 20, 5*time.Minute)
	if c == nil {
		t.Fatal("NewChallenge with empty resource should not return nil")
	}
	if c.Resource != "" {
		t.Errorf("Resource should be empty, got %q", c.Resource)
	}

	// Round-trip should work
	parsed, err := ParseChallenge(c.String())
	if err != nil {
		t.Fatalf("ParseChallenge failed for empty resource: %v", err)
	}
	if parsed.Resource != "" {
		t.Errorf("Parsed resource should be empty, got %q", parsed.Resource)
	}
}

func TestChallengeResourceWithSpecialCharacters(t *testing.T) {
	// Resource might contain colons (like DIDs)
	// Note: the format uses colons as separators, so we need to handle this
	resource := "did:monad:abc123"
	c := NewChallenge(resource, 20, 5*time.Minute)

	parsed, err := ParseChallenge(c.String())
	if err != nil {
		t.Fatalf("ParseChallenge failed: %v", err)
	}
	if parsed.Resource != resource {
		t.Errorf("Resource mismatch: got %q, want %q", parsed.Resource, resource)
	}
}

func TestChallengeValidate(t *testing.T) {
	c := NewChallenge("test-resource", 20, 5*time.Minute)

	err := c.Validate()
	if err != nil {
		t.Errorf("Valid challenge should pass validation: %v", err)
	}
}

func TestChallengeValidateInvalid(t *testing.T) {
	testCases := []struct {
		name      string
		challenge *Challenge
	}{
		{
			name: "zero bits",
			challenge: &Challenge{
				Version:    1,
				Bits:       0,
				Timestamp:  time.Now(),
				Resource:   "test",
				Rand:       "dGVzdA==",
				Expiration: 5 * time.Minute,
			},
		},
		{
			name: "negative bits",
			challenge: &Challenge{
				Version:    1,
				Bits:       -1,
				Timestamp:  time.Now(),
				Resource:   "test",
				Rand:       "dGVzdA==",
				Expiration: 5 * time.Minute,
			},
		},
		{
			name: "unsupported version",
			challenge: &Challenge{
				Version:    2,
				Bits:       20,
				Timestamp:  time.Now(),
				Resource:   "test",
				Rand:       "dGVzdA==",
				Expiration: 5 * time.Minute,
			},
		},
		{
			name: "empty rand",
			challenge: &Challenge{
				Version:    1,
				Bits:       20,
				Timestamp:  time.Now(),
				Resource:   "test",
				Rand:       "",
				Expiration: 5 * time.Minute,
			},
		},
		{
			name: "zero expiration",
			challenge: &Challenge{
				Version:    1,
				Bits:       20,
				Timestamp:  time.Now(),
				Resource:   "test",
				Rand:       "dGVzdA==",
				Expiration: 0,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.challenge.Validate()
			if err == nil {
				t.Errorf("Invalid challenge should fail validation")
			}
		})
	}
}

func TestRandSize(t *testing.T) {
	// Rand should be 16 bytes (128 bits) of entropy, base64 encoded
	c := NewChallenge("test", 20, 5*time.Minute)

	decoded, err := base64.StdEncoding.DecodeString(c.Rand)
	if err != nil {
		t.Fatalf("Failed to decode Rand: %v", err)
	}

	if len(decoded) != RandSize {
		t.Errorf("Rand should be %d bytes, got %d", RandSize, len(decoded))
	}
}
