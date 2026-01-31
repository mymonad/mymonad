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

// =============================================================================
// Solution, Solve, and Verify tests
// =============================================================================

func TestSolveWithLowDifficulty(t *testing.T) {
	// Use low difficulty (8 bits) for fast test execution
	c := NewChallenge("test-resource", 8, 5*time.Minute)

	solution, err := Solve(c)
	if err != nil {
		t.Fatalf("Solve failed: %v", err)
	}

	if solution == nil {
		t.Fatal("Solve returned nil solution")
	}
	if solution.Challenge != c {
		t.Error("Solution should reference the original challenge")
	}
	if solution.Counter < 0 {
		t.Errorf("Counter should be non-negative, got %d", solution.Counter)
	}
	if len(solution.Hash) != 32 {
		t.Errorf("Hash should be 32 bytes (SHA-256), got %d", len(solution.Hash))
	}
}

func TestSolveProducesValidSolution(t *testing.T) {
	// Use low difficulty for fast test
	c := NewChallenge("test-resource", 8, 5*time.Minute)

	solution, err := Solve(c)
	if err != nil {
		t.Fatalf("Solve failed: %v", err)
	}

	// The solution should verify
	if !solution.Verify() {
		t.Error("Solution produced by Solve should verify successfully")
	}
}

func TestSolutionVerifyValid(t *testing.T) {
	// Create a challenge and solve it
	c := NewChallenge("test-resource", 8, 5*time.Minute)

	solution, err := Solve(c)
	if err != nil {
		t.Fatalf("Solve failed: %v", err)
	}

	// Verify should return true
	if !solution.Verify() {
		t.Error("Valid solution should verify successfully")
	}
}

func TestSolutionVerifyInvalidCounter(t *testing.T) {
	// Create a valid solution first
	c := NewChallenge("test-resource", 8, 5*time.Minute)

	solution, err := Solve(c)
	if err != nil {
		t.Fatalf("Solve failed: %v", err)
	}

	// Tamper with the counter
	solution.Counter = solution.Counter + 1

	// Verify should fail (hash no longer matches)
	if solution.Verify() {
		t.Error("Solution with tampered counter should fail verification")
	}
}

func TestSolutionVerifyInvalidHash(t *testing.T) {
	// Create a valid solution first
	c := NewChallenge("test-resource", 8, 5*time.Minute)

	solution, err := Solve(c)
	if err != nil {
		t.Fatalf("Solve failed: %v", err)
	}

	// Tamper with the hash
	if len(solution.Hash) > 0 {
		solution.Hash[0] ^= 0xFF // Flip bits
	}

	// Verify should fail
	if solution.Verify() {
		t.Error("Solution with tampered hash should fail verification")
	}
}

func TestSolutionVerifyNilChallenge(t *testing.T) {
	solution := &Solution{
		Challenge: nil,
		Counter:   12345,
		Hash:      make([]byte, 32),
	}

	// Should not panic, should return false
	if solution.Verify() {
		t.Error("Solution with nil challenge should fail verification")
	}
}

func TestSolutionString(t *testing.T) {
	c := &Challenge{
		Version:    1,
		Bits:       20,
		Timestamp:  time.Unix(1706745600, 0).UTC(),
		Resource:   "did:monad:abc123",
		Rand:       "MTIzNDU2",
		Expiration: 5 * time.Minute,
	}

	solution := &Solution{
		Challenge: c,
		Counter:   12345,
		Hash:      make([]byte, 32),
	}

	s := solution.String()

	// Format should be: challenge:counter
	expected := "1:20:1706745600:did:monad:abc123:MTIzNDU2:12345"
	if s != expected {
		t.Errorf("Solution.String() = %q, want %q", s, expected)
	}
}

func TestSolutionStringWithNilChallenge(t *testing.T) {
	solution := &Solution{
		Challenge: nil,
		Counter:   12345,
		Hash:      make([]byte, 32),
	}

	// Should not panic
	s := solution.String()
	if s != "" {
		t.Errorf("Solution with nil challenge should return empty string, got %q", s)
	}
}

func TestHasLeadingZeros(t *testing.T) {
	testCases := []struct {
		name     string
		hash     []byte
		bits     int
		expected bool
	}{
		{
			name:     "all zeros, 8 bits",
			hash:     []byte{0x00, 0x00, 0x00, 0x00},
			bits:     8,
			expected: true,
		},
		{
			name:     "all zeros, 16 bits",
			hash:     []byte{0x00, 0x00, 0x00, 0x00},
			bits:     16,
			expected: true,
		},
		{
			name:     "first byte zero, 8 bits",
			hash:     []byte{0x00, 0xFF, 0xFF, 0xFF},
			bits:     8,
			expected: true,
		},
		{
			name:     "first byte zero, 9 bits",
			hash:     []byte{0x00, 0x7F, 0xFF, 0xFF}, // 0x7F = 0111 1111, 9th bit is 0
			bits:     9,
			expected: true,
		},
		{
			name:     "first byte zero, 9 bits fail",
			hash:     []byte{0x00, 0x80, 0xFF, 0xFF}, // 0x80 = 1000 0000, 9th bit is 1
			bits:     9,
			expected: false,
		},
		{
			name:     "first 4 bits zero",
			hash:     []byte{0x0F, 0xFF, 0xFF, 0xFF}, // 0x0F = 0000 1111
			bits:     4,
			expected: true,
		},
		{
			name:     "first 5 bits zero",
			hash:     []byte{0x07, 0xFF, 0xFF, 0xFF}, // 0x07 = 0000 0111
			bits:     5,
			expected: true,
		},
		{
			name:     "first 5 bits fail",
			hash:     []byte{0x08, 0xFF, 0xFF, 0xFF}, // 0x08 = 0000 1000
			bits:     5,
			expected: false,
		},
		{
			name:     "0 bits always true",
			hash:     []byte{0xFF, 0xFF, 0xFF, 0xFF},
			bits:     0,
			expected: true,
		},
		{
			name:     "first byte non-zero, 1 bit fail",
			hash:     []byte{0x80, 0xFF, 0xFF, 0xFF},
			bits:     1,
			expected: false,
		},
		{
			name:     "20 bits success",
			hash:     []byte{0x00, 0x00, 0x0F, 0xFF}, // First 20 bits: 0000 0000 0000 0000 0000
			bits:     20,
			expected: true,
		},
		{
			name:     "20 bits fail",
			hash:     []byte{0x00, 0x00, 0x10, 0xFF}, // 0x10 = 0001 0000, 20th bit is 1
			bits:     20,
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := hasLeadingZeros(tc.hash, tc.bits)
			if result != tc.expected {
				t.Errorf("hasLeadingZeros(%v, %d) = %v, want %v",
					tc.hash, tc.bits, result, tc.expected)
			}
		})
	}
}

func TestSolveWithMaxIterations(t *testing.T) {
	// Create a challenge with impossibly high difficulty
	c := NewChallenge("test-resource", 256, 5*time.Minute)

	// Use a lower max for testing
	_, err := SolveWithMaxIterations(c, 10000)
	if err == nil {
		t.Error("Solve with impossibly high difficulty should return error")
	}
	if err != ErrMaxIterationsExceeded {
		t.Errorf("Expected ErrMaxIterationsExceeded, got %v", err)
	}
}

func TestSolveWithNilChallenge(t *testing.T) {
	_, err := Solve(nil)
	if err == nil {
		t.Error("Solve with nil challenge should return error")
	}
	if err != ErrNilChallenge {
		t.Errorf("Expected ErrNilChallenge, got %v", err)
	}
}

func TestSolveDeterministic(t *testing.T) {
	// Same challenge should produce same solution
	c := &Challenge{
		Version:    1,
		Bits:       8,
		Timestamp:  time.Unix(1706745600, 0).UTC(),
		Resource:   "test-resource",
		Rand:       "dGVzdA==", // Fixed rand for deterministic test
		Expiration: 5 * time.Minute,
	}

	solution1, err := Solve(c)
	if err != nil {
		t.Fatalf("Solve failed: %v", err)
	}

	solution2, err := Solve(c)
	if err != nil {
		t.Fatalf("Solve failed: %v", err)
	}

	if solution1.Counter != solution2.Counter {
		t.Errorf("Same challenge should produce same counter: %d vs %d",
			solution1.Counter, solution2.Counter)
	}
}

func TestSolveConcurrent(t *testing.T) {
	var wg sync.WaitGroup
	numGoroutines := 10

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			c := NewChallenge("concurrent-test", 8, 5*time.Minute)
			solution, err := Solve(c)
			if err != nil {
				t.Errorf("Solve %d failed: %v", idx, err)
				return
			}
			if !solution.Verify() {
				t.Errorf("Solution %d failed verification", idx)
			}
		}(i)
	}

	wg.Wait()
}

func TestDifficultyAffectsSolveTime(t *testing.T) {
	// Lower difficulty should be faster than higher difficulty
	// Note: This is a probabilistic test, may occasionally fail

	// Low difficulty (8 bits)
	c1 := NewChallenge("test-resource", 8, 5*time.Minute)
	start1 := time.Now()
	_, err := Solve(c1)
	if err != nil {
		t.Fatalf("Solve with 8 bits failed: %v", err)
	}
	duration1 := time.Since(start1)

	// Higher difficulty (12 bits)
	c2 := NewChallenge("test-resource", 12, 5*time.Minute)
	start2 := time.Now()
	_, err = Solve(c2)
	if err != nil {
		t.Fatalf("Solve with 12 bits failed: %v", err)
	}
	duration2 := time.Since(start2)

	// On average, 12 bits should take 16x longer than 8 bits (2^4)
	// But we just check that both complete successfully
	// The timing comparison is informational
	t.Logf("8-bit solve time: %v", duration1)
	t.Logf("12-bit solve time: %v", duration2)
}

func TestParseSolution(t *testing.T) {
	// Create a valid solution first
	c := NewChallenge("test-resource", 8, 5*time.Minute)
	original, err := Solve(c)
	if err != nil {
		t.Fatalf("Solve failed: %v", err)
	}

	// Parse the solution string
	parsed, err := ParseSolution(original.String())
	if err != nil {
		t.Fatalf("ParseSolution failed: %v", err)
	}

	// Verify parsed solution matches original
	if parsed.Counter != original.Counter {
		t.Errorf("Counter mismatch: got %d, want %d", parsed.Counter, original.Counter)
	}
	if parsed.Challenge.Resource != original.Challenge.Resource {
		t.Errorf("Resource mismatch: got %q, want %q",
			parsed.Challenge.Resource, original.Challenge.Resource)
	}

	// Parsed solution should verify
	if !parsed.Verify() {
		t.Error("Parsed solution should verify successfully")
	}
}

func TestParseSolutionInvalid(t *testing.T) {
	testCases := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"no counter", "1:20:1706745600:resource:rand"},
		{"invalid counter", "1:20:1706745600:resource:rand:abc"},
		{"negative counter", "1:20:1706745600:resource:rand:-1"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseSolution(tc.input)
			if err == nil {
				t.Errorf("ParseSolution(%q) should return error", tc.input)
			}
		})
	}
}

// Benchmarks

func BenchmarkSolve8Bits(b *testing.B) {
	for i := 0; i < b.N; i++ {
		c := NewChallenge("benchmark", 8, 5*time.Minute)
		_, _ = Solve(c)
	}
}

func BenchmarkSolve12Bits(b *testing.B) {
	for i := 0; i < b.N; i++ {
		c := NewChallenge("benchmark", 12, 5*time.Minute)
		_, _ = Solve(c)
	}
}

func BenchmarkSolve16Bits(b *testing.B) {
	for i := 0; i < b.N; i++ {
		c := NewChallenge("benchmark", 16, 5*time.Minute)
		_, _ = Solve(c)
	}
}

func BenchmarkVerify(b *testing.B) {
	c := NewChallenge("benchmark", 16, 5*time.Minute)
	solution, _ := Solve(c)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		solution.Verify()
	}
}

func BenchmarkHasLeadingZeros(b *testing.B) {
	hash := make([]byte, 32)
	for i := 0; i < b.N; i++ {
		hasLeadingZeros(hash, 20)
	}
}
