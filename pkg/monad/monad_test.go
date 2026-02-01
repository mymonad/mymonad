package monad

import (
	"math"
	"sync"
	"testing"
	"time"
)

func TestNewMonad(t *testing.T) {
	dims := 384 // Standard embedding dimension
	m := New(dims)

	if m == nil {
		t.Fatal("New returned nil")
	}
	if len(m.Vector) != dims {
		t.Errorf("Vector length: got %d, want %d", len(m.Vector), dims)
	}
	if m.Version != 0 {
		t.Errorf("Initial version should be 0, got %d", m.Version)
	}
	if m.DocCount != 0 {
		t.Errorf("Initial DocCount should be 0, got %d", m.DocCount)
	}
}

func TestNewMonadZeroInitialized(t *testing.T) {
	m := New(10)

	for i, v := range m.Vector {
		if v != 0 {
			t.Errorf("Vector[%d] should be zero-initialized, got %f", i, v)
		}
	}
}

func TestMonadUpdate(t *testing.T) {
	m := New(3)

	// Initial vector is zeros
	for i, v := range m.Vector {
		if v != 0 {
			t.Errorf("Initial vector[%d] should be 0, got %f", i, v)
		}
	}

	// Update with a document embedding
	docEmbedding := []float32{0.5, 0.3, 0.2}
	if err := m.Update(docEmbedding); err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	if m.Version != 1 {
		t.Errorf("Version after update should be 1, got %d", m.Version)
	}
	if m.DocCount != 1 {
		t.Errorf("DocCount after update should be 1, got %d", m.DocCount)
	}

	// Vector should be updated (running average with 1 doc = the doc itself)
	if m.Vector[0] != 0.5 {
		t.Errorf("Vector[0] after first update should be 0.5, got %f", m.Vector[0])
	}
	if m.Vector[1] != 0.3 {
		t.Errorf("Vector[1] after first update should be 0.3, got %f", m.Vector[1])
	}
	if m.Vector[2] != 0.2 {
		t.Errorf("Vector[2] after first update should be 0.2, got %f", m.Vector[2])
	}
}

func TestMonadUpdateRunningAverage(t *testing.T) {
	m := New(3)

	// First update
	if err := m.Update([]float32{1.0, 0.0, 0.0}); err != nil {
		t.Fatalf("First update failed: %v", err)
	}

	// Second update - running average: (1.0 + 0.0) / 2 = 0.5
	if err := m.Update([]float32{0.0, 1.0, 0.0}); err != nil {
		t.Fatalf("Second update failed: %v", err)
	}

	if m.Version != 2 {
		t.Errorf("Version after 2 updates should be 2, got %d", m.Version)
	}
	if m.DocCount != 2 {
		t.Errorf("DocCount after 2 updates should be 2, got %d", m.DocCount)
	}

	expected := []float32{0.5, 0.5, 0.0}
	for i, exp := range expected {
		if math.Abs(float64(m.Vector[i]-exp)) > 0.001 {
			t.Errorf("Vector[%d] after 2 updates should be %f, got %f", i, exp, m.Vector[i])
		}
	}
}

func TestMonadUpdateDimensionMismatch(t *testing.T) {
	m := New(3)

	// Try to update with wrong dimension - should return error
	err := m.Update([]float32{1.0, 2.0}) // Only 2 elements

	if err == nil {
		t.Error("Update should return error on dimension mismatch")
	}
	if err != ErrDimensionMismatch {
		t.Errorf("Update should return ErrDimensionMismatch, got %v", err)
	}
	if m.Version != 0 {
		t.Errorf("Version should remain 0 on dimension mismatch, got %d", m.Version)
	}
	if m.DocCount != 0 {
		t.Errorf("DocCount should remain 0 on dimension mismatch, got %d", m.DocCount)
	}
}

func TestMonadCosineSimilarity(t *testing.T) {
	a := New(3)
	a.Vector = []float32{1, 0, 0}

	b := New(3)
	b.Vector = []float32{1, 0, 0}

	sim := a.CosineSimilarity(b)
	if sim < 0.999 {
		t.Errorf("Identical vectors should have similarity ~1.0, got %f", sim)
	}

	// Orthogonal vectors
	c := New(3)
	c.Vector = []float32{0, 1, 0}

	sim = a.CosineSimilarity(c)
	if sim > 0.001 {
		t.Errorf("Orthogonal vectors should have similarity ~0, got %f", sim)
	}
}

func TestMonadCosineSimilarityOpposite(t *testing.T) {
	a := New(3)
	a.Vector = []float32{1, 0, 0}

	b := New(3)
	b.Vector = []float32{-1, 0, 0}

	sim := a.CosineSimilarity(b)
	if sim > -0.999 {
		t.Errorf("Opposite vectors should have similarity ~-1.0, got %f", sim)
	}
}

func TestMonadCosineSimilarityZeroVector(t *testing.T) {
	a := New(3)
	a.Vector = []float32{1, 0, 0}

	b := New(3)
	// b.Vector is all zeros

	sim := a.CosineSimilarity(b)
	if sim != 0 {
		t.Errorf("Similarity with zero vector should be 0, got %f", sim)
	}
}

func TestMonadCosineSimilarityDimensionMismatch(t *testing.T) {
	a := New(3)
	a.Vector = []float32{1, 0, 0}

	b := New(4)
	b.Vector = []float32{1, 0, 0, 0}

	sim := a.CosineSimilarity(b)
	if sim != 0 {
		t.Errorf("Similarity with dimension mismatch should be 0, got %f", sim)
	}
}

func TestMonadClone(t *testing.T) {
	m := New(3)
	if err := m.Update([]float32{0.5, 0.3, 0.2}); err != nil {
		t.Fatalf("First update failed: %v", err)
	}
	if err := m.Update([]float32{0.1, 0.4, 0.5}); err != nil {
		t.Fatalf("Second update failed: %v", err)
	}

	clone := m.Clone()

	// Verify clone has same values
	if clone.Version != m.Version {
		t.Errorf("Clone version mismatch: got %d, want %d", clone.Version, m.Version)
	}
	if clone.DocCount != m.DocCount {
		t.Errorf("Clone DocCount mismatch: got %d, want %d", clone.DocCount, m.DocCount)
	}
	if len(clone.Vector) != len(m.Vector) {
		t.Errorf("Clone vector length mismatch: got %d, want %d", len(clone.Vector), len(m.Vector))
	}

	for i := range m.Vector {
		if clone.Vector[i] != m.Vector[i] {
			t.Errorf("Clone vector[%d] mismatch: got %f, want %f", i, clone.Vector[i], m.Vector[i])
		}
	}
}

func TestMonadCloneIndependence(t *testing.T) {
	m := New(3)
	if err := m.Update([]float32{1.0, 0.0, 0.0}); err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	clone := m.Clone()

	// Modify clone
	clone.Vector[0] = 999.0
	clone.Version = 999

	// Original should be unchanged
	if m.Vector[0] == 999.0 {
		t.Error("Original vector was modified when clone was changed - not a deep copy")
	}
	if m.Version == 999 {
		t.Error("Original version was modified when clone was changed - not a deep copy")
	}
}

func TestMonadConcurrentUpdates(t *testing.T) {
	m := New(3)

	var wg sync.WaitGroup
	numGoroutines := 100

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			embedding := []float32{float32(idx % 10) / 10.0, 0.5, 0.5}
			if err := m.Update(embedding); err != nil {
				t.Errorf("Update failed: %v", err)
			}
		}(i)
	}

	wg.Wait()

	if m.DocCount != int64(numGoroutines) {
		t.Errorf("DocCount should be %d after concurrent updates, got %d", numGoroutines, m.DocCount)
	}
	if m.Version != int64(numGoroutines) {
		t.Errorf("Version should be %d after concurrent updates, got %d", numGoroutines, m.Version)
	}
}

func TestMonadConcurrentReads(t *testing.T) {
	m := New(3)
	if err := m.Update([]float32{1.0, 0.0, 0.0}); err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	other := New(3)
	other.Vector = []float32{0.5, 0.5, 0.0}

	var wg sync.WaitGroup
	numGoroutines := 100

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = m.CosineSimilarity(other)
			_ = m.Clone()
		}()
	}

	wg.Wait()
	// If we get here without deadlock or panic, test passes
}

func TestMonadDimensions(t *testing.T) {
	dims := 384
	m := New(dims)

	if m.Dimensions() != dims {
		t.Errorf("Dimensions() should return %d, got %d", dims, m.Dimensions())
	}
}

func TestMonad_MarshalUnmarshal(t *testing.T) {
	m := New(384)
	if err := m.Update(make([]float32, 384)); err != nil {
		t.Fatalf("First update failed: %v", err)
	}
	if err := m.Update(make([]float32, 384)); err != nil {
		t.Fatalf("Second update failed: %v", err)
	}

	data, err := m.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	m2 := &Monad{}
	if err := m2.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary failed: %v", err)
	}

	// Verify version matches
	if m2.Version != m.Version {
		t.Errorf("Version mismatch: got %d, want %d", m2.Version, m.Version)
	}

	// Verify doccount matches
	if m2.DocCount != m.DocCount {
		t.Errorf("DocCount mismatch: got %d, want %d", m2.DocCount, m.DocCount)
	}

	// Verify vector length matches
	if len(m2.Vector) != len(m.Vector) {
		t.Errorf("Vector length mismatch: got %d, want %d", len(m2.Vector), len(m.Vector))
	}

	// Verify UpdatedAt matches (within nanosecond precision via UnixNano)
	if !m2.UpdatedAt.Equal(m.UpdatedAt) {
		t.Errorf("UpdatedAt mismatch: got %v, want %v", m2.UpdatedAt, m.UpdatedAt)
	}

	// Verify vector values match
	for i := range m.Vector {
		if m2.Vector[i] != m.Vector[i] {
			t.Errorf("Vector[%d] mismatch: got %f, want %f", i, m2.Vector[i], m.Vector[i])
		}
	}
}

func TestMonad_MarshalBinaryFormat(t *testing.T) {
	m := New(3)
	m.Vector = []float32{1.0, 2.0, 3.0}
	m.Version = 42
	m.DocCount = 10

	data, err := m.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	// Expected format: version(8) + doccount(8) + updatedat(8) + dims(4) + vector(dims*4)
	// = 8 + 8 + 8 + 4 + 3*4 = 40 bytes
	expectedLen := 8 + 8 + 8 + 4 + 3*4
	if len(data) != expectedLen {
		t.Errorf("Binary data length: got %d, want %d", len(data), expectedLen)
	}
}

func TestMonad_UnmarshalBinaryInvalidData(t *testing.T) {
	m := &Monad{}

	// Test with empty data
	err := m.UnmarshalBinary([]byte{})
	if err == nil {
		t.Error("UnmarshalBinary should fail with empty data")
	}

	// Test with too short data (missing header)
	err = m.UnmarshalBinary(make([]byte, 10))
	if err == nil {
		t.Error("UnmarshalBinary should fail with incomplete header")
	}

	// Test with header but missing vector data
	// Header is 28 bytes, but claims to have 100 dimensions
	shortData := make([]byte, 28)
	// Set dimensions to 100 at offset 24
	shortData[24] = 100
	shortData[25] = 0
	shortData[26] = 0
	shortData[27] = 0
	err = m.UnmarshalBinary(shortData)
	if err == nil {
		t.Error("UnmarshalBinary should fail with missing vector data")
	}
}

func TestMonad_MarshalUnmarshalWithNonZeroVector(t *testing.T) {
	m := New(5)
	m.Vector = []float32{0.1, 0.2, 0.3, 0.4, 0.5}
	m.Version = 123
	m.DocCount = 456

	data, err := m.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	m2 := &Monad{}
	if err := m2.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary failed: %v", err)
	}

	// Verify all vector values
	for i, expected := range []float32{0.1, 0.2, 0.3, 0.4, 0.5} {
		if m2.Vector[i] != expected {
			t.Errorf("Vector[%d] mismatch: got %f, want %f", i, m2.Vector[i], expected)
		}
	}
}

func TestMonad_SaveLoadFile(t *testing.T) {
	// Create a temp directory for test files
	tmpDir := t.TempDir()
	filePath := tmpDir + "/test_monad.bin"

	m := New(384)
	if err := m.Update(make([]float32, 384)); err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	m.Vector[0] = 1.5
	m.Vector[100] = 2.5
	m.Vector[383] = 3.5

	// Save to file
	if err := SaveToFile(m, filePath); err != nil {
		t.Fatalf("SaveToFile failed: %v", err)
	}

	// Load from file
	loaded, err := LoadFromFile(filePath)
	if err != nil {
		t.Fatalf("LoadFromFile failed: %v", err)
	}

	// Verify data
	if loaded.Version != m.Version {
		t.Errorf("Version mismatch: got %d, want %d", loaded.Version, m.Version)
	}
	if loaded.DocCount != m.DocCount {
		t.Errorf("DocCount mismatch: got %d, want %d", loaded.DocCount, m.DocCount)
	}
	if len(loaded.Vector) != len(m.Vector) {
		t.Errorf("Vector length mismatch: got %d, want %d", len(loaded.Vector), len(m.Vector))
	}
	if loaded.Vector[0] != 1.5 {
		t.Errorf("Vector[0] mismatch: got %f, want 1.5", loaded.Vector[0])
	}
	if loaded.Vector[100] != 2.5 {
		t.Errorf("Vector[100] mismatch: got %f, want 2.5", loaded.Vector[100])
	}
	if loaded.Vector[383] != 3.5 {
		t.Errorf("Vector[383] mismatch: got %f, want 3.5", loaded.Vector[383])
	}
}

func TestMonad_LoadFromFileNotFound(t *testing.T) {
	_, err := LoadFromFile("/nonexistent/path/monad.bin")
	if err == nil {
		t.Error("LoadFromFile should fail for non-existent file")
	}
}

func TestMonad_SaveToFileAtomicity(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := tmpDir + "/atomic_test.bin"

	m := New(10)
	m.Vector[0] = 42.0

	// Save the file
	if err := SaveToFile(m, filePath); err != nil {
		t.Fatalf("SaveToFile failed: %v", err)
	}

	// Verify file exists and is valid
	loaded, err := LoadFromFile(filePath)
	if err != nil {
		t.Fatalf("LoadFromFile failed: %v", err)
	}

	if loaded.Vector[0] != 42.0 {
		t.Errorf("Vector[0] mismatch: got %f, want 42.0", loaded.Vector[0])
	}
}

func TestMonad_MarshalUnmarshalLargeVector(t *testing.T) {
	// Test with a larger vector to ensure no buffer issues
	dims := 1536 // Common large embedding size
	m := New(dims)
	for i := range m.Vector {
		m.Vector[i] = float32(i) / float32(dims)
	}
	m.Version = 999
	m.DocCount = 1000

	data, err := m.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	m2 := &Monad{}
	if err := m2.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary failed: %v", err)
	}

	if len(m2.Vector) != dims {
		t.Errorf("Vector length mismatch: got %d, want %d", len(m2.Vector), dims)
	}

	for i := range m.Vector {
		if m2.Vector[i] != m.Vector[i] {
			t.Errorf("Vector[%d] mismatch: got %f, want %f", i, m2.Vector[i], m.Vector[i])
		}
	}
}

func TestUpdateWithDecay(t *testing.T) {
	m := New(3)

	// First update - no decay (fresh monad)
	err := m.UpdateWithDecay([]float32{1.0, 0.0, 0.0}, 0.01)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if m.GetDocCount() != 1 {
		t.Errorf("expected doc count 1, got %d", m.GetDocCount())
	}

	// Vector should be approximately [1, 0, 0]
	if m.Vector[0] < 0.9 {
		t.Errorf("expected Vector[0] near 1.0, got %f", m.Vector[0])
	}
}

func TestUpdateWithDecay_OldDataDecays(t *testing.T) {
	m := New(3)

	// Simulate old data by setting UpdatedAt in the past
	m.Vector = []float32{1.0, 0.0, 0.0}
	m.DocCount = 1
	m.UpdatedAt = time.Now().Add(-70 * 24 * time.Hour) // 70 days ago

	// Update with lambda=0.01 (half-life ~70 days)
	// Old vector should decay by ~50%
	err := m.UpdateWithDecay([]float32{0.0, 1.0, 0.0}, 0.01)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Old component should be decayed
	if m.Vector[0] > 0.6 {
		t.Errorf("expected Vector[0] to decay below 0.6, got %f", m.Vector[0])
	}

	// New component should have weight
	if m.Vector[1] < 0.3 {
		t.Errorf("expected Vector[1] above 0.3, got %f", m.Vector[1])
	}
}

func TestUpdateWithDecay_DimensionMismatch(t *testing.T) {
	m := New(3)
	err := m.UpdateWithDecay([]float32{1.0, 2.0}, 0.01) // Wrong dimension
	if err != ErrDimensionMismatch {
		t.Errorf("expected ErrDimensionMismatch, got %v", err)
	}
}
