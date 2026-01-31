package monad

import (
	"math"
	"sync"
	"testing"
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
