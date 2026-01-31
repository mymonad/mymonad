package lsh

import (
	"math"
	"sync"
	"testing"
	"time"

	"github.com/mymonad/mymonad/pkg/monad"
)

// ============================================================
// Generator Tests
// ============================================================

func TestNewGenerator(t *testing.T) {
	numHashes := 256
	dimensions := 384
	seed := int64(42)

	gen := NewGenerator(numHashes, dimensions, seed)

	if gen == nil {
		t.Fatal("NewGenerator returned nil")
	}
	if gen.numHashes != numHashes {
		t.Errorf("numHashes: got %d, want %d", gen.numHashes, numHashes)
	}
	if gen.lsh == nil {
		t.Error("Generator should have LSH instance")
	}
	if gen.lsh.NumHashes() != numHashes {
		t.Errorf("LSH numHashes: got %d, want %d", gen.lsh.NumHashes(), numHashes)
	}
	if gen.lsh.Dimensions() != dimensions {
		t.Errorf("LSH dimensions: got %d, want %d", gen.lsh.Dimensions(), dimensions)
	}
}

func TestNewGeneratorDeterministic(t *testing.T) {
	numHashes := 128
	dimensions := 100
	seed := int64(12345)

	gen1 := NewGenerator(numHashes, dimensions, seed)
	gen2 := NewGenerator(numHashes, dimensions, seed)

	// Create a test monad
	m := monad.New(dimensions)
	for i := 0; i < dimensions; i++ {
		m.Vector[i] = float32(i) / float32(dimensions)
	}

	sig1 := gen1.Generate(m)
	sig2 := gen2.Generate(m)

	// Same seed should produce identical signatures
	for i := 0; i < sig1.Signature.Size; i++ {
		if sig1.Signature.GetBit(i) != sig2.Signature.GetBit(i) {
			t.Errorf("Bit %d differs between generators with same seed", i)
			return
		}
	}
}

// ============================================================
// Generate Tests
// ============================================================

func TestGeneratorGenerate(t *testing.T) {
	numHashes := 256
	dimensions := 384
	seed := int64(42)

	gen := NewGenerator(numHashes, dimensions, seed)
	m := monad.New(dimensions)

	// Add some embeddings
	for i := 0; i < 5; i++ {
		embedding := make([]float32, dimensions)
		for j := range embedding {
			embedding[j] = float32((i*10 + j) % 100) / 100.0
		}
		if err := m.Update(embedding); err != nil {
			t.Fatalf("Update failed: %v", err)
		}
	}

	sig := gen.Generate(m)

	if sig == nil {
		t.Fatal("Generate returned nil")
	}
	if sig.Signature.Size != numHashes {
		t.Errorf("Signature size: got %d, want %d", sig.Signature.Size, numHashes)
	}
	if sig.Version != m.Version {
		t.Errorf("Version: got %d, want %d", sig.Version, m.Version)
	}
	if sig.Dimensions != dimensions {
		t.Errorf("Dimensions: got %d, want %d", sig.Dimensions, dimensions)
	}
	if sig.NumHashes != numHashes {
		t.Errorf("NumHashes: got %d, want %d", sig.NumHashes, numHashes)
	}
	if sig.GeneratedAt.IsZero() {
		t.Error("GeneratedAt should not be zero")
	}
	if time.Since(sig.GeneratedAt) > time.Second {
		t.Error("GeneratedAt should be recent")
	}
}

func TestGeneratorGenerateNilMonad(t *testing.T) {
	gen := NewGenerator(256, 384, 42)

	sig := gen.Generate(nil)

	if sig != nil {
		t.Error("Generate(nil) should return nil")
	}
}

func TestGeneratorGenerateDimensionMismatch(t *testing.T) {
	gen := NewGenerator(256, 384, 42)
	m := monad.New(100) // Different dimensions

	sig := gen.Generate(m)

	if sig != nil {
		t.Error("Generate with dimension mismatch should return nil")
	}
}

func TestGeneratorGenerateDeterministic(t *testing.T) {
	gen := NewGenerator(128, 50, 42)
	m := monad.New(50)

	for i := 0; i < 50; i++ {
		m.Vector[i] = float32(i) / 50.0
	}

	sig1 := gen.Generate(m)
	sig2 := gen.Generate(m)

	// Same monad should produce same signature
	for i := 0; i < sig1.Signature.Size; i++ {
		if sig1.Signature.GetBit(i) != sig2.Signature.GetBit(i) {
			t.Errorf("Bit %d differs between repeated generations", i)
			return
		}
	}
}

func TestGeneratorGenerateZeroVector(t *testing.T) {
	gen := NewGenerator(64, 10, 42)
	m := monad.New(10)
	// Vector is zero-initialized

	sig := gen.Generate(m)

	if sig == nil {
		t.Fatal("Generate with zero vector should return valid signature")
	}
	if sig.Signature.Size != 64 {
		t.Errorf("Signature size: got %d, want 64", sig.Signature.Size)
	}
}

// ============================================================
// SimilarityEstimate Tests
// ============================================================

func TestSimilarityEstimateIdentical(t *testing.T) {
	gen := NewGenerator(256, 100, 42)

	// Create identical monads
	m1 := monad.New(100)
	m2 := monad.New(100)

	for i := 0; i < 100; i++ {
		m1.Vector[i] = float32(i) / 100.0
		m2.Vector[i] = float32(i) / 100.0
	}

	sig1 := gen.Generate(m1)
	sig2 := gen.Generate(m2)

	estimate := sig1.SimilarityEstimate(sig2)

	// Identical vectors should have similarity ~1.0
	if estimate < 0.99 {
		t.Errorf("Identical vectors should have similarity ~1.0, got %f", estimate)
	}
}

func TestSimilarityEstimateOpposite(t *testing.T) {
	gen := NewGenerator(256, 100, 42)

	m1 := monad.New(100)
	m2 := monad.New(100)

	for i := 0; i < 100; i++ {
		m1.Vector[i] = float32(i) / 100.0
		m2.Vector[i] = -float32(i) / 100.0 // Opposite vector
	}

	sig1 := gen.Generate(m1)
	sig2 := gen.Generate(m2)

	estimate := sig1.SimilarityEstimate(sig2)

	// Opposite vectors should have similarity ~-1.0
	if estimate > -0.99 {
		t.Errorf("Opposite vectors should have similarity ~-1.0, got %f", estimate)
	}
}

func TestSimilarityEstimateOrthogonal(t *testing.T) {
	gen := NewGenerator(512, 3, 42)

	m1 := monad.New(3)
	m1.Vector = []float32{1, 0, 0}

	m2 := monad.New(3)
	m2.Vector = []float32{0, 1, 0}

	sig1 := gen.Generate(m1)
	sig2 := gen.Generate(m2)

	estimate := sig1.SimilarityEstimate(sig2)

	// Orthogonal vectors should have similarity ~0
	if math.Abs(float64(estimate)) > 0.2 {
		t.Errorf("Orthogonal vectors should have similarity ~0, got %f", estimate)
	}
}

func TestSimilarityEstimateSimilarVectors(t *testing.T) {
	gen := NewGenerator(256, 100, 42)

	m1 := monad.New(100)
	m2 := monad.New(100)

	for i := 0; i < 100; i++ {
		m1.Vector[i] = float32(i) / 100.0
		m2.Vector[i] = float32(i)/100.0 + 0.05 // Small perturbation
	}

	sig1 := gen.Generate(m1)
	sig2 := gen.Generate(m2)

	estimate := sig1.SimilarityEstimate(sig2)

	// Very similar vectors should have high similarity
	if estimate < 0.8 {
		t.Errorf("Similar vectors should have high similarity, got %f", estimate)
	}
}

func TestSimilarityEstimateNil(t *testing.T) {
	gen := NewGenerator(128, 50, 42)
	m := monad.New(50)
	for i := 0; i < 50; i++ {
		m.Vector[i] = float32(i) / 50.0
	}

	sig := gen.Generate(m)

	estimate := sig.SimilarityEstimate(nil)

	if estimate != 0 {
		t.Errorf("SimilarityEstimate with nil should return 0, got %f", estimate)
	}
}

func TestSimilarityEstimateDifferentSizes(t *testing.T) {
	gen1 := NewGenerator(128, 50, 42)
	gen2 := NewGenerator(256, 50, 42)

	m := monad.New(50)
	for i := 0; i < 50; i++ {
		m.Vector[i] = float32(i) / 50.0
	}

	sig1 := gen1.Generate(m)
	sig2 := gen2.Generate(m)

	estimate := sig1.SimilarityEstimate(sig2)

	// Different signature sizes should return 0
	if estimate != 0 {
		t.Errorf("SimilarityEstimate with different sizes should return 0, got %f", estimate)
	}
}

func TestSimilarityEstimateSymmetric(t *testing.T) {
	gen := NewGenerator(256, 50, 42)

	m1 := monad.New(50)
	m2 := monad.New(50)

	for i := 0; i < 50; i++ {
		m1.Vector[i] = float32(i) / 50.0
		m2.Vector[i] = float32(50-i) / 50.0
	}

	sig1 := gen.Generate(m1)
	sig2 := gen.Generate(m2)

	estimate12 := sig1.SimilarityEstimate(sig2)
	estimate21 := sig2.SimilarityEstimate(sig1)

	// Similarity should be symmetric
	if math.Abs(float64(estimate12-estimate21)) > 0.001 {
		t.Errorf("Similarity should be symmetric: got %f vs %f", estimate12, estimate21)
	}
}

// ============================================================
// Similarity Estimation Accuracy Tests
// ============================================================

func TestSimilarityEstimateAccuracy(t *testing.T) {
	// Test that LSH-based similarity estimate correlates with actual cosine similarity.
	// Uses more hash bits for better accuracy.
	gen := NewGenerator(512, 100, 42)

	testCases := []struct {
		name      string
		setupM2   func(m1, m2 *monad.Monad)
		tolerance float32
	}{
		{
			name: "identical",
			setupM2: func(m1, m2 *monad.Monad) {
				copy(m2.Vector, m1.Vector)
			},
			tolerance: 0.05,
		},
		{
			name: "similar",
			setupM2: func(m1, m2 *monad.Monad) {
				// Small perturbation
				for i := 0; i < 100; i++ {
					m2.Vector[i] = m1.Vector[i] + 0.1
				}
			},
			tolerance: 0.15,
		},
		{
			name: "orthogonal",
			setupM2: func(m1, m2 *monad.Monad) {
				// Orthogonal in first dimensions, zero elsewhere
				m2.Vector[0] = 0
				m2.Vector[1] = 1
			},
			tolerance: 0.2,
		},
		{
			name: "opposite",
			setupM2: func(m1, m2 *monad.Monad) {
				for i := 0; i < 100; i++ {
					m2.Vector[i] = -m1.Vector[i]
				}
			},
			tolerance: 0.05,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			m1 := monad.New(100)
			m2 := monad.New(100)

			// Create base vector
			for i := 0; i < 100; i++ {
				m1.Vector[i] = float32(i) / 100.0
			}

			// Setup m2 based on test case
			tc.setupM2(m1, m2)

			sig1 := gen.Generate(m1)
			sig2 := gen.Generate(m2)

			estimate := sig1.SimilarityEstimate(sig2)
			actualCosine := m1.CosineSimilarity(m2)

			// Estimate should be within tolerance of actual
			diff := math.Abs(float64(estimate - actualCosine))
			if diff > float64(tc.tolerance) {
				t.Errorf("Estimate %f differs from actual %f by %f (tolerance %f)",
					estimate, actualCosine, diff, tc.tolerance)
			}
		})
	}
}

// ============================================================
// Concurrency Tests
// ============================================================

func TestGeneratorConcurrentGenerate(t *testing.T) {
	gen := NewGenerator(128, 50, 42)

	var wg sync.WaitGroup
	numGoroutines := 100

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			m := monad.New(50)
			for j := 0; j < 50; j++ {
				m.Vector[j] = float32(idx+j) / 100.0
			}
			sig := gen.Generate(m)
			if sig == nil {
				t.Errorf("Concurrent generate[%d] returned nil", idx)
			}
			if sig.Signature.Size != 128 {
				t.Errorf("Concurrent generate[%d] returned wrong size: %d", idx, sig.Signature.Size)
			}
		}(i)
	}

	wg.Wait()
}

func TestGeneratorConcurrentDeterminism(t *testing.T) {
	gen := NewGenerator(128, 50, 42)

	m := monad.New(50)
	for i := 0; i < 50; i++ {
		m.Vector[i] = float32(i) / 50.0
	}

	// Get expected signature
	expected := gen.Generate(m)

	var wg sync.WaitGroup
	numGoroutines := 50
	results := make([]*MonadSignature, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = gen.Generate(m)
		}(i)
	}

	wg.Wait()

	// All results should match
	for i, sig := range results {
		for j := 0; j < sig.Signature.Size; j++ {
			if sig.Signature.GetBit(j) != expected.Signature.GetBit(j) {
				t.Errorf("Concurrent generate[%d] differs from expected at bit %d", i, j)
				return
			}
		}
	}
}

func TestSimilarityEstimateConcurrent(t *testing.T) {
	gen := NewGenerator(128, 50, 42)

	m1 := monad.New(50)
	m2 := monad.New(50)

	for i := 0; i < 50; i++ {
		m1.Vector[i] = float32(i) / 50.0
		m2.Vector[i] = float32(50-i) / 50.0
	}

	sig1 := gen.Generate(m1)
	sig2 := gen.Generate(m2)

	// Get expected result
	expected := sig1.SimilarityEstimate(sig2)

	var wg sync.WaitGroup
	numGoroutines := 50

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result := sig1.SimilarityEstimate(sig2)
			if result != expected {
				t.Errorf("Concurrent SimilarityEstimate differs: got %f, want %f", result, expected)
			}
		}()
	}

	wg.Wait()
}

// ============================================================
// MonadSignature Struct Tests
// ============================================================

func TestMonadSignatureFields(t *testing.T) {
	gen := NewGenerator(256, 100, 42)

	m := monad.New(100)
	for i := 0; i < 3; i++ {
		embedding := make([]float32, 100)
		for j := range embedding {
			embedding[j] = float32(i*j%50) / 100.0
		}
		if err := m.Update(embedding); err != nil {
			t.Fatalf("Update failed: %v", err)
		}
	}

	beforeGenerate := time.Now()
	sig := gen.Generate(m)
	afterGenerate := time.Now()

	// Check all fields are populated correctly
	if sig.Version != 3 {
		t.Errorf("Version: got %d, want 3", sig.Version)
	}
	if sig.Dimensions != 100 {
		t.Errorf("Dimensions: got %d, want 100", sig.Dimensions)
	}
	if sig.NumHashes != 256 {
		t.Errorf("NumHashes: got %d, want 256", sig.NumHashes)
	}
	if sig.GeneratedAt.Before(beforeGenerate) || sig.GeneratedAt.After(afterGenerate) {
		t.Errorf("GeneratedAt %v not between %v and %v", sig.GeneratedAt, beforeGenerate, afterGenerate)
	}
}

// ============================================================
// Edge Cases
// ============================================================

func TestGeneratorSingleHash(t *testing.T) {
	gen := NewGenerator(1, 10, 42)
	m := monad.New(10)
	for i := 0; i < 10; i++ {
		m.Vector[i] = float32(i)
	}

	sig := gen.Generate(m)

	if sig.Signature.Size != 1 {
		t.Errorf("Single hash should produce 1-bit signature, got %d", sig.Signature.Size)
	}
}

func TestGeneratorLargeSignature(t *testing.T) {
	gen := NewGenerator(1024, 100, 42)
	m := monad.New(100)
	for i := 0; i < 100; i++ {
		m.Vector[i] = float32(i) / 100.0
	}

	sig := gen.Generate(m)

	if sig.Signature.Size != 1024 {
		t.Errorf("Large signature size: got %d, want 1024", sig.Signature.Size)
	}
}

func TestSimilarityEstimateSelf(t *testing.T) {
	gen := NewGenerator(256, 50, 42)
	m := monad.New(50)
	for i := 0; i < 50; i++ {
		m.Vector[i] = float32(i) / 50.0
	}

	sig := gen.Generate(m)

	// Comparing with itself should give 1.0
	estimate := sig.SimilarityEstimate(sig)

	if estimate != 1.0 {
		t.Errorf("Self-similarity should be exactly 1.0, got %f", estimate)
	}
}

// ============================================================
// Benchmarks
// ============================================================

func BenchmarkGeneratorGenerate(b *testing.B) {
	gen := NewGenerator(256, 384, 42)
	m := monad.New(384)
	for i := 0; i < 384; i++ {
		m.Vector[i] = float32(i) / 384.0
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		gen.Generate(m)
	}
}

func BenchmarkSimilarityEstimate(b *testing.B) {
	gen := NewGenerator(256, 100, 42)

	m1 := monad.New(100)
	m2 := monad.New(100)

	for i := 0; i < 100; i++ {
		m1.Vector[i] = float32(i) / 100.0
		m2.Vector[i] = float32(100-i) / 100.0
	}

	sig1 := gen.Generate(m1)
	sig2 := gen.Generate(m2)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sig1.SimilarityEstimate(sig2)
	}
}
