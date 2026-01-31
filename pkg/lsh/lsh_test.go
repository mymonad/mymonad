package lsh

import (
	"math"
	"sync"
	"testing"
)

// ============================================================
// Signature Tests
// ============================================================

func TestSignatureNew(t *testing.T) {
	sig := NewSignature(64)

	if sig.Size != 64 {
		t.Errorf("Signature size: got %d, want %d", sig.Size, 64)
	}

	expectedBytes := 8 // 64 bits / 8 = 8 bytes
	if len(sig.Bits) != expectedBytes {
		t.Errorf("Signature bytes: got %d, want %d", len(sig.Bits), expectedBytes)
	}
}

func TestSignatureNewNonMultipleOf8(t *testing.T) {
	// 65 bits should need 9 bytes
	sig := NewSignature(65)

	if sig.Size != 65 {
		t.Errorf("Signature size: got %d, want %d", sig.Size, 65)
	}

	expectedBytes := 9 // ceil(65/8) = 9
	if len(sig.Bits) != expectedBytes {
		t.Errorf("Signature bytes: got %d, want %d", len(sig.Bits), expectedBytes)
	}
}

func TestSignatureSetGet(t *testing.T) {
	sig := NewSignature(16)

	// Initially all bits should be 0
	for i := 0; i < 16; i++ {
		if sig.GetBit(i) {
			t.Errorf("Bit %d should be 0 initially", i)
		}
	}

	// Set some bits
	sig.SetBit(0, true)
	sig.SetBit(5, true)
	sig.SetBit(15, true)

	// Verify set bits
	if !sig.GetBit(0) {
		t.Error("Bit 0 should be 1 after SetBit(0, true)")
	}
	if !sig.GetBit(5) {
		t.Error("Bit 5 should be 1 after SetBit(5, true)")
	}
	if !sig.GetBit(15) {
		t.Error("Bit 15 should be 1 after SetBit(15, true)")
	}

	// Verify unset bits remain 0
	if sig.GetBit(1) {
		t.Error("Bit 1 should still be 0")
	}
	if sig.GetBit(14) {
		t.Error("Bit 14 should still be 0")
	}

	// Test clearing a bit
	sig.SetBit(5, false)
	if sig.GetBit(5) {
		t.Error("Bit 5 should be 0 after SetBit(5, false)")
	}
}

func TestSignatureGetBitOutOfRange(t *testing.T) {
	sig := NewSignature(8)

	// Out of range should return false, not panic
	if sig.GetBit(8) {
		t.Error("Out of range bit should return false")
	}
	if sig.GetBit(100) {
		t.Error("Way out of range bit should return false")
	}
	if sig.GetBit(-1) {
		t.Error("Negative index should return false")
	}
}

// ============================================================
// LSH Constructor Tests
// ============================================================

func TestLSHNew(t *testing.T) {
	numHashes := 64
	dimensions := 128
	seed := int64(42)

	lsh := New(numHashes, dimensions, seed)

	if lsh == nil {
		t.Fatal("New returned nil")
	}
	if lsh.numHashes != numHashes {
		t.Errorf("numHashes: got %d, want %d", lsh.numHashes, numHashes)
	}
	if lsh.dimensions != dimensions {
		t.Errorf("dimensions: got %d, want %d", lsh.dimensions, dimensions)
	}
	if len(lsh.hyperplanes) != numHashes {
		t.Errorf("hyperplanes count: got %d, want %d", len(lsh.hyperplanes), numHashes)
	}

	for i, hp := range lsh.hyperplanes {
		if len(hp) != dimensions {
			t.Errorf("hyperplane[%d] dimension: got %d, want %d", i, len(hp), dimensions)
		}
	}
}

func TestLSHNewDeterministic(t *testing.T) {
	numHashes := 32
	dimensions := 64
	seed := int64(12345)

	lsh1 := New(numHashes, dimensions, seed)
	lsh2 := New(numHashes, dimensions, seed)

	// Same seed should produce identical hyperplanes
	for i := 0; i < numHashes; i++ {
		for j := 0; j < dimensions; j++ {
			if lsh1.hyperplanes[i][j] != lsh2.hyperplanes[i][j] {
				t.Errorf("Hyperplanes differ at [%d][%d]: got %f vs %f",
					i, j, lsh1.hyperplanes[i][j], lsh2.hyperplanes[i][j])
				return
			}
		}
	}
}

func TestLSHNewDifferentSeeds(t *testing.T) {
	numHashes := 32
	dimensions := 64

	lsh1 := New(numHashes, dimensions, 1)
	lsh2 := New(numHashes, dimensions, 2)

	// Different seeds should produce different hyperplanes
	different := false
	for i := 0; i < numHashes && !different; i++ {
		for j := 0; j < dimensions && !different; j++ {
			if lsh1.hyperplanes[i][j] != lsh2.hyperplanes[i][j] {
				different = true
			}
		}
	}

	if !different {
		t.Error("Different seeds should produce different hyperplanes")
	}
}

func TestLSHHyperplanesNormalized(t *testing.T) {
	lsh := New(16, 32, 42)

	for i, hp := range lsh.hyperplanes {
		var sumSq float64
		for _, v := range hp {
			sumSq += float64(v * v)
		}
		norm := math.Sqrt(sumSq)

		// Hyperplanes should be unit vectors (norm ≈ 1)
		if math.Abs(norm-1.0) > 0.001 {
			t.Errorf("Hyperplane[%d] is not normalized: norm=%f", i, norm)
		}
	}
}

// ============================================================
// Hash Tests
// ============================================================

func TestLSHHash(t *testing.T) {
	lsh := New(64, 10, 42)
	vector := []float32{0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0}

	sig := lsh.Hash(vector)

	if sig.Size != 64 {
		t.Errorf("Signature size: got %d, want %d", sig.Size, 64)
	}
}

func TestLSHHashDeterministic(t *testing.T) {
	lsh := New(64, 10, 42)
	vector := []float32{0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0}

	sig1 := lsh.Hash(vector)
	sig2 := lsh.Hash(vector)

	// Same vector should produce same signature
	for i := 0; i < sig1.Size; i++ {
		if sig1.GetBit(i) != sig2.GetBit(i) {
			t.Errorf("Bit %d differs between hashes of same vector", i)
			return
		}
	}
}

func TestLSHHashIdenticalVectors(t *testing.T) {
	lsh := New(128, 10, 42)

	v1 := []float32{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	v2 := []float32{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}

	sig1 := lsh.Hash(v1)
	sig2 := lsh.Hash(v2)

	distance := HammingDistance(sig1, sig2)
	if distance != 0 {
		t.Errorf("Identical vectors should have 0 Hamming distance, got %d", distance)
	}
}

func TestLSHHashDimensionMismatch(t *testing.T) {
	lsh := New(64, 10, 42)
	wrongDimVector := []float32{0.1, 0.2, 0.3} // Only 3 dimensions, LSH expects 10

	sig := lsh.Hash(wrongDimVector)

	// Should return empty signature on dimension mismatch
	if sig.Size != 0 {
		t.Errorf("Dimension mismatch should return empty signature, got size %d", sig.Size)
	}
}

// ============================================================
// Hamming Distance Tests
// ============================================================

func TestHammingDistanceIdentical(t *testing.T) {
	sig1 := NewSignature(64)
	sig2 := NewSignature(64)

	// Set same bits in both
	sig1.SetBit(0, true)
	sig1.SetBit(10, true)
	sig1.SetBit(63, true)

	sig2.SetBit(0, true)
	sig2.SetBit(10, true)
	sig2.SetBit(63, true)

	distance := HammingDistance(sig1, sig2)
	if distance != 0 {
		t.Errorf("Identical signatures should have distance 0, got %d", distance)
	}
}

func TestHammingDistanceAllDifferent(t *testing.T) {
	sig1 := NewSignature(8)
	sig2 := NewSignature(8)

	// sig1: all zeros (default)
	// sig2: all ones
	for i := 0; i < 8; i++ {
		sig2.SetBit(i, true)
	}

	distance := HammingDistance(sig1, sig2)
	if distance != 8 {
		t.Errorf("All different bits should have distance 8, got %d", distance)
	}
}

func TestHammingDistancePartial(t *testing.T) {
	sig1 := NewSignature(16)
	sig2 := NewSignature(16)

	// sig1: bits 0,1,2,3 set
	// sig2: bits 2,3,4,5 set
	// Difference: bits 0,1,4,5 = 4 bits different
	sig1.SetBit(0, true)
	sig1.SetBit(1, true)
	sig1.SetBit(2, true)
	sig1.SetBit(3, true)

	sig2.SetBit(2, true)
	sig2.SetBit(3, true)
	sig2.SetBit(4, true)
	sig2.SetBit(5, true)

	distance := HammingDistance(sig1, sig2)
	if distance != 4 {
		t.Errorf("Expected distance 4, got %d", distance)
	}
}

func TestHammingDistanceSizeMismatch(t *testing.T) {
	sig1 := NewSignature(64)
	sig2 := NewSignature(128)

	distance := HammingDistance(sig1, sig2)

	// Mismatched sizes should return -1 to indicate error
	if distance != -1 {
		t.Errorf("Mismatched signature sizes should return -1, got %d", distance)
	}
}

// ============================================================
// Similarity Preservation Tests
// ============================================================

func TestLSHSimilarVectorsLowDistance(t *testing.T) {
	lsh := New(256, 100, 42)

	// Create two similar vectors
	v1 := make([]float32, 100)
	v2 := make([]float32, 100)

	for i := 0; i < 100; i++ {
		v1[i] = float32(i) / 100.0
		v2[i] = float32(i)/100.0 + 0.01 // Small perturbation
	}

	sig1 := lsh.Hash(v1)
	sig2 := lsh.Hash(v2)

	distance := HammingDistance(sig1, sig2)
	maxDistance := 256 / 4 // Similar vectors should differ in less than 25% of bits

	if distance > maxDistance {
		t.Errorf("Similar vectors should have low Hamming distance, got %d (max expected %d)", distance, maxDistance)
	}
}

func TestLSHOrthogonalVectorsHalfBits(t *testing.T) {
	lsh := New(256, 3, 42)

	// Create orthogonal vectors
	v1 := []float32{1, 0, 0}
	v2 := []float32{0, 1, 0}

	sig1 := lsh.Hash(v1)
	sig2 := lsh.Hash(v2)

	distance := HammingDistance(sig1, sig2)

	// For orthogonal vectors, expected distance is ~50% of bits
	expectedDistance := 128.0 // 256 * 0.5
	tolerance := 50.0         // Allow some variance

	if math.Abs(float64(distance)-expectedDistance) > tolerance {
		t.Errorf("Orthogonal vectors should differ in ~50%% of bits. Distance=%d, expected ~%d", distance, int(expectedDistance))
	}
}

func TestLSHOppositeVectorsAllBits(t *testing.T) {
	lsh := New(128, 10, 42)

	v1 := []float32{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	v2 := make([]float32, 10)
	for i := range v1 {
		v2[i] = -v1[i]
	}

	sig1 := lsh.Hash(v1)
	sig2 := lsh.Hash(v2)

	distance := HammingDistance(sig1, sig2)

	// Opposite vectors should differ in all bits
	if distance != 128 {
		t.Errorf("Opposite vectors should differ in all bits. Distance=%d, expected 128", distance)
	}
}

func TestLSHSimilarityPreservation(t *testing.T) {
	lsh := New(256, 50, 42)

	// Base vector
	base := make([]float32, 50)
	for i := range base {
		base[i] = float32(i) / 50.0
	}

	// Similar vector (small perturbation)
	similar := make([]float32, 50)
	copy(similar, base)
	for i := range similar {
		similar[i] += 0.05
	}

	// Dissimilar vector (random)
	dissimilar := make([]float32, 50)
	for i := range dissimilar {
		dissimilar[i] = float32(50-i) / 50.0
	}

	sigBase := lsh.Hash(base)
	sigSimilar := lsh.Hash(similar)
	sigDissimilar := lsh.Hash(dissimilar)

	distSimilar := HammingDistance(sigBase, sigSimilar)
	distDissimilar := HammingDistance(sigBase, sigDissimilar)

	// Similar vectors should have lower distance than dissimilar
	if distSimilar >= distDissimilar {
		t.Errorf("Similar vectors should have lower distance than dissimilar. Similar=%d, Dissimilar=%d",
			distSimilar, distDissimilar)
	}
}

// ============================================================
// Concurrency Tests
// ============================================================

func TestLSHConcurrentHash(t *testing.T) {
	lsh := New(64, 32, 42)

	var wg sync.WaitGroup
	numGoroutines := 100

	// Run many hashes concurrently
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			vector := make([]float32, 32)
			for j := range vector {
				vector[j] = float32(idx+j) / 100.0
			}
			sig := lsh.Hash(vector)
			if sig.Size != 64 {
				t.Errorf("Concurrent hash returned wrong size: %d", sig.Size)
			}
		}(i)
	}

	wg.Wait()
}

func TestLSHConcurrentDeterminism(t *testing.T) {
	lsh := New(64, 10, 42)
	vector := []float32{0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0}

	// Get expected signature
	expected := lsh.Hash(vector)

	var wg sync.WaitGroup
	numGoroutines := 50
	results := make([]Signature, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = lsh.Hash(vector)
		}(i)
	}

	wg.Wait()

	// All results should match
	for i, sig := range results {
		for j := 0; j < sig.Size; j++ {
			if sig.GetBit(j) != expected.GetBit(j) {
				t.Errorf("Concurrent hash[%d] differs from expected at bit %d", i, j)
				return
			}
		}
	}
}

// ============================================================
// Edge Cases
// ============================================================

func TestLSHZeroVector(t *testing.T) {
	lsh := New(64, 10, 42)
	zeroVector := make([]float32, 10)

	sig := lsh.Hash(zeroVector)

	// Zero vector should still produce a valid signature
	// (all bits determined by hyperplane bias, which for normalized hyperplanes is effectively random)
	if sig.Size != 64 {
		t.Errorf("Zero vector should produce valid signature, got size %d", sig.Size)
	}
}

func TestLSHNilVector(t *testing.T) {
	lsh := New(64, 10, 42)

	sig := lsh.Hash(nil)

	if sig.Size != 0 {
		t.Errorf("Nil vector should return empty signature, got size %d", sig.Size)
	}
}

func TestLSHEmptyVector(t *testing.T) {
	lsh := New(64, 10, 42)

	sig := lsh.Hash([]float32{})

	if sig.Size != 0 {
		t.Errorf("Empty vector should return empty signature, got size %d", sig.Size)
	}
}

func TestLSHSingleHash(t *testing.T) {
	lsh := New(1, 3, 42)

	v := []float32{1, 0, 0}
	sig := lsh.Hash(v)

	if sig.Size != 1 {
		t.Errorf("Single hash LSH should produce 1-bit signature, got %d", sig.Size)
	}
}

func TestLSHLargeSignature(t *testing.T) {
	lsh := New(1024, 100, 42)

	vector := make([]float32, 100)
	for i := range vector {
		vector[i] = float32(i) / 100.0
	}

	sig := lsh.Hash(vector)

	if sig.Size != 1024 {
		t.Errorf("Large signature size: got %d, want 1024", sig.Size)
	}
	if len(sig.Bits) != 128 { // 1024 / 8 = 128 bytes
		t.Errorf("Large signature bytes: got %d, want 128", len(sig.Bits))
	}
}

// ============================================================
// Accessors Tests
// ============================================================

func TestLSHNumHashes(t *testing.T) {
	lsh := New(64, 32, 42)

	if lsh.NumHashes() != 64 {
		t.Errorf("NumHashes(): got %d, want 64", lsh.NumHashes())
	}
}

func TestLSHDimensions(t *testing.T) {
	lsh := New(64, 32, 42)

	if lsh.Dimensions() != 32 {
		t.Errorf("Dimensions(): got %d, want 32", lsh.Dimensions())
	}
}

// ============================================================
// Benchmarks
// ============================================================

func BenchmarkLSHHash(b *testing.B) {
	lsh := New(256, 384, 42)
	vector := make([]float32, 384)
	for i := range vector {
		vector[i] = float32(i) / 384.0
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lsh.Hash(vector)
	}
}

func BenchmarkHammingDistance(b *testing.B) {
	lsh := New(256, 100, 42)
	v1 := make([]float32, 100)
	v2 := make([]float32, 100)
	for i := range v1 {
		v1[i] = float32(i) / 100.0
		v2[i] = float32(100-i) / 100.0
	}

	sig1 := lsh.Hash(v1)
	sig2 := lsh.Hash(v2)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		HammingDistance(sig1, sig2)
	}
}

func BenchmarkLSHNew(b *testing.B) {
	for i := 0; i < b.N; i++ {
		New(256, 384, int64(i))
	}
}
