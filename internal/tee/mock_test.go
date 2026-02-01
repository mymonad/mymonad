package tee

import (
	"math"
	"testing"
)

func TestCosineSimilarity_IdenticalVectors(t *testing.T) {
	a := []float32{1.0, 2.0, 3.0}
	b := []float32{1.0, 2.0, 3.0}

	similarity, err := CosineSimilarity(a, b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Identical vectors should have similarity of 1.0
	if math.Abs(float64(similarity-1.0)) > 0.0001 {
		t.Errorf("expected similarity 1.0, got %f", similarity)
	}
}

func TestCosineSimilarity_OrthogonalVectors(t *testing.T) {
	a := []float32{1.0, 0.0, 0.0}
	b := []float32{0.0, 1.0, 0.0}

	similarity, err := CosineSimilarity(a, b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Orthogonal vectors should have similarity of 0.0
	if math.Abs(float64(similarity)) > 0.0001 {
		t.Errorf("expected similarity 0.0, got %f", similarity)
	}
}

func TestCosineSimilarity_OppositeVectors(t *testing.T) {
	a := []float32{1.0, 2.0, 3.0}
	b := []float32{-1.0, -2.0, -3.0}

	similarity, err := CosineSimilarity(a, b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Opposite vectors should have similarity of -1.0
	if math.Abs(float64(similarity+1.0)) > 0.0001 {
		t.Errorf("expected similarity -1.0, got %f", similarity)
	}
}

func TestCosineSimilarity_LengthMismatch(t *testing.T) {
	a := []float32{1.0, 2.0}
	b := []float32{1.0, 2.0, 3.0}

	_, err := CosineSimilarity(a, b)
	if err == nil {
		t.Fatal("expected error for length mismatch")
	}
}

func TestCosineSimilarity_EmptyVectors(t *testing.T) {
	a := []float32{}
	b := []float32{}

	_, err := CosineSimilarity(a, b)
	if err == nil {
		t.Fatal("expected error for empty vectors")
	}
}

func TestCosineSimilarity_ZeroVector(t *testing.T) {
	a := []float32{0.0, 0.0, 0.0}
	b := []float32{1.0, 2.0, 3.0}

	_, err := CosineSimilarity(a, b)
	if err == nil {
		t.Fatal("expected error for zero vector")
	}
}

func TestComputeMatch_AboveThreshold(t *testing.T) {
	// Identical vectors - 100% similarity
	vec := []float32{0.5, 0.5, 0.5, 0.5}
	localMonad := SerializeMonad(vec)
	peerMonad := SerializeMonad(vec)

	matched, err := ComputeMatch(localMonad, peerMonad, 0.9)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !matched {
		t.Error("expected match for identical vectors with 0.9 threshold")
	}
}

func TestComputeMatch_BelowThreshold(t *testing.T) {
	// Orthogonal vectors - 0% similarity
	vec1 := []float32{1.0, 0.0, 0.0, 0.0}
	vec2 := []float32{0.0, 1.0, 0.0, 0.0}
	localMonad := SerializeMonad(vec1)
	peerMonad := SerializeMonad(vec2)

	matched, err := ComputeMatch(localMonad, peerMonad, 0.5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if matched {
		t.Error("expected no match for orthogonal vectors with 0.5 threshold")
	}
}

func TestComputeMatch_ExactlyAtThreshold(t *testing.T) {
	// Similar but not identical vectors
	vec1 := []float32{1.0, 0.0, 0.0, 0.0}
	vec2 := []float32{1.0, 0.0, 0.0, 0.0}
	localMonad := SerializeMonad(vec1)
	peerMonad := SerializeMonad(vec2)

	// 1.0 similarity with 1.0 threshold should match (>= threshold)
	matched, err := ComputeMatch(localMonad, peerMonad, 1.0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !matched {
		t.Error("expected match at exact threshold")
	}
}

func TestSerializeDeserializeMonad(t *testing.T) {
	original := []float32{1.5, -2.5, 3.14159, 0.0, 1000.0}

	serialized := SerializeMonad(original)
	deserialized, err := DeserializeMonad(serialized)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(deserialized) != len(original) {
		t.Fatalf("length mismatch: expected %d, got %d", len(original), len(deserialized))
	}

	for i := range original {
		if deserialized[i] != original[i] {
			t.Errorf("value mismatch at index %d: expected %f, got %f", i, original[i], deserialized[i])
		}
	}
}

func TestDeserializeMonad_InvalidLength(t *testing.T) {
	// 5 bytes is not divisible by 4
	data := []byte{1, 2, 3, 4, 5}

	_, err := DeserializeMonad(data)
	if err == nil {
		t.Fatal("expected error for invalid length")
	}
}

func TestDeserializeMonad_Empty(t *testing.T) {
	_, err := DeserializeMonad([]byte{})
	if err == nil {
		t.Fatal("expected error for empty data")
	}
}

func TestComputeMatch_InvalidLocalMonad(t *testing.T) {
	// Invalid local monad (not divisible by 4)
	localMonad := []byte{1, 2, 3}
	peerMonad := SerializeMonad([]float32{1.0, 2.0})

	_, err := ComputeMatch(localMonad, peerMonad, 0.5)
	if err == nil {
		t.Fatal("expected error for invalid local monad")
	}
}

func TestComputeMatch_InvalidPeerMonad(t *testing.T) {
	localMonad := SerializeMonad([]float32{1.0, 2.0})
	// Invalid peer monad (not divisible by 4)
	peerMonad := []byte{1, 2, 3}

	_, err := ComputeMatch(localMonad, peerMonad, 0.5)
	if err == nil {
		t.Fatal("expected error for invalid peer monad")
	}
}

func TestComputeMatch_DifferentLengths(t *testing.T) {
	localMonad := SerializeMonad([]float32{1.0, 2.0})
	peerMonad := SerializeMonad([]float32{1.0, 2.0, 3.0})

	_, err := ComputeMatch(localMonad, peerMonad, 0.5)
	if err == nil {
		t.Fatal("expected error for different vector lengths")
	}
}
