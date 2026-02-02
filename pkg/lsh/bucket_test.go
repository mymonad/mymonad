package lsh

import "testing"

func TestDeriveBucketID(t *testing.T) {
	tests := []struct {
		name      string
		signature []byte
		want      string
	}{
		{
			name: "valid 32-byte signature",
			signature: []byte{
				0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x9A,
				0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55,
				0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
				0xEE, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
			},
			want: "/mymonad/lsh/bucket/ab",
		},
		{
			name:      "empty signature",
			signature: []byte{},
			want:      "",
		},
		{
			name:      "nil signature",
			signature: nil,
			want:      "",
		},
		{
			name:      "single byte signature",
			signature: []byte{0xFF},
			want:      "/mymonad/lsh/bucket/ff",
		},
		{
			name: "zero-prefix signature",
			signature: []byte{
				0x00, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE,
				0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
				0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			},
			want: "/mymonad/lsh/bucket/00",
		},
		{
			name:      "two byte signature",
			signature: []byte{0x7F, 0x80},
			want:      "/mymonad/lsh/bucket/7f",
		},
		{
			name:      "uppercase hex first byte",
			signature: []byte{0xFE, 0xDC, 0xBA},
			want:      "/mymonad/lsh/bucket/fe",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DeriveBucketID(tt.signature)
			if got != tt.want {
				t.Errorf("DeriveBucketID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDeriveBucketIDFromSignature(t *testing.T) {
	// Test integration with LSH Signature type
	lsh := New(64, 10, 42)
	vector := []float32{0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0}

	sig, err := lsh.Hash(vector)
	if err != nil {
		t.Fatalf("Hash failed: %v", err)
	}

	bucketID := DeriveBucketID(sig.Bits)

	// Should produce a valid bucket ID
	if bucketID == "" {
		t.Error("DeriveBucketID should return non-empty bucket ID for valid signature")
	}

	// Should have the correct prefix
	expectedPrefix := "/mymonad/lsh/bucket/"
	if len(bucketID) < len(expectedPrefix) {
		t.Errorf("BucketID too short: %s", bucketID)
	}

	if bucketID[:len(expectedPrefix)] != expectedPrefix {
		t.Errorf("BucketID should start with %s, got %s", expectedPrefix, bucketID)
	}

	// Should have exactly 2 hex characters after the prefix
	suffix := bucketID[len(expectedPrefix):]
	if len(suffix) != 2 {
		t.Errorf("BucketID suffix should be 2 hex chars, got %q", suffix)
	}
}

func TestDeriveBucketIDBucketRange(t *testing.T) {
	// Verify that all 256 possible bucket IDs can be generated
	seenBuckets := make(map[string]bool)

	for i := 0; i < 256; i++ {
		signature := []byte{byte(i)}
		bucketID := DeriveBucketID(signature)
		seenBuckets[bucketID] = true
	}

	// Should have exactly 256 unique bucket IDs
	if len(seenBuckets) != 256 {
		t.Errorf("Expected 256 unique bucket IDs, got %d", len(seenBuckets))
	}
}

func TestBucketIDBits(t *testing.T) {
	// Verify BucketIDBits constant
	if BucketIDBits != 8 {
		t.Errorf("BucketIDBits should be 8, got %d", BucketIDBits)
	}
}

func TestDeriveBucketIDDeterministic(t *testing.T) {
	signature := []byte{0x42, 0x00, 0xFF}

	// Same signature should always produce the same bucket ID
	id1 := DeriveBucketID(signature)
	id2 := DeriveBucketID(signature)
	id3 := DeriveBucketID(signature)

	if id1 != id2 || id2 != id3 {
		t.Errorf("DeriveBucketID should be deterministic: got %s, %s, %s", id1, id2, id3)
	}
}

// Benchmark for bucket derivation
func BenchmarkDeriveBucketID(b *testing.B) {
	signature := make([]byte, 32)
	for i := range signature {
		signature[i] = byte(i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DeriveBucketID(signature)
	}
}
