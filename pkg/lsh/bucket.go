// Package lsh implements Locality Sensitive Hashing using random hyperplanes.
// This file provides bucket derivation for DHT-based peer discovery.
package lsh

import "fmt"

const (
	// BucketIDBits is the number of bits used for bucket identification.
	// 8 bits = 256 possible buckets, providing a good balance between
	// bucket granularity and peer density per bucket.
	BucketIDBits = 8
)

// DeriveBucketID extracts the first N bits of the LSH signature
// to form a coarse "bucket" for DHT-based discovery.
//
// The bucket ID is used as a DHT key where peers with similar
// LSH signatures (and thus similar affinity vectors) can find
// each other. Using only the first byte (8 bits) creates 256
// possible buckets, balancing discovery efficiency with bucket
// population density.
//
// Returns empty string for nil or empty signatures.
// Output format: /mymonad/lsh/bucket/%02x (lowercase hex)
func DeriveBucketID(signature []byte) string {
	if len(signature) == 0 {
		return ""
	}
	// Use first byte as bucket ID (256 buckets)
	return fmt.Sprintf("/mymonad/lsh/bucket/%02x", signature[0])
}
