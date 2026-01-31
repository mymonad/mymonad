// Package monad provides the core Monad type representing a user's affinity vector.
// The Monad is a high-dimensional embedding built from local user data, used for
// privacy-preserving compatibility matching in the MyMonad P2P protocol.
package monad

import (
	"errors"
	"math"
	"sync"
	"time"
	"unsafe"
)

// Monad represents the user's affinity vector - a high-dimensional embedding
// that captures user preferences and characteristics from their local data.
// It is thread-safe for concurrent read/write operations.
type Monad struct {
	// Vector is the affinity embedding, typically 384 dimensions for standard models.
	Vector []float32

	// Version is incremented on each update, used for change detection.
	Version int64

	// UpdatedAt records when the Monad was last modified.
	UpdatedAt time.Time

	// DocCount tracks the number of documents that have contributed to this vector.
	// Used for computing running average during updates.
	DocCount int64

	// mu protects concurrent access to Monad fields.
	mu sync.RWMutex
}

// New creates a new Monad with the specified dimensions.
// The vector is zero-initialized, ready to incorporate document embeddings.
func New(dimensions int) *Monad {
	return &Monad{
		Vector:    make([]float32, dimensions),
		Version:   0,
		UpdatedAt: time.Now(),
		DocCount:  0,
	}
}

// ErrDimensionMismatch is returned when a document embedding has a different
// dimension than the Monad's vector.
var ErrDimensionMismatch = errors.New("dimension mismatch")

// Update incorporates a new document embedding using running average.
// The running average formula ensures that each document contributes equally
// to the final vector, regardless of when it was added.
//
// Formula: new_vector = old_vector * (n-1)/n + doc_embedding * 1/n
// where n is the new document count after this update.
//
// Returns ErrDimensionMismatch if the document embedding has a different
// dimension than the Monad's vector.
func (m *Monad) Update(docEmbedding []float32) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(docEmbedding) != len(m.Vector) {
		return ErrDimensionMismatch
	}

	m.DocCount++
	weight := 1.0 / float32(m.DocCount)

	for i := range m.Vector {
		// Running average: new = old * (n-1)/n + new * 1/n
		m.Vector[i] = m.Vector[i]*(1-weight) + docEmbedding[i]*weight
	}

	m.Version++
	m.UpdatedAt = time.Now()
	return nil
}

// CosineSimilarity computes the cosine similarity between this Monad and another.
// Returns a value between -1.0 and 1.0, where:
//   - 1.0 indicates identical vectors
//   - 0.0 indicates orthogonal vectors (no similarity)
//   - -1.0 indicates opposite vectors
//
// Returns 0 if either vector is zero-length or if dimensions don't match.
// Thread-safe: acquires read locks on both Monads in consistent order to prevent deadlock.
func (m *Monad) CosineSimilarity(other *Monad) float32 {
	// Lock in consistent order based on pointer address to prevent deadlock
	if uintptr(unsafe.Pointer(m)) < uintptr(unsafe.Pointer(other)) {
		m.mu.RLock()
		defer m.mu.RUnlock()
		other.mu.RLock()
		defer other.mu.RUnlock()
	} else if uintptr(unsafe.Pointer(m)) > uintptr(unsafe.Pointer(other)) {
		other.mu.RLock()
		defer other.mu.RUnlock()
		m.mu.RLock()
		defer m.mu.RUnlock()
	} else {
		// Same monad, only need one lock
		m.mu.RLock()
		defer m.mu.RUnlock()
	}

	if len(m.Vector) != len(other.Vector) {
		return 0
	}

	var dot, normA, normB float64
	for i := range m.Vector {
		a := float64(m.Vector[i])
		b := float64(other.Vector[i])
		dot += a * b
		normA += a * a
		normB += b * b
	}

	if normA == 0 || normB == 0 {
		return 0
	}

	return float32(dot / (math.Sqrt(normA) * math.Sqrt(normB)))
}

// Clone returns a deep copy of the Monad.
// The clone is independent and can be modified without affecting the original.
func (m *Monad) Clone() *Monad {
	m.mu.RLock()
	defer m.mu.RUnlock()

	clone := &Monad{
		Vector:    make([]float32, len(m.Vector)),
		Version:   m.Version,
		UpdatedAt: m.UpdatedAt,
		DocCount:  m.DocCount,
	}
	copy(clone.Vector, m.Vector)
	return clone
}

// Dimensions returns the number of dimensions in the affinity vector.
func (m *Monad) Dimensions() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.Vector)
}
