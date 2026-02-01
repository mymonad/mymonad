// Package monad provides the core Monad type representing a user's affinity vector.
// The Monad is a high-dimensional embedding built from local user data, used for
// privacy-preserving compatibility matching in the MyMonad P2P protocol.
package monad

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
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

// Binary format header size: version(8) + doccount(8) + updatedat(8) + dims(4) = 28 bytes
const binaryHeaderSize = 28

// ErrInvalidBinaryData is returned when binary data is malformed.
var ErrInvalidBinaryData = errors.New("invalid binary data")

// MarshalBinary encodes the Monad to binary format.
// Format: version(8) + doccount(8) + updatedat(8) + dims(4) + vector(dims*4)
// All values are encoded in little-endian byte order.
func (m *Monad) MarshalBinary() ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	dims := len(m.Vector)
	size := binaryHeaderSize + dims*4
	data := make([]byte, size)

	// Write header
	binary.LittleEndian.PutUint64(data[0:8], uint64(m.Version))
	binary.LittleEndian.PutUint64(data[8:16], uint64(m.DocCount))
	binary.LittleEndian.PutUint64(data[16:24], uint64(m.UpdatedAt.UnixNano()))
	binary.LittleEndian.PutUint32(data[24:28], uint32(dims))

	// Write vector
	offset := binaryHeaderSize
	for _, v := range m.Vector {
		binary.LittleEndian.PutUint32(data[offset:offset+4], math.Float32bits(v))
		offset += 4
	}

	return data, nil
}

// UnmarshalBinary decodes the Monad from binary format.
// The data must have been encoded with MarshalBinary.
func (m *Monad) UnmarshalBinary(data []byte) error {
	if len(data) < binaryHeaderSize {
		return fmt.Errorf("%w: data too short for header (got %d, need %d)", ErrInvalidBinaryData, len(data), binaryHeaderSize)
	}

	// Read header
	version := int64(binary.LittleEndian.Uint64(data[0:8]))
	docCount := int64(binary.LittleEndian.Uint64(data[8:16]))
	updatedAtNano := int64(binary.LittleEndian.Uint64(data[16:24]))
	dims := binary.LittleEndian.Uint32(data[24:28])

	// Validate vector data length
	expectedLen := binaryHeaderSize + int(dims)*4
	if len(data) < expectedLen {
		return fmt.Errorf("%w: data too short for vector (got %d, need %d)", ErrInvalidBinaryData, len(data), expectedLen)
	}

	// Read vector
	vector := make([]float32, dims)
	offset := binaryHeaderSize
	for i := range vector {
		bits := binary.LittleEndian.Uint32(data[offset : offset+4])
		vector[i] = math.Float32frombits(bits)
		offset += 4
	}

	// Assign to monad
	m.mu.Lock()
	defer m.mu.Unlock()

	m.Version = version
	m.DocCount = docCount
	m.UpdatedAt = time.Unix(0, updatedAtNano)
	m.Vector = vector

	return nil
}

// LoadFromFile loads a Monad from a file.
// Returns an error if the file cannot be read or the data is invalid.
func LoadFromFile(path string) (*Monad, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read monad file: %w", err)
	}

	m := &Monad{}
	if err := m.UnmarshalBinary(data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal monad: %w", err)
	}

	return m, nil
}

// SaveToFile saves a Monad to a file atomically.
// Uses temp file + rename pattern for crash safety.
// This ensures the file is never left in a partially-written state.
func SaveToFile(m *Monad, path string) error {
	data, err := m.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to marshal monad: %w", err)
	}

	// Create temp file in same directory to ensure atomic rename works
	dir := filepath.Dir(path)
	tmpFile, err := os.CreateTemp(dir, ".monad-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	// Clean up temp file on any error
	defer func() {
		if tmpFile != nil {
			tmpFile.Close()
			os.Remove(tmpPath)
		}
	}()

	// Write data to temp file
	if _, err := tmpFile.Write(data); err != nil {
		return fmt.Errorf("failed to write monad data: %w", err)
	}

	// Sync to disk to ensure durability
	if err := tmpFile.Sync(); err != nil {
		return fmt.Errorf("failed to sync monad file: %w", err)
	}

	// Close before rename
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}
	tmpFile = nil // Prevent deferred cleanup

	// Atomic rename
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	return nil
}
