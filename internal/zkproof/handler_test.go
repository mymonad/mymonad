// Package zkproof provides a service layer for zero-knowledge proof functionality.
package zkproof

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/protocol"
)

// mockHost implements a minimal host.Host for testing stream handler registration.
type mockHost struct {
	host.Host // Embed to satisfy interface
	mu        sync.Mutex
	handlers  map[protocol.ID]network.StreamHandler
}

func newMockHost() *mockHost {
	return &mockHost{
		handlers: make(map[protocol.ID]network.StreamHandler),
	}
}

func (m *mockHost) SetStreamHandler(id protocol.ID, handler network.StreamHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handlers[id] = handler
}

func (m *mockHost) hasHandler(id protocol.ID) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.handlers[id]
	return ok
}

func TestNewHandler(t *testing.T) {
	t.Run("creates_handler_with_valid_params", func(t *testing.T) {
		config := DefaultZKConfig()
		config.Enabled = false // Don't compile circuit for tests
		zkService, err := NewZKService(config)
		require.NoError(t, err)

		getLocalSig := func() []byte { return []byte("local-signature") }

		handler := NewHandler(zkService, getLocalSig)

		require.NotNil(t, handler)
		assert.Equal(t, zkService, handler.zkService)
		assert.NotNil(t, handler.getLocalSignature)
	})

	t.Run("creates_handler_with_nil_service", func(t *testing.T) {
		getLocalSig := func() []byte { return []byte("local-signature") }

		handler := NewHandler(nil, getLocalSig)

		require.NotNil(t, handler)
		assert.Nil(t, handler.zkService)
	})

	t.Run("creates_handler_with_nil_callback", func(t *testing.T) {
		config := DefaultZKConfig()
		zkService, err := NewZKService(config)
		require.NoError(t, err)

		handler := NewHandler(zkService, nil)

		require.NotNil(t, handler)
		assert.Nil(t, handler.getLocalSignature)
	})
}

func TestHandler_RegisterStreamHandler(t *testing.T) {
	t.Run("does_not_register_when_service_nil", func(t *testing.T) {
		getLocalSig := func() []byte { return []byte("local-signature") }
		handler := NewHandler(nil, getLocalSig)

		mockH := newMockHost()

		// Should not panic and should not register
		handler.RegisterStreamHandler(mockH)

		assert.False(t, mockH.hasHandler(ZKProtocolID))
	})

	t.Run("does_not_register_when_service_disabled", func(t *testing.T) {
		config := DefaultZKConfig()
		config.Enabled = false
		zkService, err := NewZKService(config)
		require.NoError(t, err)

		getLocalSig := func() []byte { return []byte("local-signature") }
		handler := NewHandler(zkService, getLocalSig)

		mockH := newMockHost()
		handler.RegisterStreamHandler(mockH)

		assert.False(t, mockH.hasHandler(ZKProtocolID))
	})

	t.Run("registers_handler_when_service_enabled", func(t *testing.T) {
		if testing.Short() {
			t.Skip("skipping test in short mode (circuit compilation is slow)")
		}

		config := DefaultZKConfig()
		config.Enabled = true
		config.ProofTimeout = 5 * time.Second
		zkService, err := NewZKService(config)
		require.NoError(t, err)

		getLocalSig := func() []byte { return makeTestSignature(0x01) }
		handler := NewHandler(zkService, getLocalSig)

		mockH := newMockHost()
		handler.RegisterStreamHandler(mockH)

		assert.True(t, mockH.hasHandler(ZKProtocolID))
	})
}

func TestHandler_RegisterStreamHandler_NilHost(t *testing.T) {
	t.Run("does_not_panic_with_nil_host_when_service_disabled", func(t *testing.T) {
		config := DefaultZKConfig()
		config.Enabled = false
		zkService, err := NewZKService(config)
		require.NoError(t, err)

		getLocalSig := func() []byte { return []byte("local-signature") }
		handler := NewHandler(zkService, getLocalSig)

		// This should not panic because we return early when service is disabled
		assert.NotPanics(t, func() {
			handler.RegisterStreamHandler(nil)
		})
	})
}
