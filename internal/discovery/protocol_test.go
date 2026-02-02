// Package discovery provides peer discovery mechanisms for the P2P network.
// These tests verify the protocol stream handler for commit-reveal exchanges.
package discovery

import (
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	pb "github.com/mymonad/mymonad/api/proto"
)

// TestWriteReadMessage verifies that messages can be serialized and
// deserialized through the wire format.
func TestWriteReadMessage(t *testing.T) {
	buf := &bytes.Buffer{}

	msg := &ProtocolMessage{
		Type:    MessageTypeCommit,
		Payload: []byte("test payload"),
	}

	err := WriteMessage(buf, msg)
	if err != nil {
		t.Fatalf("WriteMessage failed: %v", err)
	}

	read, err := ReadMessage(buf)
	if err != nil {
		t.Fatalf("ReadMessage failed: %v", err)
	}
	if read.Type != msg.Type {
		t.Errorf("Type mismatch: got %d, want %d", read.Type, msg.Type)
	}
	if !bytes.Equal(read.Payload, msg.Payload) {
		t.Errorf("Payload mismatch: got %v, want %v", read.Payload, msg.Payload)
	}
}

// TestWriteReadCommit verifies that DiscoveryCommit messages can be
// serialized and deserialized correctly.
func TestWriteReadCommit(t *testing.T) {
	buf := &bytes.Buffer{}

	commit := &pb.DiscoveryCommit{
		Commitment: make([]byte, 32),
		Timestamp:  time.Now().UnixMilli(),
		PeerId:     []byte("test-peer"),
	}

	// Fill commitment with test data
	for i := range commit.Commitment {
		commit.Commitment[i] = byte(i)
	}

	err := WriteCommit(buf, commit)
	if err != nil {
		t.Fatalf("WriteCommit failed: %v", err)
	}

	read, err := ReadCommit(buf)
	if err != nil {
		t.Fatalf("ReadCommit failed: %v", err)
	}
	if !bytes.Equal(read.Commitment, commit.Commitment) {
		t.Errorf("Commitment mismatch: got %v, want %v", read.Commitment, commit.Commitment)
	}
	if read.Timestamp != commit.Timestamp {
		t.Errorf("Timestamp mismatch: got %d, want %d", read.Timestamp, commit.Timestamp)
	}
	if !bytes.Equal(read.PeerId, commit.PeerId) {
		t.Errorf("PeerId mismatch: got %v, want %v", read.PeerId, commit.PeerId)
	}
}

// TestWriteReadReveal verifies that DiscoveryReveal messages can be
// serialized and deserialized correctly.
func TestWriteReadReveal(t *testing.T) {
	buf := &bytes.Buffer{}

	reveal := &pb.DiscoveryReveal{
		Signature: make([]byte, 32),
		Salt:      make([]byte, 16),
	}

	// Fill with test data
	for i := range reveal.Signature {
		reveal.Signature[i] = byte(i)
	}
	for i := range reveal.Salt {
		reveal.Salt[i] = byte(i + 100)
	}

	err := WriteReveal(buf, reveal)
	if err != nil {
		t.Fatalf("WriteReveal failed: %v", err)
	}

	read, err := ReadReveal(buf)
	if err != nil {
		t.Fatalf("ReadReveal failed: %v", err)
	}
	if !bytes.Equal(read.Signature, reveal.Signature) {
		t.Errorf("Signature mismatch: got %v, want %v", read.Signature, reveal.Signature)
	}
	if !bytes.Equal(read.Salt, reveal.Salt) {
		t.Errorf("Salt mismatch: got %v, want %v", read.Salt, reveal.Salt)
	}
}

// TestWriteReadReject verifies that DiscoveryReject messages can be
// serialized and deserialized correctly.
func TestWriteReadReject(t *testing.T) {
	buf := &bytes.Buffer{}

	err := WriteReject(buf, "commitment_mismatch")
	if err != nil {
		t.Fatalf("WriteReject failed: %v", err)
	}

	reject, err := ReadReject(buf)
	if err != nil {
		t.Fatalf("ReadReject failed: %v", err)
	}
	if reject.Reason != "commitment_mismatch" {
		t.Errorf("Reason mismatch: got %q, want %q", reject.Reason, "commitment_mismatch")
	}
}

// TestShouldInitiate verifies the peer initiation logic.
func TestShouldInitiate(t *testing.T) {
	// Lower peer ID should initiate
	localLow := peer.ID("AAAA")
	remoteHigh := peer.ID("ZZZZ")

	if !shouldInitiate(localLow, remoteHigh) {
		t.Error("Expected localLow to initiate against remoteHigh")
	}
	if shouldInitiate(remoteHigh, localLow) {
		t.Error("Expected remoteHigh NOT to initiate against localLow")
	}

	// Equal IDs - neither should initiate (edge case)
	if shouldInitiate(localLow, localLow) {
		t.Error("Expected equal IDs to NOT initiate")
	}
}

// TestMessageTypeConstants verifies the message type constants are correct.
func TestMessageTypeConstants(t *testing.T) {
	if MessageTypeCommit != 0 {
		t.Errorf("MessageTypeCommit should be 0, got %d", MessageTypeCommit)
	}
	if MessageTypeReveal != 1 {
		t.Errorf("MessageTypeReveal should be 1, got %d", MessageTypeReveal)
	}
	if MessageTypeReject != 2 {
		t.Errorf("MessageTypeReject should be 2, got %d", MessageTypeReject)
	}
}

// TestProtocolID verifies the protocol ID is correct.
func TestProtocolID(t *testing.T) {
	expected := "/mymonad/discovery/1.0.0"
	if ProtocolID != expected {
		t.Errorf("ProtocolID mismatch: got %q, want %q", ProtocolID, expected)
	}
}

// TestWriteMessageAllTypes verifies all message types can be written.
func TestWriteMessageAllTypes(t *testing.T) {
	types := []MessageType{MessageTypeCommit, MessageTypeReveal, MessageTypeReject}

	for _, mt := range types {
		buf := &bytes.Buffer{}
		msg := &ProtocolMessage{
			Type:    mt,
			Payload: []byte("test"),
		}

		err := WriteMessage(buf, msg)
		if err != nil {
			t.Errorf("WriteMessage failed for type %d: %v", mt, err)
		}

		read, err := ReadMessage(buf)
		if err != nil {
			t.Errorf("ReadMessage failed for type %d: %v", mt, err)
		}
		if read.Type != mt {
			t.Errorf("Type mismatch for type %d: got %d", mt, read.Type)
		}
	}
}

// TestWriteMessageEmptyPayload verifies empty payloads are handled.
func TestWriteMessageEmptyPayload(t *testing.T) {
	buf := &bytes.Buffer{}
	msg := &ProtocolMessage{
		Type:    MessageTypeReject,
		Payload: []byte{},
	}

	err := WriteMessage(buf, msg)
	if err != nil {
		t.Fatalf("WriteMessage failed: %v", err)
	}

	read, err := ReadMessage(buf)
	if err != nil {
		t.Fatalf("ReadMessage failed: %v", err)
	}
	if len(read.Payload) != 0 {
		t.Errorf("Expected empty payload, got %v", read.Payload)
	}
}

// TestReadMessageEOF verifies ReadMessage handles EOF correctly.
func TestReadMessageEOF(t *testing.T) {
	buf := &bytes.Buffer{}
	_, err := ReadMessage(buf)
	if err != io.EOF {
		t.Errorf("Expected io.EOF, got %v", err)
	}
}

// TestReadMessageTruncatedHeader verifies truncated header handling.
func TestReadMessageTruncatedHeader(t *testing.T) {
	// Only write 3 bytes (need at least 5: 1 type + 4 length)
	buf := bytes.NewBuffer([]byte{0x00, 0x00, 0x00})
	_, err := ReadMessage(buf)
	if err == nil {
		t.Error("Expected error for truncated header")
	}
}

// TestReadMessageTruncatedPayload verifies truncated payload handling.
func TestReadMessageTruncatedPayload(t *testing.T) {
	// Write header claiming 100 bytes, but only provide 5
	buf := bytes.NewBuffer([]byte{
		0x00,                   // Type: Commit
		0x00, 0x00, 0x00, 0x64, // Length: 100 (big-endian)
		0x01, 0x02, 0x03, 0x04, 0x05, // Only 5 bytes of payload
	})
	_, err := ReadMessage(buf)
	if err == nil {
		t.Error("Expected error for truncated payload")
	}
}

// TestReadMessageMaxPayloadSize verifies payload size limit is enforced.
func TestReadMessageMaxPayloadSize(t *testing.T) {
	// Write header claiming MaxPayloadSize + 1 bytes
	buf := bytes.NewBuffer([]byte{
		0x00,                   // Type: Commit
		0x01, 0x00, 0x00, 0x01, // Length: 16MB + 1 (exceeds max)
	})
	_, err := ReadMessage(buf)
	if err == nil {
		t.Error("Expected error for oversized payload")
	}
}

// TestWriteReadLargePayload verifies large (but valid) payloads work.
func TestWriteReadLargePayload(t *testing.T) {
	buf := &bytes.Buffer{}
	payload := make([]byte, 64*1024) // 64KB payload
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	msg := &ProtocolMessage{
		Type:    MessageTypeCommit,
		Payload: payload,
	}

	err := WriteMessage(buf, msg)
	if err != nil {
		t.Fatalf("WriteMessage failed: %v", err)
	}

	read, err := ReadMessage(buf)
	if err != nil {
		t.Fatalf("ReadMessage failed: %v", err)
	}
	if !bytes.Equal(read.Payload, payload) {
		t.Error("Large payload mismatch")
	}
}

// TestWriteCommitNil verifies WriteCommit handles nil correctly.
func TestWriteCommitNil(t *testing.T) {
	buf := &bytes.Buffer{}
	err := WriteCommit(buf, nil)
	if err == nil {
		t.Error("Expected error for nil commit")
	}
}

// TestWriteRevealNil verifies WriteReveal handles nil correctly.
func TestWriteRevealNil(t *testing.T) {
	buf := &bytes.Buffer{}
	err := WriteReveal(buf, nil)
	if err == nil {
		t.Error("Expected error for nil reveal")
	}
}

// TestReadCommitWrongType verifies ReadCommit rejects wrong message types.
func TestReadCommitWrongType(t *testing.T) {
	buf := &bytes.Buffer{}

	// Write a reveal message
	reveal := &pb.DiscoveryReveal{
		Signature: make([]byte, 32),
		Salt:      make([]byte, 16),
	}
	err := WriteReveal(buf, reveal)
	if err != nil {
		t.Fatalf("WriteReveal failed: %v", err)
	}

	// Try to read as commit
	_, err = ReadCommit(buf)
	if err == nil {
		t.Error("Expected error when reading wrong message type")
	}
}

// TestReadRevealWrongType verifies ReadReveal rejects wrong message types.
func TestReadRevealWrongType(t *testing.T) {
	buf := &bytes.Buffer{}

	// Write a commit message
	commit := &pb.DiscoveryCommit{
		Commitment: make([]byte, 32),
		Timestamp:  time.Now().UnixMilli(),
		PeerId:     []byte("test"),
	}
	err := WriteCommit(buf, commit)
	if err != nil {
		t.Fatalf("WriteCommit failed: %v", err)
	}

	// Try to read as reveal
	_, err = ReadReveal(buf)
	if err == nil {
		t.Error("Expected error when reading wrong message type")
	}
}

// TestReadRejectWrongType verifies ReadReject rejects wrong message types.
func TestReadRejectWrongType(t *testing.T) {
	buf := &bytes.Buffer{}

	// Write a commit message
	commit := &pb.DiscoveryCommit{
		Commitment: make([]byte, 32),
		Timestamp:  time.Now().UnixMilli(),
		PeerId:     []byte("test"),
	}
	err := WriteCommit(buf, commit)
	if err != nil {
		t.Fatalf("WriteCommit failed: %v", err)
	}

	// Try to read as reject
	_, err = ReadReject(buf)
	if err == nil {
		t.Error("Expected error when reading wrong message type")
	}
}

// TestWriteRejectReasons verifies all standard rejection reasons.
func TestWriteRejectReasons(t *testing.T) {
	reasons := []string{
		"commitment_mismatch",
		"stale_timestamp",
		"invalid_salt",
		"malformed_signature",
	}

	for _, reason := range reasons {
		buf := &bytes.Buffer{}
		err := WriteReject(buf, reason)
		if err != nil {
			t.Errorf("WriteReject failed for reason %q: %v", reason, err)
		}

		reject, err := ReadReject(buf)
		if err != nil {
			t.Errorf("ReadReject failed for reason %q: %v", reason, err)
		}
		if reject.Reason != reason {
			t.Errorf("Reason mismatch: got %q, want %q", reject.Reason, reason)
		}
	}
}

// TestShouldInitiateWithRealPeerIDs tests with realistic peer ID formats.
func TestShouldInitiateWithRealPeerIDs(t *testing.T) {
	// Peer IDs in libp2p are typically base58 encoded multihash strings
	peerA := peer.ID("QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N")
	peerB := peer.ID("QmZoAhPX3r7FQz5r3Ls8VxuLRJC6K7gNBRyrxPGGRNDjHb")

	// One should initiate, one should not
	initiateAB := shouldInitiate(peerA, peerB)
	initiateBA := shouldInitiate(peerB, peerA)

	// Exactly one should initiate
	if initiateAB == initiateBA {
		t.Error("Expected exactly one peer to initiate")
	}
}

// TestMessageWireFormat verifies the exact wire format.
func TestMessageWireFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	msg := &ProtocolMessage{
		Type:    MessageTypeCommit,
		Payload: []byte{0xDE, 0xAD, 0xBE, 0xEF},
	}

	err := WriteMessage(buf, msg)
	if err != nil {
		t.Fatalf("WriteMessage failed: %v", err)
	}

	data := buf.Bytes()
	// Expected format: [type:1 byte][length:4 bytes BE][payload]
	if len(data) != 9 { // 1 + 4 + 4
		t.Errorf("Expected 9 bytes, got %d", len(data))
	}
	if data[0] != 0x00 { // MessageTypeCommit
		t.Errorf("Expected type 0x00, got 0x%02x", data[0])
	}
	// Length should be 4 in big-endian
	if data[1] != 0x00 || data[2] != 0x00 || data[3] != 0x00 || data[4] != 0x04 {
		t.Errorf("Expected length [0,0,0,4], got [%d,%d,%d,%d]", data[1], data[2], data[3], data[4])
	}
	// Payload
	if !bytes.Equal(data[5:], []byte{0xDE, 0xAD, 0xBE, 0xEF}) {
		t.Errorf("Payload mismatch: got %v", data[5:])
	}
}
