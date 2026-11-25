package cotilla

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// DefaultChunkSize is 64 KB as specified.
const DefaultChunkSize = 64 * 1024

// MaxAttachmentChunks caps allocated chunk slots to guard against OOM / DoS on untrusted metadata.
const MaxAttachmentChunks = 16384 // 16384 * 64KB = 1 GB

// MaxAttachmentSize caps declared file size.
const MaxAttachmentSize int64 = 1 << 30 // 1 GB

// PrepareAttachment hashes, chunks, and encrypts a file payload with the room key.
func PrepareAttachment(roomKey RoomKey, name, mime string, data []byte) (*AttachmentMeta, [][]byte, error) {
	return PrepareAttachmentWithEpoch(roomKey, 0, "", name, mime, data)
}

// PrepareAttachmentWithEpoch hashes, chunks, and encrypts a file payload bound to a specific epoch and author.
func PrepareAttachmentWithEpoch(roomKey RoomKey, epochID int64, author, name, mime string, data []byte) (*AttachmentMeta, [][]byte, error) {
	h := sha256.Sum256(data)
	hashHex := hex.EncodeToString(h[:])
	fileID := hashHex[:16]

	totalChunks := (len(data) + DefaultChunkSize - 1) / DefaultChunkSize
	if totalChunks == 0 {
		totalChunks = 1
	}

	encryptedChunks := make([][]byte, totalChunks)
	for i := 0; i < totalChunks; i++ {
		start := i * DefaultChunkSize
		end := start + DefaultChunkSize
		if end > len(data) {
			end = len(data)
		}
		chunkPlaintext := data[start:end]
		aad := []byte(fmt.Sprintf("cotilla-chunk-v1:%s:%d:%d", fileID, epochID, i))
		nonce, ciphertext, err := EncryptRoomPayload(roomKey, chunkPlaintext, aad)
		if err != nil {
			return nil, nil, fmt.Errorf("cotilla: failed to encrypt chunk %d: %w", i, err)
		}

		// Pack nonce (24 bytes) + ciphertext without mutating nonce backing array
		packed := make([]byte, len(nonce)+len(ciphertext))
		copy(packed, nonce)
		copy(packed[len(nonce):], ciphertext)
		encryptedChunks[i] = packed
	}

	meta := &AttachmentMeta{
		FileID:       fileID,
		Hash:         hashHex,
		Name:         name,
		Size:         int64(len(data)),
		MIME:         mime,
		TotalChunks:  totalChunks,
		EpochID:      epochID,
		AuthorPubKey: author,
	}

	return meta, encryptedChunks, nil
}

// AttachmentAssembler handles chunk reception, decryption, and hash validation for incoming attachments.
type AttachmentAssembler struct {
	mu            sync.Mutex
	Meta          AttachmentMeta
	RoomKey       RoomKey
	chunks        [][]byte
	rawChunks     [][]byte
	received      []bool
	requested     []bool
	requestTimes  []time.Time
	receivedCnt   int
	assembled     bool
	assembledData []byte
	initErr       error
}

// NewAttachmentAssembler initializes an assembler for an announced attachment.
func NewAttachmentAssembler(meta AttachmentMeta, roomKey RoomKey) *AttachmentAssembler {
	if meta.TotalChunks <= 0 || meta.TotalChunks > MaxAttachmentChunks || meta.Size < 0 || meta.Size > MaxAttachmentSize {
		return &AttachmentAssembler{
			Meta:    meta,
			RoomKey: roomKey,
			initErr: fmt.Errorf("cotilla: invalid attachment bounds (chunks=%d, size=%d)", meta.TotalChunks, meta.Size),
		}
	}
	return &AttachmentAssembler{
		Meta:         meta,
		RoomKey:      roomKey,
		chunks:       make([][]byte, meta.TotalChunks),
		rawChunks:    make([][]byte, meta.TotalChunks),
		received:     make([]bool, meta.TotalChunks),
		requested:    make([]bool, meta.TotalChunks),
		requestTimes: make([]time.Time, meta.TotalChunks),
	}
}

// AddChunk decrypts an incoming chunk and records it if valid. Returns whether the file was completed by this chunk.
func (a *AttachmentAssembler) AddChunk(index int, packedData []byte) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.initErr != nil {
		return false, a.initErr
	}
	if index < 0 || index >= a.Meta.TotalChunks {
		return false, fmt.Errorf("cotilla: chunk index %d out of bounds (total %d)", index, a.Meta.TotalChunks)
	}
	if a.received[index] {
		return false, nil // Already received this chunk
	}

	aeadNonceSize := 24 // XChaCha20-Poly1305 nonce size
	if len(packedData) < aeadNonceSize {
		return false, errors.New("cotilla: chunk payload too short for nonce")
	}

	nonce := packedData[:aeadNonceSize]
	ciphertext := packedData[aeadNonceSize:]

	aad := []byte(fmt.Sprintf("cotilla-chunk-v1:%s:%d:%d", a.Meta.FileID, a.Meta.EpochID, index))
	plaintext, err := DecryptRoomPayload(a.RoomKey, nonce, ciphertext, aad)
	if err != nil {
		return false, fmt.Errorf("cotilla: failed to decrypt chunk %d: %w", index, err)
	}

	a.chunks[index] = plaintext
	rawCopy := make([]byte, len(packedData))
	copy(rawCopy, packedData)
	a.rawChunks[index] = rawCopy
	a.received[index] = true
	a.requested[index] = true
	a.receivedCnt++

	// Only return true the exact moment the count reaches TotalChunks for the first time
	return a.receivedCnt == a.Meta.TotalChunks && !a.assembled, nil
}

// NextMissingChunks returns up to available in-flight slots chunk indices and marks them requested.
func (a *AttachmentAssembler) NextMissingChunks(maxInFlight int) []int {
	a.mu.Lock()
	defer a.mu.Unlock()

	inFlight := 0
	for i := 0; i < a.Meta.TotalChunks; i++ {
		if a.requested[i] && !a.received[i] {
			inFlight++
		}
	}

	availableSlots := maxInFlight - inFlight
	if availableSlots <= 0 {
		return nil
	}

	now := time.Now()
	var next []int
	for i := 0; i < a.Meta.TotalChunks && len(next) < availableSlots; i++ {
		if !a.received[i] && !a.requested[i] {
			a.requested[i] = true
			a.requestTimes[i] = now
			next = append(next, i)
		}
	}
	return next
}

// RetryStaleRequests unmarks requested status for any unreceived chunks exceeding timeout.
func (a *AttachmentAssembler) RetryStaleRequests(timeout time.Duration) int {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	retried := 0
	for i := 0; i < a.Meta.TotalChunks; i++ {
		if a.requested[i] && !a.received[i] {
			if now.Sub(a.requestTimes[i]) > timeout {
				a.requested[i] = false
				retried++
			}
		}
	}
	return retried
}

// ResetUnreceivedRequests unmarks requested status for any unreceived chunks (for manual re-requests).
func (a *AttachmentAssembler) ResetUnreceivedRequests() {
	a.mu.Lock()
	defer a.mu.Unlock()

	for i := 0; i < a.Meta.TotalChunks; i++ {
		if !a.received[i] {
			a.requested[i] = false
		}
	}
}

// ReceivedCount returns the number of chunks received so far.
func (a *AttachmentAssembler) ReceivedCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.receivedCnt
}

// Progress returns received and total chunk counts.
func (a *AttachmentAssembler) Progress() (int, int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.receivedCnt, a.Meta.TotalChunks
}

// RawChunk returns the cached encrypted chunk bytes at index for swarm seeding.
func (a *AttachmentAssembler) RawChunk(index int) []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	if index < 0 || index >= len(a.rawChunks) {
		return nil
	}
	return a.rawChunks[index]
}

// ExportRawChunks returns a copy of all cached encrypted chunks for swarm seeding.
func (a *AttachmentAssembler) ExportRawChunks() [][]byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([][]byte, len(a.rawChunks))
	copy(out, a.rawChunks)
	return out
}

// MissingChunks returns indices of all chunks not yet received.
func (a *AttachmentAssembler) MissingChunks() []int {
	a.mu.Lock()
	defer a.mu.Unlock()

	var missing []int
	for i, r := range a.received {
		if !r {
			missing = append(missing, i)
		}
	}
	return missing
}

// IsComplete returns whether all chunks have been received.
func (a *AttachmentAssembler) IsComplete() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.receivedCnt == a.Meta.TotalChunks
}

// Data returns the assembled file payload if available.
func (a *AttachmentAssembler) Data() []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.assembledData
}

// Assemble concatenates all chunks and validates the SHA-256 hash.
func (a *AttachmentAssembler) Assemble() ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.initErr != nil {
		return nil, a.initErr
	}
	if a.assembled {
		return a.assembledData, nil
	}

	if a.receivedCnt != a.Meta.TotalChunks {
		return nil, fmt.Errorf("cotilla: incomplete attachment (%d/%d chunks)", a.receivedCnt, a.Meta.TotalChunks)
	}

	totalLen := 0
	for _, chunk := range a.chunks {
		totalLen += len(chunk)
	}

	out := make([]byte, 0, totalLen)
	for _, chunk := range a.chunks {
		out = append(out, chunk...)
	}

	h := sha256.Sum256(out)
	hashHex := hex.EncodeToString(h[:])
	if subtle.ConstantTimeCompare([]byte(hashHex), []byte(a.Meta.Hash)) != 1 {
		return nil, fmt.Errorf("cotilla: attachment hash mismatch (got %s, expected %s)", hashHex, a.Meta.Hash)
	}

	a.assembled = true
	a.assembledData = out
	a.chunks = nil // Free chunk slice references to cut peak memory in half
	return out, nil
}
