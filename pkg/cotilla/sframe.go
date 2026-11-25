package cotilla

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"sort"
	"sync"
	"time"
)

// RFC 9605 SFrame constants for AES_128_GCM_SHA256_128.
const (
	SFrameCipherAES128GCM uint16 = 0x0001
	sframeKeySize                = 16
	sframeSaltSize               = 12
	sframeReplayWindow           = 128
	sframeMaxLeafIndex           = 0xffff
	sframeMaxEpoch               = (uint64(1) << 47) - 1
	sframeOpenKIDBit      uint64 = uint64(1) << 63
)

var (
	ErrSFrameMissingKey    = errors.New("sframe: missing key for KID")
	ErrSFrameInvalidHeader = errors.New("sframe: malformed RFC 9605 header")
	ErrSFrameReplay        = errors.New("sframe: replayed or stale counter")
	ErrSFrameAuthFailed    = errors.New("sframe: AEAD authentication failed")
	ErrSFrameUnadmitted    = errors.New("sframe: unadmitted member cannot derive SFrame keys")
)

// MakeSFrameKID packs an MLS epoch (bits 16..62) and tree leaf index (bits 0..15) into a KID,
// leaving bit 63 clear to distinguish MLS keys from epoch-0 open/DM peer KIDs.
func MakeSFrameKID(epoch uint64, leafIndex int) (uint64, error) {
	if epoch > sframeMaxEpoch {
		return 0, fmt.Errorf("sframe: epoch %d exceeds 47-bit limit", epoch)
	}
	if leafIndex < 0 || leafIndex > sframeMaxLeafIndex {
		return 0, fmt.Errorf("sframe: leaf index %d out of 16-bit range", leafIndex)
	}
	return (epoch << 16) | uint64(leafIndex), nil
}

// MakeOpenSFrameKID derives an immutable, collision-free 64-bit KID (with bit 63 set) for
// epoch-0 open rooms and 2-peer DM calls.
func MakeOpenSFrameKID(addr string) uint64 {
	sum := sha256.Sum256([]byte("cotilla-open-kid:" + addr))
	return sframeOpenKIDBit | (binary.BigEndian.Uint64(sum[:8]) & ^sframeOpenKIDBit)
}

// SplitSFrameKID extracts the epoch and leaf index (or epoch=0, leafIndex=-1 for open KIDs).
func SplitSFrameKID(kid uint64) (epoch uint64, leafIndex int) {
	if kid&sframeOpenKIDBit != 0 {
		return 0, -1
	}
	return kid >> 16, int(kid & 0xffff)
}

func appendMinimalBE(dst []byte, v uint64) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	i := 0
	for i < 7 && buf[i] == 0 {
		i++
	}
	return append(dst, buf[i:]...)
}

func readMinimalBE(b []byte) (uint64, error) {
	if len(b) == 0 || len(b) > 8 {
		return 0, ErrSFrameInvalidHeader
	}
	if len(b) > 1 && b[0] == 0 {
		return 0, ErrSFrameInvalidHeader
	}
	var buf [8]byte
	copy(buf[8-len(b):], b)
	return binary.BigEndian.Uint64(buf[:]), nil
}

// EncodeSFrameHeader encodes KID and CTR into the variable-length RFC 9605 §4.3 header.
func EncodeSFrameHeader(kid, ctr uint64) []byte {
	var cfg byte
	var kidBytes, ctrBytes []byte

	if kid <= 7 {
		cfg |= byte(kid) << 4
	} else {
		kidBytes = appendMinimalBE(nil, kid)
		cfg |= 0x80 | (byte(len(kidBytes)-1) << 4)
	}

	if ctr <= 7 {
		cfg |= byte(ctr)
	} else {
		ctrBytes = appendMinimalBE(nil, ctr)
		cfg |= 0x08 | byte(len(ctrBytes)-1)
	}

	out := make([]byte, 0, 1+len(kidBytes)+len(ctrBytes))
	out = append(out, cfg)
	out = append(out, kidBytes...)
	out = append(out, ctrBytes...)
	return out
}

// DecodeSFrameHeader parses an RFC 9605 header, returning KID, CTR, and header byte length.
func DecodeSFrameHeader(frame []byte) (kid, ctr uint64, headerLen int, err error) {
	if len(frame) < 1 {
		return 0, 0, 0, ErrSFrameInvalidHeader
	}
	cfg := frame[0]
	off := 1

	if cfg&0x80 != 0 {
		kLen := int((cfg>>4)&0x07) + 1
		if len(frame) < off+kLen {
			return 0, 0, 0, ErrSFrameInvalidHeader
		}
		kid, err = readMinimalBE(frame[off : off+kLen])
		if err != nil {
			return 0, 0, 0, err
		}
		if kid <= 7 {
			return 0, 0, 0, ErrSFrameInvalidHeader
		}
		off += kLen
	} else {
		kid = uint64((cfg >> 4) & 0x07)
	}

	if cfg&0x08 != 0 {
		cLen := int(cfg&0x07) + 1
		if len(frame) < off+cLen {
			return 0, 0, 0, ErrSFrameInvalidHeader
		}
		ctr, err = readMinimalBE(frame[off : off+cLen])
		if err != nil {
			return 0, 0, 0, err
		}
		if ctr <= 7 {
			return 0, 0, 0, ErrSFrameInvalidHeader
		}
		off += cLen
	} else {
		ctr = uint64(cfg & 0x07)
	}

	return kid, ctr, off, nil
}

// SFrameKeyEntry stores derived RFC 9605 AES-128-GCM key + salt for a specific (epoch, leafIndex).
type SFrameKeyEntry struct {
	KID       uint64
	Epoch     uint64
	LeafIndex int
	Address   string
	Key       [sframeKeySize]byte
	Salt      [sframeSaltSize]byte
}

// Zeroize overwrites sensitive key/salt bytes in memory.
func (e *SFrameKeyEntry) Zeroize() {
	if e == nil {
		return
	}
	zeroizeBytes(e.Key[:])
	zeroizeBytes(e.Salt[:])
}

// SFrameKeyBundle represents a complete snapshot of sender and authorized receiver keys
// for an MLS channel epoch or 1:1 DM session.
type SFrameKeyBundle struct {
	ScopeID   string
	Epoch     uint64
	LeafIndex int
	Sender    SFrameKeyEntry
	Receivers []SFrameKeyEntry
}

// Zeroize overwrites all sensitive key material within the bundle.
func (b *SFrameKeyBundle) Zeroize() {
	if b == nil {
		return
	}
	b.Sender.Zeroize()
	for i := range b.Receivers {
		b.Receivers[i].Zeroize()
	}
}

// DeriveLeafSFrameKey derives the RFC 9605 key and salt for (epoch, leafIndex, address)
// from an epoch-level 32-byte exported base secret. For open/DM rooms (useOpenKID=true),
// the KID is bound immutably to addr instead of mutable leaf indices.
func DeriveLeafSFrameKey(epochBaseSecret []byte, epoch uint64, leafIndex int, addr string) (SFrameKeyEntry, error) {
	return deriveLeafSFrameKeyInternal(epochBaseSecret, epoch, leafIndex, addr, false)
}

func deriveLeafSFrameKeyInternal(epochBaseSecret []byte, epoch uint64, leafIndex int, addr string, useOpenKID bool) (SFrameKeyEntry, error) {
	if len(epochBaseSecret) < 32 {
		return SFrameKeyEntry{}, errors.New("sframe: epoch base secret must be at least 32 bytes")
	}
	var kid uint64
	if useOpenKID {
		kid = MakeOpenSFrameKID(addr)
	} else {
		var err error
		kid, err = MakeSFrameKID(epoch, leafIndex)
		if err != nil {
			return SFrameKeyEntry{}, err
		}
	}

	var kidTag [8]byte
	binary.BigEndian.PutUint64(kidTag[:], kid)
	senderInfo := "cotilla sframe sender " + string(kidTag[:])
	senderBase, err := hkdf.Expand(sha256.New, epochBaseSecret, senderInfo, 32)
	if err != nil {
		return SFrameKeyEntry{}, err
	}
	defer zeroizeBytes(senderBase)

	sframeSecret, err := hkdf.Extract(sha256.New, senderBase, nil)
	if err != nil {
		return SFrameKeyEntry{}, err
	}
	defer zeroizeBytes(sframeSecret)

	var labelCtx [10]byte
	binary.BigEndian.PutUint64(labelCtx[:8], kid)
	binary.BigEndian.PutUint16(labelCtx[8:], SFrameCipherAES128GCM)

	keyInfo := "SFrame 1.0 Secret key " + string(labelCtx[:])
	saltInfo := "SFrame 1.0 Secret salt " + string(labelCtx[:])

	derivedKey, err := hkdf.Expand(sha256.New, sframeSecret, keyInfo, sframeKeySize)
	if err != nil {
		return SFrameKeyEntry{}, err
	}
	defer zeroizeBytes(derivedKey)

	derivedSalt, err := hkdf.Expand(sha256.New, sframeSecret, saltInfo, sframeSaltSize)
	if err != nil {
		return SFrameKeyEntry{}, err
	}
	defer zeroizeBytes(derivedSalt)

	entry := SFrameKeyEntry{
		KID:       kid,
		Epoch:     epoch,
		LeafIndex: leafIndex,
		Address:   addr,
	}
	copy(entry.Key[:], derivedKey)
	copy(entry.Salt[:], derivedSalt)
	return entry, nil
}

// buildChannelSFrameBundle derives an SFrameKeyBundle from a joined MLS channel state.
func buildChannelSFrameBundle(ch *ChannelState, selfAddr string, openPeers []string) (*SFrameKeyBundle, error) {
	if ch == nil {
		return nil, errors.New("sframe: nil channel state")
	}
	if ch.evictedPeers[selfAddr] > 0 {
		return nil, ErrSFrameUnadmitted
	}
	if ch.currentEpoch == 0 && (ch.creatorPub != "" || ch.channelInvite != nil) {
		return nil, ErrSFrameUnadmitted
	}

	if ch.mlsGroup != nil && ch.currentEpoch >= 1 {
		epoch, myLeaf, leaves, baseSecret, err := ch.mlsGroup.SnapshotForSFrame("cotilla sframe v1", []byte(ch.RoomID))
		if err != nil {
			return nil, err
		}
		defer zeroizeBytes(baseSecret)
		return assembleSFrameBundle(ch.RoomID, epoch, myLeaf, selfAddr, leaves, baseSecret, false)
	}

	// Open Epoch-0 room before first commit: use immutable per-address 63-bit KIDs.
	seen := map[string]bool{selfAddr: true}
	peers := []string{selfAddr}
	for p := range ch.memberJoinEpoch {
		if !seen[p] && ch.evictedPeers[p] == 0 {
			seen[p] = true
			peers = append(peers, p)
		}
	}
	for _, p := range openPeers {
		if p != "" && !seen[p] && ch.evictedPeers[p] == 0 {
			seen[p] = true
			peers = append(peers, p)
		}
	}
	sort.Strings(peers)
	leaves := make([]LeafSnapshot, 0, len(peers))
	myLeaf := -1
	for idx, p := range peers {
		if p == selfAddr {
			myLeaf = idx
		}
		leaves = append(leaves, LeafSnapshot{LeafIndex: idx, Address: p})
	}
	if myLeaf < 0 {
		return nil, ErrSFrameUnadmitted
	}
	baseSecret, err := hkdf.Key(sha256.New, ch.RoomKey[:], []byte(ch.RoomID), "cotilla open sframe v1", 32)
	if err != nil {
		return nil, err
	}
	defer zeroizeBytes(baseSecret)
	return assembleSFrameBundle(ch.RoomID, 0, myLeaf, selfAddr, leaves, baseSecret, true)
}

// BuildDMSFrameBundle derives an SFrameKeyBundle for a 2-peer 1:1 DM session.
func BuildDMSFrameBundle(roomID string, key RoomKey, selfAddr, peerAddr string) (*SFrameKeyBundle, error) {
	if roomID == "" || selfAddr == "" || peerAddr == "" || selfAddr == peerAddr {
		return nil, errors.New("sframe: invalid DM endpoints")
	}
	peers := []string{selfAddr, peerAddr}
	sort.Strings(peers)
	myLeaf := 0
	if peers[1] == selfAddr {
		myLeaf = 1
	}
	leaves := []LeafSnapshot{
		{LeafIndex: 0, Address: peers[0]},
		{LeafIndex: 1, Address: peers[1]},
	}
	baseSecret, err := hkdf.Key(sha256.New, key[:], []byte(roomID), "cotilla dm sframe v1", 32)
	if err != nil {
		return nil, err
	}
	defer zeroizeBytes(baseSecret)
	return assembleSFrameBundle(roomID, 0, myLeaf, selfAddr, leaves, baseSecret, true)
}

func assembleSFrameBundle(scopeID string, epoch uint64, myLeaf int, selfAddr string, leaves []LeafSnapshot, baseSecret []byte, useOpenKID bool) (*SFrameKeyBundle, error) {
	sender, err := deriveLeafSFrameKeyInternal(baseSecret, epoch, myLeaf, selfAddr, useOpenKID)
	if err != nil {
		return nil, err
	}
	receivers := make([]SFrameKeyEntry, 0, len(leaves))
	for _, lf := range leaves {
		if lf.Address == selfAddr && lf.LeafIndex == myLeaf {
			continue
		}
		entry, err := deriveLeafSFrameKeyInternal(baseSecret, epoch, lf.LeafIndex, lf.Address, useOpenKID)
		if err != nil {
			sender.Zeroize()
			for i := range receivers {
				receivers[i].Zeroize()
			}
			return nil, err
		}
		receivers = append(receivers, entry)
	}
	return &SFrameKeyBundle{
		ScopeID:   scopeID,
		Epoch:     epoch,
		LeafIndex: myLeaf,
		Sender:    sender,
		Receivers: receivers,
	}, nil
}

func makeAESGCM(key [sframeKeySize]byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

func computeSFrameNonce(salt [sframeSaltSize]byte, ctr uint64) [sframeSaltSize]byte {
	var nonce [sframeSaltSize]byte
	copy(nonce[:], salt[:])
	var ctrBuf [8]byte
	binary.BigEndian.PutUint64(ctrBuf[:], ctr)
	for i := 0; i < 8; i++ {
		nonce[4+i] ^= ctrBuf[i]
	}
	return nonce
}

// SFrameEncryptFrame encrypts an encoded media frame using RFC 9605 AES-128-GCM.
func SFrameEncryptFrame(entry SFrameKeyEntry, ctr uint64, plaintext []byte) ([]byte, error) {
	aead, err := makeAESGCM(entry.Key)
	if err != nil {
		return nil, err
	}
	hdr := EncodeSFrameHeader(entry.KID, ctr)
	nonce := computeSFrameNonce(entry.Salt, ctr)
	out := make([]byte, len(hdr), len(hdr)+len(plaintext)+aead.Overhead())
	copy(out, hdr)
	return aead.Seal(out, nonce[:], plaintext, hdr), nil
}

type sframeRXEntry struct {
	entry     SFrameKeyEntry
	aead      cipher.AEAD
	hasSeen   bool
	maxCTR    uint64
	bitmapHi  uint64 // covers [maxCTR-127 .. maxCTR-64]
	bitmapLo  uint64 // covers [maxCTR-63 .. maxCTR]
	expiresAt time.Time
}

func (r *sframeRXEntry) checkAndAccept(ctr uint64) bool {
	if !r.hasSeen {
		return true
	}
	if ctr > r.maxCTR {
		return true
	}
	delta := r.maxCTR - ctr
	if delta >= sframeReplayWindow {
		return false
	}
	if delta < 64 {
		return (r.bitmapLo & (uint64(1) << delta)) == 0
	}
	return (r.bitmapHi & (uint64(1) << (delta - 64))) == 0
}

func (r *sframeRXEntry) recordAccepted(ctr uint64) {
	if !r.hasSeen {
		r.hasSeen = true
		r.maxCTR = ctr
		r.bitmapLo = 1
		r.bitmapHi = 0
		return
	}
	if ctr > r.maxCTR {
		shift := ctr - r.maxCTR
		if shift >= sframeReplayWindow {
			r.bitmapHi = 0
			r.bitmapLo = 1
		} else if shift >= 64 {
			r.bitmapHi = r.bitmapLo << (shift - 64)
			r.bitmapLo = 1
		} else {
			r.bitmapHi = (r.bitmapHi << shift) | (r.bitmapLo >> (64 - shift))
			r.bitmapLo = (r.bitmapLo << shift) | 1
		}
		r.maxCTR = ctr
		return
	}
	delta := r.maxCTR - ctr
	if delta < 64 {
		r.bitmapLo |= uint64(1) << delta
	} else if delta < sframeReplayWindow {
		r.bitmapHi |= uint64(1) << (delta - 64)
	}
}

// SFrameKeyring manages stateful SFrame encryption (monotonic TX counter) and decryption
// (anti-replay sliding window, epoch grace retention, and instant leaf revocation).
type SFrameKeyring struct {
	mu      sync.Mutex
	epoch   uint64
	txSet   bool
	txEntry SFrameKeyEntry
	txAEAD  cipher.AEAD
	txCTR   uint64
	rxKeys  map[uint64]*sframeRXEntry
}

// NewSFrameKeyring creates an empty SFrameKeyring.
func NewSFrameKeyring() *SFrameKeyring {
	return &SFrameKeyring{
		rxKeys: make(map[uint64]*sframeRXEntry),
	}
}

// InstallBundle replaces the active sender key and receiver keys, retaining previous epoch
// receiver keys for graceDuration so in-flight RTP packets across benign epoch transitions settle.
func (kr *SFrameKeyring) InstallBundle(b *SFrameKeyBundle, graceDuration time.Duration) error {
	if b == nil {
		return errors.New("sframe: nil bundle")
	}
	txAEAD, err := makeAESGCM(b.Sender.Key)
	if err != nil {
		return err
	}
	rxEntries := make(map[uint64]*sframeRXEntry, len(b.Receivers))
	for _, r := range b.Receivers {
		aead, err := makeAESGCM(r.Key)
		if err != nil {
			return err
		}
		rxEntries[r.KID] = &sframeRXEntry{entry: r, aead: aead}
	}

	now := time.Now()
	kr.mu.Lock()
	defer kr.mu.Unlock()

	if !kr.txSet || kr.txEntry.KID != b.Sender.KID {
		kr.txEntry.Zeroize()
		kr.txEntry = b.Sender
		kr.txAEAD = txAEAD
		kr.txCTR = 0
		kr.txSet = true
	}
	kr.epoch = b.Epoch

	for kid, existing := range kr.rxKeys {
		if _, keep := rxEntries[kid]; !keep {
			if graceDuration > 0 && existing.entry.Epoch < b.Epoch {
				if existing.expiresAt.IsZero() {
					existing.expiresAt = now.Add(graceDuration)
				}
				if now.Before(existing.expiresAt) {
					continue
				}
			}
			existing.entry.Zeroize()
			delete(kr.rxKeys, kid)
		}
	}
	for kid, ne := range rxEntries {
		if existing, ok := kr.rxKeys[kid]; ok {
			existing.expiresAt = time.Time{}
		} else {
			kr.rxKeys[kid] = ne
		}
	}
	return nil
}

// RevokePeer immediately zeroizes and removes all receiver keys belonging to peerAddr.
func (kr *SFrameKeyring) RevokePeer(peerAddr string) {
	kr.mu.Lock()
	defer kr.mu.Unlock()
	for kid, r := range kr.rxKeys {
		if r.entry.Address == peerAddr {
			r.entry.Zeroize()
			delete(kr.rxKeys, kid)
		}
	}
}

// RevokeLeaf immediately zeroizes and removes all receiver keys for leafIndex across all epochs.
func (kr *SFrameKeyring) RevokeLeaf(leafIndex int) {
	kr.mu.Lock()
	defer kr.mu.Unlock()
	for kid, r := range kr.rxKeys {
		if r.entry.LeafIndex == leafIndex {
			r.entry.Zeroize()
			delete(kr.rxKeys, kid)
		}
	}
}

// Clear zeroizes all keys in the keyring.
func (kr *SFrameKeyring) Clear() {
	kr.mu.Lock()
	defer kr.mu.Unlock()
	kr.txEntry.Zeroize()
	kr.txAEAD = nil
	kr.txSet = false
	kr.txCTR = 0
	for kid, r := range kr.rxKeys {
		r.entry.Zeroize()
		delete(kr.rxKeys, kid)
	}
}

// Encrypt encrypts plaintext under the current sender key with a strictly increasing counter.
func (kr *SFrameKeyring) Encrypt(plaintext []byte) ([]byte, error) {
	kr.mu.Lock()
	if !kr.txSet || kr.txAEAD == nil {
		kr.mu.Unlock()
		return nil, ErrSFrameMissingKey
	}
	entry := kr.txEntry
	aead := kr.txAEAD
	ctr := kr.txCTR
	kr.txCTR++
	kr.mu.Unlock()

	hdr := EncodeSFrameHeader(entry.KID, ctr)
	nonce := computeSFrameNonce(entry.Salt, ctr)
	out := make([]byte, len(hdr), len(hdr)+len(plaintext)+aead.Overhead())
	copy(out, hdr)
	return aead.Seal(out, nonce[:], plaintext, hdr), nil
}

// Decrypt authenticates and decrypts an SFrame frame, validating peer ownership and counter replay bounds.
// If expectedFrom is non-empty, the matching KID's leaf address must match expectedFrom.
func (kr *SFrameKeyring) Decrypt(frame []byte, expectedFrom string) ([]byte, uint64, error) {
	kid, ctr, hdrLen, err := DecodeSFrameHeader(frame)
	if err != nil {
		return nil, 0, err
	}
	now := time.Now()

	kr.mu.Lock()
	rx, ok := kr.rxKeys[kid]
	if !ok {
		kr.mu.Unlock()
		return nil, kid, ErrSFrameMissingKey
	}
	if !rx.expiresAt.IsZero() && !now.Before(rx.expiresAt) {
		rx.entry.Zeroize()
		delete(kr.rxKeys, kid)
		kr.mu.Unlock()
		return nil, kid, ErrSFrameMissingKey
	}
	if expectedFrom != "" && rx.entry.Address != expectedFrom {
		kr.mu.Unlock()
		return nil, kid, ErrSFrameAuthFailed
	}
	if !rx.checkAndAccept(ctr) {
		kr.mu.Unlock()
		return nil, kid, ErrSFrameReplay
	}
	aead := rx.aead
	salt := rx.entry.Salt
	kr.mu.Unlock()

	nonce := computeSFrameNonce(salt, ctr)
	plaintext, err := aead.Open(nil, nonce[:], frame[hdrLen:], frame[:hdrLen])
	if err != nil {
		return nil, kid, ErrSFrameAuthFailed
	}

	kr.mu.Lock()
	if rxCurrent, exists := kr.rxKeys[kid]; exists && rxCurrent == rx {
		rxCurrent.recordAccepted(ctr)
	}
	kr.mu.Unlock()

	return plaintext, kid, nil
}

// Ensure hkdf uses sha256/io imports cleanly across Go versions.
var _ func() hash.Hash = sha256.New
var _ = io.Discard
