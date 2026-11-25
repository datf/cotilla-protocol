package cotilla

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

func clampX25519Scalar(k *[32]byte) {
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
}

func zeroizeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// RoomKeySize is 32 bytes (256 bits).
const RoomKeySize = 32

// RoomKey is a 256-bit symmetric room key.
type RoomKey [RoomKeySize]byte

// String returns the URL-safe base64 encoding of the room key without padding.
func (k RoomKey) String() string {
	return base64.RawURLEncoding.EncodeToString(k[:])
}

// GenerateRoomKey creates a new random 256-bit room key.
func GenerateRoomKey() (RoomKey, error) {
	var k RoomKey
	if _, err := io.ReadFull(rand.Reader, k[:]); err != nil {
		return k, err
	}
	return k, nil
}

// ParseRoomKey parses a base64 (or hex) encoded 256-bit room key.
func ParseRoomKey(s string) (RoomKey, error) {
	var k RoomKey
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		b, err = base64.URLEncoding.DecodeString(s)
	}
	if err != nil {
		b, err = base64.StdEncoding.DecodeString(s)
	}
	if err != nil {
		b, err = hex.DecodeString(s)
	}
	if err != nil {
		return k, fmt.Errorf("cotilla: invalid room key encoding: %w", err)
	}
	if len(b) != RoomKeySize {
		return k, fmt.Errorf("cotilla: room key must be %d bytes, got %d", RoomKeySize, len(b))
	}
	copy(k[:], b)
	return k, nil
}

// Identity holds a client's long-term Ed25519 signing keypair and X25519 encryption keypair.
type Identity struct {
	SignPub  ed25519.PublicKey
	SignPriv ed25519.PrivateKey
	EncPub   [32]byte
	EncPriv  [32]byte
}

// NewIdentity generates a fresh random client identity.
func NewIdentity() (*Identity, error) {
	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	id := &Identity{
		SignPub:  signPub,
		SignPriv: signPriv,
	}
	if _, err := io.ReadFull(rand.Reader, id.EncPriv[:]); err != nil {
		return nil, err
	}
	clampX25519Scalar(&id.EncPriv)
	pub, err := curve25519.X25519(id.EncPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	copy(id.EncPub[:], pub)
	return id, nil
}

// NewIdentityFromSeed derives a deterministic Identity from a >=16 byte seed.
func NewIdentityFromSeed(seed []byte) (*Identity, error) {
	if len(seed) < 16 {
		return nil, errors.New("cotilla: identity seed must be at least 16 bytes")
	}
	id := &Identity{}

	// Derive Ed25519 signing key using HKDF-SHA256
	signSeed := make([]byte, ed25519.SeedSize)
	defer zeroizeBytes(signSeed)
	if _, err := io.ReadFull(hkdf.New(sha256.New, seed, nil, []byte("cotilla-sign-v1")), signSeed); err != nil {
		return nil, err
	}
	priv := ed25519.NewKeyFromSeed(signSeed)
	id.SignPriv = priv
	id.SignPub = priv.Public().(ed25519.PublicKey)

	// Derive X25519 encryption key using HKDF-SHA256
	if _, err := io.ReadFull(hkdf.New(sha256.New, seed, nil, []byte("cotilla-enc-v1")), id.EncPriv[:]); err != nil {
		return nil, err
	}
	clampX25519Scalar(&id.EncPriv)
	pub, err := curve25519.X25519(id.EncPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	copy(id.EncPub[:], pub)
	return id, nil
}

// Address returns the hex-encoded Ed25519 public key — the participant's identity.
func (id *Identity) Address() string {
	return hex.EncodeToString(id.SignPub)
}

// EncAddress returns the hex-encoded X25519 public encryption key.
func (id *Identity) EncAddress() string {
	return hex.EncodeToString(id.EncPub[:])
}

// Sign signs msg with the Ed25519 private key.
func (id *Identity) Sign(msg []byte) []byte {
	return ed25519.Sign(id.SignPriv, msg)
}

// Verify checks an Ed25519 signature by pubHex against msg.
func Verify(pubHex string, msg []byte, sigHex string) bool {
	pub, err := hex.DecodeString(pubHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, msg, sig)
}

// EncodeCanonical serializes a domain tag and variable-length string fields using unambiguous length-prefixing.
// Format: tag + "|" + len(f0) + ":" + f0 + "|" + len(f1) + ":" + f1 ...
func EncodeCanonical(tag string, fields ...string) []byte {
	var b strings.Builder
	b.WriteString(tag)
	for _, f := range fields {
		b.WriteByte('|')
		b.WriteString(strconv.Itoa(len(f)))
		b.WriteByte(':')
		b.WriteString(f)
	}
	return []byte(b.String())
}

// CanonicalEnvelopePayload constructs the length-prefixed canonical payload for envelope signature verification.
func CanonicalEnvelopePayload(roomID, authorPubKey, nonce, ciphertext string, epochID, timestamp int64) []byte {
	return EncodeCanonical("cotilla-envelope-v1", roomID, authorPubKey, nonce, ciphertext, strconv.FormatInt(epochID, 10), strconv.FormatInt(timestamp, 10))
}

// CanonicalPeerInfo returns length-prefixed canonical bytes for signing peer discovery frames.
func CanonicalPeerInfo(signPub, encPub string, timestamp int64) []byte {
	return EncodeCanonical("cotilla-peer-info-v1", signPub, encPub, strconv.FormatInt(timestamp, 10))
}

// InviteKeyCommitment derives a non-reversible SHA-256 key commitment for channel invitations.
func InviteKeyCommitment(roomKey string) string {
	if roomKey == "" {
		return ""
	}
	if strings.HasPrefix(roomKey, "sha256:") {
		return roomKey
	}
	sum := sha256.Sum256([]byte("cotilla-invite-key:" + roomKey))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// CanonicalChannelInvite returns length-prefixed canonical bytes for signing a room/channel invitation.
// It converts raw roomKey secrets into a salted SHA-256 commitment so redacted wire invites verify without leaking RoomKey.
func CanonicalChannelInvite(roomID, inviterPub, roomKey string, epochID, expiresAt int64) []byte {
	return EncodeCanonical("cotilla-channel-invite-v1", roomID, inviterPub, InviteKeyCommitment(roomKey), strconv.FormatInt(epochID, 10), strconv.FormatInt(expiresAt, 10))
}

// CanonicalChannelInviteWithInvitee returns canonical bytes binding an explicit invitee public address when set.
func CanonicalChannelInviteWithInvitee(roomID, inviterPub, inviteePub, roomKey string, epochID, expiresAt int64) []byte {
	if inviteePub == "" {
		return CanonicalChannelInvite(roomID, inviterPub, roomKey, epochID, expiresAt)
	}
	return EncodeCanonical("cotilla-channel-invite-v2", roomID, inviterPub, inviteePub, InviteKeyCommitment(roomKey), strconv.FormatInt(epochID, 10), strconv.FormatInt(expiresAt, 10))
}

func writeLenPrefixed(h io.Writer, data []byte) {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(data)))
	_, _ = h.Write(lenBuf[:])
	_, _ = h.Write(data)
}

func writeUint64BE(h io.Writer, v uint64) {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	_, _ = h.Write(buf[:])
}

// CanonicalEpochCommit returns length-prefixed canonical bytes for signing an epoch key rotation / member eviction / member welcome.
func CanonicalEpochCommit(epochID int64, roomID, evictor, evictorEncPub, evictedPeer, addedPeer, reason, commitDigest string, timestamp int64) []byte {
	return EncodeCanonical("cotilla-epoch-commit-mls-v2", strconv.FormatInt(epochID, 10), roomID, evictor, evictorEncPub, evictedPeer, addedPeer, reason, commitDigest, strconv.FormatInt(timestamp, 10))
}

// ComputeMLSCommitDigest creates a length-prefixed collision-free SHA-256 digest of the MLSCommit and/or MLSWelcome payload.
func ComputeMLSCommitDigest(c *EpochCommit) string {
	h := sha256.New()
	if c == nil {
		return hex.EncodeToString(h.Sum(nil))
	}
	if c.MLSCommit != nil {
		writeLenPrefixed(h, []byte("commit-v2"))
		writeLenPrefixed(h, []byte(c.MLSCommit.GroupID))
		writeUint64BE(h, c.MLSCommit.Epoch)
		writeUint64BE(h, uint64(int64(c.MLSCommit.CommitterLeaf)))
		writeUint64BE(h, uint64(int64(c.MLSCommit.RemovedLeaf)))
		if c.MLSCommit.AddedPackage != nil {
			writeLenPrefixed(h, []byte("added-kp"))
			writeLenPrefixed(h, []byte(c.MLSCommit.AddedPackage.SignPub))
			writeLenPrefixed(h, c.MLSCommit.AddedPackage.InitKey[:])
			writeUint64BE(h, uint64(c.MLSCommit.AddedPackage.Timestamp))
			writeLenPrefixed(h, c.MLSCommit.AddedPackage.Signature)
		} else {
			writeLenPrefixed(h, []byte("no-kp"))
		}
		if c.MLSCommit.Path != nil {
			writeLenPrefixed(h, []byte("path"))
			writeUint64BE(h, uint64(int64(c.MLSCommit.Path.LeafIndex)))
			writeLenPrefixed(h, c.MLSCommit.Path.LeafPublicKey[:])
			writeUint64BE(h, uint64(len(c.MLSCommit.Path.Nodes)))
			for _, pn := range c.MLSCommit.Path.Nodes {
				writeUint64BE(h, uint64(int64(pn.NodeIndex)))
				writeLenPrefixed(h, pn.PublicKey[:])
				kIndices := make([]int, 0, len(pn.EncryptedKeys))
				for idx := range pn.EncryptedKeys {
					kIndices = append(kIndices, idx)
				}
				sort.Ints(kIndices)
				writeUint64BE(h, uint64(len(kIndices)))
				for _, idx := range kIndices {
					cipher := pn.EncryptedKeys[idx]
					writeUint64BE(h, uint64(int64(idx)))
					writeLenPrefixed(h, cipher.EphemeralPub[:])
					writeLenPrefixed(h, cipher.Ciphertext)
				}
			}
		} else {
			writeLenPrefixed(h, []byte("no-path"))
		}
		writeLenPrefixed(h, c.MLSCommit.ConfirmationTag[:])
		writeLenPrefixed(h, c.MLSCommit.Signature)
	}
	if c.MLSWelcome != nil {
		writeLenPrefixed(h, []byte("welcome-v2"))
		writeLenPrefixed(h, []byte(c.MLSWelcome.GroupID))
		writeUint64BE(h, c.MLSWelcome.Epoch)
		writeUint64BE(h, uint64(int64(c.MLSWelcome.SignerLeaf)))
		writeLenPrefixed(h, c.MLSWelcome.EncryptedGroupSecret.EphemeralPub[:])
		writeLenPrefixed(h, c.MLSWelcome.EncryptedGroupSecret.Ciphertext)
		writeLenPrefixed(h, c.MLSWelcome.TreeHash[:])
		writeLenPrefixed(h, c.MLSWelcome.ConfirmedTranscriptHash[:])
		writeLenPrefixed(h, c.MLSWelcome.Signature)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// CanonicalRelayFrame returns canonical bytes for authenticating a peer-to-peer relay envelope.
func CanonicalRelayFrame(from, target, relayType string, payload []byte, timestamp int64) []byte {
	sum := sha256.Sum256(payload)
	return EncodeCanonical("cotilla-relay-v1", from, target, relayType, hex.EncodeToString(sum[:]), strconv.FormatInt(timestamp, 10))
}

// CanonicalAttachMeta returns canonical bytes for authenticating attachment metadata offers.
func CanonicalAttachMeta(roomID, fileID, hash, name, mime, author string, size int64, totalChunks int, epochID, timestamp int64) []byte {
	return EncodeCanonical(
		"cotilla-attach-meta-v1",
		roomID, fileID, hash, name, mime, author,
		strconv.FormatInt(size, 10), strconv.Itoa(totalChunks), strconv.FormatInt(epochID, 10), strconv.FormatInt(timestamp, 10),
	)
}

// CanonicalSignalingMsg returns canonical bytes for authenticating WebRTC signaling /ws control messages.
func CanonicalSignalingMsg(msgType, peer, target, sdp string, timestamp int64) []byte {
	sum := sha256.Sum256([]byte(sdp))
	return EncodeCanonical("cotilla-ws-sig-v1", msgType, peer, target, hex.EncodeToString(sum[:]), strconv.FormatInt(timestamp, 10))
}

// CanonicalPeerSignal returns canonical bytes for authenticating PeerSignal frames.
func CanonicalPeerSignal(signalID, kind, from, target, sdp string, timestamp int64) []byte {
	sum := sha256.Sum256([]byte(sdp))
	return EncodeCanonical("cotilla-peer-signal-v1", signalID, kind, from, target, hex.EncodeToString(sum[:]), strconv.FormatInt(timestamp, 10))
}

// CanonicalChannelQuery returns canonical bytes for authenticating epidemic ChannelQuery frames.
func CanonicalChannelQuery(queryID, channelID, sessionToken, senderPub string, timestamp int64) []byte {
	return EncodeCanonical("cotilla-channel-query-v1", queryID, channelID, sessionToken, senderPub, strconv.FormatInt(timestamp, 10))
}

// CanonicalChannelOffer returns canonical bytes for authenticating ChannelOffer frames.
func CanonicalChannelOffer(queryID, channelID, sessionToken, responderPub, sdpOffer string, timestamp int64) []byte {
	sum := sha256.Sum256([]byte(sdpOffer))
	return EncodeCanonical("cotilla-channel-offer-v1", queryID, channelID, sessionToken, responderPub, hex.EncodeToString(sum[:]), strconv.FormatInt(timestamp, 10))
}

// CanonicalChannelAnswer returns canonical bytes for authenticating ChannelAnswer frames.
func CanonicalChannelAnswer(channelID, sessionToken, targetPub, responderPub, sdpAnswer string, timestamp int64) []byte {
	sum := sha256.Sum256([]byte(sdpAnswer))
	return EncodeCanonical("cotilla-channel-answer-v1", channelID, sessionToken, targetPub, responderPub, hex.EncodeToString(sum[:]), strconv.FormatInt(timestamp, 10))
}

// CanonicalEpochCommitFromCommit generates the canonical byte representation for an EpochCommit struct.
func CanonicalEpochCommitFromCommit(c *EpochCommit) []byte {
	return CanonicalEpochCommit(c.EpochID, c.RoomID, c.Evictor, c.EvictorEncPub, c.EvictedPeer, c.AddedPeer, c.Reason, ComputeMLSCommitDigest(c), c.Timestamp)
}

// CanonicalLeave returns length-prefixed canonical bytes for signing a voluntary departure frame.
func CanonicalLeave(peer string, timestamp int64) []byte {
	return EncodeCanonical("cotilla-leave-v1", peer, strconv.FormatInt(timestamp, 10))
}

// CanonicalDirectInvite returns length-prefixed canonical bytes for signing an invite with forward secrecy.
func CanonicalDirectInvite(inviteID, fromSignPub, fromEncPub, ephemeralPub, toSignPub, nonce, ciphertext string, timestamp int64) []byte {
	return EncodeCanonical("cotilla-invite-v2", inviteID, fromSignPub, fromEncPub, ephemeralPub, toSignPub, nonce, ciphertext, strconv.FormatInt(timestamp, 10))
}

// CanonicalInviteResponse returns length-prefixed canonical bytes for signing an invite response.
func CanonicalInviteResponse(inviteID, fromSignPub, toSignPub string, accepted bool, timestamp int64) []byte {
	accStr := "false"
	if accepted {
		accStr = "true"
	}
	return EncodeCanonical("cotilla-invite-res-v1", inviteID, fromSignPub, toSignPub, accStr, strconv.FormatInt(timestamp, 10))
}

// CanonicalCallControl returns canonical bytes for signing an encrypted call presence control frame.
func CanonicalCallControl(scopeID, authorPub, nonceHex, ciphertextHex string, epochID, timestamp int64, isDM bool) []byte {
	dmFlag := "0"
	if isDM {
		dmFlag = "1"
	}
	return EncodeCanonical(
		"cotilla-call-ctrl-v1",
		scopeID, authorPub, dmFlag,
		nonceHex, ciphertextHex,
		strconv.FormatInt(epochID, 10), strconv.FormatInt(timestamp, 10),
	)
}

// CanonicalCallControlAAD binds the outer metadata of a CallControlFrame into AEAD AAD.
func CanonicalCallControlAAD(scopeID, authorPub string, epochID, timestamp int64, isDM bool) []byte {
	dmFlag := "0"
	if isDM {
		dmFlag = "1"
	}
	return EncodeCanonical(
		"cotilla-call-ctrl-aad-v1",
		scopeID, authorPub, dmFlag,
		strconv.FormatInt(epochID, 10), strconv.FormatInt(timestamp, 10),
	)
}

// CanonicalCallSignal returns canonical bytes for signing a pairwise Noise_IK-encrypted call signal frame.
func CanonicalCallSignal(fromSignPub, fromEncPub, toSignPub, ePubHex, nonceHex, ciphertextHex string, timestamp int64) []byte {
	return EncodeCanonical(
		"cotilla-call-sig-v1",
		fromSignPub, fromEncPub, toSignPub, ePubHex, nonceHex, ciphertextHex,
		strconv.FormatInt(timestamp, 10),
	)
}

// CanonicalCallSignalAAD binds pairwise Noise_IK call signal endpoints and timestamp.
func CanonicalCallSignalAAD(fromSignPub, toSignPub string, timestamp int64) []byte {
	return EncodeCanonical("cotilla-call-sig-aad-v1", fromSignPub, toSignPub, strconv.FormatInt(timestamp, 10))
}

// EncryptRoomPayload encrypts plaintext with the room key and additional authenticated data (AAD) using XChaCha20-Poly1305.
func EncryptRoomPayload(key RoomKey, plaintext []byte, aad []byte) (nonce []byte, ciphertext []byte, err error) {
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	ciphertext = aead.Seal(nil, nonce, plaintext, aad)
	return nonce, ciphertext, nil
}

// DecryptRoomPayload decrypts ciphertext with the room key and verifies integrity against AAD using XChaCha20-Poly1305.
func DecryptRoomPayload(key RoomKey, nonce []byte, ciphertext []byte, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, errors.New("cotilla: invalid nonce length")
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, errors.New("cotilla: decryption failed (mismatched room key or corrupted/transplanted ciphertext)")
	}
	return plaintext, nil
}

// DeriveNoiseIKInviteKey computes the forward-secret symmetric invite key using Noise_IK pattern.
// ss1 = X25519(ePriv, peerEncPub)
// ss2 = X25519(staticPriv, peerEncPub)
// key = HKDF(ss1 || ss2, "cotilla-invite-v2")
func DeriveNoiseIKInviteKey(ePriv [32]byte, staticPriv [32]byte, peerEncPub [32]byte) ([]byte, error) {
	ss1, err := curve25519.X25519(ePriv[:], peerEncPub[:])
	if err != nil {
		return nil, fmt.Errorf("cotilla: x25519 ecdh (ephemeral) failed: %w", err)
	}
	ss2, err := curve25519.X25519(staticPriv[:], peerEncPub[:])
	if err != nil {
		return nil, fmt.Errorf("cotilla: x25519 ecdh (static) failed: %w", err)
	}

	combined := append(ss1, ss2...)
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(hkdf.New(sha256.New, combined, nil, []byte("cotilla-invite-v2")), key); err != nil {
		return nil, fmt.Errorf("cotilla: hkdf invite key derivation failed: %w", err)
	}
	return key, nil
}

// DeriveNoiseIKInviteKeyRecipient computes the forward-secret symmetric invite key on the recipient side.
// ss1 = X25519(recipientPriv, ePub)
// ss2 = X25519(recipientPriv, senderEncPub)
// key = HKDF(ss1 || ss2, "cotilla-invite-v2")
func DeriveNoiseIKInviteKeyRecipient(recipientPriv [32]byte, ePub [32]byte, senderEncPub [32]byte) ([]byte, error) {
	ss1, err := curve25519.X25519(recipientPriv[:], ePub[:])
	if err != nil {
		return nil, fmt.Errorf("cotilla: x25519 ecdh (ephemeral) failed: %w", err)
	}
	ss2, err := curve25519.X25519(recipientPriv[:], senderEncPub[:])
	if err != nil {
		return nil, fmt.Errorf("cotilla: x25519 ecdh (static) failed: %w", err)
	}

	combined := append(ss1, ss2...)
	key := make([]byte, chacha20poly1305.KeySize)
	_, err = io.ReadFull(hkdf.New(sha256.New, combined, nil, []byte("cotilla-invite-v2")), key)
	zeroizeBytes(ss1)
	zeroizeBytes(ss2)
	zeroizeBytes(combined)
	if err != nil {
		zeroizeBytes(key)
		return nil, fmt.Errorf("cotilla: hkdf invite key derivation failed: %w", err)
	}
	return key, nil
}

// EncryptDirectInvite encrypts plaintext payload using Noise_IK forward secrecy with recipient's X25519 key.
// Returns ephemeral public key, nonce, and ciphertext.
func EncryptDirectInvite(sender *Identity, recipientEncPub [32]byte, payloadBytes []byte, aad []byte) (ePub [32]byte, nonce []byte, ciphertext []byte, err error) {
	var ePriv [32]byte
	if _, err := io.ReadFull(rand.Reader, ePriv[:]); err != nil {
		return ePub, nil, nil, err
	}
	clampX25519Scalar(&ePriv)
	pub, err := curve25519.X25519(ePriv[:], curve25519.Basepoint)
	if err != nil {
		zeroizeBytes(ePriv[:])
		return ePub, nil, nil, err
	}
	copy(ePub[:], pub)

	key, err := DeriveNoiseIKInviteKey(ePriv, sender.EncPriv, recipientEncPub)
	zeroizeBytes(ePriv[:])
	if err != nil {
		return ePub, nil, nil, err
	}
	defer zeroizeBytes(key)

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return ePub, nil, nil, err
	}
	nonce = make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return ePub, nil, nil, err
	}
	ciphertext = aead.Seal(nil, nonce, payloadBytes, aad)
	return ePub, nonce, ciphertext, nil
}

// DecryptDirectInvite decrypts ciphertext using recipient's private key, sender's static encryption key, and ephemeral public key.
func DecryptDirectInvite(recipient *Identity, senderEncPub [32]byte, ePub [32]byte, nonce, ciphertext, aad []byte) ([]byte, error) {
	key, err := DeriveNoiseIKInviteKeyRecipient(recipient.EncPriv, ePub, senderEncPub)
	if err != nil {
		return nil, err
	}
	defer zeroizeBytes(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, errors.New("cotilla: invalid nonce length for invite decryption")
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, errors.New("cotilla: invite decryption failed (invalid key, tampered ciphertext, or mismatched AAD)")
	}
	return plaintext, nil
}

// ComputeChannelHash derives a Meshtastic-style non-zero 32-bit hash from channel name and PSK.
func ComputeChannelHash(name string, psk RoomKey) uint32 {
	h := sha256.New()
	writeLenPrefixed(h, []byte("cotilla-channel-hash-v1"))
	writeLenPrefixed(h, []byte(name))
	_, _ = h.Write(psk[:])
	sum := h.Sum(nil)
	v := binary.BigEndian.Uint32(sum[:4])
	if v == 0 {
		return 1
	}
	return v
}

// ParseEncPub decodes a hex-encoded 32-byte X25519 public key.
func ParseEncPub(hexStr string) ([32]byte, error) {
	var out [32]byte
	raw, err := hex.DecodeString(hexStr)
	if err != nil || len(raw) != 32 {
		return out, errors.New("cotilla: invalid X25519 public key")
	}
	copy(out[:], raw)
	return out, nil
}

// SealUnicast encrypts plaintext for recipientEncHex using Noise_IK (ephemeral + static X25519).
// Output layout: [32B ePub || 24B nonce || ciphertext].
func SealUnicast(sender *Identity, recipientEncHex string, plaintext, aad []byte) ([]byte, error) {
	peerPub, err := ParseEncPub(recipientEncHex)
	if err != nil {
		return nil, err
	}
	ePub, nonce, ct, err := EncryptDirectInvite(sender, peerPub, plaintext, aad)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 32+len(nonce)+len(ct))
	out = append(out, ePub[:]...)
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// OpenUnicast decrypts a payload produced by SealUnicast from senderEncHex.
func OpenUnicast(recipient *Identity, senderEncHex string, sealed, aad []byte) ([]byte, error) {
	const headerLen = 32 + chacha20poly1305.NonceSizeX
	if len(sealed) <= headerLen {
		return nil, errors.New("cotilla: unicast payload too short")
	}
	senderPub, err := ParseEncPub(senderEncHex)
	if err != nil {
		return nil, err
	}
	var ePub [32]byte
	copy(ePub[:], sealed[:32])
	nonce := sealed[32:headerLen]
	ct := sealed[headerLen:]
	return DecryptDirectInvite(recipient, senderPub, ePub, nonce, ct, aad)
}

// SealGroupPayload encrypts plaintext with key and AAD into [24B nonce || ciphertext].
func SealGroupPayload(key RoomKey, plaintext, aad []byte) ([]byte, error) {
	nonce, ct, err := EncryptRoomPayload(key, plaintext, aad)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(nonce)+len(ct))
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// OpenGroupPayload decrypts a [24B nonce || ciphertext] group payload.
func OpenGroupPayload(key RoomKey, sealed, aad []byte) ([]byte, error) {
	ns := chacha20poly1305.NonceSizeX
	if len(sealed) <= ns {
		return nil, errors.New("cotilla: group payload too short")
	}
	return DecryptRoomPayload(key, sealed[:ns], sealed[ns:], aad)
}



