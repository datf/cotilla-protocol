package cotilla

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// Public distribution constants
const (
	DefaultAppDistRoomID = "cotilla-app-dist-v1"
	DefaultAppID         = "cotilla-web"
	DefaultAppChannel    = "stable"
	FormatSingleHTMLV1   = "single-html-v1"
	FormatBundleV1       = "bundle-v1"
)

// DefaultAppDistRoomKey derives a deterministic 256-bit symmetric RoomKey for the public distribution overlay channel.
func DefaultAppDistRoomKey() RoomKey {
	sum := sha256.Sum256([]byte("cotilla-app-dist-room-key-v1:" + DefaultAppDistRoomID))
	var k RoomKey
	copy(k[:], sum[:])
	return k
}

// AppDistRoomKeyFor derives a deterministic RoomKey for any specified app-distribution room ID.
func AppDistRoomKeyFor(distRoomID string) RoomKey {
	sum := sha256.Sum256([]byte("cotilla-app-dist-room-key-v1:" + distRoomID))
	var k RoomKey
	copy(k[:], sum[:])
	return k
}

// AppManifest describes a signed application bundle distributed over Cotilla WebRTC.
type AppManifest struct {
	AppID       string `json:"app_id"`
	Channel     string `json:"channel"`
	Version     string `json:"version"`
	Seq         uint64 `json:"seq"`
	PublishedAt int64  `json:"published_at"`
	ExpiresAt   int64  `json:"expires_at,omitempty"`
	FileID      string `json:"file_id"`
	SHA256      string `json:"sha256"`
	Size        int64  `json:"size"`
	TotalChunks int    `json:"total_chunks"`
	EntryMIME   string `json:"entry_mime"`
	Format      string `json:"format"`
	PubKey      string `json:"pub_key"`
	Signature   string `json:"signature"`
}

// CanonicalAppManifest serializes the manifest metadata for Ed25519 signature computation and verification.
func CanonicalAppManifest(m *AppManifest) []byte {
	if m == nil {
		return nil
	}
	return EncodeCanonical(
		"cotilla-app-manifest-v1",
		m.AppID,
		m.Channel,
		m.Version,
		strconv.FormatUint(m.Seq, 10),
		strconv.FormatInt(m.PublishedAt, 10),
		strconv.FormatInt(m.ExpiresAt, 10),
		m.FileID,
		m.SHA256,
		strconv.FormatInt(m.Size, 10),
		strconv.Itoa(m.TotalChunks),
		m.EntryMIME,
		m.Format,
		m.PubKey,
	)
}

// GeneratePublisherKeypair generates a new random Ed25519 keypair for signing app bundles.
func GeneratePublisherKeypair() (pubHex, privHex string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("cotilla: generate publisher keypair: %w", err)
	}
	return hex.EncodeToString(pub), hex.EncodeToString(priv), nil
}

// SignAppManifest signs an AppManifest with an Ed25519 private key.
func SignAppManifest(privHex string, m *AppManifest) error {
	if m == nil {
		return errors.New("cotilla: manifest is nil")
	}
	privBytes, err := hex.DecodeString(privHex)
	if err != nil || len(privBytes) != ed25519.PrivateKeySize {
		return errors.New("cotilla: invalid publisher private key")
	}
	priv := ed25519.PrivateKey(privBytes)
	pub := priv.Public().(ed25519.PublicKey)
	m.PubKey = hex.EncodeToString(pub)

	canonical := CanonicalAppManifest(m)
	sig := ed25519.Sign(priv, canonical)
	m.Signature = hex.EncodeToString(sig)
	return nil
}

// SignAppBundle creates, hashes, and signs an AppManifest for a raw application bundle.
func SignAppBundle(privHex, appID, channel, version string, seq uint64, bundleData []byte, mime, format string, ttl time.Duration) (*AppManifest, error) {
	if len(bundleData) == 0 {
		return nil, errors.New("cotilla: bundle data is empty")
	}
	if appID == "" {
		appID = DefaultAppID
	}
	if channel == "" {
		channel = DefaultAppChannel
	}
	if mime == "" {
		mime = "text/html; charset=utf-8"
	}
	if format == "" {
		format = FormatSingleHTMLV1
	}

	sum := sha256.Sum256(bundleData)
	shaHex := hex.EncodeToString(sum[:])
	fileID := shaHex[:16]
	totalChunks := (len(bundleData) + DefaultChunkSize - 1) / DefaultChunkSize

	now := time.Now().UnixMilli()
	var expiresAt int64
	if ttl > 0 {
		expiresAt = now + ttl.Milliseconds()
	}

	m := &AppManifest{
		AppID:       appID,
		Channel:     channel,
		Version:     version,
		Seq:         seq,
		PublishedAt: now,
		ExpiresAt:   expiresAt,
		FileID:      fileID,
		SHA256:      shaHex,
		Size:        int64(len(bundleData)),
		TotalChunks: totalChunks,
		EntryMIME:   mime,
		Format:      format,
	}

	if err := SignAppManifest(privHex, m); err != nil {
		return nil, err
	}
	return m, nil
}

// VerifyAppManifest verifies the Ed25519 signature and basic constraints of an AppManifest.
func VerifyAppManifest(m *AppManifest, pinnedPubHex, expectedAppID, expectedChannel string, minSeq uint64, nowMs int64) error {
	var validKeys []string
	if pinnedPubHex != "" {
		validKeys = []string{pinnedPubHex}
	}
	return VerifyAppManifestWithKeys(m, validKeys, expectedAppID, "", expectedChannel, minSeq, nowMs)
}

// VerifyAppManifestWithKeys validates an AppManifest against a list of allowed publisher public keys,
// app name (expectedAppID), optional version, channel, and sequence floor.
func VerifyAppManifestWithKeys(m *AppManifest, validPubKeys []string, expectedAppID, expectedVersion, expectedChannel string, minSeq uint64, nowMs int64) error {
	if m == nil {
		return errors.New("cotilla: manifest is nil")
	}
	if len(validPubKeys) > 0 && !containsKey(validPubKeys, m.PubKey) {
		return fmt.Errorf("cotilla: publisher key %s not in validSignatures", m.PubKey)
	}
	if expectedAppID != "" && m.AppID != expectedAppID {
		return fmt.Errorf("cotilla: app_id mismatch: expected %s, got %s", expectedAppID, m.AppID)
	}
	if expectedVersion != "" && m.Version != expectedVersion {
		return fmt.Errorf("cotilla: version mismatch: expected %s, got %s", expectedVersion, m.Version)
	}
	if expectedChannel != "" && m.Channel != expectedChannel {
		return fmt.Errorf("cotilla: channel mismatch: expected %s, got %s", expectedChannel, m.Channel)
	}
	if m.Seq < minSeq {
		return fmt.Errorf("cotilla: manifest seq rollback: minSeq %d > seq %d", minSeq, m.Seq)
	}
	if m.ExpiresAt > 0 && nowMs > m.ExpiresAt {
		return fmt.Errorf("cotilla: manifest expired at %d, now %d", m.ExpiresAt, nowMs)
	}
	if m.PublishedAt > nowMs+5*60*1000 {
		return fmt.Errorf("cotilla: manifest published in future: %d > now %d", m.PublishedAt, nowMs)
	}
	if m.FileID == "" || m.SHA256 == "" || m.Size <= 0 || m.TotalChunks <= 0 || m.Format == "" || m.Version == "" {
		return errors.New("cotilla: invalid manifest dimensions or missing version")
	}
	if !Verify(m.PubKey, CanonicalAppManifest(m), m.Signature) {
		return errors.New("cotilla: invalid manifest signature")
	}
	return nil
}

// VerifyAppBundle verifies both the AppManifest and the downloaded bundle bytes against a single pinned key.
func VerifyAppBundle(m *AppManifest, bundleBytes []byte, pinnedPubHex, expectedAppID, expectedChannel string, minSeq uint64, nowMs int64) error {
	var validKeys []string
	if pinnedPubHex != "" {
		validKeys = []string{pinnedPubHex}
	}
	return VerifyAppBundleWithKeys(m, bundleBytes, validKeys, expectedAppID, "", expectedChannel, minSeq, nowMs)
}

// VerifyAppBundleWithKeys verifies both the AppManifest (against validPubKeys, app name, and optional version)
// and the SHA-256 digest and chunk dimensions of the downloaded bundle bytes.
func VerifyAppBundleWithKeys(m *AppManifest, bundleBytes []byte, validPubKeys []string, expectedAppID, expectedVersion, expectedChannel string, minSeq uint64, nowMs int64) error {
	if err := VerifyAppManifestWithKeys(m, validPubKeys, expectedAppID, expectedVersion, expectedChannel, minSeq, nowMs); err != nil {
		return err
	}
	if int64(len(bundleBytes)) != m.Size {
		return fmt.Errorf("cotilla: bundle size mismatch: expected %d bytes, got %d", m.Size, len(bundleBytes))
	}
	sum := sha256.Sum256(bundleBytes)
	shaHex := hex.EncodeToString(sum[:])
	if shaHex != m.SHA256 {
		return fmt.Errorf("cotilla: bundle sha256 mismatch: expected %s, got %s", m.SHA256, shaHex)
	}
	if m.FileID != shaHex[:16] {
		return fmt.Errorf("cotilla: bundle file_id mismatch: expected %s, got %s", shaHex[:16], m.FileID)
	}
	expectedChunks := (len(bundleBytes) + DefaultChunkSize - 1) / DefaultChunkSize
	if m.TotalChunks != expectedChunks {
		return fmt.Errorf("cotilla: bundle total chunks mismatch: expected %d, got %d", expectedChunks, m.TotalChunks)
	}
	return nil
}

func containsKey(keys []string, target string) bool {
	for _, k := range keys {
		if k != "" && k == target {
			return true
		}
	}
	return false
}
