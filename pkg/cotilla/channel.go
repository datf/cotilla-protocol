package cotilla

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Envelope carries an encrypted chat message payload and author's Ed25519 signature.
// It is stored in RingBuffer for catch-up sync and delivered to Hooks.OnMessage.
type Envelope struct {
	RoomID       string `json:"room_id"`
	AuthorPubKey string `json:"author_pub_key"`
	Nonce        string `json:"nonce"`
	Ciphertext   string `json:"ciphertext"`
	Timestamp    int64  `json:"timestamp"`
	Signature    string `json:"signature"`
	EpochID      int64  `json:"epoch_id,omitempty"`
	MsgID        string `json:"-"`
}

// ID returns the unique message identifier (SHA-256 hash of signature and nonce).
func (e *Envelope) ID() string {
	if e.MsgID != "" {
		return e.MsgID
	}
	h := sha256.Sum256([]byte(e.Signature + ":" + e.Nonce))
	e.MsgID = hex.EncodeToString(h[:16])
	return e.MsgID
}

// NewEnvelope creates, encrypts, and signs a message envelope for roomID at epoch 0.
func NewEnvelope(id *Identity, roomID string, roomKey RoomKey, plaintext []byte) (*Envelope, error) {
	return NewEnvelopeWithEpoch(id, roomID, roomKey, 0, plaintext)
}

// NewEnvelopeWithEpoch creates, encrypts, and signs a message envelope bound to epochID.
func NewEnvelopeWithEpoch(id *Identity, roomID string, roomKey RoomKey, epochID int64, plaintext []byte) (*Envelope, error) {
	author := id.Address()
	aad := []byte(fmt.Sprintf("cotilla-envelope-v1:%s:%d:%s", roomID, epochID, author))
	nonceBytes, cipherBytes, err := EncryptRoomPayload(roomKey, plaintext, aad)
	if err != nil {
		return nil, err
	}
	nonceStr := base64.RawURLEncoding.EncodeToString(nonceBytes)
	cipherStr := base64.RawURLEncoding.EncodeToString(cipherBytes)
	ts := time.Now().UnixMilli()
	canonical := CanonicalEnvelopePayload(roomID, author, nonceStr, cipherStr, epochID, ts)
	env := &Envelope{
		RoomID:       roomID,
		AuthorPubKey: author,
		Nonce:        nonceStr,
		Ciphertext:   cipherStr,
		Timestamp:    ts,
		Signature:    hex.EncodeToString(id.Sign(canonical)),
		EpochID:      epochID,
	}
	_ = env.ID()
	return env, nil
}

// Verify checks the envelope signature, room ID, and clock skew window.
func (e *Envelope) Verify(expectedRoomID string, maxClockSkew time.Duration) error {
	if expectedRoomID != "" && e.RoomID != expectedRoomID {
		return errors.New("cotilla: envelope room_id mismatch")
	}
	if maxClockSkew > 0 {
		diff := time.Now().UnixMilli() - e.Timestamp
		if diff < 0 {
			diff = -diff
		}
		if diff > maxClockSkew.Milliseconds() {
			return errors.New("cotilla: envelope timestamp outside acceptable replay window")
		}
	}
	canonical := CanonicalEnvelopePayload(e.RoomID, e.AuthorPubKey, e.Nonce, e.Ciphertext, e.EpochID, e.Timestamp)
	if !Verify(e.AuthorPubKey, canonical, e.Signature) {
		return errors.New("cotilla: invalid envelope signature")
	}
	return nil
}

// Decrypt opens the envelope using roomKey and verifies integrity against context AAD.
func (e *Envelope) Decrypt(roomKey RoomKey) ([]byte, error) {
	nonceBytes, err := base64.RawURLEncoding.DecodeString(e.Nonce)
	if err != nil {
		return nil, err
	}
	cipherBytes, err := base64.RawURLEncoding.DecodeString(e.Ciphertext)
	if err != nil {
		return nil, err
	}
	aad := []byte(fmt.Sprintf("cotilla-envelope-v1:%s:%d:%s", e.RoomID, e.EpochID, e.AuthorPubKey))
	return DecryptRoomPayload(roomKey, nonceBytes, cipherBytes, aad)
}

// ChannelState holds isolated cryptographic, MLS, attachment, and sync state for one channel.
type ChannelState struct {
	RoomID      string
	ChannelHash uint32
	Kind        ChannelKind
	RoomKey     RoomKey
	BootstrapKey RoomKey // Initial PSK / K0 bootstrap key

	RingBuffer *RingBuffer

	// Epoch Ratchet, Dynamic Membership & TreeKEM (RFC 9420)
	currentEpoch     int64
	joinedEpoch      int64
	memberJoinEpoch  map[string]int64
	commitHistory    []*EpochCommit
	pendingCommits   map[int64]*EpochCommit
	epochKeys        map[int64]RoomKey
	epochTimestamps  map[int64]int64
	evictedPeers     map[string]int64
	peerInviters     map[string]string
	creatorPub       string
	channelInvite    *ChannelInvite
	mlsGroup         *MLSGroup
	myKeyPackage     *KeyPackage
	peerKeyPackages  map[string]*KeyPackage
	admittedInitKeys map[string][32]byte

	// Attachments
	localAttachments     map[string][][]byte
	assemblers           map[string]*AttachmentAssembler
	knownOffers          map[string]*AttachmentMeta
	offerSources         map[string]string
	assembledAttachments map[string][]byte
	downloading          map[string]bool

	// Deduplication
	seenEnvelopes map[string]struct{}
	seenOrder     []string
	lastSeenMsgID string

	// Expanding-Ring Targeted Sync
	syncMutex        sync.Mutex
	syncBatchSize    int
	queriedSyncPeers map[string]bool
	syncActive       bool
	syncLastReqAt    time.Time
	syncLastRespAt   time.Time

	// Public App Distribution metadata
	IsAppDist        bool
	appDistValidSigs []string
	appDistAppName   string
	appDistVersion   string
	appDistMinSeq    uint64
	appManifests     map[string]*AppManifest
}

func newChannelState(roomID string, roomKey RoomKey, kind ChannelKind, myKp *KeyPackage, cfg Config) *ChannelState {
	return &ChannelState{
		RoomID:               roomID,
		ChannelHash:          ComputeChannelHash(roomID, roomKey),
		Kind:                 kind,
		RoomKey:              roomKey,
		BootstrapKey:         roomKey,
		RingBuffer:           NewRingBuffer(cfg.RingBufferCapacity, cfg.MessageTTL),
		memberJoinEpoch:      make(map[string]int64),
		commitHistory:        make([]*EpochCommit, 0),
		pendingCommits:       make(map[int64]*EpochCommit),
		epochKeys:            map[int64]RoomKey{0: roomKey},
		epochTimestamps:      map[int64]int64{0: time.Now().UnixMilli()},
		evictedPeers:         make(map[string]int64),
		peerInviters:         make(map[string]string),
		myKeyPackage:         myKp,
		peerKeyPackages:      make(map[string]*KeyPackage),
		admittedInitKeys:     make(map[string][32]byte),
		localAttachments:     make(map[string][][]byte),
		assemblers:           make(map[string]*AttachmentAssembler),
		knownOffers:          make(map[string]*AttachmentMeta),
		offerSources:         make(map[string]string),
		assembledAttachments: make(map[string][]byte),
		downloading:          make(map[string]bool),
		seenEnvelopes:        make(map[string]struct{}),
		seenOrder:            make([]string, 0, 200),
		queriedSyncPeers:     make(map[string]bool),
		syncBatchSize:        1,
		appManifests:         make(map[string]*AppManifest),
	}
}

func (ch *ChannelState) decryptGroupPacket(p *Packet) (*SealedData, error) {
	if key, ok := ch.epochKeys[p.EpochID]; ok {
		if sd, err := OpenGroupPacket(key, p); err == nil {
			return sd, nil
		}
	}
	if sd, err := OpenGroupPacket(ch.RoomKey, p); err == nil {
		return sd, nil
	}
	if ch.BootstrapKey != ch.RoomKey {
		if sd, err := OpenGroupPacket(ch.BootstrapKey, p); err == nil {
			return sd, nil
		}
	}
	return nil, errors.New("cotilla: unable to decrypt group packet with any known epoch key")
}

func (ch *ChannelState) activeKeyAndEpoch() (RoomKey, int64) {
	if ch.Kind == ChannelPublic {
		return ch.BootstrapKey, 0
	}
	return ch.RoomKey, ch.currentEpoch
}
