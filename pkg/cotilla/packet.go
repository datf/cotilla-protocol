package cotilla

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"
)

// BroadcastAddr is the universal destination address for mesh broadcasts (32-byte 0xFF hex).
const BroadcastAddr = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

// Port identifies the application or control handler for a Packet payload.
type Port string

const (
	// Network & HyParView overlay ports
	PortPeerRequest       Port = "peer_request"
	PortPeerResponse      Port = "peer_response"
	PortWebRTCSignal      Port = "webrtc_signal"
	PortRootIntro         Port = "root_intro"
	PortAnchorSolicit     Port = "anchor_solicit"
	PortHyParViewShuffle  Port = "hyparview_shuffle"
	PortHyParViewNeighbor Port = "hyparview_neighbor"
	PortLeave             Port = "leave"

	// Group / Channel & MLS ports (always encrypted inside Packet.Payload)
	PortGroupDiscover Port = "group_discover"
	PortGroupPeerInfo Port = "group_peer_info"
	PortEpochCommit   Port = "epoch_commit"
	PortChat          Port = "chat"
	PortSyncReq       Port = "sync_req"
	PortSyncRes       Port = "sync_res"
	PortAttachMeta    Port = "attach_meta"
	PortChunkReq      Port = "chunk_req"
	PortChunkRes      Port = "chunk_res"

	// Public App Seeder Group ports (always encrypted inside Packet.Payload with group PSK)
	PortAppInviteReq   Port = "app_invite_req"
	PortAppManifestReq Port = "app_manifest_req"
	PortAppManifestRes Port = "app_manifest_res"

	// 1:1 Direct Messaging & Scoped Calls
	PortDirectInvite    Port = "direct_invite"
	PortDirectInviteRes Port = "direct_invite_res"
	PortDM              Port = "dm"
	PortCallCtrl        Port = "call_ctrl"
	PortCallSig         Port = "call_sig"
)

// Packet is the unified Meshtastic-inspired routed wire envelope for all Cotilla mesh traffic.
type Packet struct {
	ID          string `json:"id"`
	From        string `json:"from"`
	FromEnc     string `json:"from_enc,omitempty"`
	To          string `json:"to"`
	ChannelHash uint32 `json:"ch,omitempty"`
	EpochID     int64  `json:"epoch,omitempty"`
	HopLimit    int    `json:"hop"`
	HopStart    int    `json:"hop_start"`
	Timestamp   int64  `json:"ts"`
	Encrypted   bool   `json:"enc"`
	Port        Port   `json:"port,omitempty"`
	Payload     []byte `json:"payload"`
	Signature   string `json:"sig"`
}

// SealedData is the decrypted inner payload when Packet.Encrypted is true.
type SealedData struct {
	Port Port            `json:"port"`
	Body json.RawMessage `json:"body"`
}

// PeerDescriptor advertises a peer's addresses and joined channel hashes.
type PeerDescriptor struct {
	SignPub       string   `json:"sign_pub"`
	EncPub        string   `json:"enc_pub,omitempty"`
	ChannelHashes []uint32 `json:"ch,omitempty"`
}

// PeerRequestPayload is broadcast to BroadcastAddr to discover peers in the mesh.
type PeerRequestPayload struct {
	WantCount     int      `json:"want"`
	KnownPeers    []string `json:"known,omitempty"`
	ChannelHashes []uint32 `json:"ch,omitempty"`
}

// PeerResponsePayload is sent encrypted and signed back to the issuer of a PeerRequest.
type PeerResponsePayload struct {
	RequestID string           `json:"req_id"`
	Peers     []PeerDescriptor `json:"peers"`
}

// WebRTCSignalPayload carries an encrypted WebRTC SDP offer/answer routed across the mesh.
type WebRTCSignalPayload struct {
	Kind string `json:"kind"` // "offer" | "answer"
	SDP  string `json:"sdp"`
}

// ShufflePayload exchanges HyParView active/passive peer samples for mesh healing.
type ShufflePayload struct {
	Origin        PeerDescriptor   `json:"origin"`
	Peers         []PeerDescriptor `json:"peers"`
	RemainingHops int              `json:"hops,omitempty"`
	IsReply       bool             `json:"is_reply,omitempty"`
	RequestID     string           `json:"req_id,omitempty"`
}

// GroupDiscoverPayload announces interest in a group (encrypted with group PSK or epoch key).
type GroupDiscoverPayload struct {
	RoomID  string `json:"room_id"`
	Want    int    `json:"want,omitempty"`
	IsReply bool   `json:"is_reply,omitempty"`
}

// RandomID returns a random 128-bit hex identifier.
func RandomID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// CanonicalPacket computes immutable canonical bytes for Ed25519 signing (excludes HopLimit).
func CanonicalPacket(p *Packet) []byte {
	sum := sha256.Sum256(p.Payload)
	encFlag := "0"
	if p.Encrypted {
		encFlag = "1"
	}
	return EncodeCanonical(
		"cotilla-packet-v1",
		p.ID, p.From, p.FromEnc, p.To,
		strconv.FormatUint(uint64(p.ChannelHash), 10),
		strconv.FormatInt(p.EpochID, 10),
		strconv.Itoa(p.HopStart),
		strconv.FormatInt(p.Timestamp, 10),
		encFlag, string(p.Port),
		hex.EncodeToString(sum[:]),
	)
}

// PacketAAD binds immutable routing headers into the AEAD additional authenticated data.
func PacketAAD(p *Packet) []byte {
	return EncodeCanonical(
		"cotilla-packet-aad-v1",
		p.ID, p.From, p.To,
		strconv.FormatUint(uint64(p.ChannelHash), 10),
		strconv.FormatInt(p.EpochID, 10),
		strconv.FormatInt(p.Timestamp, 10),
	)
}

// SignPacket signs p with id and populates p.Signature.
func SignPacket(id *Identity, p *Packet) {
	p.Signature = hex.EncodeToString(id.Sign(CanonicalPacket(p)))
}

// VerifyPacket checks structural validity, hop bounds, replay window, and Ed25519 signature.
func VerifyPacket(p *Packet, maxHop int, replayWindow time.Duration) error {
	if p == nil || p.ID == "" || p.From == "" || p.To == "" || p.Signature == "" {
		return errors.New("cotilla: malformed packet header")
	}
	if p.HopLimit < 0 || p.HopStart <= 0 || p.HopLimit > p.HopStart || (maxHop > 0 && p.HopStart > maxHop) {
		return errors.New("cotilla: packet hop limit out of bounds")
	}
	if replayWindow > 0 {
		diff := time.Now().UnixMilli() - p.Timestamp
		if diff < 0 {
			diff = -diff
		}
		if diff > replayWindow.Milliseconds() {
			return errors.New("cotilla: packet timestamp outside replay window")
		}
	}
	if !Verify(p.From, CanonicalPacket(p), p.Signature) {
		return errors.New("cotilla: invalid packet signature")
	}
	return nil
}

// NewPlainPacket constructs and signs an unencrypted network discovery packet.
func NewPlainPacket(id *Identity, to string, port Port, hopLimit int, body any) (*Packet, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	p := &Packet{
		ID:        RandomID(),
		From:      id.Address(),
		FromEnc:   id.EncAddress(),
		To:        to,
		HopLimit:  hopLimit,
		HopStart:  hopLimit,
		Timestamp: time.Now().UnixMilli(),
		Encrypted: false,
		Port:      port,
		Payload:   raw,
	}
	SignPacket(id, p)
	return p, nil
}

// NewUnicastPacket constructs an X25519-encrypted, Ed25519-signed packet for one peer.
func NewUnicastPacket(id *Identity, toSignPub, toEncPub string, port Port, hopLimit int, body any) (*Packet, error) {
	inner, err := marshalSealedData(port, body)
	if err != nil {
		return nil, err
	}
	p := &Packet{
		ID:        RandomID(),
		From:      id.Address(),
		FromEnc:   id.EncAddress(),
		To:        toSignPub,
		HopLimit:  hopLimit,
		HopStart:  hopLimit,
		Timestamp: time.Now().UnixMilli(),
		Encrypted: true,
	}
	sealed, err := SealUnicast(id, toEncPub, inner, PacketAAD(p))
	if err != nil {
		return nil, err
	}
	p.Payload = sealed
	SignPacket(id, p)
	return p, nil
}

// NewGroupPacket constructs a group-encrypted, Ed25519-signed packet for a public or private channel.
func NewGroupPacket(id *Identity, to string, chHash uint32, epochID int64, key RoomKey, port Port, hopLimit int, body any) (*Packet, error) {
	if to == "" {
		to = BroadcastAddr
	}
	inner, err := marshalSealedData(port, body)
	if err != nil {
		return nil, err
	}
	p := &Packet{
		ID:          RandomID(),
		From:        id.Address(),
		FromEnc:     id.EncAddress(),
		To:          to,
		ChannelHash: chHash,
		EpochID:     epochID,
		HopLimit:    hopLimit,
		HopStart:    hopLimit,
		Timestamp:   time.Now().UnixMilli(),
		Encrypted:   true,
	}
	sealed, err := SealGroupPayload(key, inner, PacketAAD(p))
	if err != nil {
		return nil, err
	}
	p.Payload = sealed
	SignPacket(id, p)
	return p, nil
}

// OpenUnicastPacket decrypts a unicast Packet's inner SealedData.
func OpenUnicastPacket(id *Identity, p *Packet) (*SealedData, error) {
	plain, err := OpenUnicast(id, p.FromEnc, p.Payload, PacketAAD(p))
	if err != nil {
		return nil, err
	}
	return unmarshalSealedData(plain)
}

// OpenGroupPacket decrypts a group Packet's inner SealedData using key.
func OpenGroupPacket(key RoomKey, p *Packet) (*SealedData, error) {
	plain, err := OpenGroupPayload(key, p.Payload, PacketAAD(p))
	if err != nil {
		return nil, err
	}
	return unmarshalSealedData(plain)
}

func marshalSealedData(port Port, body any) ([]byte, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	return json.Marshal(&SealedData{Port: port, Body: raw})
}

func unmarshalSealedData(plain []byte) (*SealedData, error) {
	var sd SealedData
	if err := json.Unmarshal(plain, &sd); err != nil {
		return nil, fmt.Errorf("cotilla: decode sealed data: %w", err)
	}
	return &sd, nil
}

// MarshalPacket serializes a Packet to JSON (see TODO.md §4 for future Protobuf migration).
func MarshalPacket(p *Packet) ([]byte, error) {
	return json.Marshal(p)
}

// UnmarshalPacket deserializes a Packet from JSON.
func UnmarshalPacket(data []byte) (*Packet, error) {
	var p Packet
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// PacketCache provides bounded deduplication of seen packet IDs.
type PacketCache struct {
	mu      sync.Mutex
	entries map[string]time.Time
	ttl     time.Duration
	maxSize int
}

// NewPacketCache creates a bounded PacketCache.
func NewPacketCache(ttl time.Duration, maxSize int) *PacketCache {
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	if maxSize <= 0 {
		maxSize = 5000
	}
	return &PacketCache{
		entries: make(map[string]time.Time),
		ttl:     ttl,
		maxSize: maxSize,
	}
}

// MarkSeen records id and returns true if it was already present and unexpired.
func (c *PacketCache) MarkSeen(id string) bool {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if exp, ok := c.entries[id]; ok && now.Before(exp) {
		return true
	}
	if len(c.entries) >= c.maxSize {
		c.pruneLocked(now)
	}
	c.entries[id] = now.Add(c.ttl)
	return false
}

func (c *PacketCache) pruneLocked(now time.Time) {
	for k, exp := range c.entries {
		if now.After(exp) {
			delete(c.entries, k)
		}
	}
	if len(c.entries) >= c.maxSize {
		c.entries = make(map[string]time.Time)
	}
}
