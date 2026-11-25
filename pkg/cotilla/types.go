package cotilla

// ChannelInvite represents a cryptographically signed invitation to join a channel.
type ChannelInvite struct {
	RoomID       string         `json:"room_id"`
	InviterPub   string         `json:"inviter_pub"`
	InviteePub   string         `json:"invitee_pub,omitempty"`
	RoomKey      string         `json:"room_key,omitempty"`
	RoomKeyHash  string         `json:"room_key_hash,omitempty"`
	EpochID      int64          `json:"epoch_id"`
	ExpiresAt    int64          `json:"expires_at"`
	Signature    string         `json:"signature"`
	ParentInvite *ChannelInvite `json:"parent_invite,omitempty"`
}

// KeyCommitment returns the canonical SHA-256 key commitment for this invite.
func (inv *ChannelInvite) KeyCommitment() string {
	if inv == nil {
		return ""
	}
	if inv.RoomKeyHash != "" {
		return inv.RoomKeyHash
	}
	return InviteKeyCommitment(inv.RoomKey)
}

// Redacted returns a deep copy of the ChannelInvite chain with raw RoomKey stripped.
func (inv *ChannelInvite) Redacted() *ChannelInvite {
	if inv == nil {
		return nil
	}
	clone := *inv
	if clone.RoomKeyHash == "" && clone.RoomKey != "" {
		clone.RoomKeyHash = InviteKeyCommitment(clone.RoomKey)
	}
	clone.RoomKey = ""
	if inv.ParentInvite != nil {
		clone.ParentInvite = inv.ParentInvite.Redacted()
	}
	return &clone
}

// PeerInfoFrame announces a peer's credentials, invite provenance, and MLS KeyPackage.
type PeerInfoFrame struct {
	RoomID     string         `json:"room_id,omitempty"`
	SignPub    string         `json:"sign_pub"`
	EncPub     string         `json:"enc_pub"`
	Timestamp  int64          `json:"timestamp"`
	Signature  string         `json:"signature"`
	Invite     *ChannelInvite `json:"invite,omitempty"`
	KeyPackage *KeyPackage    `json:"key_package,omitempty"`
}

// RootIntroFrame informs an arriving node of active anchor nodes and gateway encryption key.
type RootIntroFrame struct {
	AnchorPeers []string         `json:"anchor_peers"`
	Anchors     []PeerDescriptor `json:"anchors,omitempty"`
	Fallback    bool             `json:"fallback,omitempty"`
	IsAnchor    bool             `json:"is_anchor,omitempty"`
}

// AnchorSolicitFrame asks healthy non-anchor peers to register with their signaling server.
type AnchorSolicitFrame struct {
	QueryID string   `json:"query_id"`
	Sender  string   `json:"sender"`
	Needed  int      `json:"needed"`
	Exclude []string `json:"exclude,omitempty"`
}

// EpochCommit encapsulates an MLS epoch ratchet commit (admission, eviction, or key rotation).
type EpochCommit struct {
	EpochID         int64          `json:"epoch_id"`
	RoomID          string         `json:"room_id"`
	Evictor         string         `json:"evictor"`
	EvictorEncPub   string         `json:"evictor_enc_pub,omitempty"`
	EvictedPeer     string         `json:"evicted_peer,omitempty"`
	AddedPeer       string         `json:"added_peer,omitempty"`
	Reason          string         `json:"reason,omitempty"`
	MLSCommit       *MLSCommit     `json:"mls_commit,omitempty"`
	MLSWelcome      *MLSWelcome    `json:"mls_welcome,omitempty"`
	CommitterInvite *ChannelInvite `json:"committer_invite,omitempty"`
	Timestamp       int64          `json:"timestamp"`
	Signature       string         `json:"signature"`
}

// LeaveFrame announces voluntary departure from the mesh or a channel.
type LeaveFrame struct {
	RoomID    string `json:"room_id,omitempty"`
	Peer      string `json:"peer"`
	Timestamp int64  `json:"timestamp"`
	Signature string `json:"signature"`
}

// DirectInvite encapsulates a Noise_IK encrypted invite to a 1:1 DM or breakout room.
type DirectInvite struct {
	InviteID     string `json:"invite_id"`
	FromSignPub  string `json:"from_sign_pub"`
	FromEncPub   string `json:"from_enc_pub"`
	EphemeralPub string `json:"ephemeral_pub"`
	ToSignPub    string `json:"to_sign_pub"`
	Nonce        string `json:"nonce"`
	Ciphertext   string `json:"ciphertext"`
	Timestamp    int64  `json:"timestamp"`
	Signature    string `json:"signature"`
}

// InvitePayload is the decrypted body of a DirectInvite.
type InvitePayload struct {
	Type      string `json:"type"` // "dm" | "breakout"
	RoomID    string `json:"room_id"`
	RoomKey   string `json:"room_key"`
	Title     string `json:"title,omitempty"`
	CreatedAt int64  `json:"created_at"`
}

// InviteResponse conveys accept/decline status for a DirectInvite.
type InviteResponse struct {
	InviteID    string `json:"invite_id"`
	FromSignPub string `json:"from_sign_pub"`
	ToSignPub   string `json:"to_sign_pub"`
	Accepted    bool   `json:"accepted"`
	Timestamp   int64  `json:"timestamp"`
	Signature   string `json:"signature"`
}

// CallPresencePayload is the decrypted body of CallControlFrame announcing scoped call state.
type CallPresencePayload struct {
	Action       string `json:"action"` // "join" | "leave" | "update"
	ScopeID      string `json:"scope_id"`
	IsDM         bool   `json:"is_dm,omitempty"`
	CallID       string `json:"call_id"`
	Epoch        int64  `json:"epoch"`
	LeafIndex    int    `json:"leaf_index"`
	SenderEncPub string `json:"sender_enc_pub,omitempty"`
	Audio        bool   `json:"audio"`
	Video        bool   `json:"video"`
	Screen       bool   `json:"screen"`
}

// CallControlFrame transports encrypted, signed ephemeral call presence across verified scope members.
type CallControlFrame struct {
	ScopeID    string `json:"scope_id"`
	AuthorPub  string `json:"author_pub"`
	EpochID    int64  `json:"epoch_id"`
	IsDM       bool   `json:"is_dm,omitempty"`
	Timestamp  int64  `json:"timestamp"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
	Signature  string `json:"signature"`
}

// CallSignalPayload is the Noise_IK-decrypted pairwise secondary WebRTC signaling message.
type CallSignalPayload struct {
	ScopeID string `json:"scope_id"`
	IsDM    bool   `json:"is_dm,omitempty"`
	CallID  string `json:"call_id"`
	Epoch   int64  `json:"epoch"`
	Kind    string `json:"kind"`    // "offer" | "answer" | "candidate" | "bye"
	Payload string `json:"payload"` // Raw SDP or serialized ICE candidate JSON
	From    string `json:"from,omitempty"`
}

// CallSignalFrame wraps a pairwise Noise_IK-encrypted secondary WebRTC signal.
type CallSignalFrame struct {
	From         string `json:"from"`
	FromEncPub   string `json:"from_enc_pub"`
	Target       string `json:"target"`
	EphemeralPub string `json:"ephemeral_pub"`
	Nonce        string `json:"nonce"`
	Ciphertext   string `json:"ciphertext"`
	Timestamp    int64  `json:"timestamp"`
	Signature    string `json:"signature"`
}

// AppManifestRequest asks app seeders in the public seeder group for a signed AppManifest.
type AppManifestRequest struct {
	RoomID    string `json:"room_id,omitempty"`
	AppID     string `json:"app_id"`
	Version   string `json:"version,omitempty"`
	Channel   string `json:"channel,omitempty"`
	MinSeq    uint64 `json:"min_seq,omitempty"`
	FileHash  string `json:"file_hash,omitempty"`
	RequestID string `json:"request_id,omitempty"`
}

// AppManifestResponse returns the signed AppManifest and fresh AttachmentMeta offer.
type AppManifestResponse struct {
	RoomID    string          `json:"room_id,omitempty"`
	RequestID string          `json:"request_id,omitempty"`
	Manifest  *AppManifest    `json:"manifest"`
	Offer     *AttachmentMeta `json:"offer"`
}

// SyncRequest asks connected peers for missing envelopes after joining or reconnecting.
type SyncRequest struct {
	RoomID        string   `json:"room_id,omitempty"`
	LastSeenMsgID string   `json:"last_seen_msg_id,omitempty"`
	KnownIDs      []string `json:"known_ids,omitempty"`
	CurrentEpoch  int64    `json:"current_epoch,omitempty"`
}

// SyncResponse returns missing envelopes, attachment offers, and MLS epoch commits.
type SyncResponse struct {
	RoomID    string            `json:"room_id,omitempty"`
	Envelopes []*Envelope       `json:"envelopes"`
	Offers    []*AttachmentMeta `json:"offers,omitempty"`
	Commits   []*EpochCommit    `json:"commits,omitempty"`
}

// AttachmentMeta announces an encrypted file attachment.
type AttachmentMeta struct {
	RoomID       string `json:"room_id,omitempty"`
	FileID       string `json:"file_id"`
	Hash         string `json:"hash"`
	Name         string `json:"name"`
	Size         int64  `json:"size"`
	MIME         string `json:"mime"`
	TotalChunks  int    `json:"total_chunks"`
	EpochID      int64  `json:"epoch_id,omitempty"`
	AuthorPubKey string `json:"author_pub_key,omitempty"`
	Timestamp    int64  `json:"timestamp,omitempty"`
	Signature    string `json:"signature,omitempty"`
}

// ChunkRequest asks for a specific chunk of an attachment.
type ChunkRequest struct {
	RoomID     string `json:"room_id,omitempty"`
	FileID     string `json:"file_id"`
	ChunkIndex int    `json:"chunk_index"`
}

// ChunkResponse carries an encrypted attachment chunk.
type ChunkResponse struct {
	RoomID     string `json:"room_id,omitempty"`
	FileID     string `json:"file_id"`
	ChunkIndex int    `json:"chunk_index"`
	Data       []byte `json:"data"`
}

// DMFrame carries a 1:1 encrypted DM or pairwise relay payload over a unicast Packet.
type DMFrame struct {
	Kind    string `json:"kind,omitempty"`
	Payload []byte `json:"payload"`
}
