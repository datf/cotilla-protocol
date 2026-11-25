package cotilla

import "time"

// ChannelKind distinguishes public PSK groups (e.g. app seeder) from private MLS groups.
type ChannelKind int

const (
	// ChannelPrivate uses MLS epoch keys, short TTLs, and >= 6 active group peers.
	ChannelPrivate ChannelKind = iota
	// ChannelPublic uses a shared group PSK, longer TTLs, and >= 2 active group peers.
	ChannelPublic
)

// SeederGroupConfig configures the public PSK group used for P2P app distribution.
type SeederGroupConfig struct {
	Name    string `json:"name"`
	PSK     string `json:"psk,omitempty"`     // Optional base64 256-bit PSK; derived from Name if empty
	Channel string `json:"channel,omitempty"` // Distribution track, e.g. "stable"
}

// AppBootstrapConfig configures the application bundle to discover, verify, and load.
type AppBootstrapConfig struct {
	AppName         string            `json:"appName"`                   // Manifest AppID / app name
	Version         string            `json:"version,omitempty"`         // Optional expected version
	MinSeq          uint64            `json:"minSeq,omitempty"`          // Anti-rollback sequence floor
	ValidSignatures []string          `json:"validSignatures,omitempty"` // Allowed publisher Ed25519 public keys (hex)
	SeederGroup     SeederGroupConfig `json:"seederGroup"`
}

// Config holds tunable parameters for a Cotilla mesh node.
type Config struct {
	// Peer Topology & HyParView Parameters
	MaxPeers             int           `json:"maxPeers,omitempty"`             // Hard cap on active WebRTC links (default: 16)
	MinActivePeers       int           `json:"minActivePeers,omitempty"`       // Minimum general overlay peers (default: 6)
	MinPrivateGroupPeers int           `json:"minPrivateGroupPeers,omitempty"` // Target connected peers per private group (default: 6)
	MinPublicGroupPeers  int           `json:"minPublicGroupPeers,omitempty"`  // Target connected peers per public group (default: 2)
	PassiveViewSize      int           `json:"passiveViewSize,omitempty"`      // HyParView passive descriptor pool size (default: 30)
	ShuffleInterval      time.Duration `json:"shuffleInterval,omitempty"`      // HyParView shuffle / rotation period (default: 10s)
	ShuffleTTL           int           `json:"shuffleTTL,omitempty"`           // Random walk hop count for HyParView shuffle (default: 3)
	ShuffleFanout        int           `json:"shuffleFanout,omitempty"`        // Descriptors exchanged per shuffle (default: 4)
	MaxAnchorConnections int           `json:"maxAnchorConnections,omitempty"` // Maximum anchor connections (default: 3)
	MinAnchorConnections int           `json:"minAnchorConnections,omitempty"` // Minimum anchor connections (default: 1)

	// Expanding-Ring Broadcast & TTL Policy
	InitialBroadcastTTL    int           `json:"initialBroadcastTTL,omitempty"`    // Starting TTL for broadcasts (default: 1)
	InitialBroadcastFanout int           `json:"initialBroadcastFanout,omitempty"` // Starting peer fanout for broadcasts (default: 2)
	MaxBroadcastTTL        int           `json:"maxBroadcastTTL,omitempty"`        // Cap when doubling TTL (default: 8)
	BroadcastHopTimeout    time.Duration `json:"broadcastHopTimeout,omitempty"`    // Base hop unit; retries after 2*TTL*unit (default: 500ms)
	PrivateGroupTTL        int           `json:"privateGroupTTL,omitempty"`        // Short TTL for private MLS groups (default: 3)
	PublicGroupTTL         int           `json:"publicGroupTTL,omitempty"`         // Longer TTL for public PSK groups (default: 6)
	GossipTTL              int           `json:"gossipTTL,omitempty"`              // Default hop limit for general gossip (default: 3)
	GossipFanout           int           `json:"gossipFanout,omitempty"`           // Default fanout for general forwarding (default: 3)
	GossipCacheTTL         time.Duration `json:"gossipCacheTTL,omitempty"`         // Packet deduplication cache lifetime (default: 30s)

	// Messaging, Security & Media Parameters
	RingBufferCapacity int           `json:"ringBufferCapacity,omitempty"` // Retained messages per channel (default: 200)
	MessageTTL         time.Duration `json:"messageTTL,omitempty"`         // RingBuffer catch-up retention (default: 15m)
	ChunkSize          int           `json:"chunkSize,omitempty"`          // Attachment chunk size (default: 64 KB)
	STUNServers        []string      `json:"stunServers,omitempty"`        // STUN servers for ICE gathering
	ReplayWindow       time.Duration `json:"replayWindow,omitempty"`       // Live packet clock skew limit (default: 5m)
	SyncTimeout        time.Duration `json:"syncTimeout,omitempty"`        // Targeted sync batch timeout (default: 1500ms)
	InviteTTL          time.Duration `json:"inviteTTL,omitempty"`          // Signed invite lifetime (default: 15m)
	CallEpochGrace     time.Duration `json:"callEpochGrace,omitempty"`     // SFrame prior-epoch grace (default: 3s)
}

// DefaultConfig returns the default configuration for a Cotilla mesh node.
func DefaultConfig() Config {
	return Config{
		MaxPeers:               16,
		MinActivePeers:         6,
		MinPrivateGroupPeers:   6,
		MinPublicGroupPeers:    2,
		PassiveViewSize:        30,
		ShuffleInterval:        10 * time.Second,
		ShuffleTTL:             3,
		ShuffleFanout:          4,
		MaxAnchorConnections:   3,
		MinAnchorConnections:   1,
		InitialBroadcastTTL:    1,
		InitialBroadcastFanout: 2,
		MaxBroadcastTTL:        8,
		BroadcastHopTimeout:    500 * time.Millisecond,
		PrivateGroupTTL:        3,
		PublicGroupTTL:         6,
		GossipTTL:              3,
		GossipFanout:           6,
		GossipCacheTTL:         30 * time.Second,
		RingBufferCapacity:     200,
		MessageTTL:             15 * time.Minute,
		ChunkSize:              DefaultChunkSize,
		STUNServers:            []string{"stun:stun.l.google.com:19302"},
		ReplayWindow:           5 * time.Minute,
		SyncTimeout:            1500 * time.Millisecond,
		InviteTTL:              15 * time.Minute,
		CallEpochGrace:         3 * time.Second,
	}
}

func (c Config) withDefaults() Config {
	d := DefaultConfig()
	c.applyTopologyDefaults(d)
	c.applyBroadcastDefaults(d)
	c.applySecurityDefaults(d)
	return c
}

func (c *Config) applyTopologyDefaults(d Config) {
	if c.MaxPeers <= 0 {
		c.MaxPeers = d.MaxPeers
	}
	if c.MinActivePeers <= 0 {
		c.MinActivePeers = d.MinActivePeers
	}
	if c.MinPrivateGroupPeers <= 0 {
		c.MinPrivateGroupPeers = d.MinPrivateGroupPeers
	}
	if c.MinPublicGroupPeers <= 0 {
		c.MinPublicGroupPeers = d.MinPublicGroupPeers
	}
	if c.PassiveViewSize <= 0 {
		c.PassiveViewSize = d.PassiveViewSize
	}
	if c.ShuffleInterval <= 0 {
		c.ShuffleInterval = d.ShuffleInterval
	}
	if c.ShuffleTTL <= 0 {
		c.ShuffleTTL = d.ShuffleTTL
	}
	if c.ShuffleFanout <= 0 {
		c.ShuffleFanout = d.ShuffleFanout
	}
	if c.MaxAnchorConnections <= 0 {
		c.MaxAnchorConnections = d.MaxAnchorConnections
	}
	if c.MinAnchorConnections <= 0 {
		c.MinAnchorConnections = d.MinAnchorConnections
	}
}

func (c *Config) applyBroadcastDefaults(d Config) {
	if c.InitialBroadcastTTL <= 0 {
		c.InitialBroadcastTTL = d.InitialBroadcastTTL
	}
	if c.InitialBroadcastFanout <= 0 {
		c.InitialBroadcastFanout = d.InitialBroadcastFanout
	}
	if c.MaxBroadcastTTL <= 0 {
		c.MaxBroadcastTTL = d.MaxBroadcastTTL
	}
	if c.BroadcastHopTimeout <= 0 {
		c.BroadcastHopTimeout = d.BroadcastHopTimeout
	}
	if c.PrivateGroupTTL <= 0 {
		c.PrivateGroupTTL = d.PrivateGroupTTL
	}
	if c.PublicGroupTTL <= 0 {
		c.PublicGroupTTL = d.PublicGroupTTL
	}
	if c.GossipTTL <= 0 {
		c.GossipTTL = d.GossipTTL
	}
	if c.GossipFanout <= 0 {
		c.GossipFanout = d.GossipFanout
	}
	if c.GossipCacheTTL <= 0 {
		c.GossipCacheTTL = d.GossipCacheTTL
	}
}

func (c *Config) applySecurityDefaults(d Config) {
	if c.RingBufferCapacity <= 0 {
		c.RingBufferCapacity = d.RingBufferCapacity
	}
	if c.MessageTTL <= 0 {
		c.MessageTTL = d.MessageTTL
	}
	if c.ChunkSize <= 0 {
		c.ChunkSize = d.ChunkSize
	}
	if len(c.STUNServers) == 0 {
		c.STUNServers = d.STUNServers
	}
	if c.ReplayWindow <= 0 {
		c.ReplayWindow = d.ReplayWindow
	}
	if c.SyncTimeout <= 0 {
		c.SyncTimeout = d.SyncTimeout
	}
	if c.InviteTTL <= 0 {
		c.InviteTTL = d.InviteTTL
	}
	if c.CallEpochGrace <= 0 {
		c.CallEpochGrace = d.CallEpochGrace
	}
}

// GroupTargetPeers returns the desired active peer count for the given channel kind.
func (c Config) GroupTargetPeers(kind ChannelKind) int {
	if kind == ChannelPublic {
		return c.MinPublicGroupPeers
	}
	return c.MinPrivateGroupPeers
}

// GroupTTL returns the gossip hop limit for the given channel kind.
func (c Config) GroupTTL(kind ChannelKind) int {
	if kind == ChannelPublic {
		return c.PublicGroupTTL
	}
	return c.PrivateGroupTTL
}
