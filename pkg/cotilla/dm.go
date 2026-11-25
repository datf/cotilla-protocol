package cotilla

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

// SendDirectInvite creates and sends a Noise_IK encrypted 1:1 DM or breakout invite.
func (n *Node) SendDirectInvite(targetSignPub, inviteType, title string) (*DirectInvite, *InvitePayload, error) {
	encKey := n.overlay.EncKey(targetSignPub)
	if encKey == "" {
		return nil, nil, errors.New("cotilla: unknown encryption key for target peer")
	}
	return n.SendDirectInviteWithKey(targetSignPub, encKey, inviteType, title)
}

// SendDirectInviteWithKey creates and sends a Noise_IK encrypted invite using an explicit X25519 key.
func (n *Node) SendDirectInviteWithKey(targetSignPub, targetEncPubHex, inviteType, title string) (*DirectInvite, *InvitePayload, error) {
	if targetSignPub == "" || targetSignPub == n.Address() {
		return nil, nil, errors.New("cotilla: invalid invite target")
	}
	targetEnc, err := ParseEncPub(targetEncPubHex)
	if err != nil {
		return nil, nil, err
	}
	roomKey, err := GenerateRoomKey()
	if err != nil {
		return nil, nil, err
	}
	payload := &InvitePayload{
		Type:      inviteType,
		RoomID:    "dm-" + RandomID()[:16],
		RoomKey:   roomKey.String(),
		Title:     title,
		CreatedAt: time.Now().UnixMilli(),
	}
	inv, err := n.buildSignedDirectInvite(targetSignPub, targetEnc, payload)
	if err != nil {
		return nil, nil, err
	}
	if err := n.sendUnicastPacket(targetSignPub, targetEncPubHex, PortDirectInvite, inv); err != nil {
		return nil, nil, err
	}
	return inv, payload, nil
}

func (n *Node) buildSignedDirectInvite(targetSignPub string, targetEnc [32]byte, payload *InvitePayload) (*DirectInvite, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	aad := []byte("cotilla-invite-v2:" + n.Address() + ":" + targetSignPub)
	ePub, nonce, ct, err := EncryptDirectInvite(n.ID, targetEnc, raw, aad)
	if err != nil {
		return nil, err
	}
	inv := &DirectInvite{
		InviteID:     RandomID(),
		FromSignPub:  n.Address(),
		FromEncPub:   n.ID.EncAddress(),
		EphemeralPub: hex.EncodeToString(ePub[:]),
		ToSignPub:    targetSignPub,
		Nonce:        base64.StdEncoding.EncodeToString(nonce),
		Ciphertext:   base64.StdEncoding.EncodeToString(ct),
		Timestamp:    time.Now().UnixMilli(),
	}
	canonical := CanonicalDirectInvite(inv.InviteID, inv.FromSignPub, inv.FromEncPub, inv.EphemeralPub, inv.ToSignPub, inv.Nonce, inv.Ciphertext, inv.Timestamp)
	inv.Signature = hex.EncodeToString(n.ID.Sign(canonical))
	return inv, nil
}

// RespondDirectInvite sends a signed accept/decline response for invite.
func (n *Node) RespondDirectInvite(invite *DirectInvite, accepted bool) error {
	if invite == nil || invite.FromSignPub == "" {
		return errors.New("cotilla: invalid direct invite")
	}
	now := time.Now().UnixMilli()
	canonical := CanonicalInviteResponse(invite.InviteID, n.Address(), invite.FromSignPub, accepted, now)
	res := &InviteResponse{
		InviteID:    invite.InviteID,
		FromSignPub: n.Address(),
		ToSignPub:   invite.FromSignPub,
		Accepted:    accepted,
		Timestamp:   now,
		Signature:   hex.EncodeToString(n.ID.Sign(canonical)),
	}
	return n.sendUnicastPacket(invite.FromSignPub, invite.FromEncPub, PortDirectInviteRes, res)
}

// SendViaRelay sends a unicast encrypted payload to target (used for DMs and pairwise frames).
func (n *Node) SendViaRelay(target, frameType string, payload []byte) error {
	if target == "" || target == n.Address() {
		return errors.New("cotilla: invalid relay target")
	}
	if frameType == "" {
		frameType = "dm"
	}
	return n.sendUnicastPacket(target, n.overlay.EncKey(target), PortDM, &DMFrame{
		Kind:    frameType,
		Payload: payload,
	})
}

func (n *Node) handleDirectInvite(from string, invite *DirectInvite) {
	if invite == nil || invite.ToSignPub != n.Address() {
		return
	}
	if !withinWindow(invite.Timestamp, n.Cfg.ReplayWindow) {
		return
	}
	canonical := CanonicalDirectInvite(invite.InviteID, invite.FromSignPub, invite.FromEncPub, invite.EphemeralPub, invite.ToSignPub, invite.Nonce, invite.Ciphertext, invite.Timestamp)
	if !Verify(invite.FromSignPub, canonical, invite.Signature) {
		return
	}
	n.overlay.SetEncKey(invite.FromSignPub, invite.FromEncPub)

	payload, err := n.decryptDirectInvitePayload(invite)
	if err != nil {
		n.log("failed to decrypt direct invite from %s: %v", invite.FromSignPub, err)
		return
	}
	if n.Hooks.OnDirectInvite != nil {
		n.Hooks.OnDirectInvite(invite, payload)
	}
}

func (n *Node) decryptDirectInvitePayload(invite *DirectInvite) (*InvitePayload, error) {
	fromEnc, err := ParseEncPub(invite.FromEncPub)
	if err != nil {
		return nil, err
	}
	ePub, err := ParseEncPub(invite.EphemeralPub)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.StdEncoding.DecodeString(invite.Nonce)
	if err != nil {
		return nil, err
	}
	ct, err := base64.StdEncoding.DecodeString(invite.Ciphertext)
	if err != nil {
		return nil, err
	}
	aad := []byte("cotilla-invite-v2:" + invite.FromSignPub + ":" + n.Address())
	plain, err := DecryptDirectInvite(n.ID, fromEnc, ePub, nonce, ct, aad)
	if err != nil {
		return nil, err
	}
	var payload InvitePayload
	if err := json.Unmarshal(plain, &payload); err != nil {
		return nil, err
	}
	return &payload, nil
}

func (n *Node) handleInviteResponse(from string, res *InviteResponse) {
	if res == nil || res.ToSignPub != n.Address() {
		return
	}
	if !withinWindow(res.Timestamp, n.Cfg.ReplayWindow) {
		return
	}
	canonical := CanonicalInviteResponse(res.InviteID, res.FromSignPub, res.ToSignPub, res.Accepted, res.Timestamp)
	if !Verify(res.FromSignPub, canonical, res.Signature) {
		return
	}
	if n.Hooks.OnInviteResponse != nil {
		n.Hooks.OnInviteResponse(res)
	}
}

func (n *Node) handleDM(from string, dm *DMFrame) {
	if dm == nil || len(dm.Payload) == 0 {
		return
	}
	kind := dm.Kind
	if kind == "" {
		kind = "dm"
	}
	if n.Hooks.OnRelayPayload != nil {
		n.Hooks.OnRelayPayload(from, kind, dm.Payload)
	}
}

func withinWindow(ts int64, window time.Duration) bool {
	if window <= 0 {
		return true
	}
	diff := time.Now().UnixMilli() - ts
	if diff < 0 {
		diff = -diff
	}
	return diff <= window.Milliseconds()
}
