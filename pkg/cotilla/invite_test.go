package cotilla_test

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/datf/cotilla-protocol/pkg/cotilla"
)

func TestDirectInviteCrypto_Success(t *testing.T) {
	alice, err := cotilla.NewIdentity()
	if err != nil {
		t.Fatalf("failed to create alice: %v", err)
	}
	bob, err := cotilla.NewIdentity()
	if err != nil {
		t.Fatalf("failed to create bob: %v", err)
	}

	roomKey, err := cotilla.GenerateRoomKey()
	if err != nil {
		t.Fatalf("failed to generate room key: %v", err)
	}

	payload := &cotilla.InvitePayload{
		Type:      "dm",
		RoomID:    "test-dm-room-1234",
		RoomKey:   roomKey.String(),
		Title:     "Private DM",
		CreatedAt: time.Now().UnixMilli(),
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}

	aad := []byte("cotilla-invite-v2:" + alice.Address() + ":" + bob.Address())
	ePub, nonce, ciphertext, err := cotilla.EncryptDirectInvite(alice, bob.EncPub, payloadBytes, aad)
	if err != nil {
		t.Fatalf("failed to encrypt invite: %v", err)
	}

	// Bob decrypts
	decryptedBytes, err := cotilla.DecryptDirectInvite(bob, alice.EncPub, ePub, nonce, ciphertext, aad)
	if err != nil {
		t.Fatalf("bob failed to decrypt invite: %v", err)
	}

	var decryptedPayload cotilla.InvitePayload
	if err := json.Unmarshal(decryptedBytes, &decryptedPayload); err != nil {
		t.Fatalf("failed to unmarshal decrypted payload: %v", err)
	}

	if decryptedPayload.RoomID != payload.RoomID {
		t.Errorf("expected RoomID %s, got %s", payload.RoomID, decryptedPayload.RoomID)
	}
	if decryptedPayload.RoomKey != payload.RoomKey {
		t.Errorf("expected RoomKey %s, got %s", payload.RoomKey, decryptedPayload.RoomKey)
	}
	if decryptedPayload.Type != payload.Type {
		t.Errorf("expected Type %s, got %s", payload.Type, decryptedPayload.Type)
	}
}

func TestDirectInvite_EavesdropperCannotDecrypt(t *testing.T) {
	alice, _ := cotilla.NewIdentity()
	bob, _ := cotilla.NewIdentity()
	charlie, _ := cotilla.NewIdentity() // Eavesdropper

	payload := &cotilla.InvitePayload{
		Type:    "dm",
		RoomID:  "secret-dm-5678",
		RoomKey: "supersecretkey123",
	}
	payloadBytes, _ := json.Marshal(payload)

	aad := []byte("cotilla-invite-v2:" + alice.Address() + ":" + bob.Address())
	ePub, nonce, ciphertext, err := cotilla.EncryptDirectInvite(alice, bob.EncPub, payloadBytes, aad)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	// Charlie tries to decrypt Alice's invite for Bob
	_, err = cotilla.DecryptDirectInvite(charlie, alice.EncPub, ePub, nonce, ciphertext, aad)
	if err == nil {
		t.Fatalf("expected Charlie decryption to fail, but it succeeded!")
	}
}

func TestDirectInvite_SignatureTampering(t *testing.T) {
	alice, _ := cotilla.NewIdentity()
	bob, _ := cotilla.NewIdentity()

	inviteID := "inv-001"
	nonceB64 := base64.StdEncoding.EncodeToString([]byte("123456789012345678901234"))
	cipherB64 := base64.StdEncoding.EncodeToString([]byte("encrypted-secret-payload"))
	now := time.Now().UnixMilli()
	ePubHex := hex.EncodeToString([]byte("01234567890123456789012345678901"))

	canonical := cotilla.CanonicalDirectInvite(inviteID, alice.Address(), alice.EncAddress(), ePubHex, bob.Address(), nonceB64, cipherB64, now)
	sig := hex.EncodeToString(alice.Sign(canonical))

	// Signature verification succeeds
	if !cotilla.Verify(alice.Address(), canonical, sig) {
		t.Fatal("expected signature verification to succeed")
	}

	// Tampered recipient address
	tamperedCanonical := cotilla.CanonicalDirectInvite(inviteID, alice.Address(), alice.EncAddress(), ePubHex, "tampered-address", nonceB64, cipherB64, now)
	if cotilla.Verify(alice.Address(), tamperedCanonical, sig) {
		t.Fatal("expected signature verification to fail on tampered data")
	}

	// Tampered ephemeral key
	tamperedEphemeral := cotilla.CanonicalDirectInvite(inviteID, alice.Address(), alice.EncAddress(), "tampered-ephemeral-key", bob.Address(), nonceB64, cipherB64, now)
	if cotilla.Verify(alice.Address(), tamperedEphemeral, sig) {
		t.Fatal("expected signature verification to fail on tampered ephemeral key")
	}
}

func TestInviteResponse_Verification(t *testing.T) {
	alice, _ := cotilla.NewIdentity()
	bob, _ := cotilla.NewIdentity()

	inviteID := "inv-100"
	now := time.Now().UnixMilli()

	canonical := cotilla.CanonicalInviteResponse(inviteID, bob.Address(), alice.Address(), true, now)
	sig := hex.EncodeToString(bob.Sign(canonical))

	if !cotilla.Verify(bob.Address(), canonical, sig) {
		t.Fatal("expected invite response verification to succeed")
	}

	// Tampering accepted flag
	tamperedCanonical := cotilla.CanonicalInviteResponse(inviteID, bob.Address(), alice.Address(), false, now)
	if cotilla.Verify(bob.Address(), tamperedCanonical, sig) {
		t.Fatal("expected signature verification to fail on tampered accepted status")
	}
}
