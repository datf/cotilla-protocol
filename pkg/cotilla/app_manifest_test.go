package cotilla

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

func TestAppManifest_SigningAndVerification(t *testing.T) {
	pubHex, privHex, err := GeneratePublisherKeypair()
	if err != nil {
		t.Fatalf("GeneratePublisherKeypair failed: %v", err)
	}

	bundleContent := []byte("<!DOCTYPE html><html><body><h1>Hello Cotilla</h1></body></html>")
	manifest, err := SignAppBundle(privHex, "test-app", "stable", "1.0.0", 1, bundleContent, "text/html; charset=utf-8", FormatSingleHTMLV1, 10*time.Minute)
	if err != nil {
		t.Fatalf("SignAppBundle failed: %v", err)
	}

	if manifest.PubKey != pubHex {
		t.Errorf("expected pubKey %s, got %s", pubHex, manifest.PubKey)
	}
	if manifest.FileID != manifest.SHA256[:16] {
		t.Errorf("expected FileID to be prefix of SHA256")
	}

	now := time.Now().UnixMilli()
	// Successful verification with pinned key
	err = VerifyAppBundle(manifest, bundleContent, pubHex, "test-app", "stable", 1, now)
	if err != nil {
		t.Fatalf("VerifyAppBundle failed: %v", err)
	}

	// Successful verification without pinned key (open verification)
	err = VerifyAppBundle(manifest, bundleContent, "", "test-app", "stable", 1, now)
	if err != nil {
		t.Fatalf("VerifyAppBundle (open) failed: %v", err)
	}

	// Failure: Wrong pinned key
	wrongPub, _, _ := GeneratePublisherKeypair()
	err = VerifyAppBundle(manifest, bundleContent, wrongPub, "test-app", "stable", 1, now)
	if err == nil {
		t.Fatalf("expected error on wrong pinned pubkey, got nil")
	}

	// Failure: Tampered bundle content
	tamperedContent := append([]byte(nil), bundleContent...)
	tamperedContent[len(tamperedContent)-1] = 'X'
	err = VerifyAppBundle(manifest, tamperedContent, pubHex, "test-app", "stable", 1, now)
	if err == nil {
		t.Fatalf("expected error on tampered bundle content, got nil")
	}

	// Failure: App ID mismatch
	err = VerifyAppBundle(manifest, bundleContent, pubHex, "wrong-app", "stable", 1, now)
	if err == nil {
		t.Fatalf("expected error on appID mismatch, got nil")
	}

	// Failure: Channel mismatch
	err = VerifyAppBundle(manifest, bundleContent, pubHex, "test-app", "beta", 1, now)
	if err == nil {
		t.Fatalf("expected error on channel mismatch, got nil")
	}

	// Failure: Sequence rollback
	err = VerifyAppBundle(manifest, bundleContent, pubHex, "test-app", "stable", 2, now)
	if err == nil {
		t.Fatalf("expected error on minSeq rollback, got nil")
	}

	// Failure: Expired manifest
	pastNow := manifest.ExpiresAt + 1000
	err = VerifyAppBundle(manifest, bundleContent, pubHex, "test-app", "stable", 1, pastNow)
	if err == nil {
		t.Fatalf("expected error on expired manifest, got nil")
	}

	// Failure: Tampered signature
	tamperedManifest := *manifest
	tamperedManifest.Signature = "00" + tamperedManifest.Signature[2:]
	err = VerifyAppBundle(&tamperedManifest, bundleContent, pubHex, "test-app", "stable", 1, now)
	if err == nil {
		t.Fatalf("expected error on tampered signature, got nil")
	}
}

func TestAppDistRoomKey(t *testing.T) {
	k1 := DefaultAppDistRoomKey()
	k2 := DefaultAppDistRoomKey()
	if k1 != k2 {
		t.Fatalf("expected deterministic room key")
	}
	expectedHash := sha256.Sum256([]byte("cotilla-app-dist-room-key-v1:" + DefaultAppDistRoomID))
	if hex.EncodeToString(k1[:]) != hex.EncodeToString(expectedHash[:]) {
		t.Fatalf("room key does not match expected hash")
	}
}
