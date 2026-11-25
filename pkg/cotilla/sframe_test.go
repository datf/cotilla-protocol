package cotilla

import (
	"bytes"
	"testing"
	"time"
)

func TestRFC9605HeaderEncodeDecode(t *testing.T) {
	cases := []struct {
		kid uint64
		ctr uint64
	}{
		{0, 0},
		{1, 7},
		{7, 0},
		{8, 8},
		{0x00010002, 42},
		{sframeOpenKIDBit | 0xdeadbeefcafebabe, (1 << 32) + 99},
	}

	for _, tc := range cases {
		hdr := EncodeSFrameHeader(tc.kid, tc.ctr)
		kid, ctr, n, err := DecodeSFrameHeader(hdr)
		if err != nil {
			t.Fatalf("DecodeSFrameHeader(%+v) error: %v", tc, err)
		}
		if n != len(hdr) {
			t.Fatalf("header len mismatch for %+v: got %d, want %d", tc, n, len(hdr))
		}
		if kid != tc.kid || ctr != tc.ctr {
			t.Fatalf("roundtrip mismatch: got (0x%x, %d), want (0x%x, %d)", kid, ctr, tc.kid, tc.ctr)
		}
	}

	// Non-minimal extended encoding must fail canonicality check.
	nonMinimal := []byte{0x80, 0x05} // X=1, K=0 (1B), Y=0, C=5 with kid=5 <= 7
	if _, _, _, err := DecodeSFrameHeader(nonMinimal); err == nil {
		t.Fatalf("expected non-minimal KID header to fail decode")
	}
}

func TestSFrameEncryptDecryptReplayAndEviction(t *testing.T) {
	idA, _ := NewIdentity()
	idB, _ := NewIdentity()
	idC, _ := NewIdentity()

	grpA, err := NewMLSGroup("call-group-1", idA)
	if err != nil {
		t.Fatal(err)
	}
	kpB, _ := NewKeyPackage(idB)
	commitB, welcomeB, err := grpA.CreateAddCommit(kpB)
	if err != nil {
		t.Fatal(err)
	}
	grpB, err := NewMLSGroupFromWelcome(idB, welcomeB, kpB.InitPriv)
	if err != nil {
		t.Fatal(err)
	}

	kpC, _ := NewKeyPackage(idC)
	commitC, welcomeC, err := grpA.CreateAddCommit(kpC)
	if err != nil {
		t.Fatal(err)
	}
	if err := grpB.ProcessCommit(commitC); err != nil {
		t.Fatal(err)
	}
	grpC, err := NewMLSGroupFromWelcome(idC, welcomeC, kpC.InitPriv)
	if err != nil {
		t.Fatal(err)
	}
	_ = commitB

	// Derive epoch 3 keys on all 3 active members cleanly.
	makeBundle := func(g *MLSGroup, addr string) *SFrameKeyBundle {
		ep, myLeaf, leaves, base, err := g.SnapshotForSFrame("cotilla sframe v1", []byte("call-group-1"))
		if err != nil {
			t.Fatal(err)
		}
		defer zeroizeBytes(base)
		b, err := assembleSFrameBundle("call-group-1", ep, myLeaf, addr, leaves, base, false)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	krA := NewSFrameKeyring()
	krB := NewSFrameKeyring()
	krC := NewSFrameKeyring()
	if err := krA.InstallBundle(makeBundle(grpA, idA.Address()), 3*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := krB.InstallBundle(makeBundle(grpB, idB.Address()), 3*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := krC.InstallBundle(makeBundle(grpC, idC.Address()), 3*time.Second); err != nil {
		t.Fatal(err)
	}

	// Alice encrypts Opus-sized and large VP8-sized frames; Bob & Charlie decrypt both.
	opusPlain := []byte{0xf8, 0x01, 0x02, 0x03, 0x04, 0x05}
	vp8Plain := bytes.Repeat([]byte{0xab, 0xcd}, 4096)

	ctOpus, err := krA.Encrypt(opusPlain)
	if err != nil {
		t.Fatal(err)
	}
	ctVP8, err := krA.Encrypt(vp8Plain)
	if err != nil {
		t.Fatal(err)
	}

	// Out-of-order delivery (VP8 ctr=1 before Opus ctr=0) succeeds and rejects replay.
	ptVP8, _, err := krB.Decrypt(ctVP8, idA.Address())
	if err != nil || !bytes.Equal(ptVP8, vp8Plain) {
		t.Fatalf("Bob failed VP8 decrypt: %v", err)
	}
	ptOpus, _, err := krB.Decrypt(ctOpus, idA.Address())
	if err != nil || !bytes.Equal(ptOpus, opusPlain) {
		t.Fatalf("Bob failed Opus out-of-order decrypt: %v", err)
	}
	if _, _, err := krB.Decrypt(ctOpus, idA.Address()); err != ErrSFrameReplay {
		t.Fatalf("expected ErrSFrameReplay on duplicate frame, got %v", err)
	}
	// Identity spoofing check: claiming packet came from Charlie when KID maps to Alice fails.
	if _, _, err := krC.Decrypt(ctOpus, idB.Address()); err == nil {
		t.Fatalf("expected sender mismatch error when KID owner != expectedFrom")
	}

	// Evict Charlie (grpA -> grpB remove Charlie); Alice & Bob rotate and revoke Charlie immediately.
	rmCommit, err := grpA.CreateRemoveCommit(grpC.MyLeafIndex)
	if err != nil {
		t.Fatal(err)
	}
	if err := grpB.ProcessCommit(rmCommit); err != nil {
		t.Fatal(err)
	}
	krA.RevokePeer(idC.Address())
	krB.RevokePeer(idC.Address())
	if err := krA.InstallBundle(makeBundle(grpA, idA.Address()), 3*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := krB.InstallBundle(makeBundle(grpB, idB.Address()), 3*time.Second); err != nil {
		t.Fatal(err)
	}

	// Charlie encrypts under stale epoch 3 key -> Alice/Bob must reject immediately!
	staleCT, err := krC.Encrypt([]byte("evicted frame"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := krB.Decrypt(staleCT, idC.Address()); err != ErrSFrameMissingKey {
		t.Fatalf("expected evicted Charlie's frame to fail immediately, got %v", err)
	}

	// Alice encrypts under epoch 4 -> evicted Charlie cannot decrypt; Bob succeeds!
	newCT, err := krA.Encrypt([]byte("post-eviction frame"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := krC.Decrypt(newCT, idA.Address()); err == nil {
		t.Fatalf("evicted Charlie must NOT decrypt post-eviction epoch 4 media")
	}
	if pt, _, err := krB.Decrypt(newCT, idA.Address()); err != nil || string(pt) != "post-eviction frame" {
		t.Fatalf("Bob failed post-eviction decrypt: %v", err)
	}
}
