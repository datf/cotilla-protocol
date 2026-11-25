//go:build !js && !wasip1

package cotillartc

import (
	"sync"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
)

// TestPionTransport_ConcurrentCallbackAndGlare checks:
// 1. Concurrent OnOpen/OnClose/OnStateChange registration and triggers are data-race free (-race).
// 2. Duplicate CreateOffer while a handshake/open connection already exists rejects or prevents clobbering.
func TestPionTransport_ConcurrentCallbackAndGlare(t *testing.T) {
	tr1 := New("peer-1", nil, nil)
	tr2 := New("peer-2", nil, nil)
	defer tr1.ClosePeer("peer-2")
	defer tr2.ClosePeer("peer-1")

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tr1.OnOpen(func(addr string) {})
			tr1.OnClose(func(addr string) {})
			tr1.OnStateChange(func(addr string, s webrtc.PeerConnectionState) {})
		}()
	}
	wg.Wait()

	sdp1, err := tr1.CreateOffer("peer-2")
	if err != nil {
		t.Fatalf("first CreateOffer failed: %v", err)
	}
	if sdp1 == "" {
		t.Fatalf("empty offer SDP")
	}

	// Second concurrent CreateOffer to the same active/pending peer must NOT silently teardown active PC!
	if _, err := tr1.CreateOffer("peer-2"); err == nil {
		t.Fatalf("expected second CreateOffer to active/pending peer to be rejected by glare guard")
	}
	_ = time.Millisecond
}

func TestPionTransport_StaleOfferExpiryAllowsRetryAndGlareRecovery(t *testing.T) {
	trHigh := New("peer-z", nil, nil)
	trLow := New("peer-a", nil, nil)
	defer trHigh.ClosePeer("peer-a")
	defer trLow.ClosePeer("peer-z")

	// trHigh creates an initial offer to peer-a that is never answered (e.g. dropped offer or simultaneous glare).
	if _, err := trHigh.CreateOffer("peer-a"); err != nil {
		t.Fatalf("initial CreateOffer failed: %v", err)
	}

	// Wait past pending offer expiration window (3s)
	time.Sleep(3200 * time.Millisecond)

	// 1. After pending expiry, trHigh (even though impolite peer-z > peer-a) must accept a fresh remote offer cleanly.
	lowOffer, err := trLow.CreateOffer("peer-z")
	if err != nil {
		t.Fatalf("trLow CreateOffer failed: %v", err)
	}
	ans, err := trHigh.AcceptOffer("peer-a", lowOffer)
	if err != nil {
		t.Fatalf("expected stale HaveLocalOffer on impolite peer to expire and allow AcceptOffer recovery, got: %v", err)
	}
	if ans == "" {
		t.Fatalf("expected non-empty answer SDP after stale offer recovery")
	}

	// 2. Also verify a stale un-answered offer no longer blocks CreateOffer indefinitely.
	trRetry := New("peer-m", nil, nil)
	defer trRetry.ClosePeer("peer-b")
	if _, err := trRetry.CreateOffer("peer-b"); err != nil {
		t.Fatalf("trRetry first CreateOffer failed: %v", err)
	}
	time.Sleep(3200 * time.Millisecond)
	if _, err := trRetry.CreateOffer("peer-b"); err != nil {
		t.Fatalf("expected stale HaveLocalOffer to expire so CreateOffer retry succeeds, got: %v", err)
	}
}
