//go:build !js && !wasip1

package cotillartc

import (
	"net"

	"github.com/pion/webrtc/v4"
)

type overlayPlatform struct {
	api *webrtc.API
}

func hasUsableNonLoopbackInterface() bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipNet, ok := a.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
				return true
			}
		}
	}
	return false
}

func newIsolatedSettingEngine() webrtc.SettingEngine {
	se := webrtc.SettingEngine{}
	se.SetFireOnTrackBeforeFirstRTP(true)
	if !hasUsableNonLoopbackInterface() {
		// Allow loopback ICE host candidates in isolated loopback-only test environments.
		se.SetIncludeLoopbackCandidate(true)
	}
	return se
}

func (t *PionTransport) initPlatform() {
	se := newIsolatedSettingEngine()
	t.api = webrtc.NewAPI(webrtc.WithSettingEngine(se))
}

func (t *PionTransport) createPeerConnection(config webrtc.Configuration) (*webrtc.PeerConnection, error) {
	if t.api != nil {
		return t.api.NewPeerConnection(config)
	}
	return webrtc.NewPeerConnection(config)
}
