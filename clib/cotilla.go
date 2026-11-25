//go:build clib

// Command clib builds the Cotilla protocol core as a C dynamic library (`-buildmode=c-shared`)
// for iOS, Android, and foreign C/C++ native applications.
package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"
	"unsafe"

	cot "github.com/datf/cotilla-protocol/pkg/cotilla"
)

var (
	mu     sync.Mutex
	nextH  int64 = 1
	idents       = map[int64]*cot.Identity{}
)

func store(id *cot.Identity) int64 {
	mu.Lock()
	defer mu.Unlock()
	h := nextH
	nextH++
	idents[h] = id
	return h
}

func load(h int64) *cot.Identity {
	mu.Lock()
	defer mu.Unlock()
	return idents[h]
}

//export cotilla_new_identity
func cotilla_new_identity() C.longlong {
	id, err := cot.NewIdentity()
	if err != nil {
		return -1
	}
	return C.longlong(store(id))
}

//export cotilla_identity_from_seed
func cotilla_identity_from_seed(seed *C.char, n C.int) C.longlong {
	if seed == nil || n < 0 || n > 1<<20 {
		return -1
	}
	id, err := cot.NewIdentityFromSeed(C.GoBytes(unsafe.Pointer(seed), n))
	if err != nil {
		return -1
	}
	return C.longlong(store(id))
}

//export cotilla_free_identity
func cotilla_free_identity(h C.longlong) {
	mu.Lock()
	delete(idents, int64(h))
	mu.Unlock()
}

//export cotilla_address
func cotilla_address(h C.longlong) *C.char {
	id := load(int64(h))
	if id == nil {
		return nil
	}
	return C.CString(id.Address())
}

//export cotilla_sign
func cotilla_sign(h C.longlong, msg *C.char, n C.int) *C.char {
	if n < 0 || n > 16<<20 || (n > 0 && msg == nil) {
		return nil
	}
	id := load(int64(h))
	if id == nil {
		return nil
	}
	var payload []byte
	if n > 0 {
		payload = C.GoBytes(unsafe.Pointer(msg), n)
	}
	sig := id.Sign(payload)
	return C.CString(hex.EncodeToString(sig))
}

//export cotilla_verify
func cotilla_verify(pubHex *C.char, msg *C.char, n C.int, sigHex *C.char) C.int {
	if pubHex == nil || sigHex == nil || n < 0 || n > 16<<20 || (n > 0 && msg == nil) {
		return 0
	}
	var payload []byte
	if n > 0 {
		payload = C.GoBytes(unsafe.Pointer(msg), n)
	}
	if cot.Verify(C.GoString(pubHex), payload, C.GoString(sigHex)) {
		return 1
	}
	return 0
}

//export cotilla_generate_room_key
func cotilla_generate_room_key() *C.char {
	key, err := cot.GenerateRoomKey()
	if err != nil {
		return nil
	}
	return C.CString(key.String())
}

//export cotilla_seal_envelope
func cotilla_seal_envelope(h C.longlong, roomID *C.char, roomKeyB64 *C.char, plaintext *C.char, n C.int) *C.char {
	id := load(int64(h))
	if id == nil {
		return nil
	}
	key, err := cot.ParseRoomKey(C.GoString(roomKeyB64))
	if err != nil {
		return nil
	}
	env, err := cot.NewEnvelope(id, C.GoString(roomID), key, C.GoBytes(unsafe.Pointer(plaintext), n))
	if err != nil {
		return nil
	}
	b, err := json.Marshal(env)
	if err != nil {
		return nil
	}
	return C.CString(string(b))
}

//export cotilla_open_envelope
func cotilla_open_envelope(roomKeyB64 *C.char, envelopeJSON *C.char) *C.char {
	key, err := cot.ParseRoomKey(C.GoString(roomKeyB64))
	if err != nil {
		return nil
	}
	var env cot.Envelope
	if err := json.Unmarshal([]byte(C.GoString(envelopeJSON)), &env); err != nil {
		return nil
	}
	pt, err := env.Decrypt(key)
	if err != nil {
		return nil
	}
	return C.CString(string(pt))
}

//export cotilla_verify_envelope
func cotilla_verify_envelope(expectedRoomID *C.char, envelopeJSON *C.char) C.int {
	var env cot.Envelope
	if err := json.Unmarshal([]byte(C.GoString(envelopeJSON)), &env); err != nil {
		return 0
	}
	if err := env.Verify(C.GoString(expectedRoomID), 5*time.Minute); err != nil {
		return 0
	}
	return 1
}

//export cotilla_free_string
func cotilla_free_string(s *C.char) {
	C.free(unsafe.Pointer(s))
}

func main() {}
