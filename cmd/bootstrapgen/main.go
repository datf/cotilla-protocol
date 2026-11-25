package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/datf/cotilla-protocol/pkg/cotilla"
)

type publisherKeyFile struct {
	PubKeyHex  string `json:"pub_hex"`
	PrivKeyHex string `json:"priv_hex"`
}

func getWasmExecJS() ([]byte, error) {
	// First try web/wasm_exec.js if present
	if data, err := os.ReadFile("web/wasm_exec.js"); err == nil && len(data) > 0 {
		return data, nil
	}
	// Try go env GOROOT
	cmd := exec.Command("go", "env", "GOROOT")
	out, err := cmd.Output()
	if err == nil {
		goroot := strings.TrimSpace(string(out))
		p := filepath.Join(goroot, "lib", "wasm", "wasm_exec.js")
		if data, err := os.ReadFile(p); err == nil && len(data) > 0 {
			return data, nil
		}
	}
	return nil, fmt.Errorf("wasm_exec.js not found in web/ or GOROOT")
}

func main() {
	var (
		templatePath = flag.String("template", "cmd/bootstrapgen/template.html", "Path to bootstrap HTML template")
		chatSrcPath  = flag.String("chat-src", "apps/basic-chat/index.html", "Path to basic chat app source HTML")
		cotillaJS    = flag.String("cotilla-js", "web/cotilla.js", "Path to cotilla.js client library")
		keyFilePath  = flag.String("key-file", "dist/publisher.json", "Path to publisher keypair JSON file")
		bundleOut    = flag.String("bundle-out", "dist/cotilla-chat.html", "Output path for bundled chat app HTML")
		manifestOut  = flag.String("manifest-out", "dist/cotilla-chat.manifest.json", "Output path for signed AppManifest JSON")
		bootstrapOut = flag.String("bootstrap-out", "bootstrap/index.html", "Output path for bootstrap index.html")
		appID        = flag.String("app-id", "cotilla-chat", "Application ID")
		channel      = flag.String("channel", cotilla.DefaultAppChannel, "Distribution channel")
		distRoomID   = flag.String("dist-room", cotilla.DefaultAppDistRoomID, "Distribution room ID")
		seq          = flag.Uint64("seq", 1, "Monotonic sequence number")
		version      = flag.String("version", "1.0.0", "Application version")
	)
	flag.Parse()

	// Ensure output directories exist
	if err := os.MkdirAll(filepath.Dir(*bundleOut), 0755); err != nil {
		log.Fatalf("mkdir %s: %v", filepath.Dir(*bundleOut), err)
	}
	if err := os.MkdirAll(filepath.Dir(*bootstrapOut), 0755); err != nil {
		log.Fatalf("mkdir %s: %v", filepath.Dir(*bootstrapOut), err)
	}

	// 1. Assemble basic chat app bundle (inlines web/cotilla.js)
	chatSrc, err := os.ReadFile(*chatSrcPath)
	if err != nil {
		log.Fatalf("read %s: %v", *chatSrcPath, err)
	}
	cotillaJSBytes, err := os.ReadFile(*cotillaJS)
	if err != nil {
		log.Fatalf("read %s: %v", *cotillaJS, err)
	}

	bundledHTML := strings.Replace(string(chatSrc), "/* __COTILLA_CLIENT_JS__ */", string(cotillaJSBytes), 1)
	if err := os.WriteFile(*bundleOut, []byte(bundledHTML), 0644); err != nil {
		log.Fatalf("write %s: %v", *bundleOut, err)
	}
	log.Printf("Assembled bundle: %s (%d bytes)", *bundleOut, len(bundledHTML))

	// 2. Obtain or generate publisher keypair
	var kf publisherKeyFile
	if keyBytes, err := os.ReadFile(*keyFilePath); err == nil && len(keyBytes) > 0 {
		if err := json.Unmarshal(keyBytes, &kf); err != nil {
			log.Fatalf("parse key file %s: %v", *keyFilePath, err)
		}
	} else {
		pub, priv, err := cotilla.GeneratePublisherKeypair()
		if err != nil {
			log.Fatalf("generate publisher keypair: %v", err)
		}
		kf = publisherKeyFile{PubKeyHex: pub, PrivKeyHex: priv}
		data, _ := json.MarshalIndent(kf, "", "  ")
		if err := os.WriteFile(*keyFilePath, append(data, '\n'), 0600); err != nil {
			log.Fatalf("write %s: %v", *keyFilePath, err)
		}
		log.Printf("Generated dev publisher keypair: %s (pub: %s)", *keyFilePath, pub)
	}

	// 3. Sign app bundle into AppManifest
	manifest, err := cotilla.SignAppBundle(kf.PrivKeyHex, *appID, *channel, *version, *seq, []byte(bundledHTML), "text/html; charset=utf-8", cotilla.FormatSingleHTMLV1, 365*24*time.Hour)
	if err != nil {
		log.Fatalf("sign app bundle: %v", err)
	}
	manifestData, _ := json.MarshalIndent(manifest, "", "  ")
	if err := os.WriteFile(*manifestOut, append(manifestData, '\n'), 0644); err != nil {
		log.Fatalf("write %s: %v", *manifestOut, err)
	}
	log.Printf("Signed manifest: %s (app: %s, fileID: %s, sha256: %s)", *manifestOut, manifest.AppID, manifest.FileID, manifest.SHA256[:16])

	// 4. Read wasm_exec.js and template.html
	wasmExecJS, err := getWasmExecJS()
	if err != nil {
		log.Fatalf("get wasm_exec.js: %v", err)
	}

	tmplBytes, err := os.ReadFile(*templatePath)
	if err != nil {
		log.Fatalf("read template %s: %v", *templatePath, err)
	}
	tmplStr := string(tmplBytes)

	// Inlining substitutions
	tmplStr = strings.Replace(tmplStr, "/* __WASM_EXEC_JS__ */", string(wasmExecJS), 1)
	tmplStr = strings.Replace(tmplStr, "__PINNED_PUB_KEY__", manifest.PubKey, -1)
	tmplStr = strings.Replace(tmplStr, "__APP_ID__", manifest.AppID, -1)
	tmplStr = strings.Replace(tmplStr, "__CHANNEL__", manifest.Channel, -1)
	tmplStr = strings.Replace(tmplStr, "__DIST_ROOM_ID__", *distRoomID, -1)

	if err := os.WriteFile(*bootstrapOut, []byte(tmplStr), 0644); err != nil {
		log.Fatalf("write %s: %v", *bootstrapOut, err)
	}
	log.Printf("Generated bootstrap HTML: %s (%d bytes)", *bootstrapOut, len(tmplStr))
}
