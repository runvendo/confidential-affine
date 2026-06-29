// unlock-gate: the first container in a confidential Affine enclave.
// LOCKED until a user supplies the workspace passphrase over Tinfoil's attested
// channel. It derives the data key (Argon2id + unwrap a passphrase-wrapped key
// stored in R2), holds it in memory, serves it to in-enclave sidecars
// (postgres-walg) on a private port, and once unlocked reverse-proxies all
// traffic (HTTP + WebSocket) to Affine. The passphrase and key never touch
// Vendo/Tinfoil infrastructure: only ciphertext (the wrapped key) is in R2, and
// the passphrase only ever exists in the user's browser and this attested enclave.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	argonTime    = 3
	argonMemory  = 256 * 1024 // 256 MiB
	argonThreads = 4
	keyLen       = 32
)

type keyWrap struct {
	Salt    string `json:"salt"`    // base64
	Wrapped string `json:"wrapped"` // base64(nonce||box)
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory"`
	Threads uint8  `json:"threads"`
}

type gate struct {
	mu        sync.RWMutex
	key       []byte
	proxy     *httputil.ReverseProxy
	r2        *minio.Client
	bucket    string
	keyObject string
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
func must(k string) string {
	v := os.Getenv(k)
	if v == "" {
		log.Fatalf("missing required env %s", k)
	}
	return v
}

func (g *gate) unlocked() bool { g.mu.RLock(); defer g.mu.RUnlock(); return g.key != nil }
func (g *gate) getKey() []byte { g.mu.RLock(); defer g.mu.RUnlock(); return g.key }

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		log.Fatal(err)
	}
	return b
}

// derive + unwrap (or first-run create) the data key from the passphrase.
func (g *gate) unlock(ctx context.Context, passphrase string) error {
	// Only a genuine NoSuchKey is first-run. Never overwrite an existing wrap on
	// a transient error or a wrong passphrase (that would destroy the data key).
	if _, statErr := g.r2.StatObject(ctx, g.bucket, g.keyObject, minio.StatObjectOptions{}); statErr != nil {
		if minio.ToErrorResponse(statErr).Code == "NoSuchKey" {
			return g.firstRun(ctx, passphrase)
		}
		return statErr
	}
	obj, err := g.r2.GetObject(ctx, g.bucket, g.keyObject, minio.GetObjectOptions{})
	if err != nil {
		return err
	}
	raw, err := io.ReadAll(obj)
	if err != nil {
		return err
	}
	var kw keyWrap
	if err := json.Unmarshal(raw, &kw); err != nil {
		return errors.New("corrupt keywrap")
	}
	salt, _ := base64.StdEncoding.DecodeString(kw.Salt)
	wrapped, _ := base64.StdEncoding.DecodeString(kw.Wrapped)
	if len(wrapped) < 24 {
		return errors.New("corrupt keywrap")
	}
	kek := argon2.IDKey([]byte(passphrase), salt, kw.Time, kw.Memory, kw.Threads, keyLen)
	var nonce [24]byte
	copy(nonce[:], wrapped[:24])
	var kekArr [32]byte
	copy(kekArr[:], kek)
	K, ok := secretbox.Open(nil, wrapped[24:], &nonce, &kekArr)
	if !ok {
		return errors.New("wrong passphrase")
	}
	g.setKey(K)
	return nil
}

func (g *gate) firstRun(ctx context.Context, passphrase string) error {
	K := randBytes(keyLen)
	salt := randBytes(16)
	kek := argon2.IDKey([]byte(passphrase), salt, argonTime, argonMemory, argonThreads, keyLen)
	var nonce [24]byte
	copy(nonce[:], randBytes(24))
	var kekArr [32]byte
	copy(kekArr[:], kek)
	sealed := secretbox.Seal(nonce[:], K, &nonce, &kekArr)
	kw := keyWrap{
		Salt:    base64.StdEncoding.EncodeToString(salt),
		Wrapped: base64.StdEncoding.EncodeToString(sealed),
		Time:    argonTime, Memory: argonMemory, Threads: argonThreads,
	}
	body, _ := json.Marshal(kw)
	_, err := g.r2.PutObject(ctx, g.bucket, g.keyObject, bytes.NewReader(body), int64(len(body)),
		minio.PutObjectOptions{ContentType: "application/json"})
	if err != nil {
		return err
	}
	g.setKey(K)
	log.Printf("[unlock-gate] first run: generated + wrapped new data key -> %s", g.keyObject)
	return nil
}

// the data key WAL-G uses: base64 of K (matches WALG_LIBSODIUM_KEY_TRANSFORM=base64).
func (g *gate) setKey(K []byte) { g.mu.Lock(); g.key = K; g.mu.Unlock() }

func (g *gate) handleUnlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Passphrase string `json:"passphrase"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil || len(req.Passphrase) < 1 {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := g.unlock(ctx, req.Passphrase); err != nil {
		log.Printf("[unlock-gate] unlock failed: %v", err)
		http.Error(w, `{"error":"unlock failed"}`, http.StatusUnauthorized)
		return
	}
	log.Printf("[unlock-gate] UNLOCKED")
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"unlocked"}`))
}

// public listener (behind the shim): unlock page when locked, proxy when unlocked.
func (g *gate) public(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/__health":
		w.Write([]byte("ok"))
		return
	case "/__unlock":
		g.handleUnlock(w, r)
		return
	}
	if g.unlocked() {
		g.proxy.ServeHTTP(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusServiceUnavailable)
	w.Write([]byte(unlockHTML))
}

// private listener (web network only): hand the data key to in-enclave sidecars.
func (g *gate) keyHandler(w http.ResponseWriter, r *http.Request) {
	k := g.getKey()
	if k == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	w.Write([]byte(base64.StdEncoding.EncodeToString(k)))
}

func main() {
	affine := env("AFFINE_UPSTREAM", "http://affine:3010")
	u, err := url.Parse(affine)
	if err != nil {
		log.Fatal(err)
	}
	r2, err := minio.New(must("R2_ACCOUNT_ID")+".r2.cloudflarestorage.com", &minio.Options{
		Creds:  credentials.NewStaticV4(must("R2_ACCESS_KEY_ID"), must("R2_SECRET_ACCESS_KEY"), ""),
		Secure: true,
		Region: "auto",
	})
	if err != nil {
		log.Fatal(err)
	}
	g := &gate{
		proxy:     httputil.NewSingleHostReverseProxy(u), // handles HTTP + WebSocket upgrades
		r2:        r2,
		bucket:    must("R2_BUCKET"),
		keyObject: env("KEYWRAP_OBJECT", "confidential-affine/keywrap.json"),
	}

	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/key", g.keyHandler)
		log.Printf("[unlock-gate] private key listener on :9090")
		log.Fatal(http.ListenAndServe(":9090", mux))
	}()

	log.Printf("[unlock-gate] public listener on :3010 -> %s (locked)", affine)
	log.Fatal(http.ListenAndServe(":3010", http.HandlerFunc(g.public)))
}

const unlockHTML = `<!doctype html><html><head><meta charset=utf-8><title>Unlock your private workspace</title>
<meta name=viewport content="width=device-width,initial-scale=1">
<style>body{font:16px system-ui;max-width:34rem;margin:6rem auto;padding:0 1rem;color:#111}
h1{font-size:1.4rem}input,button{font:inherit;padding:.6rem .8rem;border-radius:.5rem;border:1px solid #ccc;width:100%;box-sizing:border-box}
button{margin-top:.8rem;background:#111;color:#fff;border:0;cursor:pointer}.muted{color:#666;font-size:.9rem}#err{color:#c00;margin-top:.6rem}</style></head>
<body><h1>Unlock your private workspace</h1>
<p class=muted>This workspace is end-to-end encrypted. Enter your passphrase to unlock it. We cannot recover it for you.</p>
<input id=p type=password placeholder="Workspace passphrase" autofocus>
<button onclick=u()>Unlock</button><div id=err></div>
<script>async function u(){document.getElementById('err').textContent='';
var r=await fetch('/__unlock',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({passphrase:document.getElementById('p').value})});
if(r.ok){document.body.innerHTML='<h1>Unlocked. Starting your workspace…</h1><p class=muted>Reloading shortly.</p>';setTimeout(function(){location.reload()},8000);}
else{document.getElementById('err').textContent='Unlock failed. Check your passphrase.';}}
document.getElementById('p').addEventListener('keydown',function(e){if(e.key==='Enter')u()});</script></body></html>`
