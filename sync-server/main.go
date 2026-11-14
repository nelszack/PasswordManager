// pm-sync stores opaque encrypted vault snapshots. Run behind Tailscale Serve.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

var version = "dev"
var buildID = "dev"

type serverVersion struct {
	Protocol int    `json:"protocol"`
	Version  string `json:"version"`
	Build    string `json:"build"`
}

func versionInfo() serverVersion { return serverVersion{1, version, buildID} }

const maxVault = 128 << 20

// Upper bound for the JSON head (32 hex version characters and a bounded size).
const maxHeadBytes = 64

type snapshot struct {
	Version string `json:"version"`
	Size    int64  `json:"size"`
}
type vaultInfo struct {
	ID string `json:"id"`
	snapshot
}
type server struct {
	root       string
	budget     int64
	keep       int
	mu         sync.Mutex
	changed    chan struct{}
	generation string
	reserved   int64 // Upload space reserved while request bodies stream without mu.
	used       int64
	usageReady bool
	vaultLocks map[string]*vaultLock
	slots      chan struct{}
}

type vaultLock struct {
	mu   sync.Mutex
	refs int
}

// The global mutex protects accounting/events only; disk work uses per-vault locks.
func (s *server) lockVault(id string) func() {
	s.mu.Lock()
	if s.vaultLocks == nil {
		s.vaultLocks = make(map[string]*vaultLock)
	}
	lock := s.vaultLocks[id]
	if lock == nil {
		lock = &vaultLock{}
		s.vaultLocks[id] = lock
	}
	lock.refs++
	s.mu.Unlock()
	lock.mu.Lock()
	return func() {
		lock.mu.Unlock()
		s.mu.Lock()
		lock.refs--
		if lock.refs == 0 {
			delete(s.vaultLocks, id)
		}
		s.mu.Unlock()
	}
}
func directoryUsage(root string) (int64, error) {
	var used int64
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			info, err := d.Info()
			if err != nil {
				return err
			}
			used += info.Size()
		}
		return nil
	})
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	return used, err
}

// Reconstruct once at startup/first upload. Reservations cover all in-flight disk work.
func (s *server) initializeUsage() error {
	if s.usageReady {
		return nil
	}
	used, err := directoryUsage(filepath.Join(s.root, "vaults"))
	if err == nil {
		s.used = used
		s.usageReady = true
	}
	return err
}
func validID(s string, size int) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == size && s == strings.ToLower(s)
}
func randomID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
func syncDirectory(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
func atomicWrite(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".pending-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}
func (s *server) authorized(r *http.Request) bool {
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		return false
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !validID(token, 32) {
		return false
	}
	digest := sha256.Sum256([]byte(token))
	expected, err := os.ReadFile(filepath.Join(s.root, "devices", hex.EncodeToString(digest[:])+".json"))
	return err == nil && len(expected) > 0
}
func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}
func (s *server) head(id string) (snapshot, error) {
	var h snapshot
	b, err := os.ReadFile(filepath.Join(s.root, "vaults", id, "head.json"))
	if err != nil {
		return h, err
	}
	err = json.Unmarshal(b, &h)
	if err == nil && (!validID(h.Version, 16) || h.Size <= 0 || h.Size > maxVault) {
		err = errors.New("invalid snapshot metadata")
	}
	return h, err
}
func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == "GET" && r.URL.Path == "/v1/health" {
		writeJSON(w, versionInfo())
		return
	}
	if !s.authorized(r) {
		http.Error(w, "unauthorized", 401)
		return
	}
	if r.URL.Path == "/v1/events" && r.Method == "GET" {
		s.mu.Lock()
		generation, changed := s.generation, s.changed
		s.mu.Unlock()
		if r.URL.Query().Get("since") == generation {
			timer := time.NewTimer(25 * time.Second)
			defer timer.Stop()
			select {
			case <-changed:
			case <-timer.C:
			case <-r.Context().Done():
				return
			}
		}
		s.mu.Lock()
		generation = s.generation
		s.mu.Unlock()
		writeJSON(w, map[string]string{"generation": generation})
		return
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		http.Error(w, "busy", 503)
		return
	}
	if r.URL.Path == "/v1/vaults" && r.Method == "GET" {
		entries, err := os.ReadDir(filepath.Join(s.root, "vaults"))
		if err != nil {
			http.Error(w, "storage unavailable", 500)
			return
		}
		vaults := []vaultInfo{}
		for _, e := range entries {
			if e.IsDir() && validID(e.Name(), 16) {
				release := s.lockVault(e.Name())
				h, err := s.head(e.Name())
				release()
				if errors.Is(err, os.ErrNotExist) {
					continue
				}
				if err != nil {
					http.Error(w, "invalid vault metadata", 500)
					return
				}
				vaults = append(vaults, vaultInfo{e.Name(), h})
			}
		}
		writeJSON(w, vaults)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/v1/vaults/")
	if !strings.HasPrefix(r.URL.Path, "/v1/vaults/") || !validID(id, 16) {
		http.NotFound(w, r)
		return
	}
	release := s.lockVault(id)
	locked := true
	unlock := func() {
		if locked {
			release()
			locked = false
		}
	}
	defer unlock()
	h, err := s.head(id)
	exists := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		http.Error(w, "storage unavailable", 500)
		return
	}
	switch r.Method {
	case "GET", "HEAD":
		if !exists {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("ETag", `"`+h.Version+`"`)
		w.Header().Set("Content-Type", "application/octet-stream")
		f, err := os.Open(filepath.Join(s.root, "vaults", id, h.Version+".vault"))
		if err != nil {
			http.Error(w, "snapshot unavailable", 500)
			return
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil || info.Size() != h.Size {
			http.Error(w, "invalid snapshot", 500)
			return
		}
		// Snapshots are immutable. An open descriptor remains valid if a later
		// commit prunes its directory entry while this client is downloading.
		unlock()
		http.ServeContent(w, r, "vault", time.Time{}, f)
	case "PUT":
		if (exists && r.Header.Get("If-Match") != `"`+h.Version+`"`) || (!exists && r.Header.Get("If-None-Match") != "*") {
			http.Error(w, "vault changed; reconcile both copies", 412)
			return
		}
		// Reserve quota without holding any lock during the network transfer.
		s.mu.Lock()
		if err := s.initializeUsage(); err != nil {
			s.mu.Unlock()
			http.Error(w, "storage unavailable", 500)
			return
		}
		available := min(int64(maxVault), s.budget-s.used-s.reserved-maxHeadBytes)
		if available <= 0 {
			s.mu.Unlock()
			http.Error(w, "storage quota reached", 507)
			return
		}
		if r.ContentLength > 0 {
			available = min(available, r.ContentLength)
		}
		reservation := available + maxHeadBytes
		s.reserved += reservation
		s.mu.Unlock()
		defer func() {
			s.mu.Lock()
			s.reserved -= reservation
			s.mu.Unlock()
		}()
		unlock()
		dir := filepath.Join(s.root, "vaults", id)
		// Stage outside vault directories so an interrupted first upload is never listed.
		f, err := os.CreateTemp(s.root, ".upload-")
		if err != nil {
			http.Error(w, "storage unavailable", 500)
			return
		}
		defer os.Remove(f.Name())
		n, err := io.Copy(f, io.LimitReader(r.Body, available+1))
		if err != nil || n == 0 || n > available {
			f.Close()
			http.Error(w, "upload exceeds storage or size limit", 413)
			return
		}
		if err = f.Sync(); err != nil {
			f.Close()
			http.Error(w, "could not save upload", 500)
			return
		}
		if err = f.Close(); err != nil {
			http.Error(w, "could not save upload", 500)
			return
		}
		// Serialize the durable commit, not the network transfer. A competing
		// writer may have advanced this vault while this body was arriving.
		release = s.lockVault(id)
		locked = true
		current, err := s.head(id)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			http.Error(w, "storage unavailable", 500)
			return
		}
		if (err == nil && r.Header.Get("If-Match") != `"`+current.Version+`"`) ||
			(errors.Is(err, os.ErrNotExist) && r.Header.Get("If-None-Match") != "*") {
			http.Error(w, "vault changed; reconcile both copies", 412)
			return
		}
		beforeBytes, err := directoryUsage(dir)
		if err != nil {
			http.Error(w, "storage unavailable", 500)
			return
		}
		// Reconcile even partially committed/failed writes, including orphan snapshots.
		// Only this vault is scanned; unrelated commits continue concurrently.
		accounted := false
		reconcile := func() {
			if accounted {
				return
			}
			accounted = true
			afterBytes, scanErr := directoryUsage(dir)
			s.mu.Lock()
			if scanErr != nil {
				s.used += reservation
			} else {
				s.used += afterBytes - beforeBytes
			}
			s.reserved -= reservation
			reservation = 0
			s.mu.Unlock()
		}
		defer reconcile()
		if err = os.MkdirAll(dir, 0700); err != nil {
			http.Error(w, "storage unavailable", 500)
			return
		}
		if err = syncDirectory(filepath.Dir(dir)); err != nil {
			http.Error(w, "could not save vault directory", 500)
			return
		}
		version := randomID()
		if err = os.Rename(f.Name(), filepath.Join(dir, version+".vault")); err != nil {
			http.Error(w, "could not save snapshot", 500)
			return
		}
		next := snapshot{version, n}
		b, _ := json.Marshal(next)
		if err = atomicWrite(filepath.Join(dir, "head.json"), b); err != nil {
			http.Error(w, "commit outcome uncertain; check current version", 500)
			return
		}
		// Keep current plus a small number of previous versions. Never delete current.
		files, _ := os.ReadDir(dir)
		var previous []os.FileInfo
		for _, e := range files {
			if strings.HasSuffix(e.Name(), ".vault") && e.Name() != version+".vault" {
				if i, e := e.Info(); e == nil {
					previous = append(previous, i)
				}
			}
		}
		sort.Slice(previous, func(i, j int) bool { return previous[i].ModTime().After(previous[j].ModTime()) })
		for i := max(s.keep-1, 0); i < len(previous); i++ {
			_ = os.Remove(filepath.Join(dir, previous[i].Name()))
		}
		s.mu.Lock()
		close(s.changed)
		s.changed = make(chan struct{})
		s.generation = randomID()
		w.Header().Set("ETag", `"`+version+`"`)
		s.mu.Unlock()
		// Release accounting and this vault before a slow client reads its reply.
		reconcile()
		unlock()
		writeJSON(w, next)
	default:
		w.Header().Set("Allow", "GET, HEAD, PUT")
		http.Error(w, "method not allowed", 405)
	}
}
func main() {
	showVersion := flag.Bool("version", false, "Print sync server version and protocol as JSON")
	healthCheck := flag.String("health-check", "", "Verify a running local server matches this executable")
	root := flag.String("data", "./sync-data", "Private storage directory")
	listen := flag.String("listen", "127.0.0.1:8788", "Listen address; use an HTTPS reverse proxy such as Tailscale Serve")
	budget := flag.Int64("max-storage", 256<<20, "Maximum vault storage bytes, including upload headroom")
	keep := flag.Int("keep", 3, "Snapshots retained per vault, including current")
	add := flag.String("add-device", "", "Create a device credential with this label, then exit")
	credential := flag.String("credential-file", "", "New private file receiving the device token")
	revoke := flag.String("revoke-device", "", "Revoke device by its credential ID, then exit")
	flag.Parse()
	if *showVersion {
		b, _ := json.Marshal(versionInfo())
		fmt.Println(string(b))
		return
	}
	if *healthCheck != "" {
		if !strings.HasPrefix(*healthCheck, "http://127.0.0.1:") {
			log.Fatal("health check must use a loopback HTTP endpoint")
		}
		client := &http.Client{Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
		res, err := client.Get(*healthCheck + "/v1/health")
		if err != nil {
			log.Fatal(err)
		}
		defer res.Body.Close()
		var remote serverVersion
		if res.StatusCode != 200 || json.NewDecoder(io.LimitReader(res.Body, 4096)).Decode(&remote) != nil || remote != versionInfo() {
			log.Fatal("running sync server does not match the installed binary")
		}
		return
	}
	if *budget < maxVault || *keep < 1 {
		log.Fatal("max-storage must be at least 128 MiB and keep at least 1")
	}
	for _, dir := range []string{*root, filepath.Join(*root, "devices"), filepath.Join(*root, "vaults")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			log.Fatal(err)
		}
	}
	if *add != "" {
		if *credential == "" {
			log.Fatal("--credential-file is required")
		}
		token := randomID() + randomID()
		digest := sha256.Sum256([]byte(token))
		id := hex.EncodeToString(digest[:])
		f, err := os.OpenFile(*credential, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			log.Fatal(err)
		}
		if _, err = f.WriteString(token + "\n"); err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			log.Fatal(err)
		}
		b, _ := json.Marshal(map[string]string{"name": *add, "created": time.Now().UTC().Format(time.RFC3339)})
		if err = atomicWrite(filepath.Join(*root, "devices", id+".json"), b); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Device credential written to %s. Revoke with --revoke-device %s\n", *credential, id)
		return
	}
	if *revoke != "" {
		if !validID(*revoke, 32) {
			log.Fatal("invalid credential ID")
		}
		if err := os.Remove(filepath.Join(*root, "devices", *revoke+".json")); err != nil {
			log.Fatal(err)
		}
		return
	}
	lock, err := os.OpenFile(filepath.Join(*root, "server.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		log.Fatal(err)
	}
	defer lock.Close()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		log.Fatal("another sync server owns this data directory")
	}
	s := &server{root: *root, budget: *budget, keep: *keep, changed: make(chan struct{}), generation: randomID(), slots: make(chan struct{}, 16)}
	// Remove only incomplete uploads left by a terminated process.
	pending, _ := filepath.Glob(filepath.Join(*root, ".upload-*"))
	for _, p := range pending {
		_ = os.Remove(p)
	}
	if err := s.initializeUsage(); err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{Addr: *listen, Handler: s, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 60 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 16 << 10}
	log.Printf("Encrypted vault sync listening on %s", *listen)
	log.Fatal(srv.ListenAndServe())
}
