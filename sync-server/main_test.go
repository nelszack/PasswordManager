package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type gatedReader struct {
	io.Reader
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (r *gatedReader) Read(p []byte) (int, error) {
	r.once.Do(func() { close(r.entered); <-r.release })
	return r.Reader.Read(p)
}

func await(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("request blocked behind another client's transfer")
	}
}

func TestSlowUploadDoesNotBlockReadsAndRechecksTheBase(t *testing.T) {
	s, h, token := fixture(t)
	path := "/v1/vaults/" + strings.Repeat("e", 32)
	base := request(t, h, token, "PUT", path, "*", "initial").Header.Get("ETag")
	body := &gatedReader{Reader: strings.NewReader("slow"), entered: make(chan struct{}), release: make(chan struct{})}
	defer close(body.release)
	req := httptest.NewRequest("PUT", path, body)
	requestHeaders(req, token, base)
	result := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { s.ServeHTTP(result, req); close(done) }()
	await(t, body.entered)
	// Both reads and another commit must finish before the slow body resumes.
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		for _, method := range []string{"HEAD", "PUT"} {
			r := httptest.NewRequest(method, path, strings.NewReader("winner"))
			requestHeaders(r, token, base)
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			if w.Code != 200 {
				t.Errorf("%s: %d", method, w.Code)
			}
		}
	}()
	await(t, finished)
	// Let the defer release the body only after testing concurrent progress.
	body.release <- struct{}{}
	await(t, done)
	if result.Code != 412 {
		t.Fatalf("stale upload: %d", result.Code)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reserved != 0 {
		t.Fatalf("leaked reservation: %d", s.reserved)
	}
}

func TestConcurrentUploadsReserveAndReleaseQuota(t *testing.T) {
	s, _, token := fixture(t)
	s.budget = 128
	body := &gatedReader{Reader: strings.NewReader("small"), entered: make(chan struct{}), release: make(chan struct{})}
	defer close(body.release)
	r := httptest.NewRequest("PUT", "/v1/vaults/"+strings.Repeat("a", 32), body)
	requestHeaders(r, token, "*")
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { s.ServeHTTP(w, r); close(done) }()
	await(t, body.entered)
	second := httptest.NewRequest("PUT", "/v1/vaults/"+strings.Repeat("b", 32), strings.NewReader("other"))
	requestHeaders(second, token, "*")
	denied := httptest.NewRecorder()
	finished := make(chan struct{})
	go func() { s.ServeHTTP(denied, second); close(finished) }()
	await(t, finished)
	if denied.Code != 507 {
		t.Fatalf("unreserved quota: %d", denied.Code)
	}
	body.release <- struct{}{}
	await(t, done)
	if w.Code != 200 {
		t.Fatalf("upload: %d", w.Code)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reserved != 0 {
		t.Fatalf("leaked reservation: %d", s.reserved)
	}
}

type interruptedUpload struct{}

func (interruptedUpload) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestInterruptedUploadReleasesQuotaAndRemovesItsStagingFile(t *testing.T) {
	s, _, token := fixture(t)
	r := httptest.NewRequest("PUT", "/v1/vaults/"+strings.Repeat("c", 32),
		io.MultiReader(strings.NewReader("partial"), interruptedUpload{}))
	requestHeaders(r, token, "*")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 413 {
		t.Fatalf("interrupted upload: %d", w.Code)
	}
	if s.reserved != 0 {
		t.Fatalf("leaked reservation: %d", s.reserved)
	}
	files, err := filepath.Glob(filepath.Join(s.root, ".upload-*"))
	if err != nil || len(files) != 0 {
		t.Fatalf("staging files: %v, %v", files, err)
	}
	entries, err := os.ReadDir(filepath.Join(s.root, "vaults"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("uncommitted vault: %v, %v", entries, err)
	}
}

type gatedWriter struct {
	*httptest.ResponseRecorder
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *gatedWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.entered); <-w.release })
	return w.ResponseRecorder.Write(p)
}

func TestDownloadSurvivesPruningWithoutBlockingAnotherCommit(t *testing.T) {
	s, h, token := fixture(t)
	s.keep = 1
	path := "/v1/vaults/" + strings.Repeat("f", 32)
	base := request(t, h, token, "PUT", path, "*", "original").Header.Get("ETag")
	w := &gatedWriter{ResponseRecorder: httptest.NewRecorder(), entered: make(chan struct{}), release: make(chan struct{})}
	defer close(w.release)
	r := httptest.NewRequest("GET", path, nil)
	requestHeaders(r, token, "")
	done := make(chan struct{})
	go func() { s.ServeHTTP(w, r); close(done) }()
	await(t, w.entered)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		r := httptest.NewRequest("PUT", path, strings.NewReader("replacement"))
		requestHeaders(r, token, base)
		result := httptest.NewRecorder()
		s.ServeHTTP(result, r)
		if result.Code != 200 {
			t.Errorf("commit: %d", result.Code)
		}
	}()
	await(t, finished)
	w.release <- struct{}{}
	await(t, done)
	if w.Body.String() != "original" {
		t.Fatalf("download changed: %q", w.Body.String())
	}
}

func fixture(t *testing.T) (*server, *httptest.Server, string) {
	t.Helper()
	root := t.TempDir()
	for _, d := range []string{"devices", "vaults"} {
		if e := os.Mkdir(filepath.Join(root, d), 0700); e != nil {
			t.Fatal(e)
		}
	}
	token := strings.Repeat("a", 64)
	hash := sha256.Sum256([]byte(token))
	if e := os.WriteFile(filepath.Join(root, "devices", hex.EncodeToString(hash[:])+".json"), []byte(`{"name":"test"}`), 0600); e != nil {
		t.Fatal(e)
	}
	s := &server{root: root, budget: 256 << 20, keep: 3, changed: make(chan struct{}), generation: randomID(), slots: make(chan struct{}, 16)}
	h := httptest.NewServer(s)
	t.Cleanup(h.Close)
	return s, h, token
}
func requestHeaders(req *http.Request, token, base string) {
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if base == "*" {
		req.Header.Set("If-None-Match", "*")
	} else if base != "" {
		req.Header.Set("If-Match", base)
	}
}

func request(t *testing.T, h *httptest.Server, token, method, path, base, body string) *http.Response {
	t.Helper()
	req, e := http.NewRequest(method, h.URL+path, bytes.NewBufferString(body))
	if e != nil {
		t.Fatal(e)
	}
	requestHeaders(req, token, base)
	res, e := h.Client().Do(req)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { res.Body.Close() })
	return res
}
func TestConditionalUploadsAndRetention(t *testing.T) {
	s, h, token := fixture(t)
	path := "/v1/vaults/" + strings.Repeat("b", 32)
	first := request(t, h, token, "PUT", path, "*", "encrypted-one")
	if first.StatusCode != 200 {
		t.Fatal(first.Status)
	}
	version := first.Header.Get("ETag")
	stale := request(t, h, token, "PUT", path, "*", "would-overwrite")
	if stale.StatusCode != 412 {
		t.Fatal(stale.Status)
	}
	for i := 0; i < 5; i++ {
		res := request(t, h, token, "PUT", path, version, "encrypted-next")
		if res.StatusCode != 200 {
			t.Fatal(res.Status)
		}
		next := res.Header.Get("ETag")
		if next == version {
			t.Fatal("version reused")
		}
		version = next
	}
	stale = request(t, h, token, "PUT", path, first.Header.Get("ETag"), "stale")
	if stale.StatusCode != 412 {
		t.Fatal(stale.Status)
	}
	current := request(t, h, token, "GET", path, "", "")
	data, _ := io.ReadAll(current.Body)
	if string(data) != "encrypted-next" {
		t.Fatal(string(data))
	}
	files, e := filepath.Glob(filepath.Join(s.root, "vaults", strings.Repeat("b", 32), "*.vault"))
	if e != nil || len(files) != 3 {
		t.Fatalf("retention: %v %v", files, e)
	}
	// Restarting must retain the durable head/version.
	restarted := &server{root: s.root, budget: s.budget, keep: s.keep, changed: make(chan struct{}), generation: randomID(), slots: make(chan struct{}, 16)}
	head, e := restarted.head(strings.Repeat("b", 32))
	if e != nil || `"`+head.Version+`"` != version {
		t.Fatalf("restart lost head: %+v %v", head, e)
	}
}
func TestAuthenticationRevocationAndPaths(t *testing.T) {
	s, h, token := fixture(t)
	if res := request(t, h, "", "GET", "/v1/vaults", "", ""); res.StatusCode != 401 {
		t.Fatal(res.Status)
	}
	if res := request(t, h, token, "PUT", "/v1/vaults/not-an-id", "*", "encrypted"); res.StatusCode != 404 {
		t.Fatal(res.Status)
	}
	if res := request(t, h, token, "GET", "/v1/vaults", "", ""); res.StatusCode != 200 {
		t.Fatal(res.Status)
	}
	hash := sha256.Sum256([]byte(token))
	if e := os.Remove(filepath.Join(s.root, "devices", hex.EncodeToString(hash[:])+".json")); e != nil {
		t.Fatal(e)
	}
	if res := request(t, h, token, "GET", "/v1/vaults", "", ""); res.StatusCode != 401 {
		t.Fatal(res.Status)
	}
}
func TestNotificationsAndQuota(t *testing.T) {
	s, h, token := fixture(t)
	s.mu.Lock()
	generation := s.generation
	s.mu.Unlock()
	done := make(chan string, 1)
	go func() {
		req, _ := http.NewRequest("GET", h.URL+"/v1/events?since="+generation, nil)
		requestHeaders(req, token, "")
		res, e := h.Client().Do(req)
		if e != nil {
			done <- e.Error()
			return
		}
		defer res.Body.Close()
		var v map[string]string
		e = json.NewDecoder(res.Body).Decode(&v)
		if e != nil {
			done <- e.Error()
			return
		}
		done <- v["generation"]
	}()
	res := request(t, h, token, "PUT", "/v1/vaults/"+strings.Repeat("b", 32), "*", "encrypted")
	if res.StatusCode != 200 {
		t.Fatal(res.Status)
	}
	select {
	case next := <-done:
		if next == generation || !validID(next, 16) {
			t.Fatal(next)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("notification did not wake")
	}
	s.mu.Lock()
	s.budget = 1
	s.mu.Unlock()
	res = request(t, h, token, "PUT", "/v1/vaults/"+strings.Repeat("c", 32), "*", "more")
	if res.StatusCode != 507 {
		t.Fatal(res.Status)
	}
	res = request(t, h, token, "GET", "/v1/vaults/"+strings.Repeat("b", 32), "", "")
	if res.StatusCode != 200 {
		t.Fatal("quota damaged existing vault")
	}
}

func TestOnlyOneConcurrentWriterCanCommitTheSameBase(t *testing.T) {
	_, h, token := fixture(t)
	path := "/v1/vaults/" + strings.Repeat("d", 32)
	first := request(t, h, token, "PUT", path, "*", "initial")
	base := first.Header.Get("ETag")
	start := make(chan struct{})
	statuses := make(chan int, 2)
	for _, contents := range []string{"laptop", "desktop"} {
		go func(contents string) {
			<-start
			req, _ := http.NewRequest("PUT", h.URL+path, strings.NewReader(contents))
			requestHeaders(req, token, base)
			res, err := h.Client().Do(req)
			if err != nil {
				statuses <- 0
				return
			}
			defer res.Body.Close()
			statuses <- res.StatusCode
		}(contents)
	}
	close(start)
	one, two := <-statuses, <-statuses
	if !((one == 200 && two == 412) || (one == 412 && two == 200)) {
		t.Fatalf("concurrent writers returned %d and %d", one, two)
	}
}

func TestHealthReportsProtocolAndBuildWithoutExposingVaults(t *testing.T) {
	_, h, _ := fixture(t)
	res := request(t, h, "", "GET", "/v1/health", "", "")
	if res.StatusCode != 200 {
		t.Fatal(res.Status)
	}
	var info serverVersion
	if err := json.NewDecoder(res.Body).Decode(&info); err != nil {
		t.Fatal(err)
	}
	if info != versionInfo() {
		t.Fatalf("unexpected health response: %+v", info)
	}
	res = request(t, h, "", "GET", "/v1/vaults", "", "")
	if res.StatusCode != 401 {
		t.Fatal("health endpoint bypassed vault authorization")
	}
}
