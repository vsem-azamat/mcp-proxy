package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/mark3labs/mcp-go/mcp"
)

// Secret escrow: instead of dropping a redacted value, keep it in memory for a
// while under a random handle, so the owner can release it through an
// authenticated HTTP API (/_escrow/) without the value ever entering an agent's
// context. Values live only in this process: never on disk, never in logs.

const (
	// escrowKeyHashEnv holds the hex SHA-256 of the escrow API key. The key
	// itself never reaches the proxy. Unset disables the escrow.
	escrowKeyHashEnv = "MCP_HUB_ESCROW_KEY_SHA256"
	escrowRoute      = "/_escrow/"

	defaultEscrowTTL        = 24 * time.Hour
	defaultEscrowMaxEntries = 1000
	defaultFileMaxBytes     = 20 << 20
	// maxEscrowValueBytes bounds one text value. A larger finding is still
	// redacted, just without a handle.
	maxEscrowValueBytes = 64 << 10
	// maxEscrowTotalBytes bounds the text values held at once; the oldest
	// entries are evicted beyond it.
	maxEscrowTotalBytes = 16 << 20
	escrowSweepInterval = time.Minute
)

// escrowHandleAlphabet is lower-case RFC 4648 base32.
var (
	escrowHandleEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)
	escrowHandlePattern  = regexp.MustCompile(`^k[a-z2-7]{10}$`)
)

type escrowEntry struct {
	handle   string
	kind     string // rule kind, or "file"
	server   string
	tool     string
	source   map[string]any
	created  time.Time
	expires  time.Time
	value    []byte // text secrets
	dedupKey string

	// file entries
	isFile   bool
	filePath string   // resolved path, for logs never
	fileRoot *os.Root // root the file was opened through
	fileRel  string   // path relative to fileRoot
	fileName string
	size     int64
	fileHash [sha256.Size]byte
	kinds    []string
}

type escrowStore struct {
	mu         sync.Mutex
	entries    map[string]*escrowEntry
	byDedup    map[string]string
	maxEntries int
	totalBytes int
	now        func() time.Time
}

func newEscrowStore(maxEntries int) *escrowStore {
	if maxEntries <= 0 {
		maxEntries = defaultEscrowMaxEntries
	}
	return &escrowStore{
		entries:    make(map[string]*escrowEntry),
		byDedup:    make(map[string]string),
		maxEntries: maxEntries,
		now:        time.Now,
	}
}

func newEscrowHandle() (string, error) {
	var raw [7]byte // 56 bits; 10 base32 characters use 50 of them
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return "k" + escrowHandleEncoding.EncodeToString(raw[:])[:10], nil
}

// wipe overwrites a value before it is dropped, so it does not linger in the
// heap longer than necessary. Best effort: Go may have copied it.
func (e *escrowEntry) wipe() {
	clear(e.value)
	e.value = nil
}

// removeLocked drops an entry. Callers hold s.mu.
func (s *escrowStore) removeLocked(entry *escrowEntry) {
	delete(s.entries, entry.handle)
	s.totalBytes -= len(entry.value)
	if entry.dedupKey != "" && s.byDedup[entry.dedupKey] == entry.handle {
		delete(s.byDedup, entry.dedupKey)
	}
	entry.wipe()
}

// sweepLocked drops expired entries. Callers hold s.mu.
func (s *escrowStore) sweepLocked(now time.Time) {
	for _, entry := range s.entries {
		if !now.Before(entry.expires) {
			s.removeLocked(entry)
		}
	}
}

// insert adds an entry under a fresh handle, evicting the oldest entry when
// the store is full.
func (s *escrowStore) insert(entry *escrowEntry) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if entry.dedupKey != "" {
		if handle, ok := s.byDedup[entry.dedupKey]; ok {
			if existing := s.entries[handle]; existing != nil && now.Before(existing.expires) {
				// Seeing the secret again keeps the handle the caller now
				// holds alive for a full TTL.
				if entry.expires.After(existing.expires) {
					existing.expires = entry.expires
				}
				entry.wipe()
				return handle, nil
			}
		}
	}
	if len(s.entries) >= s.maxEntries {
		s.sweepLocked(now)
	}
	for len(s.entries) > 0 && (len(s.entries) >= s.maxEntries || s.totalBytes+len(entry.value) > maxEscrowTotalBytes) {
		var oldest *escrowEntry
		for _, candidate := range s.entries {
			if oldest == nil || candidate.created.Before(oldest.created) {
				oldest = candidate
			}
		}
		slog.Warn("Escrow full, evicting oldest entry", "handle", oldest.handle, "maxEntries", s.maxEntries)
		s.removeLocked(oldest)
	}
	for range 5 {
		handle, err := newEscrowHandle()
		if err != nil {
			return "", err
		}
		if _, taken := s.entries[handle]; taken {
			continue
		}
		entry.handle = handle
		entry.created = now
		if entry.expires.IsZero() || !entry.expires.After(now) {
			entry.expires = now.Add(defaultEscrowTTL)
		}
		s.entries[handle] = entry
		s.totalBytes += len(entry.value)
		if entry.dedupKey != "" {
			s.byDedup[entry.dedupKey] = handle
		}
		return handle, nil
	}
	return "", errors.New("could not allocate an escrow handle")
}

// get returns a copy of a live entry's metadata and value.
func (s *escrowStore) get(handle string) (escrowEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[handle]
	if !ok {
		return escrowEntry{}, false
	}
	if !s.now().Before(entry.expires) {
		s.removeLocked(entry)
		return escrowEntry{}, false
	}
	copied := *entry
	copied.value = slices.Clone(entry.value)
	return copied, true
}

func (s *escrowStore) remove(handle string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[handle]
	if !ok {
		return false
	}
	expired := !s.now().Before(entry.expires)
	s.removeLocked(entry)
	return !expired
}

func (s *escrowStore) sweepLoop(ctx context.Context) {
	ticker := time.NewTicker(escrowSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.mu.Lock()
			s.sweepLocked(s.now())
			s.mu.Unlock()
		}
	}
}

// escrow ties the store to the configuration: per-server TTLs and file tools.
type escrow struct {
	store      *escrowStore
	keyHash    [sha256.Size]byte
	ttl        map[string]time.Duration
	fileTools  map[string]map[string]bool
	fileMaxLen map[string]int64
	fileRoots  map[string][]fileRoot
}

// fileRoot is an opened download directory. Files are opened through it, so
// a symlink anywhere in the path cannot lead outside it.
type fileRoot struct {
	path string
	root *os.Root
}

// activeEscrow is set by setupEscrow when the escrow is enabled.
var activeEscrow *escrow

// escrowHook keeps each finding in the escrow and returns a marker with its
// handle.
type escrowHook struct{ escrow *escrow }

func (h escrowHook) Replace(_ context.Context, source RedactionSource, finding RedactionFinding) string {
	if len(finding.Value) > maxEscrowValueBytes {
		return RedactionMarker(finding.Kind)
	}
	sum := sha256.Sum256([]byte(finding.Value))
	entry := &escrowEntry{
		kind:     finding.Kind,
		server:   source.Server,
		tool:     source.Name,
		source:   summarizeArguments(source.Arguments),
		value:    []byte(finding.Value),
		dedupKey: source.Server + "\x00" + finding.Kind + "\x00" + hex.EncodeToString(sum[:]),
		expires:  time.Now().Add(h.escrow.ttlFor(source.Server)),
	}
	handle, err := h.escrow.store.insert(entry)
	if err != nil {
		slog.Error("Escrow insert failed", "err", err)
		return RedactionMarker(finding.Kind)
	}
	slog.Info("Escrowed secret", "handle", handle, "type", finding.Kind, "client", source.Server, "name", source.Name)
	return escrowMarker(finding.Kind, handle)
}

func escrowMarker(kind, handle string) string {
	return "[REDACTED:" + kind + " #" + handle + "]"
}

func (e *escrow) ttlFor(server string) time.Duration {
	if ttl, ok := e.ttl[server]; ok && ttl > 0 {
		return ttl
	}
	return defaultEscrowTTL
}

// summaryKeys are the request arguments that identify where a secret came
// from (chat, space, message, attachment) without carrying message text or
// the secret itself.
var summaryKeys = map[string]bool{
	"chat_id": true, "message_id": true, "message_ids": true, "topic_id": true, "reply_to": true,
	"space": true, "space_name": true, "message_name": true, "thread_name": true, "attachment_name": true,
	"conversation_id": true, "conversationId": true, "channel_id": true, "chat": true, "peer": true,
	"messageId": true, "threadId": true, "account": true,
}

func summarizeArguments(arguments map[string]any) map[string]any {
	summary := make(map[string]any)
	for key, value := range arguments {
		if !summaryKeys[key] {
			continue
		}
		switch v := value.(type) {
		case string:
			if len(v) <= 200 && !strings.ContainsAny(v, "\r\n") {
				summary[key] = v
			}
		case float64, int, int64, bool, json.Number:
			summary[key] = v
		case []any:
			if len(v) <= 20 {
				items := make([]any, 0, len(v))
				for _, item := range v {
					switch item.(type) {
					case string, float64, int, int64, json.Number:
						items = append(items, item)
					}
				}
				summary[key] = items
			}
		}
	}
	return summary
}

// escrowPreview shows the first 4 and last 3 characters of a long value, less
// of a shorter one, and nothing of a very short one.
func escrowPreview(value []byte) string {
	if !utf8.Valid(value) {
		return "…"
	}
	runes := []rune(string(value))
	switch n := len(runes); {
	case n >= 12:
		return string(runes[:4]) + "…" + string(runes[n-3:])
	case n >= 8:
		return string(runes[:2]) + "…" + string(runes[n-1:])
	default:
		return "…"
	}
}

// setupEscrow enables the escrow when the key hash is configured: it installs
// the redaction hook and mounts the API on mux.
func setupEscrow(ctx context.Context, mux *http.ServeMux, config *Config) {
	hashHex := os.Getenv(escrowKeyHashEnv)
	if strings.TrimSpace(hashHex) == "" {
		slog.Info("Secret escrow disabled", "reason", escrowKeyHashEnv+" is not set")
		return
	}
	e, err := newEscrow(hashHex, config)
	if err != nil {
		slog.Error("Secret escrow disabled", "reason", err)
		return
	}
	activeEscrow = e
	SetRedactionHook(escrowHook{escrow: e})
	go e.store.sweepLoop(ctx)
	mux.Handle(escrowRoute, e.handler())
	slog.Info("Secret escrow enabled", "route", escrowRoute, "maxEntries", e.store.maxEntries)
}

// newEscrow builds the escrow from the key hash and the redact settings.
func newEscrow(hashHex string, config *Config) (*escrow, error) {
	decoded, err := hex.DecodeString(strings.ToLower(strings.TrimSpace(hashHex)))
	if err != nil || len(decoded) != sha256.Size {
		return nil, errors.New(escrowKeyHashEnv + " is not a hex SHA-256")
	}
	maxEntries := 0
	if config.McpProxy != nil && config.McpProxy.Options != nil && config.McpProxy.Options.Redact != nil {
		maxEntries = config.McpProxy.Options.Redact.EscrowMaxEntries
	}
	e := &escrow{
		store:      newEscrowStore(maxEntries),
		ttl:        make(map[string]time.Duration),
		fileTools:  make(map[string]map[string]bool),
		fileMaxLen: make(map[string]int64),
		fileRoots:  make(map[string][]fileRoot),
	}
	copy(e.keyHash[:], decoded)
	var defaultTTL time.Duration
	if config.McpProxy != nil && config.McpProxy.Options != nil && config.McpProxy.Options.Redact != nil {
		defaultTTL = time.Duration(config.McpProxy.Options.Redact.EscrowTTL)
	}
	for name, server := range config.McpServers {
		if server == nil || server.Options == nil || server.Options.Redact == nil {
			continue
		}
		redact := server.Options.Redact
		e.ttl[name] = time.Duration(redact.EscrowTTL)
		if e.ttl[name] == 0 {
			e.ttl[name] = defaultTTL
		}
		for _, root := range redact.FileRoots {
			resolved, err := filepath.EvalSymlinks(root)
			var opened *os.Root
			if err == nil && filepath.IsAbs(resolved) {
				opened, err = os.OpenRoot(resolved)
			}
			if err == nil {
				e.fileRoots[name] = append(e.fileRoots[name], fileRoot{path: resolved, root: opened})
			} else {
				slog.Warn("redact.fileRoots entry does not exist, ignored", "client", name, "root", root)
			}
		}
		if len(redact.FileTools) > 0 && len(e.fileRoots[name]) == 0 {
			slog.Warn("redact.fileTools is set but no fileRoots exist, so downloads are not scanned", "client", name)
		}
		tools := make(map[string]bool, len(redact.FileTools))
		for _, tool := range redact.FileTools {
			tools[tool] = true
		}
		e.fileTools[name] = tools
		e.fileMaxLen[name] = redact.FileMaxBytes
	}
	return e, nil
}

func (e *escrow) handler() http.Handler {
	return chainMiddleware(http.HandlerFunc(e.serveHTTP), recoverMiddleware("_escrow"))
}

func (e *escrow) authorized(r *http.Request) bool {
	header := r.Header.Get("Authorization")
	if len(header) < len(bearerPrefix) || !strings.EqualFold(header[:len(bearerPrefix)], bearerPrefix) {
		return false
	}
	key := strings.TrimSpace(header[len(bearerPrefix):])
	if key == "" {
		return false
	}
	sum := sha256.Sum256([]byte(key))
	return subtle.ConstantTimeCompare(sum[:], e.keyHash[:]) == 1
}

type escrowMeta struct {
	Handle    string         `json:"handle"`
	Type      string         `json:"type"`
	Kind      string         `json:"kind"`
	Server    string         `json:"server"`
	Tool      string         `json:"tool"`
	Source    map[string]any `json:"source"`
	CreatedAt string         `json:"created_at"`
	ExpiresAt string         `json:"expires_at"`
	Preview   string         `json:"preview"`
	FileName  string         `json:"file_name,omitempty"`
	Size      *int64         `json:"size,omitempty"`
}

func (e *escrow) serveHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	rest := strings.TrimPrefix(r.URL.Path, escrowRoute)
	handle, sub, _ := strings.Cut(rest, "/")
	status := http.StatusOK
	op := "value"
	if sub == "meta" {
		op = "meta"
	} else if r.Method == http.MethodDelete {
		op = "delete"
	}
	logHandle := handle
	if !escrowHandlePattern.MatchString(handle) {
		logHandle = "<invalid>"
	}
	defer func() {
		slog.Info("Escrow access", "op", op, "handle", logHandle, "status", status, "remote", r.RemoteAddr, "forwardedFor", r.Header.Get("X-Forwarded-For"))
	}()

	if !e.authorized(r) {
		status = http.StatusUnauthorized
		w.Header().Set("WWW-Authenticate", `Bearer realm="escrow"`)
		http.Error(w, "Unauthorized", status)
		return
	}
	if !escrowHandlePattern.MatchString(handle) || (sub != "" && sub != "meta") {
		status = http.StatusNotFound
		http.Error(w, "Not Found", status)
		return
	}

	switch {
	case sub == "meta" && (r.Method == http.MethodGet || r.Method == http.MethodHead):
		entry, ok := e.store.get(handle)
		if !ok {
			status = http.StatusNotFound
			http.Error(w, "Not Found", status)
			return
		}
		meta := escrowMeta{
			Handle:    entry.handle,
			Type:      entry.kind,
			Kind:      "text",
			Server:    entry.server,
			Tool:      entry.tool,
			Source:    entry.source,
			CreatedAt: entry.created.UTC().Format(time.RFC3339),
			ExpiresAt: entry.expires.UTC().Format(time.RFC3339),
			Preview:   escrowPreview(entry.value),
		}
		if entry.isFile {
			meta.Kind = "file"
			meta.Preview = ""
			meta.FileName = entry.fileName
			size := entry.size
			meta.Size = &size
		}
		if meta.Source == nil {
			meta.Source = map[string]any{}
		}
		clear(entry.value)
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodHead {
			return
		}
		_ = json.NewEncoder(w).Encode(meta)
	case sub == "" && r.Method == http.MethodGet:
		entry, ok := e.store.get(handle)
		if !ok {
			status = http.StatusNotFound
			http.Error(w, "Not Found", status)
			return
		}
		value := entry.value
		if entry.isFile {
			content, err := readEscrowedFile(&entry)
			if err != nil {
				slog.Warn("Escrowed file unavailable", "handle", handle, "reason", err.Error())
				status = http.StatusNotFound
				http.Error(w, "Not Found", status)
				return
			}
			value = content
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprint(len(value)))
		_, _ = w.Write(value)
		clear(value)
	case sub == "" && r.Method == http.MethodDelete:
		if !e.store.remove(handle) {
			status = http.StatusNotFound
			http.Error(w, "Not Found", status)
			return
		}
		status = http.StatusNoContent
		w.WriteHeader(status)
	default:
		status = http.StatusMethodNotAllowed
		http.Error(w, "Method Not Allowed", status)
	}
}

// readEscrowedFile returns the file's bytes if it is still the file that was
// scanned (same size and SHA-256).
func readEscrowedFile(entry *escrowEntry) ([]byte, error) {
	if entry.fileRoot == nil {
		return nil, errors.New("file has no root")
	}
	f, err := entry.fileRoot.OpenFile(entry.fileRel, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("file cannot be opened")
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != entry.size {
		return nil, errors.New("file changed since it was scanned")
	}
	content, err := io.ReadAll(io.LimitReader(f, entry.size+1))
	if err != nil {
		return nil, errors.New("file cannot be read")
	}
	if sha256.Sum256(content) != entry.fileHash {
		clear(content)
		return nil, errors.New("file changed since it was scanned")
	}
	return content, nil
}

// ---- downloaded files ----

// filePathKeys are result and argument members that name a downloaded file.
var filePathKeys = []string{"path", "file_path", "filePath", "outputPath", "output_path", "localPath", "local_path", "savedTo", "saved_to"}

var downloadedToPattern = regexp.MustCompile(`(?i)(?:downloaded|saved|written)\s+to\s+(?:"([^"\r\n]+)"|'([^'\r\n]+)'|(/[^\s"'<>]+))`)

// secretFileExtensions mark files whose content is a credential store even
// when it is binary or matches no rule.
var (
	secretFileExtensions = []string{".p12", ".pfx", ".jks", ".keystore", ".kdbx", ".ppk"}
	scannedFileNames     = regexp.MustCompile(`(?i)(^\.env(\..*)?$|\.env$|\.(pem|key|json|ya?ml|toml|ini|conf|cfg|properties|txt|log|sh|xml|csv|md|tf|tfvars)$|^id_[a-z0-9_]+$|kubeconfig|credentials|secrets?)`)
)

// fileScanSlots bounds concurrent file scans, so parallel downloads cannot
// pull many large files into memory at once.
var fileScanSlots = make(chan struct{}, 2)

// mtimeSlack tolerates clock granularity between the call start and the
// file's modification time.
const mtimeSlack = 2 * time.Second

// scanToolFile looks for a file the tool downloaded during this call. If it
// holds secrets, the result is rewritten so that it no longer names the file,
// and the path is kept in the escrow instead.
//
// Only files under the server's fileRoots that were written during the call
// are considered, so neither a caller (through arguments) nor a downstream
// (through result text) can make the hub read an arbitrary file such as its
// own token file.
func (r *redactor) scanToolFile(request mcp.CallToolRequest, result *mcp.CallToolResult, callStart time.Time) *mcp.CallToolResult {
	e := activeEscrow
	if r == nil || e == nil || result == nil || result.IsError {
		return result
	}
	toolName := request.Params.Name
	if !e.fileTools[r.server][toolName] || len(e.fileRoots[r.server]) == 0 {
		return result
	}
	maxBytes := e.fileMaxLen[r.server]
	if maxBytes <= 0 {
		maxBytes = defaultFileMaxBytes
	}
	for _, candidate := range downloadedFilePaths(request, result) {
		path := candidate.path
		// A path only the caller named must have been created after the call
		// started; one the tool reported gets a little slack for clocks.
		since := callStart.Add(-mtimeSlack)
		if candidate.fromArguments {
			since = callStart
		}
		file, ok := openDownloadedFile(path, e.fileRoots[r.server], since)
		if !ok {
			continue
		}
		kinds, size, hash, found := r.scanFile(file, maxBytes)
		_ = file.f.Close()
		if !found {
			continue
		}
		entry := &escrowEntry{
			kind:     "file",
			server:   r.server,
			tool:     toolName,
			source:   summarizeArguments(request.GetArguments()),
			isFile:   true,
			filePath: file.resolved,
			fileRoot: file.root,
			fileRel:  file.rel,
			fileName: filepath.Base(file.resolved),
			size:     size,
			fileHash: hash,
			kinds:    kinds,
			expires:  time.Now().Add(e.ttlFor(r.server)),
		}
		handle, err := e.store.insert(entry)
		if err != nil {
			slog.Error("Escrow insert failed", "err", err)
			handle = ""
		}
		slog.Info("Escrowed downloaded file", "handle", handle, "client", r.server, "tool", toolName, "kinds", kinds, "size", size)
		marker := RedactionMarker("file")
		if handle != "" {
			marker = escrowMarker("file", handle)
		}
		notice := fmt.Sprintf("%s file_name=%s size=%d bytes; contains: %s. The file is withheld from this conversation; the owner can release it.",
			marker, filepath.Base(file.resolved), size, strings.Join(kinds, ", "))
		withholdFile(result, []string{path, file.resolved, candidate.raw}, marker, notice)
	}
	return result
}

type downloadedFile struct {
	f        *os.File
	resolved string
	root     *os.Root
	rel      string
}

// openDownloadedFile opens path if it lies under one of roots and is a
// regular file with a single link whose inode changed (ctime) at or after
// since. The file is opened through the root handle, so no symlink in any
// component can lead outside the root, and every check runs on the opened
// file. ctime is used instead of mtime because a writer can set mtime freely.
func openDownloadedFile(path string, roots []fileRoot, since time.Time) (downloadedFile, bool) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return downloadedFile{}, false
	}
	var root fileRoot
	var rel string
	for _, candidate := range roots {
		if r, err := filepath.Rel(candidate.path, resolved); err == nil && r != ".." && !strings.HasPrefix(r, "../") && r != "." {
			root, rel = candidate, r
			break
		}
	}
	if root.root == nil {
		slog.Warn("Downloaded file is outside fileRoots, not scanned", "file", filepath.Base(resolved))
		return downloadedFile{}, false
	}
	f, err := root.root.OpenFile(rel, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return downloadedFile{}, false
	}
	info, err := f.Stat()
	stat, ok := info.Sys().(*syscall.Stat_t)
	if err != nil || !ok || !info.Mode().IsRegular() || stat.Nlink != 1 {
		_ = f.Close()
		return downloadedFile{}, false
	}
	if time.Unix(stat.Ctim.Unix()).Before(since) {
		_ = f.Close()
		slog.Warn("File named by a download tool predates the call, not scanned", "file", filepath.Base(resolved))
		return downloadedFile{}, false
	}
	return downloadedFile{f: f, resolved: resolved, root: root.root, rel: rel}, true
}

// downloadedFilePaths collects absolute paths a file tool reported, in its
// result (structured members at any depth, file:// URIs, "downloaded to"
// text) or in its arguments (an output path the caller chose).
type pathCandidate struct {
	path          string // cleaned absolute path
	raw           string // as written in the result, for withholding
	fromArguments bool
}

func downloadedFilePaths(request mcp.CallToolRequest, result *mcp.CallToolResult) []pathCandidate {
	var paths []pathCandidate
	fromArguments := false
	add := func(raw string) {
		candidate := strings.TrimSpace(raw)
		if rest, ok := strings.CutPrefix(candidate, "file://"); ok {
			unescaped, err := url.PathUnescape(rest)
			if err != nil {
				return
			}
			candidate = unescaped
		}
		candidate = strings.TrimRight(candidate, ".,;")
		if !filepath.IsAbs(candidate) {
			return
		}
		candidate = filepath.Clean(candidate)
		for i := range paths {
			if paths[i].path == candidate {
				// Reported by the tool as well: not caller-only.
				paths[i].fromArguments = paths[i].fromArguments && fromArguments
				return
			}
		}
		paths = append(paths, pathCandidate{path: candidate, raw: strings.TrimRight(strings.TrimSpace(raw), ".,;"), fromArguments: fromArguments})
	}
	var walk func(key string, value any, depth int)
	walk = func(key string, value any, depth int) {
		if depth > 8 {
			return
		}
		switch v := value.(type) {
		case map[string]any:
			for k, item := range v {
				walk(k, item, depth+1)
			}
		case []any:
			for _, item := range v {
				walk(key, item, depth+1)
			}
		case string:
			if slices.Contains(filePathKeys, key) || strings.HasPrefix(v, "file://") {
				add(v)
			}
		}
	}
	if len(result.RawStructuredContent) > 0 {
		var decoded any
		if json.Unmarshal(result.RawStructuredContent, &decoded) == nil {
			walk("", decoded, 0)
		}
	} else if result.StructuredContent != nil {
		walk("", result.StructuredContent, 0)
	}
	for _, content := range result.Content {
		if uri := contentURI(content); uri != "" {
			add(uri)
		}
		text := contentText(content)
		if text == "" {
			continue
		}
		var decoded any
		if json.Unmarshal([]byte(text), &decoded) == nil {
			walk("", decoded, 0)
		}
		for _, match := range downloadedToPattern.FindAllStringSubmatch(text, -1) {
			for _, group := range match[1:] {
				if group != "" {
					add(group)
					break
				}
			}
		}
	}
	fromArguments = true
	walk("", request.GetArguments(), 0)
	return paths
}

func contentText(content mcp.Content) string {
	switch v := content.(type) {
	case mcp.TextContent:
		return v.Text
	case *mcp.TextContent:
		if v != nil {
			return v.Text
		}
	}
	return ""
}

func contentURI(content mcp.Content) string {
	switch v := content.(type) {
	case mcp.ResourceLink:
		return v.URI
	case *mcp.ResourceLink:
		if v != nil {
			return v.URI
		}
	case mcp.EmbeddedResource:
		return resourceURI(v.Resource)
	case *mcp.EmbeddedResource:
		if v != nil {
			return resourceURI(v.Resource)
		}
	}
	return ""
}

func resourceURI(contents mcp.ResourceContents) string {
	switch v := contents.(type) {
	case mcp.TextResourceContents:
		return v.URI
	case *mcp.TextResourceContents:
		if v != nil {
			return v.URI
		}
	case mcp.BlobResourceContents:
		return v.URI
	case *mcp.BlobResourceContents:
		if v != nil {
			return v.URI
		}
	}
	return ""
}

// scanFile reports the secret kinds found in an opened regular file.
func (r *redactor) scanFile(file downloadedFile, maxBytes int64) ([]string, int64, [sha256.Size]byte, bool) {
	var hash [sha256.Size]byte
	info, err := file.f.Stat()
	if err != nil {
		return nil, 0, hash, false
	}
	name := filepath.Base(file.resolved)
	if info.Size() > maxBytes {
		slog.Warn("Downloaded file too large to scan for secrets", "client", r.server, "file", name, "size", info.Size())
		return nil, 0, hash, false
	}
	fileScanSlots <- struct{}{}
	defer func() { <-fileScanSlots }()
	content, err := io.ReadAll(io.LimitReader(file.f, maxBytes+1))
	if err != nil || int64(len(content)) != info.Size() {
		return nil, 0, hash, false
	}
	defer clear(content)
	hash = sha256.Sum256(content)

	lower := strings.ToLower(name)
	for _, ext := range secretFileExtensions {
		if strings.HasSuffix(lower, ext) {
			return []string{"secret_file"}, info.Size(), hash, true
		}
	}
	if !scannedFileNames.MatchString(name) && !looksLikeText(content) {
		return nil, 0, hash, false
	}
	if !utf8.Valid(content) {
		return nil, 0, hash, false
	}
	stats := make(map[string]int)
	r.detect(string(content), stats)
	if len(stats) == 0 {
		return nil, 0, hash, false
	}
	kinds := make([]string, 0, len(stats))
	for kind := range stats {
		kinds = append(kinds, kind)
	}
	slices.Sort(kinds)
	return kinds, info.Size(), hash, true
}

// detect counts findings without replacing anything (and without calling the
// hook, so nothing is escrowed per finding).
func (r *redactor) detect(text string, stats map[string]int) {
	for _, f := range r.find(text) {
		stats[f.kind]++
	}
	if looksLikeJSON(text) {
		var decoded any
		if json.Unmarshal([]byte(text), &decoded) == nil {
			r.detectValue("", decoded, stats)
		}
	}
}

func (r *redactor) detectValue(key string, value any, stats map[string]int) {
	switch v := value.(type) {
	case map[string]any:
		for k, item := range v {
			r.detectValue(k, item, stats)
		}
	case []any:
		for _, item := range v {
			r.detectValue(key, item, stats)
		}
	case string:
		if kind, ok := secretKeyKind(key); ok && !isPlaceholderValue(v) && !r.disabled[kind] {
			stats[kind]++
			return
		}
		for _, f := range r.find(v) {
			stats[f.kind]++
		}
	}
}

func looksLikeText(content []byte) bool {
	head := content
	if len(head) > 8192 {
		head = head[:8192]
	}
	if slices.Contains(head, 0) {
		return false
	}
	// Allow a multi-byte rune cut at the boundary.
	for i := 0; i < 4 && len(head) > 0 && !utf8.Valid(head); i++ {
		head = head[:len(head)-1]
	}
	return utf8.Valid(head)
}

// withholdFile removes every mention of the file from a result: text content
// that names a path is replaced by notice, resource links and embedded
// resources pointing at it are replaced by notice, and string members of
// structuredContent holding it become marker (a string, so an output schema
// that requires the member still validates).
func withholdFile(result *mcp.CallToolResult, paths []string, marker, notice string) {
	mentions := func(text string) bool {
		for _, path := range paths {
			if path != "" && strings.Contains(text, path) {
				return true
			}
		}
		return false
	}
	for i, content := range result.Content {
		if mentions(contentText(content)) || mentions(contentURI(content)) {
			result.Content[i] = mcp.NewTextContent(notice)
		}
	}
	var replace func(value any, depth int) (any, bool)
	replace = func(value any, depth int) (any, bool) {
		if depth > 8 {
			return value, false
		}
		switch v := value.(type) {
		case map[string]any:
			changed := false
			for k, item := range v {
				if updated, ok := replace(item, depth+1); ok {
					v[k] = updated
					changed = true
				}
			}
			return v, changed
		case []any:
			changed := false
			for i, item := range v {
				if updated, ok := replace(item, depth+1); ok {
					v[i] = updated
					changed = true
				}
			}
			return v, changed
		case string:
			if mentions(v) {
				return marker, true
			}
		}
		return value, false
	}
	var structured any
	if len(result.RawStructuredContent) > 0 {
		if json.Unmarshal(result.RawStructuredContent, &structured) != nil {
			structured = nil
		}
	} else {
		structured = result.StructuredContent
	}
	if structured == nil {
		return
	}
	if updated, changed := replace(structured, 0); changed {
		result.StructuredContent = updated
		if encoded, err := json.Marshal(updated); err == nil {
			result.RawStructuredContent = encoded
		} else {
			result.StructuredContent = nil
			result.RawStructuredContent = nil
		}
	}
}
