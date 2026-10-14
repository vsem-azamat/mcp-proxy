package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
)

const testEscrowKey = "test-escrow-key-0123456789abcdef"

func testEscrowHash() string {
	sum := sha256.Sum256([]byte(testEscrowKey))
	return hex.EncodeToString(sum[:])
}

func newTestEscrow(t *testing.T, redact *RedactConfig) *escrow {
	t.Helper()
	e, err := newEscrow(testEscrowHash(), &Config{
		McpProxy:   &MCPProxyConfigV2{Options: &OptionsV2{Redact: redact}},
		McpServers: map[string]*MCPClientConfigV2{"chat": {Options: &OptionsV2{Redact: redact}}},
	})
	if err != nil {
		t.Fatalf("newEscrow: %v", err)
	}
	return e
}

// installEscrow makes e the active escrow for the duration of a test. Tests
// using it must not be parallel.
func installEscrow(t *testing.T, e *escrow) {
	t.Helper()
	activeEscrow = e
	SetRedactionHook(escrowHook{escrow: e})
	t.Cleanup(func() {
		activeEscrow = nil
		SetRedactionHook(nil)
	})
}

func escrowRequest(t *testing.T, e *escrow, method, path, auth string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	e.handler().ServeHTTP(rec, req)
	return rec
}

var markerPattern = regexp.MustCompile(`\[REDACTED:([a-z_]+) #(k[a-z2-7]{10})\]`)

func TestEscrowHandleFormat(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	for range 200 {
		handle, err := newEscrowHandle()
		if err != nil {
			t.Fatal(err)
		}
		if !escrowHandlePattern.MatchString(handle) {
			t.Fatalf("handle %q does not match %s", handle, escrowHandlePattern)
		}
		if seen[handle] {
			t.Fatalf("duplicate handle %q", handle)
		}
		seen[handle] = true
	}
}

func TestEscrowPreview(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"AKIAIOSFODNN7EXAMPLEX2Q": "AKIA…X2Q",
		"hunter2!x":               "hu…x",
		"hunter2":                 "…",
		"пароль-секретный":        "паро…ный",
	}
	for value, want := range tests {
		if got := escrowPreview([]byte(value)); got != want {
			t.Errorf("preview(%q) = %q, want %q", value, got, want)
		}
	}
}

func TestEscrowStoreExpiryDedupAndEviction(t *testing.T) {
	t.Parallel()
	store := newEscrowStore(2)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }

	a, _ := store.insert(&escrowEntry{kind: "password", value: []byte("one"), dedupKey: "d1", expires: now.Add(time.Hour)})
	again, _ := store.insert(&escrowEntry{kind: "password", value: []byte("one"), dedupKey: "d1", expires: now.Add(time.Hour)})
	if a != again {
		t.Fatalf("same secret got two handles: %s, %s", a, again)
	}
	now = now.Add(time.Second)
	b, _ := store.insert(&escrowEntry{kind: "password", value: []byte("two"), expires: now.Add(time.Hour)})
	now = now.Add(time.Second)
	c, _ := store.insert(&escrowEntry{kind: "password", value: []byte("three"), expires: now.Add(time.Hour)})
	if _, ok := store.get(a); ok {
		t.Fatal("oldest entry should have been evicted")
	}
	if _, ok := store.get(b); !ok {
		t.Fatal("entry b missing")
	}
	now = now.Add(2 * time.Hour)
	if _, ok := store.get(c); ok {
		t.Fatal("expired entry still readable")
	}
	if store.remove(b) {
		t.Fatal("removing an expired entry should report not found")
	}
}

func TestEscrowHTTPContract(t *testing.T) {
	t.Parallel()
	e := newTestEscrow(t, &RedactConfig{Enabled: true, EscrowTTL: Duration(time.Hour)})
	secret := "AKIAIOSFODNN7EXAMPLEX2Q"
	marker := escrowHook{escrow: e}.Replace(context.Background(), RedactionSource{
		Server: "chat", Method: "tools/call", Name: "get_messages",
		Arguments: map[string]any{"chat_id": float64(42), "message_ids": []any{float64(7)}, "text": "password: x", "query": "secret"},
	}, RedactionFinding{Kind: "aws_access_key", Value: secret})
	m := markerPattern.FindStringSubmatch(marker)
	if m == nil || m[1] != "aws_access_key" {
		t.Fatalf("marker = %q", marker)
	}
	handle := m[2]
	auth := "Bearer " + testEscrowKey

	// Wrong or missing key, and a client token: 401, even for unknown handles.
	for _, bad := range []string{"", "Bearer nope", "Bearer " + testEscrowKey + "x", testEscrowKey} {
		for _, path := range []string{"/_escrow/" + handle + "/meta", "/_escrow/" + handle, "/_escrow/kaaaaaaaaaa"} {
			if rec := escrowRequest(t, e, http.MethodGet, path, bad); rec.Code != http.StatusUnauthorized {
				t.Errorf("GET %s with %q = %d, want 401", path, bad, rec.Code)
			}
		}
	}

	rec := escrowRequest(t, e, http.MethodGet, "/_escrow/"+handle+"/meta", auth)
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("meta = %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), secret) {
		t.Fatal("meta leaks the value")
	}
	var meta map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &meta); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]any{"handle": handle, "type": "aws_access_key", "kind": "text", "server": "chat", "tool": "get_messages", "preview": "AKIA…X2Q"} {
		if meta[key] != want {
			t.Errorf("meta[%s] = %v, want %v", key, meta[key], want)
		}
	}
	source := meta["source"].(map[string]any)
	if source["chat_id"] != float64(42) || source["text"] != nil || source["query"] != nil {
		t.Errorf("source = %v, want ids only", source)
	}
	created, err1 := time.Parse(time.RFC3339, meta["created_at"].(string))
	expires, err2 := time.Parse(time.RFC3339, meta["expires_at"].(string))
	if err1 != nil || err2 != nil || expires.Sub(created) < 59*time.Minute || expires.Sub(created) > 61*time.Minute {
		t.Errorf("created_at/expires_at = %v / %v", meta["created_at"], meta["expires_at"])
	}
	if _, ok := meta["file_name"]; ok {
		t.Error("text entry must not carry file_name")
	}

	rec = escrowRequest(t, e, http.MethodGet, "/_escrow/"+handle, auth)
	if rec.Code != http.StatusOK || rec.Body.String() != secret || rec.Header().Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("value = %d %q %s", rec.Code, rec.Body, rec.Header().Get("Content-Type"))
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("value must not be cacheable")
	}

	if rec = escrowRequest(t, e, http.MethodDelete, "/_escrow/"+handle, auth); rec.Code != http.StatusNoContent {
		t.Fatalf("delete = %d", rec.Code)
	}
	for _, path := range []string{"/_escrow/" + handle, "/_escrow/" + handle + "/meta", "/_escrow/kaaaaaaaaaa", "/_escrow/not-a-handle", "/_escrow/" + handle + "/other"} {
		if rec = escrowRequest(t, e, http.MethodGet, path, auth); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s after delete = %d, want 404", path, rec.Code)
		}
	}
	if rec = escrowRequest(t, e, http.MethodDelete, "/_escrow/"+handle, auth); rec.Code != http.StatusNotFound {
		t.Errorf("second delete = %d, want 404", rec.Code)
	}
}

func TestEscrowDisabledWithoutValidHash(t *testing.T) {
	t.Parallel()
	for _, bad := range []string{"", "zz", strings.Repeat("a", 63)} {
		if _, err := newEscrow(bad, &Config{McpProxy: &MCPProxyConfigV2{}}); err == nil {
			t.Errorf("newEscrow(%q) succeeded", bad)
		}
	}
}

// Not parallel: installs the process-wide escrow.
func TestEscrowMarkersInToolResults(t *testing.T) {
	e := newTestEscrow(t, &RedactConfig{Enabled: true})
	installEscrow(t, e)
	r := newRedactor("chat", &OptionsV2{Redact: &RedactConfig{Enabled: true}})

	request := mcp.CallToolRequest{}
	request.Params.Name = "get_messages"
	request.Params.Arguments = map[string]any{"chat_id": "c1"}
	result := &mcp.CallToolResult{Content: []mcp.Content{mcp.NewTextContent(`{"messages":[{"text":"пароль: Qwerty-12345"},{"text":"again пароль: Qwerty-12345"}]}`)}}
	r.toolResult(context.Background(), request, result)
	text := result.Content[0].(mcp.TextContent).Text
	matches := markerPattern.FindAllStringSubmatch(text, -1)
	if len(matches) != 2 || strings.Contains(text, "Qwerty-12345") {
		t.Fatalf("text = %s", text)
	}
	if matches[0][2] != matches[1][2] {
		t.Errorf("the same secret got two handles: %s", text)
	}
	entry, ok := e.store.get(matches[0][2])
	if !ok || string(entry.value) != "Qwerty-12345" || entry.kind != "password" || entry.tool != "get_messages" {
		t.Fatalf("entry = %+v", entry)
	}
}

func TestRussianLabels(t *testing.T) {
	t.Parallel()
	r := testRedactor(false)
	positives := map[string]string{
		"Пароль: Summer-Blue-77!":                                   "Summer-Blue-77!",
		"пароль — qwerty123":                                        "qwerty123",
		"вот пароль Zx9-kL2m":                                       "Zx9-kL2m",
		"токен: abcdef123456":                                       "abcdef123456",
		"Ключ = AbCdEf-998877":                                      "AbCdEf-998877",
		"логин/пароль: admin / Qwerty123":                           "Qwerty123",
		"логин и пароль - root:toor-77":                             "toor-77",
		"Пароль​: hunter22":                                         "hunter22",
		"пароль: «correct horse battery 9»":                         "correct horse battery 9",
		"секрет: s3cr3t-value":                                      "s3cr3t-value",
		"код доступа: 774411":                                       "774411",
		"апи ключ: zz-top-secret-1":                                 "zz-top-secret-1",
		"ПАРОЛЬ: Upper-Case-1":                                      "Upper-Case-1",
		"не забудь, пароль: tr1cky.":                                "tr1cky",
		"пароль от wifi: wifi-Pass-2026":                            "wifi-Pass-2026",
		"ключа нет, токен: xyz-123-abc-tail":                        "xyz-123-abc-tail",
		"пароль от почты: mail-Pw-1":                                "mail-Pw-1",
		"пароль к wifi — Wifi2026x":                                 "Wifi2026x",
		"Пароль:\nNextLine-77":                                      "NextLine-77",
		"Пароли: first-Pw-1":                                        "first-Pw-1",
		"ключ доступа: acc-key-9911":                                "acc-key-9911",
		"пароль -- dash-Pw-2":                                       "dash-Pw-2",
		"пароль: `tick-Pw-3`":                                       "tick-Pw-3",
		"логин/пароль: admin / Qwerty123, ключ " + fake("AKIA", 16): "Qwerty123",
	}
	for text, secret := range positives {
		got := redactForTest(r, text)
		if strings.Contains(got, secret) || !strings.Contains(got, "[REDACTED:") {
			t.Errorf("%q -> %q, secret survived", text, got)
		}
	}
	negatives := []string{
		"пароль был изменён",
		"токен истёк",
		"токен: истёк",
		"ключ от квартиры у соседа",
		"ключ: в верхнем ящике",
		"Обычное сообщение без доступов",
		"пароль: ********",
		"пароль: нет",
		"ключевой момент: завтра",
		"токен USDT-TRC20",
		"токен ERC-20",
		"ключ ssh-rsa",
		"ключ: ED25519",
		"ключ — 2048 бит",
		"ключ - 12:30",
		"секрет: 50%",
		"токен — Telegram выдаёт",
		"логин/пароль - пришлю позже в личку",
		"пароль от почты сменили",
	}
	for _, text := range negatives {
		if got := redactForTest(r, text); got != text {
			t.Errorf("%q changed to %q", text, got)
		}
	}
}

// Not parallel: installs the process-wide escrow.
func TestDownloadedFileWithSecretsIsWithheld(t *testing.T) {
	dir := t.TempDir()
	e := newTestEscrow(t, &RedactConfig{Enabled: true, FileTools: []string{"download_media", "download_attachment"}, FileRoots: []string{dir}})
	installEscrow(t, e)
	r := newRedactor("chat", &OptionsV2{Redact: &RedactConfig{Enabled: true}})
	start := time.Now()
	envFile := filepath.Join(dir, "telegram_1_2_3.txt")
	content := "DB_HOST=db\nDB_PASSWORD=hunter2!x\n"
	writeFile(t, envFile, content)
	plainFile := filepath.Join(dir, "notes.txt")
	writeFile(t, plainFile, "nothing secret here\n")
	binFile := filepath.Join(dir, "photo.jpg")
	writeFile(t, binFile, "\xff\xd8\xff\x00binary")

	call := func(tool, text string, structured map[string]any) *mcp.CallToolResult {
		request := mcp.CallToolRequest{}
		request.Params.Name = tool
		request.Params.Arguments = map[string]any{"chat_id": 1, "message_id": 2}
		result := &mcp.CallToolResult{Content: []mcp.Content{mcp.NewTextContent(text)}}
		if structured != nil {
			raw, _ := json.Marshal(structured)
			result.StructuredContent = structured
			result.RawStructuredContent = raw
		}
		result = r.toolResult(context.Background(), request, result)
		return r.scanToolFile(request, result, start)
	}

	// Telegram-style text result.
	result := call("download_media", "Media downloaded to "+envFile+".", nil)
	text := result.Content[0].(mcp.TextContent).Text
	m := markerPattern.FindStringSubmatch(text)
	if m == nil || m[1] != "file" || strings.Contains(text, envFile) || !strings.Contains(text, "file_name=telegram_1_2_3.txt") || !strings.Contains(text, "password") {
		t.Fatalf("text = %q", text)
	}
	handle := m[2]
	auth := "Bearer " + testEscrowKey
	rec := escrowRequest(t, e, http.MethodGet, "/_escrow/"+handle+"/meta", auth)
	var meta map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &meta)
	if meta["kind"] != "file" || meta["type"] != "file" || meta["file_name"] != "telegram_1_2_3.txt" || meta["size"] != float64(len(content)) || meta["preview"] != "" {
		t.Fatalf("meta = %s", rec.Body)
	}
	if strings.Contains(rec.Body.String(), dir) {
		t.Error("meta must not reveal the path")
	}
	rec = escrowRequest(t, e, http.MethodGet, "/_escrow/"+handle, auth)
	if body, _ := io.ReadAll(rec.Body); rec.Code != http.StatusOK || string(body) != content {
		t.Fatalf("file value = %d %q", rec.Code, body)
	}
	// A file that changed after the scan is not served.
	writeFile(t, envFile, content+"MORE=1\n")
	if rec = escrowRequest(t, e, http.MethodGet, "/_escrow/"+handle, auth); rec.Code != http.StatusNotFound {
		t.Errorf("changed file = %d, want 404", rec.Code)
	}

	// Google Chat-style structured result: path member replaced, schema kept.
	gcFile := filepath.Join(dir, ".env")
	writeFile(t, gcFile, "export GITHUB_TOKEN="+fake("ghp_", 36)+"\n")
	structured := map[string]any{"path": gcFile, "file_name": ".env", "bytes": 50, "content_type": "text/plain", "sha256": "abc"}
	raw, _ := json.Marshal(structured)
	result = call("download_attachment", string(raw), structured)
	if strings.Contains(string(result.RawStructuredContent), gcFile) || !markerPattern.MatchString(string(result.RawStructuredContent)) {
		t.Errorf("structured = %s", result.RawStructuredContent)
	}
	if text := result.Content[0].(mcp.TextContent).Text; strings.Contains(text, gcFile) || !markerPattern.MatchString(text) {
		t.Errorf("text = %s", text)
	}

	// Nested structured members and file:// links are found and withheld.
	nestedFile := filepath.Join(dir, "nested.env")
	writeFile(t, nestedFile, "API_TOKEN="+fake("", 30)+"\n")
	nested := map[string]any{"file": map[string]any{"path": nestedFile}, "link": "file://" + nestedFile}
	result = call("download_attachment", "ok", nested)
	if strings.Contains(string(result.RawStructuredContent), nestedFile) {
		t.Errorf("nested structured = %s", result.RawStructuredContent)
	}

	// Paths outside fileRoots, files older than the call and symlinks out of
	// the root are never read, whoever names them.
	outside := t.TempDir()
	tokens := filepath.Join(outside, "tokens.env")
	writeFile(t, tokens, "MCP_TOKEN=abcdef123456\n")
	oldFile := filepath.Join(dir, "old.env")
	writeFile(t, oldFile, "OLD_PASSWORD=old-pass-1\n")
	link := filepath.Join(dir, "link.env")
	if err := os.Symlink(tokens, link); err != nil {
		t.Fatal(err)
	}
	hard := filepath.Join(dir, "hard.env")
	writeFile(t, filepath.Join(dir, "orig.env"), "HARD_PASSWORD=hard-pass-1\n")
	if err := os.Link(filepath.Join(dir, "orig.env"), hard); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{tokens, oldFile, link, hard} {
		request := mcp.CallToolRequest{}
		request.Params.Name = "download_media"
		request.Params.Arguments = map[string]any{"file_path": path}
		text := "Media downloaded to " + path + "."
		callStart := start
		if path == oldFile {
			// The file's inode changed before this call started.
			callStart = time.Now().Add(time.Minute)
		}
		result := r.scanToolFile(request, &mcp.CallToolResult{Content: []mcp.Content{mcp.NewTextContent(text)}}, callStart)
		if got := result.Content[0].(mcp.TextContent).Text; got != text {
			t.Errorf("%s was scanned: %q", path, got)
		}
	}

	// Files without secrets, binary files and other tools pass through.
	for _, tc := range []struct{ tool, text string }{
		{"download_media", "Media downloaded to " + plainFile + "."},
		{"download_media", "Media downloaded to " + binFile + "."},
		{"get_messages", "Media downloaded to " + gcFile + "."},
	} {
		result := call(tc.tool, tc.text, nil)
		if got := result.Content[0].(mcp.TextContent).Text; got != tc.text {
			t.Errorf("%s %q changed to %q", tc.tool, tc.text, got)
		}
	}
}

func TestEscrowRouteIsReserved(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"_escrow", "_escrow/x"} {
		if err := validateServerName(name); err == nil {
			t.Errorf("server name %q accepted", name)
		}
	}
	if err := validateServerName("escrow"); err != nil {
		t.Errorf("escrow rejected: %v", err)
	}
}

func TestMain(m *testing.M) {
	// The escrow tests rely on no key hash leaking in from the environment.
	_ = os.Unsetenv(escrowKeyHashEnv)
	os.Exit(m.Run())
}

func TestEscrowRepeatExtendsExpiry(t *testing.T) {
	t.Parallel()
	store := newEscrowStore(10)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	h, _ := store.insert(&escrowEntry{kind: "password", value: []byte("one"), dedupKey: "d", expires: now.Add(time.Hour)})
	now = now.Add(59 * time.Minute)
	_, _ = store.insert(&escrowEntry{kind: "password", value: []byte("one"), dedupKey: "d", expires: now.Add(time.Hour)})
	now = now.Add(30 * time.Minute)
	if _, ok := store.get(h); !ok {
		t.Fatal("a secret seen again must keep its handle alive")
	}
}

func TestEscrowTotalBytesCap(t *testing.T) {
	t.Parallel()
	store := newEscrowStore(100000)
	big := strings.Repeat("x", maxEscrowValueBytes)
	for i := 0; i < 2*maxEscrowTotalBytes/maxEscrowValueBytes; i++ {
		if _, err := store.insert(&escrowEntry{kind: "k", value: []byte(big + fmt.Sprint(i))}); err != nil {
			t.Fatal(err)
		}
	}
	if store.totalBytes > maxEscrowTotalBytes {
		t.Fatalf("totalBytes = %d, cap %d", store.totalBytes, maxEscrowTotalBytes)
	}
}

// Not parallel: sets the environment and installs the process-wide escrow.
func TestEscrowRouteIgnoresClientTokens(t *testing.T) {
	t.Setenv(escrowKeyHashEnv, testEscrowHash())
	t.Cleanup(func() {
		activeEscrow = nil
		SetRedactionHook(nil)
	})
	mux := http.NewServeMux()
	config := &Config{McpProxy: &MCPProxyConfigV2{Options: &OptionsV2{AuthTokens: []string{"client-token"}}}}
	setupEscrow(t.Context(), mux, config)
	for auth, want := range map[string]int{
		"Bearer client-token":     http.StatusUnauthorized,
		"":                        http.StatusUnauthorized,
		"Bearer " + testEscrowKey: http.StatusNotFound,
	} {
		req := httptest.NewRequest(http.MethodGet, "/_escrow/kaaaaaaaaaa/meta", nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("auth %q: status %d, want %d", auth, rec.Code, want)
		}
	}
}
