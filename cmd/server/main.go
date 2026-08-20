package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/net/proxy"
	_ "modernc.org/sqlite"
)

type App struct {
	db            *sql.DB
	key           []byte
	session       string
	admin         string
	cookieSecure  bool
	loginMu       sync.Mutex
	loginAttempts map[string]loginAttempt
	routingMu     sync.Mutex
	mihomoMu      sync.Mutex
	proxyCacheMu  sync.Mutex
	proxyCache    proxyCache
	clientCache   map[int64]*http.Client
	proxyVersion  atomic.Uint64
	gatewaySem    chan struct{}
	rr            atomic.Uint64
	ctx           context.Context
	cancel        context.CancelFunc
	backgroundWG  sync.WaitGroup
	hcMu          sync.Mutex
	hcStateMu     sync.Mutex
	hcRunning     bool
	hcLastRun     time.Time
	hcDuration    time.Duration
	hcPassed      int
	hcFailed      int
}

type loginAttempt struct {
	Failures     int
	WindowStart  time.Time
	BlockedUntil time.Time
}

type proxyCache struct {
	loadedAt time.Time
	proxies  []ProxyRecord
	version  uint64
}

const (
	adminSessionPrefix        = "admin_session_"
	usageRetentionSettingKey  = "usage_retention_days"
	defaultUsageRetentionDays = 90
	upstreamRequestTimeout    = 120 * time.Second
)

var (
	chinaLocation         = time.FixedZone("Asia/Shanghai", 8*60*60)
	usageRetentionOptions = map[int]struct{}{7: {}, 30: {}, 90: {}, 180: {}}
)

type ProxyRecord struct {
	ID            int64      `json:"id"`
	URI           string     `json:"uri"`
	Scheme        string     `json:"scheme"`
	Host          string     `json:"host"`
	Port          int        `json:"port"`
	Username      string     `json:"username,omitempty"`
	Password      string     `json:"-"`
	Enabled       bool       `json:"enabled"`
	HealthStatus  string     `json:"health_status"`
	FailureCount  int        `json:"failure_count"`
	UsageState    string     `json:"usage_state,omitempty"`
	CooldownUntil *time.Time `json:"cooldown_until,omitempty"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	LastCheckedAt *time.Time `json:"last_checked_at,omitempty"`
	LastCheckOK   bool       `json:"last_check_ok"`
	CreatedAt     time.Time  `json:"created_at"`
}

type ModelRecord struct {
	ID          int64           `json:"id"`
	ModelID     string          `json:"model_id"`
	DisplayName string          `json:"display_name"`
	IsFree      bool            `json:"is_free"`
	FreeReason  string          `json:"free_reason"`
	Pricing     json.RawMessage `json:"pricing_metadata,omitempty"`
	Raw         json.RawMessage `json:"raw_metadata,omitempty"`
	RefreshedAt time.Time       `json:"refreshed_at"`
}

type upstreamConfig struct {
	BaseURL        string
	APIKey         string
	VisionBaseURL  string
	VisionAPIKey   string
	VisionModel    string
	VisionUseProxy bool
	CustomHeaders  map[string]string
	UpdatedAt      time.Time
	LastRefresh    *time.Time
	LastError      string
}

type mihomoConfig struct {
	ControlURL string
	Secret     string
	EntryProxy string
	Selector   string
}

const defaultMihomoSelector = "🚀节点选择"

var skippedMihomoGroups = map[string]struct{}{
	"select": {}, "selector": {}, "urltest": {}, "fallback": {}, "loadbalance": {}, "relay": {}, "pass": {}, "passrule": {}, "direct": {}, "reject": {}, "rejectdrop": {}, "compatible": {}, "global": {},
}

var skippedMihomoNames = map[string]struct{}{
	"DIRECT": {}, "REJECT": {}, "REJECT-DROP": {}, "PASS": {}, "PASS-RULE": {}, "COMPATIBLE": {}, "GLOBAL": {},
}

// 订阅服务商常嵌入的“流量/到期”展示伪节点，无实际连接能力
var skippedMihomoNamePatterns = []string{"剩余流量", "套餐到期", "已用流量", "套餐余额", "到期时间"}

func normalizeMihomoType(t string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(t) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func containsString(list []string, target string) bool {
	for _, s := range list {
		if s == target {
			return true
		}
	}
	return false
}

type usageRequest struct {
	ID                  int64     `json:"id"`
	CreatedAt           time.Time `json:"created_at"`
	RequestKind         string    `json:"request_kind"`
	Model               string    `json:"model"`
	ProxyID             *int64    `json:"proxy_id,omitempty"`
	ProxyURI            string    `json:"proxy_uri,omitempty"`
	Status              string    `json:"status"`
	StatusCode          int       `json:"status_code"`
	LatencyMS           int64     `json:"latency_ms"`
	FirstTokenLatencyMS *int64    `json:"first_token_latency_ms,omitempty"`
	RetryCount          int       `json:"retry_count"`
	PromptTokens        *int64    `json:"prompt_tokens,omitempty"`
	CompletionTokens    *int64    `json:"completion_tokens,omitempty"`
	TotalTokens         *int64    `json:"total_tokens,omitempty"`
	ErrorMessage        string    `json:"error_message,omitempty"`
	ErrorOrigin         string    `json:"error_origin"`
}

type tokenUsage struct {
	Prompt     *int64
	Completion *int64
	Total      *int64
}

var defaultUpstreamHeaders = map[string]string{
	"User-Agent":        "opencode/1.18.12 ai-sdk/provider-utils/4.0.23 runtime/bun/1.3.13",
	"X-Opencode-Client": "cli",
}

var protectedUpstreamHeaders = map[string]struct{}{
	"authorization":       {},
	"connection":          {},
	"content-length":      {},
	"content-type":        {},
	"host":                {},
	"keep-alive":          {},
	"proxy-authorization": {},
	"proxy-connection":    {},
	"te":                  {},
	"trailer":             {},
	"transfer-encoding":   {},
	"upgrade":             {},
}

var blockedDownstreamHeaders = map[string]struct{}{
	"connection":          {},
	"content-length":      {},
	"keep-alive":          {},
	"proxy-authenticate":  {},
	"proxy-authorization": {},
	"proxy-connection":    {},
	"set-cookie":          {},
	"te":                  {},
	"trailer":             {},
	"transfer-encoding":   {},
	"upgrade":             {},
}

func main() {
	port := getenv("PORT", "8080")
	dbPath := getenv("DATABASE_PATH", "./data/app.db")
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o750); err != nil {
		log.Fatal(err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	// A single pooled connection serializes SQLite writers. busy_timeout also
	// protects against short-lived locks from backup and maintenance tools.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := migrate(db); err != nil {
		log.Fatal(err)
	}
	if _, err := db.Exec("PRAGMA busy_timeout=5000"); err != nil {
		log.Fatal(err)
	}
	appKey := []byte(os.Getenv("APP_ENCRYPTION_KEY"))
	if len(appKey) < 32 {
		log.Fatal("APP_ENCRYPTION_KEY must contain at least 32 characters")
	}
	if looksLikePlaceholderSecret(string(appKey)) {
		log.Print("SECURITY WARNING: APP_ENCRYPTION_KEY appears to be a placeholder; migrate encrypted credentials to a random key")
	}
	sessionSecret := os.Getenv("SESSION_SECRET")
	if len(sessionSecret) < 32 {
		log.Fatal("SESSION_SECRET must contain at least 32 characters")
	}
	if looksLikePlaceholderSecret(sessionSecret) {
		log.Print("SECURITY WARNING: SESSION_SECRET appears to be a placeholder and should be replaced")
	}
	cookieSecure, err := envBool("COOKIE_SECURE", false)
	if err != nil {
		log.Fatal(err)
	}
	maxConcurrent, err := envInt("MAX_CONCURRENT_REQUESTS", 100, 1, 10000)
	if err != nil {
		log.Fatal(err)
	}
	h := sha256.Sum256(appKey)
	app := &App{
		db:            db,
		key:           h[:],
		session:       sessionSecret,
		admin:         os.Getenv("ADMIN_PASSWORD"),
		cookieSecure:  cookieSecure,
		loginAttempts: make(map[string]loginAttempt),
		clientCache:   make(map[int64]*http.Client),
		gatewaySem:    make(chan struct{}, maxConcurrent),
	}
	app.ctx, app.cancel = signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer app.cancel()
	if err := app.ensureAdmin(); err != nil {
		log.Fatal(err)
	}
	if previousSecret := os.Getenv("APP_ENCRYPTION_KEY_PREVIOUS"); previousSecret != "" {
		if len(previousSecret) < 32 {
			log.Fatal("APP_ENCRYPTION_KEY_PREVIOUS must contain at least 32 characters")
		}
		previousHash := sha256.Sum256([]byte(previousSecret))
		migrated, err := app.rotateEncryptionKey(previousHash[:])
		if err != nil {
			log.Fatalf("APP_ENCRYPTION_KEY migration failed: %v", err)
		}
		log.Printf("APP_ENCRYPTION_KEY migration completed; re-encrypted %d values", migrated)
	}
	if err := app.deleteExpiredAdminSessions(); err != nil {
		log.Fatal(err)
	}
	if err := app.ensureClientKey(); err != nil {
		log.Fatal(err)
	}
	app.deleteExpiredProxies()
	if err := app.deleteExpiredUsage(); err != nil {
		log.Fatal(err)
	}
	app.startBackground()
	mux := http.NewServeMux()
	app.routes(mux)
	server := &http.Server{Addr: ":" + port, Handler: app.withMiddleware(mux), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: upstreamRequestTimeout, WriteTimeout: 0, IdleTimeout: 120 * time.Second}
	log.Printf("opencode proxy pool listening on :%s", port)
	serverErr := make(chan error, 1)
	go func() { serverErr <- server.ListenAndServe() }()
	select {
	case err := <-serverErr:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Printf("server stopped unexpectedly: %v", err)
		}
	case <-app.ctx.Done():
		log.Print("shutdown signal received")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Printf("server shutdown failed: %v", err)
		}
		cancel()
	}
	app.stopBackground()
}

func (a *App) appContext() context.Context {
	if a.ctx != nil {
		return a.ctx
	}
	return context.Background()
}

func (a *App) runBackground(fn func()) {
	a.backgroundWG.Add(1)
	go func() {
		defer a.backgroundWG.Done()
		fn()
	}()
}

func (a *App) startBackground() {
	a.runBackground(a.expiredProxyJanitor)
	a.runBackground(a.healthCheckLoop)
	a.runBackground(a.unverifiedCheckLoop)
}

func (a *App) stopBackground() {
	if a.cancel != nil {
		a.cancel()
	}
	a.backgroundWG.Wait()
}

func getenv(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}

func envBool(key string, fallback bool) (bool, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("%s must be true or false", key)
	}
	return value, nil
}

func envInt(key string, fallback, min, max int) (int, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < min || value > max {
		return 0, fmt.Errorf("%s must be between %d and %d", key, min, max)
	}
	return value, nil
}

func looksLikePlaceholderSecret(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	for _, marker := range []string{"change-me", "change-this", "replace-with", "development-", "example"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func migrate(db *sql.DB) error {
	_, err := db.Exec(`PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS proxies (id INTEGER PRIMARY KEY AUTOINCREMENT, uri TEXT UNIQUE NOT NULL, scheme TEXT NOT NULL, host TEXT NOT NULL, port INTEGER NOT NULL, username TEXT, encrypted_password TEXT, enabled INTEGER NOT NULL DEFAULT 1, health_status TEXT NOT NULL DEFAULT 'unknown', failure_count INTEGER NOT NULL DEFAULT 0, cooldown_until TEXT, expires_at TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS models (id INTEGER PRIMARY KEY AUTOINCREMENT, model_id TEXT UNIQUE NOT NULL, display_name TEXT, is_free INTEGER NOT NULL, free_reason TEXT, pricing_metadata TEXT, raw_metadata TEXT, refreshed_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS usage_requests (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL, request_kind TEXT NOT NULL DEFAULT 'chat', model TEXT NOT NULL, proxy_id INTEGER, proxy_uri TEXT, status TEXT NOT NULL, status_code INTEGER NOT NULL DEFAULT 0, latency_ms INTEGER NOT NULL DEFAULT 0, first_token_latency_ms INTEGER, retry_count INTEGER NOT NULL DEFAULT 0, prompt_tokens INTEGER, completion_tokens INTEGER, total_tokens INTEGER, error_message TEXT, error_origin TEXT NOT NULL DEFAULT '', FOREIGN KEY(proxy_id) REFERENCES proxies(id));
CREATE TABLE IF NOT EXISTS session_proxy_routes (session_key TEXT PRIMARY KEY, proxy_id INTEGER NOT NULL, request_count INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, FOREIGN KEY(proxy_id) REFERENCES proxies(id));
CREATE INDEX IF NOT EXISTS idx_usage_created ON usage_requests(created_at); CREATE INDEX IF NOT EXISTS idx_usage_model ON usage_requests(model);`)
	if err != nil {
		return err
	}
	// Existing databases predate proxy expiry; SQLite reports a duplicate-column
	// error for upgraded databases, which is intentionally ignored here.
	for _, statement := range []string{
		"ALTER TABLE proxies ADD COLUMN expires_at TEXT",
		"ALTER TABLE proxies ADD COLUMN last_checked_at TEXT",
		"ALTER TABLE proxies ADD COLUMN last_check_ok INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE usage_requests ADD COLUMN proxy_uri TEXT",
		"ALTER TABLE usage_requests ADD COLUMN request_kind TEXT NOT NULL DEFAULT 'chat'",
		"ALTER TABLE usage_requests ADD COLUMN first_token_latency_ms INTEGER",
		"ALTER TABLE usage_requests ADD COLUMN error_origin TEXT NOT NULL DEFAULT ''",
	} {
		if _, alterErr := db.Exec(statement); alterErr != nil && !strings.Contains(strings.ToLower(alterErr.Error()), "duplicate column") {
			return alterErr
		}
	}
	for _, statement := range []string{
		"CREATE INDEX IF NOT EXISTS idx_proxies_expires_at ON proxies(expires_at)",
		"CREATE INDEX IF NOT EXISTS idx_session_proxy_routes_updated_at ON session_proxy_routes(updated_at)",
		"CREATE INDEX IF NOT EXISTS idx_usage_status ON usage_requests(status)",
		"CREATE INDEX IF NOT EXISTS idx_usage_error_origin ON usage_requests(error_origin)",
		"CREATE INDEX IF NOT EXISTS idx_usage_kind_created ON usage_requests(request_kind,created_at)",
	} {
		if _, indexErr := db.Exec(statement); indexErr != nil {
			return indexErr
		}
	}
	return backfillUsageErrorOrigins(db)
}

func backfillUsageErrorOrigins(db *sql.DB) error {
	rows, err := db.Query("SELECT id,COALESCE(request_kind,'chat'),status,status_code,COALESCE(error_message,'') FROM usage_requests WHERE COALESCE(error_origin,'')=''")
	if err != nil {
		return err
	}
	type usageOriginUpdate struct {
		id     int64
		origin string
	}
	updates := []usageOriginUpdate{}
	for rows.Next() {
		var id int64
		var kind, status, message string
		var code int
		if err := rows.Scan(&id, &kind, &status, &code, &message); err != nil {
			_ = rows.Close()
			return err
		}
		updates = append(updates, usageOriginUpdate{id: id, origin: usageErrorOrigin(kind, status, code, message)})
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if len(updates) == 0 {
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	statement, err := tx.Prepare("UPDATE usage_requests SET error_origin=? WHERE id=?")
	if err != nil {
		return err
	}
	defer statement.Close()
	for _, update := range updates {
		if _, err := statement.Exec(update.origin, update.id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (a *App) ensureAdmin() error {
	var hash string
	err := a.db.QueryRow("SELECT value FROM settings WHERE key='admin_hash'").Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		if err := validateAdminPassword(a.admin); err != nil {
			return fmt.Errorf("ADMIN_PASSWORD is required for first startup: %w", err)
		}
		if subtle.ConstantTimeCompare([]byte(a.admin), []byte("admin")) == 1 || looksLikePlaceholderSecret(a.admin) {
			return errors.New("ADMIN_PASSWORD must not use a default or placeholder value")
		}
		h, e := bcrypt.GenerateFromPassword([]byte(a.admin), bcrypt.DefaultCost)
		if e != nil {
			return e
		}
		_, e = a.db.Exec("INSERT INTO settings(key,value) VALUES('admin_hash',?)", string(h))
		return e
	}
	if err == nil && hash == "" {
		return errors.New("stored admin_hash is empty")
	}
	return err
}

func (a *App) ensureClientKey() error {
	var enc string
	err := a.db.QueryRow("SELECT value FROM settings WHERE key='client_key'").Scan(&enc)
	if errors.Is(err, sql.ErrNoRows) {
		key, e := randomKey()
		if e != nil {
			return e
		}
		_, e = a.db.Exec("INSERT INTO settings(key,value) VALUES('client_key',?)", hashToken(key))
		return e
	}
	return err
}

func randomKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	// Keep the client credential in the conservative token alphabet accepted by
	// clients that reject underscores in API keys.
	return "ocp-" + strings.ReplaceAll(base64.RawURLEncoding.EncodeToString(b), "_", "-"), nil
}
func hashToken(s string) string {
	h := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func validateAdminPassword(password string) error {
	length := len([]byte(password))
	if length < 8 {
		return errors.New("password must be at least 8 bytes")
	}
	if length > 72 {
		return errors.New("password must not exceed 72 bytes")
	}
	return nil
}

func (a *App) adminSessionKey(token string) string {
	mac := hmac.New(sha256.New, []byte(a.session))
	_, _ = mac.Write([]byte(token))
	return adminSessionPrefix + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (a *App) deleteExpiredAdminSessions() error {
	_, err := a.db.Exec(
		"DELETE FROM settings WHERE key GLOB 'session_ocp-*' OR (key GLOB 'admin_session_*' AND value <= ?)",
		time.Now().UTC().Format(time.RFC3339),
	)
	return err
}

func requestIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func (a *App) loginRetryAfter(ip string) time.Duration {
	const window = 15 * time.Minute
	now := time.Now()
	a.loginMu.Lock()
	defer a.loginMu.Unlock()
	if len(a.loginAttempts) > 1024 {
		for key, attempt := range a.loginAttempts {
			if now.Sub(attempt.WindowStart) > window && !attempt.BlockedUntil.After(now) {
				delete(a.loginAttempts, key)
			}
		}
	}
	attempt, ok := a.loginAttempts[ip]
	if !ok {
		return 0
	}
	if attempt.BlockedUntil.After(now) {
		return time.Until(attempt.BlockedUntil)
	}
	if now.Sub(attempt.WindowStart) > window {
		delete(a.loginAttempts, ip)
	}
	return 0
}

func (a *App) recordLoginFailure(ip string) {
	const (
		window      = 15 * time.Minute
		blockFor    = 15 * time.Minute
		maxFailures = 5
	)
	now := time.Now()
	a.loginMu.Lock()
	defer a.loginMu.Unlock()
	attempt := a.loginAttempts[ip]
	if attempt.WindowStart.IsZero() || now.Sub(attempt.WindowStart) > window {
		attempt = loginAttempt{WindowStart: now}
	}
	attempt.Failures++
	if attempt.Failures >= maxFailures {
		attempt.BlockedUntil = now.Add(blockFor)
	}
	a.loginAttempts[ip] = attempt
}

func (a *App) clearLoginFailures(ip string) {
	a.loginMu.Lock()
	delete(a.loginAttempts, ip)
	a.loginMu.Unlock()
}

func (a *App) setSessionCookie(w http.ResponseWriter, token string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     "ocp_session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   a.cookieSecure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   maxAge,
	})
}

func (a *App) routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := a.db.PingContext(ctx); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("POST /v1/chat/completions", a.gatewayChat)
	mux.HandleFunc("GET /v1/models", a.gatewayModels)
	mux.HandleFunc("POST /api/auth/login", a.login)
	mux.HandleFunc("POST /api/auth/logout", a.logout)
	mux.HandleFunc("GET /api/auth/me", a.requireAdmin(a.me))
	mux.HandleFunc("POST /api/auth/password", a.requireAdmin(a.changePassword))
	mux.HandleFunc("GET /api/settings/upstream", a.requireAdmin(a.getUpstream))
	mux.HandleFunc("PUT /api/settings/upstream", a.requireAdmin(a.putUpstream))
	mux.HandleFunc("PUT /api/settings/routing", a.requireAdmin(a.putRouting))
	mux.HandleFunc("GET /api/settings/usage-retention", a.requireAdmin(a.getUsageRetention))
	mux.HandleFunc("PUT /api/settings/usage-retention", a.requireAdmin(a.putUsageRetention))
	mux.HandleFunc("POST /api/settings/upstream/test", a.requireAdmin(a.testUpstream))
	mux.HandleFunc("GET /api/settings/mihomo", a.requireAdmin(a.getMihomo))
	mux.HandleFunc("PUT /api/settings/mihomo", a.requireAdmin(a.putMihomo))
	mux.HandleFunc("GET /api/settings/mihomo/nodes", a.requireAdmin(a.mihomoNodes))
	mux.HandleFunc("GET /api/settings/healthcheck", a.requireAdmin(a.getHealthCheck))
	mux.HandleFunc("PUT /api/settings/healthcheck", a.requireAdmin(a.putHealthCheck))
	mux.HandleFunc("POST /api/settings/healthcheck/run", a.requireAdmin(a.runHealthCheckNow))
	mux.HandleFunc("POST /api/settings/healthcheck/run-unverified", a.requireAdmin(a.runUnverifiedNow))
	mux.HandleFunc("GET /api/settings/client-key", a.requireAdmin(a.getClientKey))
	mux.HandleFunc("POST /api/settings/client-key/rotate", a.requireAdmin(a.rotateClientKey))
	mux.HandleFunc("POST /api/settings/models/refresh", a.requireAdmin(a.refreshModels))
	mux.HandleFunc("GET /api/models", a.requireAdmin(a.listModels))
	mux.HandleFunc("GET /api/models/free", a.requireAdmin(a.listFreeModels))
	mux.HandleFunc("GET /api/proxies", a.requireAdmin(a.listProxies))
	mux.HandleFunc("POST /api/proxies", a.requireAdmin(a.addProxy))
	mux.HandleFunc("POST /api/proxies/import", a.requireAdmin(a.importProxies))
	mux.HandleFunc("POST /api/proxies/bulk-delete", a.requireAdmin(a.bulkDeleteProxies))
	mux.HandleFunc("PATCH /api/proxies/{id}", a.requireAdmin(a.patchProxy))
	mux.HandleFunc("DELETE /api/proxies/{id}", a.requireAdmin(a.deleteProxy))
	mux.HandleFunc("POST /api/proxies/{id}/test", a.requireAdmin(a.testProxy))
	mux.HandleFunc("GET /api/stats/summary", a.requireAdmin(a.statsSummary))
	mux.HandleFunc("GET /api/stats/timeseries", a.requireAdmin(a.statsTimeseries))
	mux.HandleFunc("GET /api/stats/models", a.requireAdmin(a.statsModels))
	mux.HandleFunc("GET /api/usage/requests", a.requireAdmin(a.usageList))
	mux.HandleFunc("GET /api/usage/rates", a.requireAdmin(a.usageRates))
	webDir := getenv("WEB_DIR", "./web/dist")
	mux.HandleFunc("/", serveSPA(webDir))
}

func (a *App) withMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'; form-action 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; connect-src 'self'")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
		}
		if r.Method == "OPTIONS" {
			w.WriteHeader(204)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func serveSPA(dir string) http.HandlerFunc {
	fs := http.FileServer(http.Dir(dir))
	return func(w http.ResponseWriter, r *http.Request) {
		p := filepath.Join(dir, filepath.Clean(r.URL.Path))
		if r.URL.Path != "/" {
			if _, err := os.Stat(p); err == nil {
				fs.ServeHTTP(w, r)
				return
			}
		}
		http.ServeFile(w, r, filepath.Join(dir, "index.html"))
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func readJSON(r *http.Request, v any) error {
	body, err := readLimitedBody(r.Body, 2<<20)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain one JSON value")
	}
	return nil
}

func readLimitedBody(r io.Reader, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("request body exceeds %d bytes", limit)
	}
	return body, nil
}

func (a *App) login(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Password string `json:"password"`
	}
	if readJSON(r, &in) != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid request"})
		return
	}
	ip := requestIP(r)
	if retryAfter := a.loginRetryAfter(ip); retryAfter > 0 {
		seconds := int(retryAfter.Round(time.Second).Seconds())
		if seconds < 1 {
			seconds = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(seconds))
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many login attempts"})
		return
	}
	var hash string
	if err := a.db.QueryRow("SELECT value FROM settings WHERE key='admin_hash'").Scan(&hash); err != nil {
		writeJSON(w, 500, map[string]string{"error": "authentication service unavailable"})
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(in.Password)) != nil {
		a.recordLoginFailure(ip)
		writeJSON(w, 401, map[string]string{"error": "invalid password"})
		return
	}
	token, err := randomKey()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "could not create session"})
		return
	}
	if _, err = a.db.Exec(
		"INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)",
		a.adminSessionKey(token),
		time.Now().Add(12*time.Hour).UTC().Format(time.RFC3339),
	); err != nil {
		writeJSON(w, 500, map[string]string{"error": "could not create session"})
		return
	}
	a.clearLoginFailures(ip)
	a.setSessionCookie(w, token, 43200)
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	if !sameOriginMutation(r) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-site request rejected"})
		return
	}
	if cookie, err := r.Cookie("ocp_session"); err == nil && cookie.Value != "" {
		if _, err := a.db.Exec("DELETE FROM settings WHERE key=?", a.adminSessionKey(cookie.Value)); err != nil {
			writeJSON(w, 500, map[string]string{"error": "could not revoke session"})
			return
		}
	}
	a.setSessionCookie(w, "", -1)
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (a *App) requireAdmin(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !sameOriginMutation(r) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-site request rejected"})
			return
		}
		if !a.isAdmin(r) {
			writeJSON(w, 401, map[string]string{"error": "authentication required"})
			return
		}
		fn(w, r)
	}
}

func sameOriginMutation(r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")), "cross-site") {
		return false
	}
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	return err == nil && parsed.Host != "" && strings.EqualFold(parsed.Host, r.Host)
}
func (a *App) isAdmin(r *http.Request) bool {
	c, err := r.Cookie("ocp_session")
	if err != nil || c.Value == "" {
		return false
	}
	var exp string
	key := a.adminSessionKey(c.Value)
	if a.db.QueryRow("SELECT value FROM settings WHERE key=?", key).Scan(&exp) != nil {
		return false
	}
	t, e := time.Parse(time.RFC3339, exp)
	if e != nil || !t.After(time.Now()) {
		_, _ = a.db.Exec("DELETE FROM settings WHERE key=?", key)
		return false
	}
	return true
}
func (a *App) me(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"authenticated": true})
}
func (a *App) changePassword(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if readJSON(r, &in) != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid request"})
		return
	}
	if err := validateAdminPassword(in.New); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	var hash string
	if err := a.db.QueryRow("SELECT value FROM settings WHERE key='admin_hash'").Scan(&hash); err != nil {
		writeJSON(w, 500, map[string]string{"error": "could not verify current password"})
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(in.Current)) != nil {
		writeJSON(w, 400, map[string]string{"error": "current password is invalid"})
		return
	}
	h, err := bcrypt.GenerateFromPassword([]byte(in.New), bcrypt.DefaultCost)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "password could not be processed"})
		return
	}
	tx, err := a.db.Begin()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "could not update password"})
		return
	}
	if _, err = tx.Exec("UPDATE settings SET value=? WHERE key='admin_hash'", string(h)); err != nil {
		_ = tx.Rollback()
		writeJSON(w, 500, map[string]string{"error": "could not update password"})
		return
	}
	if _, err = tx.Exec("DELETE FROM settings WHERE key GLOB 'admin_session_*' OR key GLOB 'session_ocp-*'"); err != nil {
		_ = tx.Rollback()
		writeJSON(w, 500, map[string]string{"error": "could not revoke existing sessions"})
		return
	}
	if err = tx.Commit(); err != nil {
		writeJSON(w, 500, map[string]string{"error": "could not update password"})
		return
	}
	a.setSessionCookie(w, "", -1)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *App) getUpstream(w http.ResponseWriter, _ *http.Request) {
	cfg, err := a.loadUpstream()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	var models int
	if err := a.db.QueryRow("SELECT COUNT(*) FROM models WHERE is_free=1").Scan(&models); err != nil {
		writeJSON(w, 500, map[string]string{"error": "could not count models"})
		return
	}
	writeJSON(w, 200, map[string]any{"base_url": cfg.BaseURL, "has_api_key": cfg.APIKey != "", "vision_base_url": cfg.VisionBaseURL, "has_vision_api_key": cfg.VisionAPIKey != "", "vision_model": cfg.VisionModel, "vision_use_proxy": cfg.VisionUseProxy, "vision_configured": cfg.VisionBaseURL != "" && cfg.VisionModel != "", "custom_headers": cfg.CustomHeaders, "last_model_refresh_at": cfg.LastRefresh, "last_model_refresh_error": cfg.LastError, "free_model_count": models, "gateway_base_url": "/v1", "client_key_configured": a.clientKeyConfigured(), "session_proxy_request_limit": a.sessionProxyRequestLimit(), "quota_429_cooldown_minutes": a.quota429CooldownMinutes()})
}

func (a *App) putRouting(w http.ResponseWriter, r *http.Request) {
	var in struct {
		SessionProxyRequestLimit int `json:"session_proxy_request_limit"`
		Quota429CooldownMinutes  int `json:"quota_429_cooldown_minutes"`
	}
	if readJSON(r, &in) != nil || in.SessionProxyRequestLimit < 0 || in.SessionProxyRequestLimit > 100000 {
		writeJSON(w, 400, map[string]string{"error": "session_proxy_request_limit must be between 0 and 100000"})
		return
	}
	if in.Quota429CooldownMinutes < 0 || in.Quota429CooldownMinutes > 10080 {
		writeJSON(w, 400, map[string]string{"error": "quota_429_cooldown_minutes must be between 0 and 10080"})
		return
	}
	_, err := a.db.Exec("INSERT OR REPLACE INTO settings(key,value) VALUES('session_proxy_request_limit',?),('quota_429_cooldown_minutes',?)", strconv.Itoa(in.SessionProxyRequestLimit), strconv.Itoa(in.Quota429CooldownMinutes))
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "could not save routing configuration"})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "session_proxy_request_limit": in.SessionProxyRequestLimit, "quota_429_cooldown_minutes": in.Quota429CooldownMinutes})
}

func (a *App) quota429CooldownMinutes() int {
	const defaultMinutes = 1440
	var raw string
	if a.db.QueryRow("SELECT value FROM settings WHERE key='quota_429_cooldown_minutes'").Scan(&raw) != nil {
		return defaultMinutes
	}
	minutes, err := strconv.Atoi(raw)
	if err != nil || minutes < 0 || minutes > 10080 {
		return defaultMinutes
	}
	return minutes
}

func (a *App) markProxyQuotaCooldown(id int64, minutes int) {
	if minutes <= 0 {
		return
	}
	if _, err := a.db.Exec("UPDATE proxies SET health_status='cooldown',cooldown_until=?,updated_at=? WHERE id=?", time.Now().Add(time.Duration(minutes)*time.Minute).UTC().Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339), id); err != nil {
		log.Printf("mark proxy quota cooldown failed: %v", err)
		return
	}
	a.invalidateProxySnapshot()
}

func (a *App) markProxyCheckFailed(id int64) {
	max := a.healthcheckMaxFailures()
	if max <= 0 {
		a.markProxyQuotaCooldown(id, a.healthcheckIntervalMinutes())
		return
	}
	var count int
	if a.db.QueryRow("SELECT failure_count FROM proxies WHERE id=?", id).Scan(&count) != nil {
		a.markProxyQuotaCooldown(id, a.healthcheckIntervalMinutes())
		return
	}
	count++
	if count >= max {
		now := time.Now().UTC()
		if _, err := a.db.Exec("UPDATE proxies SET enabled=0,cooldown_until=NULL,updated_at=? WHERE id=?", now.Format(time.RFC3339), id); err != nil {
			log.Printf("disable proxy %d after %d consecutive health check failures failed: %v", id, count, err)
		} else {
			a.invalidateProxyCache()
			log.Printf("health check: proxy %d disabled after %d consecutive failures (max_failures=%d)", id, count, max)
		}
		return
	}
	now := time.Now().UTC()
	if _, err := a.db.Exec("UPDATE proxies SET health_status='cooldown',failure_count=?,cooldown_until=?,updated_at=? WHERE id=?", count, now.Add(time.Duration(a.healthcheckIntervalMinutes())*time.Minute).Format(time.RFC3339), now.Format(time.RFC3339), id); err != nil {
		log.Printf("mark proxy check failure failed: %v", err)
		return
	}
	a.invalidateProxySnapshot()
}

func (a *App) healthcheckIntervalMinutes() int {
	const defaultMinutes = 120
	var raw string
	if a.db.QueryRow("SELECT value FROM settings WHERE key='healthcheck_interval_minutes'").Scan(&raw) != nil {
		return defaultMinutes
	}
	minutes, err := strconv.Atoi(raw)
	if err != nil || minutes < 0 || minutes > 10080 {
		return defaultMinutes
	}
	return minutes
}

func (a *App) healthcheckTestURL() string {
	var raw string
	if a.db.QueryRow("SELECT value FROM settings WHERE key='healthcheck_test_url'").Scan(&raw) != nil {
		return ""
	}
	return strings.TrimSpace(raw)
}

func (a *App) healthcheckMaxFailures() int {
	const defaultMax = 3
	var raw string
	if a.db.QueryRow("SELECT value FROM settings WHERE key='healthcheck_max_failures'").Scan(&raw) != nil {
		return defaultMax
	}
	max, err := strconv.Atoi(raw)
	if err != nil || max < 0 || max > 100000 {
		return defaultMax
	}
	return max
}

func (a *App) getHealthCheck(w http.ResponseWriter, r *http.Request) {
	a.hcStateMu.Lock()
	running := a.hcRunning
	lastRun := a.hcLastRun
	duration := a.hcDuration
	passed := a.hcPassed
	failed := a.hcFailed
	a.hcStateMu.Unlock()
	healthy, cooldown, unknown := a.poolHealthCounts()
	var nextRun any
	if lastRun.IsZero() {
		nextRun = time.Now().UTC().Format(time.RFC3339)
	} else {
		interval := a.healthcheckIntervalMinutes()
		if interval > 0 {
			nextRun = lastRun.Add(time.Duration(interval) * time.Minute).UTC().Format(time.RFC3339)
		}
	}
	writeJSON(w, 200, map[string]any{
		"interval_minutes": a.healthcheckIntervalMinutes(),
		"test_url":         a.healthcheckTestURL(),
		"max_failures":     a.healthcheckMaxFailures(),
		"running":          running,
		"last_run_at":      formatTimeOrNull(lastRun),
		"last_duration_s":  int(duration.Seconds()),
		"last_passed":      passed,
		"last_failed":      failed,
		"next_run_at":      nextRun,
		"healthy_proxies":  healthy,
		"cooldown_proxies": cooldown,
		"unknown_proxies":  unknown,
		"total_proxies":    healthy + cooldown + unknown,
	})
}

func (a *App) poolHealthCounts() (healthy, cooldown, unknown int) {
	rows, err := a.db.Query("SELECT health_status, COUNT(*) FROM proxies WHERE enabled=1 GROUP BY health_status")
	if err != nil {
		return 0, 0, 0
	}
	defer rows.Close()
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			continue
		}
		switch status {
		case "healthy":
			healthy += count
		case "cooldown":
			cooldown += count
		default:
			unknown += count
		}
	}
	return healthy, cooldown, unknown
}

func (a *App) putHealthCheck(w http.ResponseWriter, r *http.Request) {
	var in struct {
		IntervalMinutes int    `json:"interval_minutes"`
		TestURL         string `json:"test_url"`
		MaxFailures     int    `json:"max_failures"`
	}
	if readJSON(r, &in) != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid body"})
		return
	}
	if in.IntervalMinutes < 0 || in.IntervalMinutes > 10080 {
		writeJSON(w, 400, map[string]string{"error": "interval_minutes must be between 0 and 10080"})
		return
	}
	if in.MaxFailures < 0 || in.MaxFailures > 100000 {
		writeJSON(w, 400, map[string]string{"error": "max_failures must be between 0 and 100000"})
		return
	}
	testURL := strings.TrimSpace(in.TestURL)
	if testURL != "" {
		parsed, e := url.Parse(testURL)
		if e != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			writeJSON(w, 400, map[string]string{"error": "test_url must use http or https"})
			return
		}
	}
	if _, err := a.db.Exec("INSERT OR REPLACE INTO settings(key,value) VALUES('healthcheck_interval_minutes',?),('healthcheck_test_url',?),('healthcheck_max_failures',?)", strconv.Itoa(in.IntervalMinutes), testURL, strconv.Itoa(in.MaxFailures)); err != nil {
		writeJSON(w, 500, map[string]string{"error": "could not save health check configuration"})
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *App) runHealthCheckNow(w http.ResponseWriter, r *http.Request) {
	if !a.hcMu.TryLock() {
		writeJSON(w, 409, map[string]string{"error": "health check is already running"})
		return
	}
	a.hcMu.Unlock()
	a.runBackground(a.runProxyHealthCheck)
	writeJSON(w, 200, map[string]bool{"started": true})
}

func (a *App) runUnverifiedNow(w http.ResponseWriter, r *http.Request) {
	if !a.hcMu.TryLock() {
		writeJSON(w, 409, map[string]string{"error": "health check is already running"})
		return
	}
	a.hcMu.Unlock()
	a.runBackground(a.runUnverifiedHealthCheck)
	writeJSON(w, 200, map[string]bool{"started": true})
}
func formatTimeOrNull(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC().Format(time.RFC3339)
}

func (a *App) healthCheckLoop() {
	for {
		interval := a.healthcheckIntervalMinutes()
		if interval > 0 {
			a.runProxyHealthCheck()
		}
		wait := time.Duration(interval) * time.Minute
		if wait <= 0 {
			wait = time.Minute
		}
		select {
		case <-a.appContext().Done():
			return
		case <-time.After(wait):
		}
	}
}

func (a *App) unverifiedCheckLoop() {
	a.runUnverifiedHealthCheck()
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-a.appContext().Done():
			return
		case <-ticker.C:
			a.runUnverifiedHealthCheck()
		}
	}
}

func (a *App) healthCheckTargets() (method, testURL string, payload []byte) {
	method, testURL, payload = "GET", a.healthcheckTestURL(), []byte(nil)
	if testURL == "" {
		cfg, _ := a.loadUpstream()
		if cfg.BaseURL != "" {
			var model string
			if a.db.QueryRow("SELECT model_id FROM models WHERE is_free=1 ORDER BY model_id LIMIT 1").Scan(&model) == nil && model != "" {
				method = "POST"
				testURL = upstreamEndpoint(cfg.BaseURL, "/chat/completions")
				payload, _ = json.Marshal(map[string]any{
					"model":      model,
					"messages":   []map[string]string{{"role": "user", "content": "ping"}},
					"max_tokens": 1,
					"stream":     false,
				})
			}
		}
		if testURL == "" {
			testURL = "https://www.gstatic.com/generate_204"
		}
	}
	return method, testURL, payload
}

const healthCheckConcurrency = 10

func (a *App) runChecks(proxies []ProxyRecord, method, testURL string, payload []byte) (passed, failed int) {
	if len(proxies) == 0 {
		return 0, 0
	}
	workers := healthCheckConcurrency
	if len(proxies) < workers {
		workers = len(proxies)
	}
	jobs := make(chan ProxyRecord)
	var workersWG sync.WaitGroup
	var mu sync.Mutex
	check := func(p ProxyRecord) {
		ok := a.healthCheckProxy(p, method, testURL, payload)
		mu.Lock()
		if ok {
			passed++
		} else {
			failed++
		}
		mu.Unlock()
		if ok {
			a.markProxySuccess(p.ID)
		} else {
			a.markProxyCheckFailed(p.ID)
		}
		a.recordProxyCheck(p.ID, ok)
	}
	workersWG.Add(workers)
	for range workers {
		go func() {
			defer workersWG.Done()
			for p := range jobs {
				check(p)
			}
		}()
	}
	for _, p := range proxies {
		jobs <- p
	}
	close(jobs)
	workersWG.Wait()
	return passed, failed
}

func (a *App) runProxyHealthCheck() {
	if !a.hcMu.TryLock() {
		return
	}
	defer a.hcMu.Unlock()
	a.hcStateMu.Lock()
	a.hcRunning = true
	a.hcStateMu.Unlock()
	start := time.Now()
	log.Printf("health check started")
	proxies, err := a.allEnabledProxies()
	if err != nil {
		log.Printf("health check: could not load proxies: %v", err)
		a.hcStateMu.Lock()
		a.hcRunning = false
		a.hcStateMu.Unlock()
		return
	}
	method, testURL, payload := a.healthCheckTargets()
	passed, failed := a.runChecks(proxies, method, testURL, payload)
	a.hcStateMu.Lock()
	a.hcRunning = false
	a.hcLastRun = time.Now()
	a.hcDuration = time.Since(start)
	a.hcPassed = passed
	a.hcFailed = failed
	a.hcStateMu.Unlock()
	log.Printf("health check finished: %d passed, %d failed in %s", passed, failed, a.hcDuration)
}

func (a *App) runUnverifiedHealthCheck() {
	if !a.hcMu.TryLock() {
		return
	}
	defer a.hcMu.Unlock()
	a.hcStateMu.Lock()
	a.hcRunning = true
	a.hcStateMu.Unlock()
	start := time.Now()
	log.Printf("unverified health check started")
	rows, err := a.db.Query("SELECT id,uri,scheme,host,port,COALESCE(username,''),COALESCE(encrypted_password,''),enabled,health_status,failure_count,COALESCE(cooldown_until,''),COALESCE(expires_at,''),COALESCE(last_checked_at,''),last_check_ok,created_at FROM proxies WHERE enabled=1 AND health_status='unknown' ORDER BY id")
	if err != nil {
		log.Printf("unverified health check: could not load proxies: %v", err)
		a.hcStateMu.Lock()
		a.hcRunning = false
		a.hcStateMu.Unlock()
		return
	}
	proxies, scanErr := scanProxies(rows)
	_ = rows.Close()
	if scanErr != nil {
		log.Printf("unverified health check: could not scan proxies: %v", scanErr)
		a.hcStateMu.Lock()
		a.hcRunning = false
		a.hcStateMu.Unlock()
		return
	}
	method, testURL, payload := a.healthCheckTargets()
	passed, failed := a.runChecks(proxies, method, testURL, payload)
	a.hcStateMu.Lock()
	a.hcRunning = false
	a.hcLastRun = time.Now()
	a.hcDuration = time.Since(start)
	a.hcPassed = passed
	a.hcFailed = failed
	a.hcStateMu.Unlock()
	log.Printf("unverified health check finished: %d checked, %d passed, %d failed in %s", len(proxies), passed, failed, a.hcDuration)
}

func (a *App) allEnabledProxies() ([]ProxyRecord, error) {
	rows, err := a.db.Query("SELECT id,uri,scheme,host,port,COALESCE(username,''),COALESCE(encrypted_password,''),enabled,health_status,failure_count,COALESCE(cooldown_until,''),COALESCE(expires_at,''),COALESCE(last_checked_at,''),last_check_ok,created_at FROM proxies WHERE enabled=1 ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ProxyRecord{}
	for rows.Next() {
		var p ProxyRecord
		var en, lastOK int
		var cool, expires, checked, created, encrypted string
		if err := rows.Scan(&p.ID, &p.URI, &p.Scheme, &p.Host, &p.Port, &p.Username, &encrypted, &en, &p.HealthStatus, &p.FailureCount, &cool, &expires, &checked, &lastOK, &created); err != nil {
			return nil, err
		}
		p.Password, err = a.decrypt(encrypted)
		if err != nil {
			return nil, fmt.Errorf("could not decrypt proxy %d credentials: %w", p.ID, err)
		}
		p.Enabled = en == 1
		p.LastCheckOK = lastOK == 1
		p.CreatedAt, _ = time.Parse(time.RFC3339, created)
		if checked != "" {
			t, _ := time.Parse(time.RFC3339, checked)
			p.LastCheckedAt = &t
		}
		if expires != "" {
			t, _ := time.Parse(time.RFC3339, expires)
			if t.After(time.Now().UTC()) {
				p.ExpiresAt = &t
			}
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (a *App) healthCheckProxy(p ProxyRecord, method, testURL string, payload []byte) bool {
	ctx, cancel := context.WithTimeout(a.appContext(), 15*time.Second)
	defer cancel()
	var req *http.Request
	var err error
	if payload != nil {
		req, err = http.NewRequestWithContext(ctx, method, testURL, bytes.NewReader(payload))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
		}
	} else {
		req, err = http.NewRequestWithContext(ctx, method, testURL, nil)
	}
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "relaydesk-healthcheck/1.0")
	resp, err := a.doProxyRequest(req, p)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

func (a *App) sessionProxyRequestLimit() int {
	const defaultLimit = 50
	var raw string
	if a.db.QueryRow("SELECT value FROM settings WHERE key='session_proxy_request_limit'").Scan(&raw) != nil {
		return defaultLimit
	}
	limit, err := strconv.Atoi(raw)
	if err != nil || limit < 0 || limit > 100000 {
		return defaultLimit
	}
	return limit
}

func (a *App) usageRetentionDays() int {
	var raw string
	if a.db.QueryRow("SELECT value FROM settings WHERE key=?", usageRetentionSettingKey).Scan(&raw) != nil {
		return defaultUsageRetentionDays
	}
	days, err := strconv.Atoi(raw)
	if err != nil {
		return defaultUsageRetentionDays
	}
	if _, ok := usageRetentionOptions[days]; !ok {
		return defaultUsageRetentionDays
	}
	return days
}

func usageRetentionCutoff(days int, now time.Time) string {
	return now.UTC().AddDate(0, 0, -days).Format(time.RFC3339)
}

func (a *App) deleteExpiredUsage() error {
	_, err := a.db.Exec(
		"DELETE FROM usage_requests WHERE created_at < ?",
		usageRetentionCutoff(a.usageRetentionDays(), time.Now()),
	)
	return err
}

func (a *App) getUsageRetention(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]int{"usage_retention_days": a.usageRetentionDays()})
}

func (a *App) putUsageRetention(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Days int `json:"usage_retention_days"`
	}
	if readJSON(r, &in) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	if _, ok := usageRetentionOptions[in.Days]; !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "usage_retention_days must be 7, 30, 90, or 180"})
		return
	}
	tx, err := a.db.Begin()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not save usage retention"})
		return
	}
	if _, err = tx.Exec("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)", usageRetentionSettingKey, strconv.Itoa(in.Days)); err == nil {
		_, err = tx.Exec("DELETE FROM usage_requests WHERE created_at < ?", usageRetentionCutoff(in.Days, time.Now()))
	}
	if err != nil {
		_ = tx.Rollback()
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not save usage retention"})
		return
	}
	if err = tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not save usage retention"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "usage_retention_days": in.Days})
}

func (a *App) clientKeyConfigured() bool {
	var hash string
	return a.db.QueryRow("SELECT value FROM settings WHERE key='client_key'").Scan(&hash) == nil && hash != ""
}

func (a *App) getClientKey(w http.ResponseWriter, _ *http.Request) {
	var plain string
	_ = a.db.QueryRow("SELECT value FROM settings WHERE key='client_key_plain'").Scan(&plain)
	plain = strings.TrimSpace(plain)
	if plain == "" {
		writeJSON(w, 200, map[string]any{"client_key": "", "configured": a.clientKeyConfigured()})
		return
	}
	writeJSON(w, 200, map[string]any{"client_key": plain, "configured": true})
}

func (a *App) rotateClientKey(w http.ResponseWriter, _ *http.Request) {
	key, err := randomKey()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "could not generate client key"})
		return
	}
	if _, err := a.db.Exec("INSERT OR REPLACE INTO settings(key,value) VALUES('client_key',?),('client_key_plain',?)", hashToken(key), key); err != nil {
		writeJSON(w, 500, map[string]string{"error": "could not rotate client key"})
		return
	}
	writeJSON(w, 200, map[string]any{"client_key": key, "warning": "copy this key now; it will not be shown again"})
}
func (a *App) putUpstream(w http.ResponseWriter, r *http.Request) {
	var in struct {
		BaseURL        string             `json:"base_url"`
		APIKey         string             `json:"api_key"`
		VisionBaseURL  string             `json:"vision_base_url"`
		VisionAPIKey   string             `json:"vision_api_key"`
		VisionModel    string             `json:"vision_model"`
		VisionUseProxy *bool              `json:"vision_use_proxy"`
		CustomHeaders  *map[string]string `json:"custom_headers"`
	}
	if readJSON(r, &in) != nil || in.BaseURL == "" {
		writeJSON(w, 400, map[string]string{"error": "base_url is required"})
		return
	}
	normalizedBaseURL, e := validateUpstreamBaseURL(in.BaseURL)
	if e != nil {
		writeJSON(w, 400, map[string]string{"error": e.Error()})
		return
	}
	old, _ := a.loadUpstream()
	in.APIKey = normalizeAPIKey(in.APIKey)
	in.VisionBaseURL = strings.TrimSpace(in.VisionBaseURL)
	if in.VisionBaseURL != "" {
		in.VisionBaseURL, e = validateUpstreamBaseURL(in.VisionBaseURL)
		if e != nil {
			writeJSON(w, 400, map[string]string{"error": "vision " + e.Error()})
			return
		}
	}
	in.VisionAPIKey = normalizeAPIKey(in.VisionAPIKey)
	if in.VisionAPIKey == "" {
		in.VisionAPIKey = old.VisionAPIKey
	}
	in.VisionModel = strings.TrimSpace(in.VisionModel)
	if in.VisionBaseURL == "" || in.VisionModel == "" {
		in.VisionBaseURL = ""
		in.VisionModel = ""
	}
	if in.APIKey == "" {
		in.APIKey = old.APIKey
	}
	visionUseProxy := old.VisionUseProxy
	if in.VisionUseProxy != nil {
		visionUseProxy = *in.VisionUseProxy
	}
	headers := old.CustomHeaders
	if in.CustomHeaders != nil {
		var headerErr error
		headers, headerErr = validateCustomHeaders(*in.CustomHeaders)
		if headerErr != nil {
			writeJSON(w, 400, map[string]string{"error": headerErr.Error()})
			return
		}
	}
	enc, e := a.encrypt(in.APIKey)
	if e != nil {
		writeJSON(w, 500, map[string]string{"error": "encryption failed"})
		return
	}
	headersJSON, e := json.Marshal(headers)
	if e != nil {
		writeJSON(w, 500, map[string]string{"error": "could not encode custom headers"})
		return
	}
	headersEnc, e := a.encrypt(string(headersJSON))
	if e != nil {
		writeJSON(w, 500, map[string]string{"error": "could not encrypt custom headers"})
		return
	}
	visionEnc, e := a.encrypt(in.VisionAPIKey)
	if e != nil {
		writeJSON(w, 500, map[string]string{"error": "vision encryption failed"})
		return
	}
	_, e = a.db.Exec("INSERT OR REPLACE INTO settings(key,value) VALUES('upstream_base_url',?),('upstream_api_key',?),('upstream_vision_base_url',?),('upstream_vision_api_key',?),('upstream_vision_model',?),('upstream_vision_use_proxy',?),('upstream_custom_headers',?)", normalizedBaseURL, enc, in.VisionBaseURL, visionEnc, in.VisionModel, strconv.FormatBool(visionUseProxy), headersEnc)
	if e != nil {
		writeJSON(w, 500, map[string]string{"error": e.Error()})
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (a *App) loadUpstream() (upstreamConfig, error) {
	cfg := upstreamConfig{CustomHeaders: defaultHeaders(), VisionUseProxy: true}
	var b, e string
	err := a.db.QueryRow("SELECT value FROM settings WHERE key='upstream_base_url'").Scan(&b)
	if errors.Is(err, sql.ErrNoRows) {
		return cfg, nil
	}
	if err != nil {
		return cfg, err
	}
	if keyErr := a.db.QueryRow("SELECT value FROM settings WHERE key='upstream_api_key'").Scan(&e); keyErr != nil && !errors.Is(keyErr, sql.ErrNoRows) {
		return cfg, keyErr
	}
	key, decryptErr := a.decrypt(e)
	if decryptErr != nil {
		return cfg, fmt.Errorf("could not decrypt upstream API key")
	}
	key = normalizeAPIKey(key)
	var encryptedHeaders string
	if err := a.db.QueryRow("SELECT value FROM settings WHERE key='upstream_custom_headers'").Scan(&encryptedHeaders); err == nil && encryptedHeaders != "" {
		plain, decryptErr := a.decrypt(encryptedHeaders)
		if decryptErr != nil {
			return cfg, fmt.Errorf("could not decrypt custom headers")
		}
		var headers map[string]string
		if json.Unmarshal([]byte(plain), &headers) != nil {
			return cfg, fmt.Errorf("stored custom headers are invalid")
		}
		validated, headerErr := validateCustomHeaders(headers)
		if headerErr != nil {
			return cfg, fmt.Errorf("stored custom headers are invalid")
		}
		cfg.CustomHeaders = validated
	}
	var visionBaseURL, visionModel, encryptedVisionKey string
	if visionErr := a.db.QueryRow("SELECT value FROM settings WHERE key='upstream_vision_base_url'").Scan(&visionBaseURL); visionErr != nil && !errors.Is(visionErr, sql.ErrNoRows) {
		return cfg, visionErr
	}
	if visionErr := a.db.QueryRow("SELECT value FROM settings WHERE key='upstream_vision_api_key'").Scan(&encryptedVisionKey); visionErr != nil && !errors.Is(visionErr, sql.ErrNoRows) {
		return cfg, visionErr
	}
	visionKey := ""
	if encryptedVisionKey != "" {
		visionKey, decryptErr = a.decrypt(encryptedVisionKey)
		if decryptErr != nil {
			return cfg, fmt.Errorf("could not decrypt vision API key")
		}
		visionKey = normalizeAPIKey(visionKey)
	}
	if visionErr := a.db.QueryRow("SELECT value FROM settings WHERE key='upstream_vision_model'").Scan(&visionModel); visionErr != nil && !errors.Is(visionErr, sql.ErrNoRows) {
		return cfg, visionErr
	}
	var visionUseProxyRaw string
	if visionErr := a.db.QueryRow("SELECT value FROM settings WHERE key='upstream_vision_use_proxy'").Scan(&visionUseProxyRaw); visionErr != nil && !errors.Is(visionErr, sql.ErrNoRows) {
		return cfg, visionErr
	}
	if visionUseProxyRaw != "" {
		if visionUseProxy, parseErr := strconv.ParseBool(visionUseProxyRaw); parseErr == nil {
			cfg.VisionUseProxy = visionUseProxy
		}
	}
	var lr, le string
	if refreshErr := a.db.QueryRow("SELECT value FROM settings WHERE key='last_model_refresh_at'").Scan(&lr); refreshErr != nil && !errors.Is(refreshErr, sql.ErrNoRows) {
		return cfg, refreshErr
	}
	if refreshErr := a.db.QueryRow("SELECT value FROM settings WHERE key='last_model_refresh_error'").Scan(&le); refreshErr != nil && !errors.Is(refreshErr, sql.ErrNoRows) {
		return cfg, refreshErr
	}
	var t *time.Time
	if parsed, x := time.Parse(time.RFC3339, lr); x == nil {
		t = &parsed
	}
	cfg.BaseURL = b
	cfg.APIKey = key
	cfg.VisionBaseURL = strings.TrimRight(strings.TrimSpace(visionBaseURL), "/")
	cfg.VisionAPIKey = visionKey
	cfg.VisionModel = strings.TrimSpace(visionModel)
	cfg.LastRefresh = t
	cfg.LastError = le
	return cfg, nil
}

func (a *App) getMihomo(w http.ResponseWriter, r *http.Request) {
	cfg, err := a.loadMihomo()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "could not load mihomo settings"})
		return
	}
	writeJSON(w, 200, map[string]any{
		"control_url": cfg.ControlURL,
		"has_secret":  cfg.Secret != "",
		"entry_proxy": cfg.EntryProxy,
		"selector":    cfg.Selector,
		"configured":  cfg.ControlURL != "" && cfg.EntryProxy != "",
	})
}

func (a *App) putMihomo(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ControlURL string `json:"control_url"`
		Secret     string `json:"secret"`
		EntryProxy string `json:"entry_proxy"`
		Selector   string `json:"selector"`
	}
	if readJSON(r, &in) != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid body"})
		return
	}
	old, _ := a.loadMihomo()
	controlURL := strings.TrimSpace(in.ControlURL)
	if controlURL != "" {
		parsed, e := url.Parse(controlURL)
		if e != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			writeJSON(w, 400, map[string]string{"error": "control_url must use http or https"})
			return
		}
		controlURL = strings.TrimRight(parsed.String(), "/")
	}
	secret := strings.TrimSpace(in.Secret)
	if secret == "" {
		secret = old.Secret
	}
	entryProxy := strings.TrimSpace(in.EntryProxy)
	if entryProxy != "" {
		parsed, e := url.Parse(entryProxy)
		if e != nil || parsed.Hostname() == "" {
			writeJSON(w, 400, map[string]string{"error": "invalid entry_proxy"})
			return
		}
		sch := strings.ToLower(parsed.Scheme)
		if sch != "http" && sch != "https" && sch != "socks5" && sch != "socks5h" {
			writeJSON(w, 400, map[string]string{"error": "entry_proxy must use http, https, socks5 or socks5h"})
			return
		}
	}
	selector := strings.TrimSpace(in.Selector)
	if selector == "" {
		selector = defaultMihomoSelector
	}
	enc, e := a.encrypt(secret)
	if e != nil {
		writeJSON(w, 500, map[string]string{"error": "encryption failed"})
		return
	}
	_, e = a.db.Exec("INSERT OR REPLACE INTO settings(key,value) VALUES('mihomo_control_url',?),('mihomo_secret',?),('mihomo_entry_proxy',?),('mihomo_selector',?)", controlURL, enc, entryProxy, selector)
	if e != nil {
		writeJSON(w, 500, map[string]string{"error": e.Error()})
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *App) loadMihomo() (mihomoConfig, error) {
	cfg := mihomoConfig{Selector: defaultMihomoSelector}
	var control, encryptedSecret, entry, selector string
	controlErr := a.db.QueryRow("SELECT value FROM settings WHERE key='mihomo_control_url'").Scan(&control)
	if controlErr != nil && !errors.Is(controlErr, sql.ErrNoRows) {
		return cfg, controlErr
	}
	secretErr := a.db.QueryRow("SELECT value FROM settings WHERE key='mihomo_secret'").Scan(&encryptedSecret)
	if secretErr != nil && !errors.Is(secretErr, sql.ErrNoRows) {
		return cfg, secretErr
	}
	if encryptedSecret != "" {
		secret, decryptErr := a.decrypt(encryptedSecret)
		if decryptErr != nil {
			return cfg, fmt.Errorf("could not decrypt mihomo secret")
		}
		cfg.Secret = secret
	}
	entryErr := a.db.QueryRow("SELECT value FROM settings WHERE key='mihomo_entry_proxy'").Scan(&entry)
	if entryErr != nil && !errors.Is(entryErr, sql.ErrNoRows) {
		return cfg, entryErr
	}
	selectorErr := a.db.QueryRow("SELECT value FROM settings WHERE key='mihomo_selector'").Scan(&selector)
	if selectorErr != nil && !errors.Is(selectorErr, sql.ErrNoRows) {
		return cfg, selectorErr
	}
	cfg.ControlURL = strings.TrimRight(strings.TrimSpace(control), "/")
	cfg.EntryProxy = strings.TrimSpace(entry)
	if strings.TrimSpace(selector) != "" {
		cfg.Selector = strings.TrimSpace(selector)
	}
	return cfg, nil
}

func (a *App) mihomoNodes(w http.ResponseWriter, r *http.Request) {
	cfg, err := a.loadMihomo()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "could not load mihomo settings"})
		return
	}
	if cfg.ControlURL == "" {
		writeJSON(w, 400, map[string]string{"error": "mihomo control_url is not configured"})
		return
	}
	req, e := http.NewRequest("GET", cfg.ControlURL+"/proxies", nil)
	if e != nil {
		writeJSON(w, 500, map[string]string{"error": e.Error()})
		return
	}
	if cfg.Secret != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.Secret)
	}
	resp, e := directHTTPClient(10 * time.Second).Do(req)
	if e != nil {
		writeJSON(w, 502, map[string]string{"error": "mihomo control unreachable: " + truncateError(e.Error())})
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		writeJSON(w, 502, map[string]string{"error": fmt.Sprintf("mihomo control returned HTTP %d", resp.StatusCode)})
		return
	}
	var data struct {
		Proxies map[string]struct {
			Type string `json:"type"`
		} `json:"proxies"`
	}
	if json.NewDecoder(resp.Body).Decode(&data) != nil {
		writeJSON(w, 502, map[string]string{"error": "could not parse mihomo response"})
		return
	}
	nodes := []string{}
	for name, info := range data.Proxies {
		if _, skip := skippedMihomoNames[name]; skip {
			continue
		}
		if _, skip := skippedMihomoGroups[normalizeMihomoType(info.Type)]; skip {
			continue
		}
		if hasMihomoInfoMarker(name) {
			continue
		}
		nodes = append(nodes, name)
	}
	sort.Strings(nodes)
	writeJSON(w, 200, map[string]any{"nodes": nodes, "selector": cfg.Selector})
}

func hasMihomoInfoMarker(name string) bool {
	for _, pattern := range skippedMihomoNamePatterns {
		if strings.Contains(name, pattern) {
			return true
		}
	}
	return false
}

// mihomoProxyInfo describes a single proxy or group as reported by mihomo.
type mihomoProxyInfo struct {
	Type string   `json:"type"`
	All  []string `json:"all"`
	Now  string   `json:"now"`
}

// putMihomoSelector sends a PUT to switch the named selector group to target.
func putMihomoSelector(cfg mihomoConfig, selector, target string) error {
	body, _ := json.Marshal(map[string]string{"name": target})
	req, err := http.NewRequest("PUT", cfg.ControlURL+"/proxies/"+url.PathEscape(selector), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if cfg.Secret != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.Secret)
	}
	resp, err := directHTTPClient(10 * time.Second).Do(req)
	if err != nil {
		return fmt.Errorf("mihomo switch %s failed: %w", selector, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("mihomo switch %s failed: HTTP %d", selector, resp.StatusCode)
	}
	return nil
}

// getMihomoProxy fetches a single proxy/group info from mihomo.
func getMihomoProxy(cfg mihomoConfig, name string) (mihomoProxyInfo, error) {
	req, err := http.NewRequest("GET", cfg.ControlURL+"/proxies/"+url.PathEscape(name), nil)
	if err != nil {
		return mihomoProxyInfo{}, err
	}
	if cfg.Secret != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.Secret)
	}
	resp, err := directHTTPClient(10 * time.Second).Do(req)
	if err != nil {
		return mihomoProxyInfo{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return mihomoProxyInfo{}, fmt.Errorf("mihomo get %s: HTTP %d", name, resp.StatusCode)
	}
	var info mihomoProxyInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return mihomoProxyInfo{}, fmt.Errorf("mihomo get %s: %w", name, err)
	}
	return info, nil
}

// switchMihomoNode routes traffic for the given node through the configured
// selector. When the selector is a flat group that contains the node directly
// it switches in one step. When the selector only references sub-groups (for
// example "Proxy" -> ["Auto","Japan",...]) it walks the sub-groups to find the
// one that contains the node, switches the selector to that sub-group, and —
// when the sub-group is itself a manual Selector — switches it to the node.
func switchMihomoNode(cfg mihomoConfig, nodeName string) error {
	if cfg.ControlURL == "" {
		return errors.New("mihomo control_url is not configured")
	}
	selector := cfg.Selector
	if selector == "" {
		selector = defaultMihomoSelector
	}

	// Fast path: try switching the selector directly to the node. This works
	// when the selector is a flat group listing every proxy.
	if err := putMihomoSelector(cfg, selector, nodeName); err == nil {
		return nil
	}

	// Slow path: the selector references sub-groups. Look up its members and
	// find the sub-group that contains the target node.
	selInfo, err := getMihomoProxy(cfg, selector)
	if err != nil {
		return fmt.Errorf("mihomo selector %s lookup failed: %w", selector, err)
	}
	for _, member := range selInfo.All {
		if member == nodeName {
			// The node itself is a direct member; the fast path should have
			// handled it, so this is a defensive no-op.
			return nil
		}
		memberInfo, err := getMihomoProxy(cfg, member)
		if err != nil {
			continue
		}
		if !containsString(memberInfo.All, nodeName) {
			continue
		}
		// Found the sub-group containing the node. Route the selector to it.
		if err := putMihomoSelector(cfg, selector, member); err != nil {
			return fmt.Errorf("mihomo switch %s -> %s failed: %w", selector, member, err)
		}
		// If the sub-group is a manual Selector, pin it to the target node so
		// url-test/auto groups do not override the choice. url-test groups
		// cannot be switched and already route to the lowest-latency member.
		if normalizeMihomoType(memberInfo.Type) == "selector" {
			if err := putMihomoSelector(cfg, member, nodeName); err != nil {
				return fmt.Errorf("mihomo switch %s -> %s failed: %w", member, nodeName, err)
			}
		}
		return nil
	}
	return fmt.Errorf("mihomo node %q not found in selector %s or its sub-groups", nodeName, selector)
}

func normalizeAPIKey(raw string) string {
	key := strings.TrimSpace(raw)
	if len(key) >= 2 && ((key[0] == '"' && key[len(key)-1] == '"') || (key[0] == '\'' && key[len(key)-1] == '\'')) {
		key = strings.TrimSpace(key[1 : len(key)-1])
	}
	if len(key) >= 7 && strings.EqualFold(key[:7], "bearer ") {
		key = strings.TrimSpace(key[7:])
	}
	return key
}

func validateUpstreamBaseURL(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" {
		return "", errors.New("invalid base_url")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", errors.New("base_url must use http or https")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("base_url must not contain credentials, query parameters, or a fragment")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	return strings.TrimRight(parsed.String(), "/"), nil
}

func defaultHeaders() map[string]string {
	headers := make(map[string]string, len(defaultUpstreamHeaders))
	for name, value := range defaultUpstreamHeaders {
		headers[name] = value
	}
	return headers
}

func validateCustomHeaders(headers map[string]string) (map[string]string, error) {
	if len(headers) > 32 {
		return nil, fmt.Errorf("too many custom headers (maximum 32)")
	}
	validated := make(map[string]string, len(headers))
	for rawName, rawValue := range headers {
		name := strings.TrimSpace(rawName)
		value := strings.TrimSpace(rawValue)
		if !validHeaderName(name) {
			return nil, fmt.Errorf("invalid header name %q", rawName)
		}
		if !validHeaderValue(value) {
			return nil, fmt.Errorf("header %q contains an invalid value", name)
		}
		if _, reserved := protectedUpstreamHeaders[strings.ToLower(name)]; reserved {
			return nil, fmt.Errorf("header %q is managed by the gateway", name)
		}
		canonical := http.CanonicalHeaderKey(name)
		if _, duplicate := validated[canonical]; duplicate {
			return nil, fmt.Errorf("duplicate header %q", name)
		}
		validated[canonical] = value
	}
	return validated, nil
}

func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			continue
		}
		if !strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c)) {
			return false
		}
	}
	return true
}

func validHeaderValue(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] < 0x20 || value[i] == 0x7f {
			return false
		}
	}
	return true
}

func applyCustomHeaders(req *http.Request, headers map[string]string) {
	for name, value := range headers {
		req.Header.Set(name, value)
	}
}

func (a *App) refreshModels(w http.ResponseWriter, r *http.Request) {
	cfg, e := a.loadUpstream()
	if e != nil || cfg.BaseURL == "" {
		writeJSON(w, 400, map[string]string{"error": "configure upstream first"})
		return
	}
	req, requestErr := http.NewRequestWithContext(r.Context(), "GET", upstreamEndpoint(cfg.BaseURL, "/models"), nil)
	if requestErr != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid upstream endpoint"})
		return
	}
	applyUpstreamHeaders(req, cfg)
	resp, e := directHTTPClient(90 * time.Second).Do(req)
	if e != nil {
		a.saveRefreshError(e.Error())
		writeJSON(w, 502, map[string]string{"error": e.Error()})
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		a.saveRefreshError(string(b))
		writeJSON(w, 502, map[string]string{"error": "upstream returned " + resp.Status})
		return
	}
	var payload struct {
		Data []map[string]any `json:"data"`
	}
	if e = json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&payload); e != nil {
		a.saveRefreshError(e.Error())
		writeJSON(w, 502, map[string]string{"error": "invalid models response"})
		return
	}
	now := time.Now().UTC()
	tx, e := a.db.Begin()
	if e != nil {
		writeJSON(w, 500, map[string]string{"error": e.Error()})
		return
	}
	if _, e = tx.Exec("DELETE FROM models"); e != nil {
		_ = tx.Rollback()
		writeJSON(w, 500, map[string]string{"error": "could not replace model cache"})
		return
	}
	free := 0
	for _, m := range payload.Data {
		id, _ := m["id"].(string)
		if id == "" {
			continue
		}
		raw, _ := json.Marshal(m)
		display := id
		if v, ok := m["name"].(string); ok && v != "" {
			display = v
		}
		pricing, _ := json.Marshal(m["pricing"])
		isFree, reason := classifyFree(id, m)
		if isFree {
			free++
		}
		if _, e = tx.Exec("INSERT INTO models(model_id,display_name,is_free,free_reason,pricing_metadata,raw_metadata,refreshed_at) VALUES(?,?,?,?,?,?,?)", id, display, boolInt(isFree), reason, string(pricing), string(raw), now.Format(time.RFC3339)); e != nil {
			_ = tx.Rollback()
			writeJSON(w, 500, map[string]string{"error": e.Error()})
			return
		}
	}
	if free == 0 {
		_ = tx.Rollback()
		a.saveRefreshError("no free models detected")
		writeJSON(w, 200, map[string]any{"ok": true, "free_model_count": 0, "warning": "no free models detected; previous cache was kept"})
		return
	}
	if e = tx.Commit(); e != nil {
		writeJSON(w, 500, map[string]string{"error": e.Error()})
		return
	}
	if _, e = a.db.Exec("INSERT OR REPLACE INTO settings(key,value) VALUES('last_model_refresh_at',?),('last_model_refresh_error','')", now.Format(time.RFC3339)); e != nil {
		writeJSON(w, 500, map[string]string{"error": "models were refreshed but refresh metadata could not be saved"})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "free_model_count": free})
}

func applyUpstreamHeaders(req *http.Request, cfg upstreamConfig) {
	applyCustomHeaders(req, cfg.CustomHeaders)
	if cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	}
}

func (a *App) testUpstream(w http.ResponseWriter, r *http.Request) {
	cfg, err := a.loadUpstream()
	if err != nil || cfg.BaseURL == "" {
		writeJSON(w, 400, map[string]string{"error": "configure upstream first"})
		return
	}
	var model string
	if err := a.db.QueryRow("SELECT model_id FROM models WHERE is_free=1 ORDER BY model_id LIMIT 1").Scan(&model); err != nil || model == "" {
		writeJSON(w, 400, map[string]string{"error": "refresh a free model first"})
		return
	}
	body, _ := json.Marshal(map[string]any{
		"model":      model,
		"messages":   []map[string]string{{"role": "user", "content": "ping"}},
		"max_tokens": 1,
		"stream":     false,
	})
	result := map[string]any{"model": model}
	result["direct"] = a.testUpstreamRequest(r.Context(), cfg, body, nil)
	proxies, proxyErr := a.availableProxies()
	if proxyErr != nil {
		writeJSON(w, 500, map[string]string{"error": "could not load proxies"})
		return
	}
	if len(proxies) > 0 {
		result["proxy"] = a.testUpstreamRequest(r.Context(), cfg, body, &proxies[0])
	} else {
		result["proxy"] = map[string]any{"status": "not_available", "message": "no healthy proxy available"}
	}
	writeJSON(w, 200, result)
}

func (a *App) testUpstreamRequest(ctx context.Context, cfg upstreamConfig, body []byte, p *ProxyRecord) map[string]any {
	var resp *http.Response
	var err error
	if p == nil {
		req, requestErr := http.NewRequestWithContext(ctx, "POST", upstreamEndpoint(cfg.BaseURL, "/chat/completions"), strings.NewReader(string(body)))
		if requestErr != nil {
			err = requestErr
		} else {
			applyUpstreamHeaders(req, cfg)
			req.Header.Set("Content-Type", "application/json")
			resp, err = directHTTPClient(90 * time.Second).Do(req)
		}
	} else {
		req, _ := http.NewRequestWithContext(ctx, "POST", "http://relaydesk.invalid", nil)
		resp, err = a.forward(req, body, cfg, *p)
	}
	result := map[string]any{}
	if p != nil {
		result["proxy_uri"] = p.URI
	}
	if err != nil {
		result["status"] = "network_error"
		result["message"] = truncateError(err.Error())
		return result
	}
	defer resp.Body.Close()
	captured, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	result["status_code"] = resp.StatusCode
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		result["status"] = "ok"
		return result
	}
	result["status"] = "rejected"
	if summary := upstreamErrorSummary(captured); summary != "" {
		result["message"] = summary
	}
	return result
}
func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
func classifyFree(id string, m map[string]any) (bool, string) {
	lowerID := strings.ToLower(id)
	suffix := strings.HasSuffix(lowerID, ":free") || strings.HasSuffix(lowerID, "-free")
	pricingZero := false
	if p, ok := m["pricing"].(map[string]any); ok {
		in := priceZero(p["prompt"])
		if !in {
			in = priceZero(p["input"])
		}
		out := priceZero(p["completion"])
		if !out {
			out = priceZero(p["output"])
		}
		pricingZero = in && out
	}
	if suffix && pricingZero {
		return true, "id_suffix_and_pricing_zero"
	}
	if suffix {
		return true, "id_suffix"
	}
	if pricingZero {
		return true, "pricing_zero"
	}
	return false, ""
}
func priceZero(v any) bool {
	switch x := v.(type) {
	case float64:
		return x == 0
	case int:
		return x == 0
	case string:
		s := strings.TrimSpace(strings.TrimPrefix(x, "$"))
		f, e := strconv.ParseFloat(s, 64)
		return e == nil && f == 0
	}
	return false
}
func (a *App) saveRefreshError(s string) {
	if _, err := a.db.Exec("INSERT OR REPLACE INTO settings(key,value) VALUES('last_model_refresh_error',?)", s); err != nil {
		log.Printf("save model refresh error failed: %v", err)
	}
}
func (a *App) listModels(w http.ResponseWriter, _ *http.Request) {
	rows, err := a.db.Query("SELECT id,model_id,display_name,is_free,free_reason,pricing_metadata,raw_metadata,refreshed_at FROM models ORDER BY model_id")
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "could not query models"})
		return
	}
	defer rows.Close()
	models, err := scanModels(rows)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "could not read models"})
		return
	}
	writeJSON(w, 200, models)
}
func (a *App) listFreeModels(w http.ResponseWriter, _ *http.Request) {
	rows, err := a.db.Query("SELECT id,model_id,display_name,is_free,free_reason,pricing_metadata,raw_metadata,refreshed_at FROM models WHERE is_free=1 ORDER BY model_id")
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "could not query models"})
		return
	}
	defer rows.Close()
	models, err := scanModels(rows)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "could not read models"})
		return
	}
	writeJSON(w, 200, models)
}
func scanModels(rows *sql.Rows) ([]ModelRecord, error) {
	out := []ModelRecord{}
	for rows.Next() {
		var x ModelRecord
		var free int
		var p, raw, ts string
		if err := rows.Scan(&x.ID, &x.ModelID, &x.DisplayName, &free, &x.FreeReason, &p, &raw, &ts); err != nil {
			return nil, err
		}
		x.IsFree = free == 1
		x.Pricing = json.RawMessage(p)
		x.Raw = json.RawMessage(raw)
		x.RefreshedAt, _ = time.Parse(time.RFC3339, ts)
		out = append(out, x)
	}
	return out, rows.Err()
}

func (a *App) gatewayModels(w http.ResponseWriter, r *http.Request) {
	if !a.validClient(r) {
		writeJSON(w, 401, map[string]string{"error": "invalid client key"})
		return
	}
	rows, err := a.db.Query("SELECT model_id,display_name,raw_metadata FROM models WHERE is_free=1 ORDER BY model_id")
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "could not query models"})
		return
	}
	defer rows.Close()
	data := []map[string]any{}
	for rows.Next() {
		var id, name, raw string
		if err := rows.Scan(&id, &name, &raw); err != nil {
			writeJSON(w, 500, map[string]string{"error": "could not read models"})
			return
		}
		item := map[string]any{"id": id, "object": "model", "owned_by": "opencode-proxy", "name": name}
		var metadata map[string]any
		if json.Unmarshal([]byte(raw), &metadata) == nil {
			for _, field := range []string{"architecture", "input_modalities", "output_modalities", "supported_parameters"} {
				if value, ok := metadata[field]; ok {
					item[field] = value
				}
			}
		}
		data = append(data, item)
	}
	if err := rows.Err(); err != nil {
		writeJSON(w, 500, map[string]string{"error": "could not read models"})
		return
	}
	writeJSON(w, 200, map[string]any{"object": "list", "data": data})
}

func upstreamEndpoint(base, endpoint string) string {
	parsed, err := url.Parse(strings.TrimRight(base, "/"))
	if err != nil {
		return ""
	}
	path := strings.TrimRight(parsed.Path, "/")
	if !strings.HasSuffix(path, "/v1") {
		path += "/v1"
	}
	parsed.Path = path + "/" + strings.TrimLeft(endpoint, "/")
	return parsed.String()
}
func clientCredential(r *http.Request) string {
	supplied := ""
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		supplied = auth[7:]
	}
	if supplied == "" {
		// OpenAI-compatible clients are not fully consistent: some use
		// x-api-key/api-key instead of Authorization Bearer.
		for _, name := range []string{"X-API-Key", "API-Key"} {
			if value := r.Header.Get(name); value != "" {
				supplied = value
				break
			}
		}
	}
	supplied = strings.TrimSpace(supplied)
	if len(supplied) >= 2 && ((supplied[0] == '"' && supplied[len(supplied)-1] == '"') || (supplied[0] == '\'' && supplied[len(supplied)-1] == '\'')) {
		supplied = strings.TrimSpace(supplied[1 : len(supplied)-1])
	}
	return supplied
}

func (a *App) validClient(r *http.Request) bool {
	supplied := clientCredential(r)
	var h string
	if a.db.QueryRow("SELECT value FROM settings WHERE key='client_key'").Scan(&h) != nil {
		return false
	}
	if supplied == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(hashToken(supplied)), []byte(h)) == 1
}

func sessionKey(r *http.Request, user json.RawMessage) string {
	sessionID := ""
	for _, header := range []string{"X-Relay-Session-ID", "X-OpenCode-Session-ID", "X-Session-ID"} {
		if value := strings.TrimSpace(r.Header.Get(header)); value != "" {
			sessionID = value
			break
		}
	}
	if sessionID == "" && len(user) > 0 {
		_ = json.Unmarshal(user, &sessionID)
		sessionID = strings.TrimSpace(sessionID)
	}
	if sessionID == "" {
		sessionID = "__global__"
	}
	clientID := hashToken(clientCredential(r))
	return hashToken(clientID + "\x00" + sessionID)
}

func (a *App) gatewayChat(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	if !a.validClient(r) {
		writeJSON(w, 401, map[string]string{"error": "invalid client key"})
		return
	}
	select {
	case a.gatewaySem <- struct{}{}:
		defer func() { <-a.gatewaySem }()
	default:
		w.Header().Set("Retry-After", "1")
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "gateway is at capacity"})
		return
	}
	body, err := readLimitedBody(r.Body, 16<<20)
	if err != nil {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "invalid or oversized body"})
		return
	}
	var parsed struct {
		Model string          `json:"model"`
		User  json.RawMessage `json:"user"`
	}
	if json.Unmarshal(body, &parsed) != nil || parsed.Model == "" {
		writeJSON(w, 400, map[string]string{"error": "model is required"})
		return
	}
	var exists int
	if err := a.db.QueryRow("SELECT COUNT(*) FROM models WHERE model_id=? AND is_free=1", parsed.Model).Scan(&exists); err != nil {
		writeJSON(w, 500, map[string]string{"error": "could not validate model"})
		return
	}
	if exists == 0 {
		writeJSON(w, 400, map[string]string{"error": "model is not an available free model"})
		return
	}
	cfg, _ := a.loadUpstream()
	if cfg.BaseURL == "" {
		writeJSON(w, 503, map[string]string{"error": "upstream is not configured"})
		return
	}
	hasImage := requestHasImageInput(body)
	visionEnabled := hasImage && cfg.VisionBaseURL != "" && cfg.VisionModel != ""
	if hasImage && !visionEnabled {
		if known, supportsImage := a.cachedModelSupportsImage(parsed.Model); known && !supportsImage {
			message := fmt.Sprintf("model %q only supports text input; choose a Free model with image support or remove image_url", parsed.Model)
			a.recordUsage(parsed.Model, nil, "", "error", http.StatusBadRequest, time.Since(start), nil, 0, nil, errors.New(message))
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": message,
				"code":  "unsupported_input_modality",
			})
			return
		}
	}
	proxies, err := a.availableProxies()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "could not load proxies"})
		return
	}
	if len(proxies) == 0 {
		writeJSON(w, 503, map[string]string{"error": "no healthy proxies available"})
		return
	}
	requestSessionKey := sessionKey(r, parsed.User)
	attempts := len(proxies)
	if attempts > 8 {
		attempts = 8
	}
	var lastErr error
	used := map[int64]struct{}{}
	for i := 0; i < attempts; i++ {
		p, ok, pickErr := a.pickSessionProxy(requestSessionKey, proxies, used)
		if pickErr != nil {
			lastErr = pickErr
			break
		}
		if !ok {
			break
		}
		used[p.ID] = struct{}{}
		bodyToForward := body
		if visionEnabled {
			helperStarted := time.Now()
			helperProxy := p
			var helperProxyID *int64 = &p.ID
			helperProxyURI := p.URI
			if !cfg.VisionUseProxy {
				helperProxy = ProxyRecord{}
				helperProxyID = nil
				helperProxyURI = ""
			}
			helpBody, buildErr := buildVisionRequest(body, cfg.VisionModel)
			if buildErr != nil {
				lastErr = buildErr
				a.recordUsageKind("vision_helper", cfg.VisionModel, helperProxyID, helperProxyURI, "error", 0, time.Since(helperStarted), nil, i, nil, buildErr)
				break
			}
			visionCfg := upstreamConfig{BaseURL: cfg.VisionBaseURL, APIKey: cfg.VisionAPIKey}
			helperCtx, helperCancel := visionRequestContext(r)
			helperRequest := r.Clone(helperCtx)
			helpResp, helpErr := a.forward(helperRequest, helpBody, visionCfg, helperProxy)
			if helpErr != nil {
				helperCancel()
				lastErr = fmt.Errorf("vision helper request failed: %w", helpErr)
				a.recordUsageKind("vision_helper", cfg.VisionModel, helperProxyID, helperProxyURI, "error", 0, time.Since(helperStarted), nil, i, nil, lastErr)
				if cfg.VisionUseProxy {
					a.markProxyFailure(p.ID)
					a.clearSessionProxy(requestSessionKey, p.ID)
					continue
				}
				break
			}
			var helpFirstToken *time.Duration
			helpReader := io.Reader(io.LimitReader(helpResp.Body, 4<<20))
			if helpResp.StatusCode < 300 {
				helpReader = &firstByteReader{reader: helpReader, onFirstByte: func() {
					latency := time.Since(helperStarted)
					helpFirstToken = &latency
				}}
			}
			helpCaptured, readErr := io.ReadAll(helpReader)
			helpTokens := parseUsageBytes(helpCaptured)
			helpStatus := helpResp.StatusCode
			_ = helpResp.Body.Close()
			helperCancel()
			if readErr != nil {
				lastErr = fmt.Errorf("vision helper response failed: %w", readErr)
				a.recordUsageKind("vision_helper", cfg.VisionModel, helperProxyID, helperProxyURI, "error", helpStatus, time.Since(helperStarted), nil, i, helpTokens, lastErr)
				if cfg.VisionUseProxy {
					continue
				}
				break
			}
			if helpStatus >= 300 {
				detail := upstreamErrorSummary(helpCaptured)
				if detail == "" {
					detail = fmt.Sprintf("upstream returned HTTP %d", helpStatus)
				}
				lastErr = fmt.Errorf("vision helper failed: %s", detail)
				a.recordUsageKind("vision_helper", cfg.VisionModel, helperProxyID, helperProxyURI, "error", helpStatus, time.Since(helperStarted), nil, i, helpTokens, lastErr)
				if cfg.VisionUseProxy && helpStatus == http.StatusTooManyRequests && i+1 < attempts {
					a.markProxyQuotaCooldown(p.ID, a.quota429CooldownMinutes())
					a.clearSessionProxy(requestSessionKey, p.ID)
					continue
				}
				break
			}
			description, extractErr := extractVisionDescription(helpCaptured)
			if extractErr != nil {
				lastErr = extractErr
				a.recordUsageKind("vision_helper", cfg.VisionModel, helperProxyID, helperProxyURI, "error", helpStatus, time.Since(helperStarted), nil, i, helpTokens, lastErr)
				break
			}
			bodyToForward, buildErr = replaceImageContent(body, description)
			if buildErr != nil {
				lastErr = buildErr
				a.recordUsageKind("vision_helper", cfg.VisionModel, helperProxyID, helperProxyURI, "error", helpStatus, time.Since(helperStarted), nil, i, helpTokens, lastErr)
				break
			}
			a.recordUsageKind("vision_helper", cfg.VisionModel, helperProxyID, helperProxyURI, "success", helpStatus, time.Since(helperStarted), helpFirstToken, i, helpTokens, nil)
		}
		resp, e := a.forward(r, bodyToForward, cfg, p)
		if e != nil {
			lastErr = e
			a.markProxyFailure(p.ID)
			a.clearSessionProxy(requestSessionKey, p.ID)
			continue
		}
		a.markProxySuccess(p.ID)
		if resp.StatusCode == http.StatusTooManyRequests {
			a.markProxyQuotaCooldown(p.ID, a.quota429CooldownMinutes())
			a.clearSessionProxy(requestSessionKey, p.ID)
		}
		if resp.StatusCode == http.StatusTooManyRequests && i+1 < attempts {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			_ = resp.Body.Close()
			continue
		}
		tokens, upstreamError, firstTokenLatency, copyErr := a.copyResponse(w, resp, start)
		pid := p.ID
		status := "success"
		if resp.StatusCode >= 400 || copyErr != nil {
			status = "error"
			firstTokenLatency = nil
		}
		var requestError error
		if upstreamError != "" {
			requestError = errors.New(upstreamError)
		}
		if copyErr != nil {
			requestError = errors.Join(requestError, copyErr)
		}
		a.recordUsage(parsed.Model, &pid, p.URI, status, resp.StatusCode, time.Since(start), firstTokenLatency, i, tokens, requestError)
		return
	}
	a.recordUsage(parsed.Model, nil, "", "error", 502, time.Since(start), nil, attempts, nil, lastErr)
	writeJSON(w, 502, map[string]string{"error": "all proxies failed", "detail": lastErrString(lastErr)})
}
func lastErrString(e error) string {
	if e == nil {
		return ""
	}
	return e.Error()
}
func (a *App) forward(r *http.Request, body []byte, cfg upstreamConfig, p ProxyRecord) (*http.Response, error) {
	req, err := http.NewRequestWithContext(r.Context(), "POST", upstreamEndpoint(cfg.BaseURL, "/chat/completions"), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	applyUpstreamHeaders(req, cfg)
	req.Header.Set("Content-Type", "application/json")
	return a.doProxyRequest(req, p)
}

func (a *App) doProxyRequest(req *http.Request, p ProxyRecord) (*http.Response, error) {
	if p.Scheme == "mihomo" {
		// Mihomo has one mutable selector; keep switching and dialing atomic.
		a.mihomoMu.Lock()
		defer a.mihomoMu.Unlock()
	}
	client, err := a.httpClient(p)
	if err != nil {
		return nil, err
	}
	return client.Do(req)
}

func visionRequestContext(r *http.Request) (context.Context, context.CancelFunc) {
	// The client can cancel a streamed chat request while the helper is still
	// reading an image. Keep the helper alive briefly, with its own hard limit.
	return context.WithTimeout(context.WithoutCancel(r.Context()), upstreamRequestTimeout)
}

func buildVisionRequest(body []byte, visionModel string) ([]byte, error) {
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("could not prepare image request: %w", err)
	}
	messages, ok := payload["messages"].([]any)
	if !ok || len(messages) == 0 {
		return nil, errors.New("image input requires chat messages")
	}
	helperMessages := make([]any, 0, len(messages)+1)
	helperMessages = append(helperMessages, map[string]any{
		"role":    "system",
		"content": "Describe every image in the conversation in concise, factual text. Include visible text, objects, layout, and relevant details. Return only the description so another text-only model can use it.",
	})
	helperMessages = append(helperMessages, messages...)
	helperPayload := map[string]any{
		"model":      visionModel,
		"messages":   helperMessages,
		"max_tokens": 768,
		"stream":     false,
	}
	return json.Marshal(helperPayload)
}

func extractVisionDescription(body []byte) (string, error) {
	var payload struct {
		Choices []struct {
			Message struct {
				Content          json.RawMessage `json:"content"`
				ReasoningContent json.RawMessage `json:"reasoning_content"`
			} `json:"message"`
			Text json.RawMessage `json:"text"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", errors.New("vision helper returned invalid JSON")
	}
	if len(payload.Choices) == 0 {
		return "", errors.New("vision helper returned no choices")
	}
	choice := payload.Choices[0]
	description := extractTextContent(choice.Message.Content)
	if strings.TrimSpace(description) == "" {
		description = extractTextContent(choice.Message.ReasoningContent)
	}
	if strings.TrimSpace(description) == "" {
		description = extractTextContent(choice.Text)
	}
	if strings.TrimSpace(description) == "" {
		return "", errors.New("vision helper returned an empty description")
	}
	return strings.TrimSpace(description), nil
}

func extractTextContent(raw json.RawMessage) string {
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return text
	}
	var parts []map[string]any
	if json.Unmarshal(raw, &parts) != nil {
		return ""
	}
	texts := make([]string, 0, len(parts))
	for _, part := range parts {
		if value, ok := part["text"].(string); ok && strings.TrimSpace(value) != "" {
			texts = append(texts, value)
		}
	}
	return strings.Join(texts, "\n")
}

func replaceImageContent(body []byte, description string) ([]byte, error) {
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("could not rewrite image content: %w", err)
	}
	messages, ok := payload["messages"].([]any)
	if !ok {
		return nil, errors.New("image input requires chat messages")
	}
	replaced := false
	for _, rawMessage := range messages {
		message, ok := rawMessage.(map[string]any)
		if !ok {
			continue
		}
		content, ok := message["content"]
		if !ok {
			continue
		}
		rewritten, found := replaceImageContentValue(content, description)
		if !found {
			continue
		}
		message["content"] = rewritten
		replaced = true
	}
	if !replaced {
		return nil, errors.New("could not locate image content in chat messages")
	}
	return json.Marshal(payload)
}

func replaceImageContentValue(content any, description string) (any, bool) {
	if isImageContentPart(content) {
		return imageDescriptionContent(description), true
	}
	parts, ok := content.([]any)
	if !ok {
		return content, false
	}
	rewritten := make([]any, 0, len(parts))
	replaced := false
	for _, part := range parts {
		if isImageContentPart(part) {
			rewritten = append(rewritten, imageDescriptionContent(description))
			replaced = true
			continue
		}
		rewritten = append(rewritten, part)
	}
	return rewritten, replaced
}

func imageDescriptionContent(description string) map[string]any {
	return map[string]any{"type": "text", "text": "[\u56fe\u7247\u5185\u5bb9]\n" + description}
}

func addTokenUsage(first, second *tokenUsage) *tokenUsage {
	if first == nil {
		return second
	}
	if second == nil {
		return first
	}
	return &tokenUsage{
		Prompt:     addTokenValue(first.Prompt, second.Prompt),
		Completion: addTokenValue(first.Completion, second.Completion),
		Total:      addTokenValue(first.Total, second.Total),
	}
}

func addTokenValue(first, second *int64) *int64 {
	if first == nil || second == nil {
		return nil
	}
	total := *first + *second
	return &total
}

func (a *App) httpClient(p ProxyRecord) (*http.Client, error) {
	if p.Scheme == "mihomo" {
		return a.mihomoClient(p)
	}
	if p.ID > 0 {
		a.proxyCacheMu.Lock()
		client := a.clientCache[p.ID]
		a.proxyCacheMu.Unlock()
		if client != nil {
			return client, nil
		}
	}
	proxyURL, err := proxyURLForRecord(p)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Transport: newSplitTransport(proxyURL)}
	if p.ID > 0 {
		a.proxyCacheMu.Lock()
		if a.clientCache == nil {
			a.clientCache = make(map[int64]*http.Client)
		}
		if cached := a.clientCache[p.ID]; cached != nil {
			a.proxyCacheMu.Unlock()
			client.Transport.(interface{ CloseIdleConnections() }).CloseIdleConnections()
			return cached, nil
		}
		a.clientCache[p.ID] = client
		a.proxyCacheMu.Unlock()
	}
	return client, nil
}

func baseTransport() *http.Transport {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	// Direct requests must not inherit HTTP_PROXY/HTTPS_PROXY from the host.
	tr.Proxy = nil
	tr.DialContext = (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	tr.ResponseHeaderTimeout = upstreamRequestTimeout
	return tr
}

func directHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{Transport: newSplitTransport(nil), Timeout: timeout}
}

func proxyURLForRecord(p ProxyRecord) (*url.URL, error) {
	if strings.TrimSpace(p.URI) == "" {
		return nil, nil
	}
	u, err := url.Parse(p.URI)
	if err != nil {
		return nil, err
	}
	if p.Username != "" {
		u.User = url.UserPassword(p.Username, p.Password)
	}
	return u, nil
}

func configureProxyTransport(tr *http.Transport, proxyURI, username, password string) error {
	u, err := url.Parse(proxyURI)
	if err != nil {
		return err
	}
	if u.Scheme == "socks5" || u.Scheme == "socks5h" {
		var auth *proxy.Auth
		if username != "" {
			auth = &proxy.Auth{User: username, Password: password}
		}
		d, err := proxy.SOCKS5("tcp", u.Host, auth, proxy.Direct)
		if err != nil {
			return err
		}
		tr.Proxy = nil
		tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			if contextDialer, ok := d.(proxy.ContextDialer); ok {
				return contextDialer.DialContext(ctx, network, address)
			}
			return d.Dial(network, address)
		}
		return nil
	}
	if username != "" {
		u.User = url.UserPassword(username, password)
	}
	tr.Proxy = http.ProxyURL(u)
	return nil
}

func (a *App) mihomoClient(p ProxyRecord) (*http.Client, error) {
	cfg, err := a.loadMihomo()
	if err != nil {
		return nil, err
	}
	if cfg.EntryProxy == "" {
		return nil, errors.New("mihomo entry proxy is not configured")
	}
	if err := switchMihomoNode(cfg, p.Host); err != nil {
		return nil, err
	}
	entryProxy, err := url.Parse(cfg.EntryProxy)
	if err != nil {
		return nil, err
	}
	return &http.Client{Transport: newSplitTransport(entryProxy)}, nil
}
func (a *App) copyResponse(w http.ResponseWriter, resp *http.Response, startedAt time.Time) (*tokenUsage, string, *time.Duration, error) {
	defer resp.Body.Close()
	blocked := make(map[string]struct{}, len(blockedDownstreamHeaders)+4)
	for name := range blockedDownstreamHeaders {
		blocked[name] = struct{}{}
	}
	for _, value := range resp.Header.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			if name = strings.ToLower(strings.TrimSpace(name)); name != "" {
				blocked[name] = struct{}{}
			}
		}
	}
	for k, v := range resp.Header {
		if _, skip := blocked[strings.ToLower(k)]; skip {
			continue
		}
		for _, x := range v {
			w.Header().Add(k, x)
		}
	}
	w.WriteHeader(resp.StatusCode)
	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	captured := &limitedCapture{limit: 2 << 20}
	var firstTokenLatency *time.Duration
	markFirstToken := func() {
		if firstTokenLatency != nil || resp.StatusCode >= 400 {
			return
		}
		latency := time.Since(startedAt)
		firstTokenLatency = &latency
	}
	var copyErr error
	if strings.Contains(contentType, "text/event-stream") {
		buf := make([]byte, 32*1024)
		flusher, _ := w.(http.Flusher)
		detector := &sseContentDetector{}
		for {
			n, err := resp.Body.Read(buf)
			if n > 0 {
				_, _ = captured.Write(buf[:n])
				if detector.Observe(buf[:n]) {
					markFirstToken()
				}
				if _, writeErr := w.Write(buf[:n]); writeErr != nil {
					copyErr = writeErr
					break
				}
				if flusher != nil {
					flusher.Flush()
				}
			}
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				copyErr = err
				break
			}
		}
		if detector.Flush() {
			markFirstToken()
		}
	} else {
		reader := io.Reader(resp.Body)
		if resp.StatusCode < 400 {
			reader = &firstByteReader{reader: reader, onFirstByte: markFirstToken}
		}
		_, copyErr = io.Copy(io.MultiWriter(w, captured), reader)
	}
	var summary string
	if resp.StatusCode >= 400 {
		summary = upstreamErrorSummary(captured.Bytes())
	}
	return parseUsageBytes(captured.Bytes()), summary, firstTokenLatency, copyErr
}

type firstByteReader struct {
	reader      io.Reader
	onFirstByte func()
	seen        bool
}

func (r *firstByteReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n > 0 && !r.seen {
		r.seen = true
		r.onFirstByte()
	}
	return n, err
}

type sseContentDetector struct {
	buffer []byte
	found  bool
}

func (d *sseContentDetector) Observe(chunk []byte) bool {
	if d.found {
		return false
	}
	d.buffer = append(d.buffer, chunk...)
	for {
		newline := bytes.IndexByte(d.buffer, '\n')
		if newline < 0 {
			break
		}
		line := d.buffer[:newline]
		d.buffer = d.buffer[newline+1:]
		if d.observeLine(line) {
			return true
		}
	}
	if len(d.buffer) > 1<<20 {
		d.buffer = d.buffer[:0]
	}
	return false
}

func (d *sseContentDetector) Flush() bool {
	if d.found || len(d.buffer) == 0 {
		return false
	}
	line := d.buffer
	d.buffer = nil
	return d.observeLine(line)
}

func (d *sseContentDetector) observeLine(line []byte) bool {
	line = bytes.TrimSpace(line)
	if !bytes.HasPrefix(line, []byte("data:")) {
		return false
	}
	payload := bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
	if len(payload) == 0 || bytes.Equal(payload, []byte("[DONE]")) {
		return false
	}
	var event struct {
		Choices []struct {
			Delta map[string]json.RawMessage `json:"delta"`
		} `json:"choices"`
	}
	if json.Unmarshal(payload, &event) != nil {
		return false
	}
	for _, choice := range event.Choices {
		if content, ok := choice.Delta["content"]; ok && contentValuePresent(content) {
			d.found = true
			return true
		}
	}
	return false
}

func contentValuePresent(raw json.RawMessage) bool {
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return false
	}
	return textContentPresent(value)
}

func textContentPresent(value any) bool {
	switch typed := value.(type) {
	case string:
		return typed != ""
	case []any:
		for _, item := range typed {
			if textContentPresent(item) {
				return true
			}
		}
	case map[string]any:
		for _, key := range []string{"text", "content", "output_text"} {
			if item, ok := typed[key]; ok && textContentPresent(item) {
				return true
			}
		}
	}
	return false
}

type limitedCapture struct {
	buf   bytes.Buffer
	limit int
}

func (w *limitedCapture) Write(p []byte) (int, error) {
	remaining := w.limit - w.buf.Len()
	if remaining > 0 {
		if remaining > len(p) {
			remaining = len(p)
		}
		_, _ = w.buf.Write(p[:remaining])
	}
	return len(p), nil
}

func (w *limitedCapture) Bytes() []byte {
	return w.buf.Bytes()
}

func requestHasImageInput(body []byte) bool {
	var payload map[string]any
	if json.Unmarshal(body, &payload) != nil {
		return false
	}
	messages, ok := payload["messages"].([]any)
	if !ok {
		return false
	}
	for _, rawMessage := range messages {
		message, ok := rawMessage.(map[string]any)
		if !ok {
			continue
		}
		if content, ok := message["content"]; ok && containsImageContent(content) {
			return true
		}
	}
	return false
}

func containsImageContent(content any) bool {
	if isImageContentPart(content) {
		return true
	}
	parts, ok := content.([]any)
	if !ok {
		return false
	}
	for _, part := range parts {
		if isImageContentPart(part) {
			return true
		}
	}
	return false
}

func isImageContentPart(value any) bool {
	part, ok := value.(map[string]any)
	if !ok {
		return false
	}
	if kind, ok := part["type"].(string); ok {
		switch strings.ToLower(strings.TrimSpace(kind)) {
		case "image_url", "input_image", "image":
			return true
		}
	}
	_, hasImageURL := part["image_url"]
	return hasImageURL
}

func (a *App) cachedModelSupportsImage(model string) (known, supported bool) {
	var raw string
	if err := a.db.QueryRow("SELECT raw_metadata FROM models WHERE model_id=? AND is_free=1", model).Scan(&raw); err != nil {
		return false, false
	}
	return modelImageSupport([]byte(raw))
}

func modelImageSupport(raw []byte) (known, supported bool) {
	var metadata struct {
		InputModalities []string `json:"input_modalities"`
		Modalities      []string `json:"modalities"`
		Modality        string   `json:"modality"`
		Architecture    struct {
			InputModalities []string `json:"input_modalities"`
			Modality        string   `json:"modality"`
		} `json:"architecture"`
	}
	if json.Unmarshal(raw, &metadata) != nil {
		return false, false
	}
	for _, modalities := range [][]string{metadata.InputModalities, metadata.Modalities, metadata.Architecture.InputModalities} {
		if modalities == nil {
			continue
		}
		known = true
		for _, modality := range modalities {
			if isImageModality(modality) {
				supported = true
			}
		}
	}
	for _, modality := range []string{metadata.Modality, metadata.Architecture.Modality} {
		if strings.TrimSpace(modality) == "" {
			continue
		}
		known = true
		if isImageModality(modality) {
			supported = true
		}
	}
	return known, supported
}

func isImageModality(modality string) bool {
	modality = strings.ToLower(strings.TrimSpace(modality))
	return modality == "image" || modality == "image_url" || strings.Contains(modality, "vision") || strings.Contains(modality, "image")
}

func upstreamErrorSummary(body []byte) string {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return ""
	}
	var payload struct {
		Error json.RawMessage `json:"error"`
	}
	if json.Unmarshal(body, &payload) == nil && len(payload.Error) > 0 {
		var detail struct {
			Message string `json:"message"`
			Type    string `json:"type"`
		}
		if json.Unmarshal(payload.Error, &detail) == nil {
			if detail.Message != "" {
				return truncateError(detail.Message)
			}
			if detail.Type != "" {
				return truncateError(detail.Type)
			}
		}
	}
	return truncateError(trimmed)
}

func truncateError(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 500 {
		return s[:500]
	}
	return s
}

func parseUsageBytes(body []byte) *tokenUsage {
	var found map[string]any
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "data:"))
		if line == "" || line == "[DONE]" {
			continue
		}
		var obj map[string]any
		if json.Unmarshal([]byte(line), &obj) == nil {
			if u, ok := obj["usage"].(map[string]any); ok {
				found = u
			}
		}
	}
	if found == nil {
		var obj map[string]any
		if json.Unmarshal(body, &obj) == nil {
			found, _ = obj["usage"].(map[string]any)
		}
	}
	if found == nil {
		return nil
	}
	return &tokenUsage{Prompt: usageNumber(found["prompt_tokens"]), Completion: usageNumber(found["completion_tokens"]), Total: usageNumber(found["total_tokens"])}
}

func usageNumber(v any) *int64 {
	var n int64
	switch x := v.(type) {
	case float64:
		n = int64(x)
	case json.Number:
		n, _ = x.Int64()
	case int64:
		n = x
	default:
		return nil
	}
	return &n
}

func (a *App) availableProxies() ([]ProxyRecord, error) {
	now := time.Now().UTC()
	version := a.proxyVersion.Load()
	a.proxyCacheMu.Lock()
	if a.proxyCache.version == version && a.proxyCache.loadedAt.After(now.Add(-5*time.Second)) {
		proxies := cloneProxies(a.proxyCache.proxies)
		a.proxyCacheMu.Unlock()
		return proxies, nil
	}
	a.proxyCacheMu.Unlock()

	a.deleteExpiredProxies()
	a.deleteStaleSessionRoutes()
	rows, err := a.db.Query("SELECT id,uri,scheme,host,port,COALESCE(username,''),COALESCE(encrypted_password,''),enabled,health_status,failure_count,COALESCE(cooldown_until,''),COALESCE(expires_at,''),COALESCE(last_checked_at,''),last_check_ok,created_at FROM proxies WHERE enabled=1 ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ProxyRecord{}
	for rows.Next() {
		var p ProxyRecord
		var en, lastOK int
		var cool, expires, checked, created, encrypted string
		if err := rows.Scan(&p.ID, &p.URI, &p.Scheme, &p.Host, &p.Port, &p.Username, &encrypted, &en, &p.HealthStatus, &p.FailureCount, &cool, &expires, &checked, &lastOK, &created); err != nil {
			return nil, err
		}
		p.Password, err = a.decrypt(encrypted)
		if err != nil {
			return nil, fmt.Errorf("could not decrypt proxy %d credentials: %w", p.ID, err)
		}
		p.Enabled = en == 1
		p.LastCheckOK = lastOK == 1
		p.CreatedAt, _ = time.Parse(time.RFC3339, created)
		if checked != "" {
			t, _ := time.Parse(time.RFC3339, checked)
			p.LastCheckedAt = &t
		}
		if cool != "" {
			t, _ := time.Parse(time.RFC3339, cool)
			p.CooldownUntil = &t
			if t.After(now) {
				continue
			}
		}
		if expires != "" {
			t, _ := time.Parse(time.RFC3339, expires)
			p.ExpiresAt = &t
			if !t.After(now) {
				continue
			}
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	a.proxyCacheMu.Lock()
	a.proxyCache = proxyCache{loadedAt: now, proxies: cloneProxies(out), version: version}
	a.proxyCacheMu.Unlock()
	return out, nil
}

func cloneProxies(proxies []ProxyRecord) []ProxyRecord {
	return append([]ProxyRecord(nil), proxies...)
}

func (a *App) invalidateProxyCache() {
	a.proxyVersion.Add(1)
	a.proxyCacheMu.Lock()
	for _, client := range a.clientCache {
		if transport, ok := client.Transport.(interface{ CloseIdleConnections() }); ok {
			transport.CloseIdleConnections()
		}
	}
	a.proxyCache = proxyCache{}
	a.clientCache = make(map[int64]*http.Client)
	a.proxyCacheMu.Unlock()
}

func (a *App) invalidateProxySnapshot() {
	a.proxyVersion.Add(1)
	a.proxyCacheMu.Lock()
	a.proxyCache = proxyCache{}
	a.proxyCacheMu.Unlock()
}

func (a *App) deleteExpiredProxies() {
	result, err := a.db.Exec("DELETE FROM proxies WHERE expires_at IS NOT NULL AND expires_at <> '' AND expires_at <= ?", time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		log.Printf("delete expired proxies failed: %v", err)
		return
	}
	if deleted, _ := result.RowsAffected(); deleted > 0 {
		a.invalidateProxyCache()
	}
}

func (a *App) resetExpiredCooldowns() {
	result, err := a.db.Exec("UPDATE proxies SET health_status='unknown',cooldown_until=NULL,updated_at=? WHERE enabled=1 AND health_status='cooldown' AND cooldown_until IS NOT NULL AND cooldown_until<>'' AND cooldown_until<=?", time.Now().UTC().Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		log.Printf("reset expired cooldowns failed: %v", err)
		return
	}
	if updated, _ := result.RowsAffected(); updated > 0 {
		a.invalidateProxySnapshot()
	}
}

func (a *App) deleteStaleSessionRoutes() {
	cutoff := time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339)
	if _, err := a.db.Exec("DELETE FROM session_proxy_routes WHERE updated_at < ? OR proxy_id NOT IN (SELECT id FROM proxies)", cutoff); err != nil {
		log.Printf("delete stale session routes failed: %v", err)
	}
}

func (a *App) expiredProxyJanitor() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-a.appContext().Done():
			return
		case <-ticker.C:
			a.deleteExpiredProxies()
			a.resetExpiredCooldowns()
			a.deleteStaleSessionRoutes()
			if err := a.deleteExpiredUsage(); err != nil {
				log.Printf("delete expired usage records failed: %v", err)
			}
			if err := a.deleteExpiredAdminSessions(); err != nil {
				log.Printf("delete expired admin sessions failed: %v", err)
			}
		}
	}
}

func (a *App) pickSessionProxy(key string, proxies []ProxyRecord, used map[int64]struct{}) (ProxyRecord, bool, error) {
	a.routingMu.Lock()
	defer a.routingMu.Unlock()
	if key != "" {
		limit := a.sessionProxyRequestLimit()
		var currentID int64
		var requestCount int
		err := a.db.QueryRow("SELECT proxy_id,request_count FROM session_proxy_routes WHERE session_key=?", key).Scan(&currentID, &requestCount)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return ProxyRecord{}, false, err
		}
		for _, candidate := range proxies {
			if candidate.ID == currentID {
				if _, skipped := used[candidate.ID]; !skipped && (limit == 0 || requestCount < limit) {
					if _, err := a.db.Exec("UPDATE session_proxy_routes SET request_count=request_count+1,updated_at=? WHERE session_key=? AND proxy_id=?", time.Now().UTC().Format(time.RFC3339), key, candidate.ID); err != nil {
						return ProxyRecord{}, false, err
					}
					return candidate, true, nil
				}
				break
			}
		}
	}
	eligible := make([]ProxyRecord, 0, len(proxies))
	for _, candidate := range proxies {
		if _, skipped := used[candidate.ID]; !skipped {
			eligible = append(eligible, candidate)
		}
	}
	if len(eligible) == 0 {
		return ProxyRecord{}, false, nil
	}
	selected := eligible[(int(a.rr.Add(1))-1)%len(eligible)]
	if key != "" {
		now := time.Now().UTC().Format(time.RFC3339)
		if _, err := a.db.Exec(`INSERT INTO session_proxy_routes(session_key,proxy_id,request_count,created_at,updated_at) VALUES(?,?,1,?,?) ON CONFLICT(session_key) DO UPDATE SET proxy_id=excluded.proxy_id,request_count=1,updated_at=excluded.updated_at`, key, selected.ID, now, now); err != nil {
			return ProxyRecord{}, false, err
		}
	}
	return selected, true, nil
}

func (a *App) clearSessionProxy(key string, proxyID int64) {
	if key == "" {
		return
	}
	if _, err := a.db.Exec("DELETE FROM session_proxy_routes WHERE session_key=? AND proxy_id=?", key, proxyID); err != nil {
		log.Printf("clear session proxy failed: %v", err)
	}
}
func (a *App) markProxyFailure(id int64) {
	if _, err := a.db.Exec("UPDATE proxies SET health_status='cooldown',failure_count=failure_count+1,cooldown_until=?,updated_at=? WHERE id=?", time.Now().Add(time.Minute).UTC().Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339), id); err != nil {
		log.Printf("mark proxy failure failed: %v", err)
		return
	}
	a.invalidateProxySnapshot()
}
func (a *App) markProxySuccess(id int64) {
	if _, err := a.db.Exec("UPDATE proxies SET health_status='healthy',failure_count=0,cooldown_until=NULL,updated_at=? WHERE id=?", time.Now().UTC().Format(time.RFC3339), id); err != nil {
		log.Printf("mark proxy success failed: %v", err)
		return
	}
	a.invalidateProxySnapshot()
}

func (a *App) listProxies(w http.ResponseWriter, r *http.Request) {
	a.deleteExpiredProxies()
	a.deleteStaleSessionRoutes()
	query := r.URL.Query()
	state := strings.TrimSpace(query.Get("state"))
	if state == "" {
		state = "all"
	}
	now := time.Now().UTC()
	where, args, ok := proxyFilterClause(state, now)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "state must be all, unverified, healthy, cooldown, disabled, unused, or in_use"})
		return
	}

	// Keep the original array response for existing API consumers. The console
	// explicitly requests pagination so large proxy pools are never fetched or
	// rendered in one response.
	pageText, hasPage := query["page"]
	pageSizeText, hasPageSize := query["page_size"]
	if !hasPage && !hasPageSize {
		rows, err := a.db.Query(proxySelect+where+" ORDER BY p.id DESC", args...)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "could not query proxies"})
			return
		}
		defer rows.Close()
		proxies, err := scanProxies(rows)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "could not read proxies"})
			return
		}
		if err := a.annotateProxyUsageStates(proxies, now); err != nil {
			writeJSON(w, 500, map[string]string{"error": "could not read proxy usage state"})
			return
		}
		writeJSON(w, 200, proxies)
		return
	}

	page, err := parseProxyPageParam(pageText, 1, 1, 1_000_000)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "page must be an integer between 1 and 1000000"})
		return
	}
	pageSize, err := parseProxyPageParam(pageSizeText, 50, 1, 200)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "page_size must be an integer between 1 and 200"})
		return
	}

	var total int
	if err := a.db.QueryRow("SELECT COUNT(*) FROM proxies p"+where, args...).Scan(&total); err != nil {
		writeJSON(w, 500, map[string]string{"error": "could not count proxies"})
		return
	}
	totalPages := (total + pageSize - 1) / pageSize
	if totalPages == 0 {
		totalPages = 1
	}
	if page > totalPages {
		page = totalPages
	}
	offset := (page - 1) * pageSize
	pageArgs := append(append([]any{}, args...), pageSize, offset)
	rows, err := a.db.Query(proxySelect+where+" ORDER BY p.id DESC LIMIT ? OFFSET ?", pageArgs...)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "could not query proxies"})
		return
	}
	defer rows.Close()
	proxies, err := scanProxies(rows)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "could not read proxies"})
		return
	}
	if err := a.annotateProxyUsageStates(proxies, now); err != nil {
		writeJSON(w, 500, map[string]string{"error": "could not read proxy usage state"})
		return
	}
	writeJSON(w, 200, map[string]any{
		"items":       proxies,
		"page":        page,
		"page_size":   pageSize,
		"total":       total,
		"total_pages": totalPages,
	})
}

const proxySelect = "SELECT p.id,p.uri,p.scheme,p.host,p.port,COALESCE(p.username,''),COALESCE(p.encrypted_password,''),p.enabled,p.health_status,p.failure_count,COALESCE(p.cooldown_until,''),COALESCE(p.expires_at,''),COALESCE(p.last_checked_at,''),p.last_check_ok,p.created_at FROM proxies p"

func proxyFilterClause(state string, now time.Time) (string, []any, bool) {
	nowText := now.Format(time.RFC3339)
	switch state {
	case "all":
		return "", nil, true
	case "unverified":
		return " WHERE p.enabled=1 AND p.health_status='unknown' AND (p.cooldown_until IS NULL OR p.cooldown_until='' OR p.cooldown_until<=?)", []any{nowText}, true
	case "healthy":
		return " WHERE p.enabled=1 AND p.health_status='healthy'", nil, true
	case "cooldown":
		return " WHERE p.enabled=1 AND p.cooldown_until IS NOT NULL AND p.cooldown_until<>'' AND p.cooldown_until>?", []any{nowText}, true
	case "disabled":
		return " WHERE p.enabled=0", nil, true
	case "unused":
		return " WHERE p.enabled=1 AND (p.cooldown_until IS NULL OR p.cooldown_until='' OR p.cooldown_until<=?) AND p.id NOT IN (SELECT proxy_id FROM session_proxy_routes WHERE updated_at>=?)", []any{nowText, now.Add(-24 * time.Hour).Format(time.RFC3339)}, true
	case "in_use":
		return " WHERE p.enabled=1 AND (p.cooldown_until IS NULL OR p.cooldown_until='' OR p.cooldown_until<=?) AND p.id IN (SELECT proxy_id FROM session_proxy_routes WHERE updated_at>=?)", []any{nowText, now.Add(-24 * time.Hour).Format(time.RFC3339)}, true
	default:
		return "", nil, false
	}
}

func (a *App) annotateProxyUsageStates(proxies []ProxyRecord, now time.Time) error {
	if len(proxies) == 0 {
		return nil
	}
	rows, err := a.db.Query("SELECT DISTINCT proxy_id FROM session_proxy_routes WHERE updated_at>=?", now.Add(-24*time.Hour).Format(time.RFC3339))
	if err != nil {
		return err
	}
	defer rows.Close()
	active := map[int64]struct{}{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return err
		}
		active[id] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for i := range proxies {
		p := &proxies[i]
		if p.CooldownUntil != nil && p.CooldownUntil.After(now) {
			p.UsageState = "cooldown"
		} else if p.Enabled {
			if _, ok := active[p.ID]; ok {
				p.UsageState = "in_use"
				continue
			}
			p.UsageState = "unused"
		} else {
			p.UsageState = "unused"
		}
	}
	return nil
}

func parseProxyPageParam(values []string, defaultValue, min, max int) (int, error) {
	if len(values) == 0 || strings.TrimSpace(values[0]) == "" {
		return defaultValue, nil
	}
	value, err := strconv.Atoi(values[0])
	if err != nil || value < min || value > max {
		return 0, fmt.Errorf("invalid page parameter")
	}
	return value, nil
}
func scanProxies(rows *sql.Rows) ([]ProxyRecord, error) {
	out := []ProxyRecord{}
	for rows.Next() {
		var p ProxyRecord
		var en, lastOK int
		var cool, expires, checked, created, encrypted string
		if err := rows.Scan(&p.ID, &p.URI, &p.Scheme, &p.Host, &p.Port, &p.Username, &encrypted, &en, &p.HealthStatus, &p.FailureCount, &cool, &expires, &checked, &lastOK, &created); err != nil {
			return nil, err
		}
		p.Enabled = en == 1
		p.LastCheckOK = lastOK == 1
		p.CreatedAt, _ = time.Parse(time.RFC3339, created)
		if cool != "" {
			t, _ := time.Parse(time.RFC3339, cool)
			p.CooldownUntil = &t
		}
		if expires != "" {
			t, _ := time.Parse(time.RFC3339, expires)
			p.ExpiresAt = &t
		}
		if checked != "" {
			t, _ := time.Parse(time.RFC3339, checked)
			p.LastCheckedAt = &t
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
func parseProxy(raw string) (ProxyRecord, error) {
	trimmed := strings.TrimSpace(raw)
	if strings.HasPrefix(strings.ToLower(trimmed), "mihomo://") {
		name := strings.TrimSpace(trimmed[len("mihomo://"):])
		if name == "" {
			return ProxyRecord{}, fmt.Errorf("mihomo node name is required")
		}
		return ProxyRecord{Scheme: "mihomo", Host: name, Port: 0, Enabled: true, HealthStatus: "unknown", URI: "mihomo://" + name, CreatedAt: time.Now().UTC()}, nil
	}
	u, e := url.Parse(trimmed)
	if e != nil || u.Hostname() == "" {
		return ProxyRecord{}, fmt.Errorf("invalid proxy")
	}
	sch := strings.ToLower(u.Scheme)
	if sch != "http" && sch != "https" && sch != "socks5" && sch != "socks5h" {
		return ProxyRecord{}, fmt.Errorf("unsupported proxy scheme")
	}
	port := u.Port()
	if port == "" {
		return ProxyRecord{}, fmt.Errorf("proxy port is required")
	}
	n, er := strconv.Atoi(port)
	if er != nil || n < 1 || n > 65535 {
		return ProxyRecord{}, fmt.Errorf("invalid proxy port")
	}
	safe := *u
	p := ProxyRecord{Scheme: sch, Host: u.Hostname(), Port: n, Enabled: true, HealthStatus: "unknown", CreatedAt: time.Now().UTC()}
	if u.User != nil {
		p.Username = u.User.Username()
		if password, ok := u.User.Password(); ok {
			p.Password = password
		}
		safe.User = url.User(p.Username)
	}
	p.URI = safe.String()
	return p, nil
}

func redactProxyInput(raw string) string {
	raw = strings.TrimSpace(raw)
	if parsed, err := url.Parse(raw); err == nil && parsed.Host != "" {
		if parsed.User != nil {
			parsed.User = url.User(parsed.User.Username())
		}
		return parsed.String()
	}
	if strings.Contains(raw, "@") {
		return "<redacted proxy URI>"
	}
	if len(raw) > 256 {
		return raw[:256] + "..."
	}
	return raw
}

func parseProxyExpiry(raw string) (*time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return nil, fmt.Errorf("invalid expires_at; use RFC3339")
	}
	t = t.UTC()
	if !t.After(time.Now().UTC()) {
		return nil, fmt.Errorf("expires_at must be in the future")
	}
	return &t, nil
}

func resolveProxyExpiry(raw string, days int) (*time.Time, error) {
	if days < 0 {
		return nil, fmt.Errorf("expires_in_days must be zero or greater")
	}
	if days > 0 && strings.TrimSpace(raw) != "" {
		return nil, fmt.Errorf("use either expires_at or expires_in_days")
	}
	if days > 0 {
		t := time.Now().UTC().Add(time.Duration(days) * 24 * time.Hour)
		return &t, nil
	}
	return parseProxyExpiry(raw)
}

func (a *App) addProxy(w http.ResponseWriter, r *http.Request) {
	var in struct {
		URI           string `json:"uri"`
		ExpiresAt     string `json:"expires_at"`
		ExpiresInDays int    `json:"expires_in_days"`
	}
	if readJSON(r, &in) != nil {
		writeJSON(w, 400, map[string]string{"error": "uri is required"})
		return
	}
	p, e := parseProxy(in.URI)
	if e != nil {
		writeJSON(w, 400, map[string]string{"error": e.Error()})
		return
	}
	p.ExpiresAt, e = resolveProxyExpiry(in.ExpiresAt, in.ExpiresInDays)
	if e != nil {
		writeJSON(w, 400, map[string]string{"error": e.Error()})
		return
	}
	id, e := a.insertProxy(p)
	if e != nil {
		if strings.Contains(strings.ToLower(e.Error()), "unique constraint") {
			writeJSON(w, 409, map[string]string{"error": "proxy already exists"})
		} else {
			writeJSON(w, 500, map[string]string{"error": "could not save proxy"})
		}
		return
	}
	p.ID = id
	writeJSON(w, 201, p)
}
func (a *App) importProxies(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Text          string `json:"text"`
		ExpiresAt     string `json:"expires_at"`
		ExpiresInDays int    `json:"expires_in_days"`
	}
	if readJSON(r, &in) != nil {
		writeJSON(w, 400, map[string]string{"error": "text is required"})
		return
	}
	expiresAt, err := resolveProxyExpiry(in.ExpiresAt, in.ExpiresInDays)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	type result struct {
		Line   int    `json:"line"`
		URI    string `json:"uri"`
		Status string `json:"status"`
		Error  string `json:"error,omitempty"`
	}
	results := []result{}
	for i, line := range strings.Split(in.Text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		p, e := parseProxy(line)
		if e != nil {
			results = append(results, result{i + 1, redactProxyInput(line), "invalid", e.Error()})
			continue
		}
		p.ExpiresAt = expiresAt
		if _, e = a.insertProxy(p); e != nil {
			status := "error"
			message := "could not save proxy"
			if strings.Contains(strings.ToLower(e.Error()), "unique constraint") {
				status = "duplicate"
				message = "proxy already exists"
			}
			results = append(results, result{i + 1, p.URI, status, message})
			continue
		}
		results = append(results, result{i + 1, p.URI, "imported", ""})
	}
	imported := 0
	for _, r := range results {
		if r.Status == "imported" {
			imported++
		}
	}
	if imported > 0 {
		a.runBackground(a.runUnverifiedHealthCheck)
	}
	writeJSON(w, 200, map[string]any{"results": results})
}
func (a *App) insertProxy(p ProxyRecord) (int64, error) {
	encrypted, e := a.encrypt(p.Password)
	if e != nil {
		return 0, e
	}
	var expiresAt any
	if p.ExpiresAt != nil {
		expiresAt = p.ExpiresAt.UTC().Format(time.RFC3339)
	}
	res, e := a.db.Exec("INSERT INTO proxies(uri,scheme,host,port,username,encrypted_password,enabled,health_status,failure_count,expires_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?, ?,0,?,?,?)", p.URI, p.Scheme, p.Host, p.Port, p.Username, encrypted, 1, "unknown", expiresAt, p.CreatedAt.Format(time.RFC3339), p.CreatedAt.Format(time.RFC3339))
	if e != nil {
		return 0, e
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	a.invalidateProxyCache()
	return id, nil
}
func (a *App) proxyID(r *http.Request) (int64, error) {
	return strconv.ParseInt(r.PathValue("id"), 10, 64)
}
func (a *App) patchProxy(w http.ResponseWriter, r *http.Request) {
	id, e := a.proxyID(r)
	if e != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid id"})
		return
	}
	var in struct {
		Enabled *bool `json:"enabled"`
	}
	if readJSON(r, &in) != nil || in.Enabled == nil {
		writeJSON(w, 400, map[string]string{"error": "enabled is required"})
		return
	}
	res, e := a.db.Exec("UPDATE proxies SET enabled=?,updated_at=? WHERE id=?", boolInt(*in.Enabled), time.Now().UTC().Format(time.RFC3339), id)
	if e != nil {
		writeJSON(w, 500, map[string]string{"error": "could not update proxy"})
		return
	}
	updated, err := res.RowsAffected()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "could not confirm proxy update"})
		return
	}
	if updated == 0 {
		writeJSON(w, 404, map[string]string{"error": "proxy not found"})
		return
	}
	a.invalidateProxyCache()
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (a *App) deleteProxy(w http.ResponseWriter, r *http.Request) {
	id, e := a.proxyID(r)
	if e != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid id"})
		return
	}
	res, e := a.db.Exec("DELETE FROM proxies WHERE id=?", id)
	if e != nil {
		writeJSON(w, 500, map[string]string{"error": e.Error()})
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		writeJSON(w, 404, map[string]string{"error": "proxy not found"})
		return
	}
	a.invalidateProxyCache()
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *App) bulkDeleteProxies(w http.ResponseWriter, r *http.Request) {
	var in struct {
		IDs         []int64 `json:"ids"`
		AllDisabled bool    `json:"all_disabled"`
	}
	if readJSON(r, &in) != nil || (len(in.IDs) == 0 && !in.AllDisabled) {
		writeJSON(w, 400, map[string]string{"error": "ids or all_disabled are required"})
		return
	}
	ids := in.IDs
	if in.AllDisabled {
		rows, err := a.db.Query("SELECT id FROM proxies WHERE enabled=0")
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "could not load disabled proxies"})
			return
		}
		ids = ids[:0]
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				_ = rows.Close()
				writeJSON(w, 500, map[string]string{"error": "could not load disabled proxies"})
				return
			}
			ids = append(ids, id)
		}
		_ = rows.Close()
		if len(ids) == 0 {
			writeJSON(w, 200, map[string]any{"ok": true, "deleted": 0})
			return
		}
	} else if len(ids) > 1000 {
		writeJSON(w, 400, map[string]string{"error": "too many proxy ids"})
		return
	}
	tx, err := a.db.Begin()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "could not delete proxies"})
		return
	}
	seen := make(map[int64]struct{}, len(ids))
	deleted := int64(0)
	for _, id := range ids {
		if id <= 0 {
			_ = tx.Rollback()
			writeJSON(w, 400, map[string]string{"error": "invalid proxy id"})
			return
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		res, deleteErr := tx.Exec("DELETE FROM proxies WHERE id=?", id)
		if deleteErr != nil {
			_ = tx.Rollback()
			writeJSON(w, 500, map[string]string{"error": "could not delete proxies"})
			return
		}
		count, _ := res.RowsAffected()
		deleted += count
	}
	if err = tx.Commit(); err != nil {
		writeJSON(w, 500, map[string]string{"error": "could not delete proxies"})
		return
	}
	if deleted > 0 {
		a.invalidateProxyCache()
	}
	writeJSON(w, 200, map[string]any{"ok": true, "deleted": deleted})
}

func (a *App) testProxy(w http.ResponseWriter, r *http.Request) {
	id, e := a.proxyID(r)
	if e != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid id"})
		return
	}
	var p ProxyRecord
	var en, lastOK int
	var encrypted, expires, checked, created string
	queryErr := a.db.QueryRow("SELECT id,uri,scheme,host,port,COALESCE(username,''),COALESCE(encrypted_password,''),enabled,health_status,failure_count,COALESCE(expires_at,''),COALESCE(last_checked_at,''),last_check_ok,created_at FROM proxies WHERE id=?", id).Scan(&p.ID, &p.URI, &p.Scheme, &p.Host, &p.Port, &p.Username, &encrypted, &en, &p.HealthStatus, &p.FailureCount, &expires, &checked, &lastOK, &created)
	if errors.Is(queryErr, sql.ErrNoRows) {
		writeJSON(w, 404, map[string]string{"error": "proxy not found"})
		return
	}
	if queryErr != nil {
		writeJSON(w, 500, map[string]string{"error": "could not load proxy"})
		return
	}
	if expires != "" {
		t, parseErr := time.Parse(time.RFC3339, expires)
		if parseErr != nil || !t.After(time.Now().UTC()) {
			if _, err := a.db.Exec("DELETE FROM proxies WHERE id=?", id); err != nil {
				writeJSON(w, 500, map[string]string{"error": "could not delete expired proxy"})
				return
			}
			a.invalidateProxyCache()
			writeJSON(w, 404, map[string]string{"error": "proxy has expired"})
			return
		}
		p.ExpiresAt = &t
	}
	p.Enabled = en == 1
	p.CreatedAt, _ = time.Parse(time.RFC3339, created)
	p.Password, _ = a.decrypt(encrypted)
	var resp *http.Response
	if e == nil {
		req, _ := http.NewRequestWithContext(r.Context(), "GET", "https://api.ipify.org?format=json", nil)
		resp, e = a.doProxyRequest(req, p)
	}
	if resp != nil {
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		if e == nil && (resp.StatusCode < 200 || resp.StatusCode >= 300) {
			e = fmt.Errorf("proxy test returned HTTP %d", resp.StatusCode)
		}
	}
	if e != nil {
		a.markProxyFailure(id)
		a.recordProxyCheck(id, false)
		writeJSON(w, 502, map[string]any{"ok": false, "error": truncateError(e.Error())})
		return
	}
	a.markProxySuccess(id)
	a.recordProxyCheck(id, true)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *App) recordProxyCheck(id int64, ok bool) {
	okValue := 0
	if ok {
		okValue = 1
	}
	if _, err := a.db.Exec("UPDATE proxies SET last_checked_at=?,last_check_ok=? WHERE id=?", time.Now().UTC().Format(time.RFC3339), okValue, id); err != nil {
		log.Printf("record proxy check failed: %v", err)
	}
}

func (a *App) recordUsage(model string, proxyID *int64, proxyURI, status string, code int, lat time.Duration, firstTokenLatency *time.Duration, retries int, tokens any, e error) {
	a.recordUsageKind("chat", model, proxyID, proxyURI, status, code, lat, firstTokenLatency, retries, tokens, e)
}

func (a *App) recordUsageKind(kind, model string, proxyID *int64, proxyURI, status string, code int, lat time.Duration, firstTokenLatency *time.Duration, retries int, tokens any, e error) {
	var p, c, t *int64
	if v, ok := tokens.(*tokenUsage); ok && v != nil {
		p, c, t = v.Prompt, v.Completion, v.Total
	}
	var firstTokenMS any
	if firstTokenLatency != nil {
		firstTokenMS = firstTokenLatency.Milliseconds()
	}
	var id any
	if proxyID != nil {
		id = *proxyID
	}
	if kind == "" {
		kind = "chat"
	}
	errorMessage := lastErrString(e)
	origin := usageErrorOrigin(kind, status, code, errorMessage)
	if _, err := a.db.Exec("INSERT INTO usage_requests(created_at,request_kind,model,proxy_id,proxy_uri,status,status_code,latency_ms,first_token_latency_ms,retry_count,prompt_tokens,completion_tokens,total_tokens,error_message,error_origin) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", time.Now().UTC().Format(time.RFC3339), kind, model, id, proxyURI, status, code, lat.Milliseconds(), firstTokenMS, retries, p, c, t, errorMessage, origin); err != nil {
		log.Printf("record usage failed: %v", err)
	}
}

func usageErrorOrigin(kind, status string, code int, message string) string {
	if kind != "chat" {
		return "internal"
	}
	lower := strings.ToLower(strings.TrimSpace(message))
	if code == 0 || code == 499 || code >= http.StatusInternalServerError || code == http.StatusUnavailableForLegalReasons {
		return "external"
	}
	for _, marker := range []string{
		"context canceled",
		"context deadline exceeded",
		"unexpected eof",
		"proxyconnect",
		"not enough bandwidth",
		"could not locate image content",
		"vision helper",
		"error from provider",
		"upstream request failed",
		"all proxies failed",
	} {
		if strings.Contains(lower, marker) {
			return "external"
		}
	}
	if status == "success" {
		return "none"
	}
	return "user"
}

const usageOriginSQL = "COALESCE(NULLIF(u.error_origin,''),'user')"
const usageSelect = "SELECT u.id,u.created_at,COALESCE(u.request_kind,'chat'),u.model,u.proxy_id,COALESCE(NULLIF(u.proxy_uri,''),p.uri,''),u.status,u.status_code,u.latency_ms,u.first_token_latency_ms,u.retry_count,u.prompt_tokens,u.completion_tokens,u.total_tokens,COALESCE(u.error_message,'')," + usageOriginSQL + " FROM usage_requests u LEFT JOIN proxies p ON p.id=u.proxy_id"

func (a *App) usageList(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	paged := false
	for _, key := range []string{"page", "page_size", "from", "to", "model", "status"} {
		if _, present := query[key]; present {
			paged = true
			break
		}
	}
	if !paged {
		limit := 50
		if v, _ := strconv.Atoi(query.Get("limit")); v > 0 && v < 200 {
			limit = v
		}
		out, err := a.queryUsageRequests(usageSelect+" ORDER BY u.id DESC LIMIT ?", limit)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "could not query usage records"})
			return
		}
		writeJSON(w, 200, out)
		return
	}

	page, err := parseProxyPageParam(query["page"], 1, 1, 1_000_000)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "page must be an integer between 1 and 1000000"})
		return
	}
	pageSize, err := parseProxyPageParam(query["page_size"], 25, 1, 200)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "page_size must be an integer between 1 and 200"})
		return
	}
	status := strings.TrimSpace(query.Get("status"))
	if status != "" && status != "success" && status != "error" && status != "external" {
		writeJSON(w, 400, map[string]string{"error": "status must be success, error, or external"})
		return
	}
	fromTime, err := parseUsageTime(query.Get("from"))
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "from must be an RFC3339 timestamp"})
		return
	}
	toTime, err := parseUsageTime(query.Get("to"))
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "to must be an RFC3339 timestamp"})
		return
	}
	if fromTime != nil && toTime != nil && fromTime.After(*toTime) {
		writeJSON(w, 400, map[string]string{"error": "from must not be after to"})
		return
	}

	clauses := []string{}
	args := []any{}
	if fromTime != nil {
		clauses = append(clauses, "u.created_at>=?")
		args = append(args, fromTime.UTC().Format(time.RFC3339))
	}
	if toTime != nil {
		clauses = append(clauses, "u.created_at<=?")
		args = append(args, toTime.UTC().Format(time.RFC3339))
	}
	if model := strings.TrimSpace(query.Get("model")); model != "" {
		clauses = append(clauses, "u.model=?")
		args = append(args, model)
	}
	switch status {
	case "success":
		clauses = append(clauses, "u.status='success'")
	case "error":
		clauses = append(clauses, "u.status='error'", usageOriginSQL+"='user'")
	case "external":
		clauses = append(clauses, "u.status='error'", usageOriginSQL+"='external'")
	}
	where := ""
	if len(clauses) > 0 {
		where = " WHERE " + strings.Join(clauses, " AND ")
	}

	var total int
	if err := a.db.QueryRow("SELECT COUNT(*) FROM usage_requests u"+where, args...).Scan(&total); err != nil {
		writeJSON(w, 500, map[string]string{"error": "could not count usage records"})
		return
	}
	totalPages := (total + pageSize - 1) / pageSize
	if totalPages == 0 {
		totalPages = 1
	}
	if page > totalPages {
		page = totalPages
	}
	offset := (page - 1) * pageSize
	pageArgs := append(append([]any{}, args...), pageSize, offset)
	items, err := a.queryUsageRequests(usageSelect+where+" ORDER BY u.id DESC LIMIT ? OFFSET ?", pageArgs...)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "could not query usage records"})
		return
	}
	models, err := a.usageModels()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "could not query usage models"})
		return
	}
	writeJSON(w, 200, map[string]any{
		"items":       items,
		"page":        page,
		"page_size":   pageSize,
		"total":       total,
		"total_pages": totalPages,
		"models":      models,
	})
}

func parseUsageTime(raw string) (*time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}

func (a *App) queryUsageRequests(query string, args ...any) ([]usageRequest, error) {
	rows, err := a.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []usageRequest{}
	for rows.Next() {
		var x usageRequest
		var ts string
		if err := rows.Scan(&x.ID, &ts, &x.RequestKind, &x.Model, &x.ProxyID, &x.ProxyURI, &x.Status, &x.StatusCode, &x.LatencyMS, &x.FirstTokenLatencyMS, &x.RetryCount, &x.PromptTokens, &x.CompletionTokens, &x.TotalTokens, &x.ErrorMessage, &x.ErrorOrigin); err != nil {
			return nil, err
		}
		x.CreatedAt, _ = time.Parse(time.RFC3339, ts)
		out = append(out, x)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (a *App) usageModels() ([]string, error) {
	rows, err := a.db.Query("SELECT DISTINCT model FROM usage_requests WHERE model<>'' ORDER BY model")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	models := []string{}
	for rows.Next() {
		var model string
		if err := rows.Scan(&model); err != nil {
			return nil, err
		}
		models = append(models, model)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return models, nil
}

func (a *App) usageRates(w http.ResponseWriter, _ *http.Request) {
	now := time.Now().UTC()
	cutoff := now.Add(-time.Minute).Format(time.RFC3339)
	var rpm, tpm int64
	if err := a.db.QueryRow("SELECT COUNT(*),COALESCE(SUM(total_tokens),0) FROM usage_requests WHERE request_kind='chat' AND created_at>=? AND created_at<=?", cutoff, now.Format(time.RFC3339)).Scan(&rpm, &tpm); err != nil {
		writeJSON(w, 500, map[string]string{"error": "could not calculate usage rates"})
		return
	}
	writeJSON(w, 200, map[string]any{
		"window_seconds": 60,
		"rpm":            rpm,
		"tpm":            tpm,
		"measured_at":    now.Format(time.RFC3339),
	})
}
func (a *App) statsSummary(w http.ResponseWriter, _ *http.Request) {
	a.deleteExpiredProxies()
	now := time.Now().UTC()
	dayStart := chinaDayStart(now).Format(time.RFC3339)
	var total, counted, external, success, pt, ct, tt, free, active int64
	query := `SELECT
		COUNT(*),
		COALESCE(SUM(CASE WHEN status='success' THEN 1 ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN COALESCE(NULLIF(error_origin,''),'user')<>'external' THEN 1 ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN COALESCE(NULLIF(error_origin,''),'user')='external' THEN 1 ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN created_at>=? AND created_at<=? THEN COALESCE(prompt_tokens,0) ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN created_at>=? AND created_at<=? THEN COALESCE(completion_tokens,0) ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN created_at>=? AND created_at<=? THEN COALESCE(total_tokens,0) ELSE 0 END),0),
		(SELECT COUNT(*) FROM models WHERE is_free=1),
		(SELECT COUNT(*) FROM proxies WHERE enabled=1)
		FROM usage_requests WHERE request_kind='chat'`
	nowText := now.Format(time.RFC3339)
	if err := a.db.QueryRow(query, dayStart, nowText, dayStart, nowText, dayStart, nowText).Scan(&total, &success, &counted, &external, &pt, &ct, &tt, &free, &active); err != nil {
		writeJSON(w, 500, map[string]string{"error": "could not calculate summary"})
		return
	}
	writeJSON(w, 200, map[string]any{"requests": total, "counted_requests": counted, "external_requests": external, "success": success, "success_rate": rate(success, counted), "prompt_tokens": pt, "completion_tokens": ct, "total_tokens": tt, "free_models": free, "active_proxies": active})
}

func chinaDayStart(now time.Time) time.Time {
	local := now.In(chinaLocation)
	return time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, chinaLocation).UTC()
}

func rate(a, b int64) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}
func (a *App) statsTimeseries(w http.ResponseWriter, _ *http.Request) {
	rows, err := a.db.Query("SELECT date(created_at,'+8 hours') day,COUNT(*),COALESCE(SUM(total_tokens),0) FROM usage_requests WHERE request_kind='chat' GROUP BY day ORDER BY day DESC LIMIT 30")
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "could not query timeseries"})
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var day string
		var n, t int64
		if err := rows.Scan(&day, &n, &t); err != nil {
			writeJSON(w, 500, map[string]string{"error": "could not read timeseries"})
			return
		}
		out = append(out, map[string]any{"day": day, "requests": n, "tokens": t})
	}
	if err := rows.Err(); err != nil {
		writeJSON(w, 500, map[string]string{"error": "could not read timeseries"})
		return
	}
	writeJSON(w, 200, out)
}
func (a *App) statsModels(w http.ResponseWriter, _ *http.Request) {
	rows, err := a.db.Query("SELECT model,COUNT(*),COALESCE(SUM(total_tokens),0) FROM usage_requests WHERE request_kind='chat' GROUP BY model ORDER BY COUNT(*) DESC")
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "could not query model statistics"})
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var m string
		var n, t int64
		if err := rows.Scan(&m, &n, &t); err != nil {
			writeJSON(w, 500, map[string]string{"error": "could not read model statistics"})
			return
		}
		out = append(out, map[string]any{"model": m, "requests": n, "tokens": t})
	}
	if err := rows.Err(); err != nil {
		writeJSON(w, 500, map[string]string{"error": "could not read model statistics"})
		return
	}
	writeJSON(w, 200, out)
}

func (a *App) encrypt(s string) (string, error) {
	return encryptWithKey(a.key, s)
}

func encryptWithKey(key []byte, value string) (string, error) {
	block, e := aes.NewCipher(key)
	if e != nil {
		return "", e
	}
	g, e := cipher.NewGCM(block)
	if e != nil {
		return "", e
	}
	nonce := make([]byte, g.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return "", e
	}
	return base64.RawStdEncoding.EncodeToString(g.Seal(nonce, nonce, []byte(value), nil)), nil
}
func (a *App) decrypt(s string) (string, error) {
	return decryptWithKey(a.key, s)
}

func decryptWithKey(key []byte, value string) (string, error) {
	if value == "" {
		return "", nil
	}
	b, e := base64.RawStdEncoding.DecodeString(value)
	if e != nil {
		return "", e
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		return "", e
	}
	g, e := cipher.NewGCM(block)
	if e != nil {
		return "", e
	}
	n := g.NonceSize()
	if len(b) < n {
		return "", errors.New("invalid ciphertext")
	}
	out, e := g.Open(nil, b[:n], b[n:], nil)
	return string(out), e
}

func (a *App) rotateEncryptionKey(previousKey []byte) (int, error) {
	if subtle.ConstantTimeCompare(a.key, previousKey) == 1 {
		return 0, nil
	}
	tx, err := a.db.Begin()
	if err != nil {
		return 0, err
	}
	rollback := func(err error) (int, error) {
		_ = tx.Rollback()
		return 0, err
	}

	type settingValue struct {
		key   string
		value string
	}
	settings := []settingValue{}
	rows, err := tx.Query("SELECT key,value FROM settings WHERE key IN ('upstream_api_key','upstream_custom_headers')")
	if err != nil {
		return rollback(err)
	}
	for rows.Next() {
		var item settingValue
		if err = rows.Scan(&item.key, &item.value); err != nil {
			_ = rows.Close()
			return rollback(err)
		}
		settings = append(settings, item)
	}
	if err = rows.Err(); err != nil {
		_ = rows.Close()
		return rollback(err)
	}
	_ = rows.Close()

	type proxyValue struct {
		id    int64
		value string
	}
	proxies := []proxyValue{}
	rows, err = tx.Query("SELECT id,COALESCE(encrypted_password,'') FROM proxies")
	if err != nil {
		return rollback(err)
	}
	for rows.Next() {
		var item proxyValue
		if err = rows.Scan(&item.id, &item.value); err != nil {
			_ = rows.Close()
			return rollback(err)
		}
		proxies = append(proxies, item)
	}
	if err = rows.Err(); err != nil {
		_ = rows.Close()
		return rollback(err)
	}
	_ = rows.Close()

	migrated := 0
	rotate := func(value string) (string, bool, error) {
		if value == "" {
			return value, false, nil
		}
		if _, currentErr := decryptWithKey(a.key, value); currentErr == nil {
			return value, false, nil
		}
		plain, previousErr := decryptWithKey(previousKey, value)
		if previousErr != nil {
			return "", false, errors.New("encrypted value cannot be decrypted with the current or previous key")
		}
		encrypted, encryptErr := encryptWithKey(a.key, plain)
		return encrypted, true, encryptErr
	}
	for _, item := range settings {
		value, changed, rotateErr := rotate(item.value)
		if rotateErr != nil {
			return rollback(fmt.Errorf("setting %s: %w", item.key, rotateErr))
		}
		if changed {
			if _, err = tx.Exec("UPDATE settings SET value=? WHERE key=?", value, item.key); err != nil {
				return rollback(err)
			}
			migrated++
		}
	}
	for _, item := range proxies {
		value, changed, rotateErr := rotate(item.value)
		if rotateErr != nil {
			return rollback(fmt.Errorf("proxy %d: %w", item.id, rotateErr))
		}
		if changed {
			if _, err = tx.Exec("UPDATE proxies SET encrypted_password=? WHERE id=?", value, item.id); err != nil {
				return rollback(err)
			}
			migrated++
		}
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return migrated, nil
}
