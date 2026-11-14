package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"encoding/base64"
	"encoding/base32"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

//go:embed migrations/*.sql
var migrations embed.FS

type Config struct {
	Port, DatabaseURL, MongoURL, MongoDatabase, JWTSecret, WebhookSecret string
	AdminEmail, AdminPassword                                            string
	SMTPHost, SMTPPort, SMTPUsername, SMTPPassword, SMTPFrom            string
	AlertWebhookEncryptionKey                                           string
	SessionHours                                                        int
	DashboardURL                                                        string
	MFAEncryptionKey                                                    string
	OIDCAuthURL, OIDCTokenURL, OIDCUserInfoURL, OIDCClientID, OIDCClientSecret, OIDCRedirectURL, OIDCDefaultRole string
	OIDCAutoProvision                                                   bool
	RetentionDays                                                       int
}

type App struct {
	pg        *pgxpool.Pool
	configs   *mongo.Collection
	cfg       Config
	client    *http.Client
	mongoClient *mongo.Client
	scheduler *Scheduler
	retentionMu sync.RWMutex
	lastRetentionAt time.Time
	lastRetentionErr string
}

type Target struct {
	ID                      uuid.UUID `json:"id"`
	Name                    string    `json:"name"`
	BaseURL                 string    `json:"base_url"`
	Type                    string    `json:"type"`
	ScheduleIntervalSeconds int       `json:"schedule_interval_seconds"`
	CreatedAt               time.Time `json:"created_at"`
}

type ProbeConfig struct {
	TargetID string `bson:"target_id" json:"target_id"`
	L1       struct {
		TimeoutMS int `bson:"timeout_ms" json:"timeout_ms"`
	} `bson:"l1" json:"l1"`
	L2 AuthConfig     `bson:"l2" json:"l2"`
	L3 ContractConfig `bson:"l3" json:"l3"`
	L4 struct {
		Assertions []Assertion `bson:"assertions" json:"assertions"`
	} `bson:"l4" json:"l4"`
}
type AuthConfig struct {
	AuthType       string `bson:"auth_type" json:"auth_type"`
	TokenEnvVar    string `bson:"token_env_var" json:"token_env_var"`
	HeaderName     string `bson:"header_name" json:"header_name"`
	ExpectedStatus int    `bson:"expected_status" json:"expected_status"`
}
type ContractConfig struct {
	Type           string         `bson:"type" json:"type"`
	Method         string         `bson:"method" json:"method"`
	Path           string         `bson:"path" json:"path"`
	Query          string         `bson:"query" json:"query"`
	ExpectedStatus int            `bson:"expected_status" json:"expected_status"`
	ExpectedShape  map[string]any `bson:"expected_shape" json:"expected_shape"`
}
type Assertion struct {
	Field string `bson:"field" json:"field"`
	Rule  string `bson:"rule" json:"rule"`
	Value any    `bson:"value,omitempty" json:"value,omitempty"`
}
type LayerResult struct {
	Layer        int               `json:"layer"`
	Status       string            `json:"status"`
	LatencyMS    int               `json:"latency_ms"`
	ErrorMessage string            `json:"error_message,omitempty"`
	Diagnostics  *ProbeDiagnostics `json:"diagnostics,omitempty"`
	CheckedAt    time.Time         `json:"checked_at"`
}
type ProbeDiagnostics struct {
	ExpectedStatus  int            `json:"expected_status,omitempty"`
	ActualStatus    int            `json:"actual_status,omitempty"`
	ExpectedShape   map[string]any `json:"expected_shape,omitempty"`
	ResponsePreview any            `json:"response_preview,omitempty"`
	BaselineCaptured bool          `json:"baseline_captured,omitempty"`
	BaselineChanges  []BaselineChange `json:"baseline_changes,omitempty"`
}
type BaselineChange struct { Path string `json:"path"`; Change string `json:"change"`; Before string `json:"before,omitempty"`; After string `json:"after,omitempty"` }
type RunResponse struct {
	ID            uuid.UUID     `json:"id"`
	TargetID      uuid.UUID     `json:"target_id"`
	OverallStatus string        `json:"overall_status"`
	StartedAt     time.Time     `json:"started_at"`
	FinishedAt    time.Time     `json:"finished_at"`
	Results       []LayerResult `json:"results"`
	IncidentID    *uuid.UUID    `json:"incident_id,omitempty"`
	Verdict       string        `json:"verdict,omitempty"`
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
func config() Config {
	return Config{Port: getenv("PORT", "8080"), DatabaseURL: getenv("DATABASE_URL", "postgres://meridian:meridian@postgres:5432/meridian?sslmode=disable"), MongoURL: getenv("MONGO_URL", "mongodb://mongo:27017"), MongoDatabase: getenv("MONGO_DATABASE", "meridian"), JWTSecret: getenv("JWT_SECRET", "change-me-in-production"), WebhookSecret: getenv("WEBHOOK_SECRET", "change-me-webhook"), AdminEmail: getenv("ADMIN_EMAIL", "admin@meridian.local"), AdminPassword: getenv("ADMIN_PASSWORD", "meridian-demo"), SMTPHost: getenv("SMTP_HOST", ""), SMTPPort: getenv("SMTP_PORT", "587"), SMTPUsername: getenv("SMTP_USERNAME", ""), SMTPPassword: getenv("SMTP_PASSWORD", ""), SMTPFrom: getenv("SMTP_FROM", ""), AlertWebhookEncryptionKey: os.Getenv("ALERT_WEBHOOK_ENCRYPTION_KEY"), MFAEncryptionKey: getenv("MFA_ENCRYPTION_KEY", getenv("JWT_SECRET", "change-me-in-production")), DashboardURL: strings.TrimRight(getenv("DASHBOARD_URL", "http://meridian.localhost:5173"), "/"), OIDCAuthURL: getenv("OIDC_AUTH_URL", ""), OIDCTokenURL: getenv("OIDC_TOKEN_URL", ""), OIDCUserInfoURL: getenv("OIDC_USERINFO_URL", ""), OIDCClientID: getenv("OIDC_CLIENT_ID", ""), OIDCClientSecret: getenv("OIDC_CLIENT_SECRET", ""), OIDCRedirectURL: getenv("OIDC_REDIRECT_URL", ""), OIDCDefaultRole: getenv("OIDC_DEFAULT_ROLE", "viewer"), OIDCAutoProvision: strings.EqualFold(getenv("OIDC_AUTO_PROVISION", "false"), "true"), RetentionDays: max(1, func() int { value, err := strconv.Atoi(getenv("RETENTION_DAYS", "90")); if err != nil { return 90 }; return value }()), SessionHours: max(1, func() int { value, err := strconv.Atoi(getenv("SESSION_HOURS", "24")); if err != nil { return 24 }; return value }())}
}

// Alert webhook URLs often contain an unrevocable delivery token. They are
// encrypted before persistence and never returned by the management API.
func (a *App) alertEncryptionKey() ([]byte, error) {
	if strings.TrimSpace(a.cfg.AlertWebhookEncryptionKey) == "" {
		return nil, errors.New("ALERT_WEBHOOK_ENCRYPTION_KEY is not configured")
	}
	sum := sha256.Sum256([]byte(a.cfg.AlertWebhookEncryptionKey))
	return sum[:], nil
}

func (a *App) encryptAlertWebhook(value string) (string, error) {
	key, err := a.alertEncryptionKey()
	if err != nil { return "", err }
	block, err := aes.NewCipher(key)
	if err != nil { return "", err }
	gcm, err := cipher.NewGCM(block)
	if err != nil { return "", err }
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil { return "", err }
	return "enc:v1:" + base64.RawStdEncoding.EncodeToString(gcm.Seal(nonce, nonce, []byte(value), nil)), nil
}

func (a *App) decryptAlertWebhook(value string) (string, error) {
	if !strings.HasPrefix(value, "enc:v1:") { return value, nil } // Legacy rules remain deliverable but stay masked.
	key, err := a.alertEncryptionKey()
	if err != nil { return "", err }
	payload, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(value, "enc:v1:"))
	if err != nil { return "", errors.New("invalid encrypted alert webhook") }
	block, err := aes.NewCipher(key)
	if err != nil { return "", err }
	gcm, err := cipher.NewGCM(block)
	if err != nil { return "", err }
	if len(payload) < gcm.NonceSize() { return "", errors.New("invalid encrypted alert webhook") }
	plain, err := gcm.Open(nil, payload[:gcm.NonceSize()], payload[gcm.NonceSize():], nil)
	if err != nil { return "", errors.New("could not decrypt alert webhook") }
	return string(plain), nil
}

func (a *App) encryptMFASecret(value string) (string, error) {
	key := sha256.Sum256([]byte(a.cfg.MFAEncryptionKey)); block, err := aes.NewCipher(key[:]); if err != nil { return "", err }
	gcm, err := cipher.NewGCM(block); if err != nil { return "", err }; nonce:=make([]byte,gcm.NonceSize()); if _,err=io.ReadFull(rand.Reader,nonce);err!=nil{return "",err}
	return "mfa:v1:"+base64.RawStdEncoding.EncodeToString(gcm.Seal(nonce,nonce,[]byte(value),nil)),nil
}

func (a *App) decryptMFASecret(value string) (string, error) {
	if !strings.HasPrefix(value,"mfa:v1:") { return "", errors.New("invalid MFA secret") }; encoded,err:=base64.RawStdEncoding.DecodeString(strings.TrimPrefix(value,"mfa:v1:"));if err!=nil{return "",err}
	key:=sha256.Sum256([]byte(a.cfg.MFAEncryptionKey));block,err:=aes.NewCipher(key[:]);if err!=nil{return "",err};gcm,err:=cipher.NewGCM(block);if err!=nil{return "",err};if len(encoded)<gcm.NonceSize(){return "",errors.New("invalid MFA secret")};plain,err:=gcm.Open(nil,encoded[:gcm.NonceSize()],encoded[gcm.NonceSize():],nil);return string(plain),err
}

func totpCode(secret string, at time.Time) (string, bool) {
	key,err:=base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.ReplaceAll(secret," ","")));if err!=nil{return "",false};counter:=uint64(at.Unix()/30);message:=make([]byte,8);for i:=7;i>=0;i--{message[i]=byte(counter);counter>>=8};mac:=hmac.New(sha1.New,key);_,_=mac.Write(message);sum:=mac.Sum(nil);offset:=int(sum[len(sum)-1]&0x0f);value:=int(sum[offset]&0x7f)<<24|int(sum[offset+1])<<16|int(sum[offset+2])<<8|int(sum[offset+3]);return fmt.Sprintf("%06d",value%1000000),true
}

func validTOTP(secret, code string) bool { code=strings.TrimSpace(code); for _,delta:=range []int{-30,0,30}{want,ok:=totpCode(secret,time.Now().Add(time.Duration(delta)*time.Second));if ok&&hmac.Equal([]byte(want),[]byte(code)){return true}};return false }

func alertWebhookHint(value string) string {
	if parsed, err := url.Parse(value); err == nil && parsed.Hostname() != "" { return parsed.Hostname() }
	return "configured"
}

func (a *App) encryptLegacyAlertWebhooks(ctx context.Context) error {
	rows, err := a.pg.Query(ctx, `SELECT id,webhook_url FROM alert_rules WHERE webhook_url NOT LIKE 'enc:v1:%'`)
	if err != nil { return err }
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var webhook string
		if err := rows.Scan(&id, &webhook); err != nil { return err }
		encrypted, err := a.encryptAlertWebhook(webhook)
		if err != nil { return fmt.Errorf("encrypt legacy alert webhook: %w", err) }
		if _, err := a.pg.Exec(ctx, `UPDATE alert_rules SET webhook_url=$1 WHERE id=$2`, encrypted, id); err != nil { return err }
	}
	return rows.Err()
}

type scheduledJob struct {
	cancel       context.CancelFunc
	activeCancel context.CancelFunc
	mu           sync.Mutex
	running      bool
}
type Scheduler struct {
	app    *App
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
	jobs   map[uuid.UUID]*scheduledJob
}

func NewScheduler(app *App, parent context.Context) *Scheduler {
	ctx, cancel := context.WithCancel(parent)
	return &Scheduler{app: app, ctx: ctx, cancel: cancel, jobs: map[uuid.UUID]*scheduledJob{}}
}
func (s *Scheduler) Start() error {
	rows, err := s.app.pg.Query(s.ctx, `SELECT id,schedule_interval_seconds FROM targets WHERE schedule_interval_seconds > 0 AND agent_id IS NULL`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var seconds int
		if err := rows.Scan(&id, &seconds); err != nil {
			return err
		}
		s.Upsert(id, time.Duration(seconds)*time.Second)
	}
	return rows.Err()
}
func (s *Scheduler) Upsert(targetID uuid.UUID, interval time.Duration) {
	s.mu.Lock()
	if existing := s.jobs[targetID]; existing != nil {
		existing.cancel()
		delete(s.jobs, targetID)
	}
	if interval <= 0 {
		s.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(s.ctx)
	job := &scheduledJob{cancel: cancel}
	s.jobs[targetID] = job
	s.mu.Unlock()
	go s.run(ctx, targetID, interval, job)
}
func (s *Scheduler) run(ctx context.Context, targetID uuid.UUID, interval time.Duration, job *scheduledJob) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runOnce(ctx, targetID, job)
		}
	}
}
func (s *Scheduler) runOnce(parent context.Context, targetID uuid.UUID, job *scheduledJob) {
	job.mu.Lock()
	if job.running {
		job.mu.Unlock()
		return
	}
	job.running = true
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	job.activeCancel = cancel
	job.mu.Unlock()
	defer func() { cancel(); job.mu.Lock(); job.running = false; job.activeCancel = nil; job.mu.Unlock() }()
	_, _ = s.app.execute(ctx, targetID, "scheduler")
}
func (s *Scheduler) Pause(targetID uuid.UUID) {
	s.mu.Lock()
	job := s.jobs[targetID]
	if job != nil {
		job.cancel()
		delete(s.jobs, targetID)
	}
	s.mu.Unlock()
	if job != nil {
		job.mu.Lock()
		if job.activeCancel != nil {
			job.activeCancel()
		}
		job.mu.Unlock()
	}
}
func (s *Scheduler) Stop() {
	s.cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, job := range s.jobs {
		job.cancel()
	}
	s.jobs = map[uuid.UUID]*scheduledJob{}
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cfg := config()
	pg, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		panic(err)
	}
	if err = pg.Ping(ctx); err != nil {
		panic(err)
	}
	if err = runMigrations(ctx, pg); err != nil {
		panic(err)
	}
	if err = seedAdmin(ctx, pg, cfg); err != nil {
		panic(err)
	}
	mongoClient, err := mongo.Connect(options.Client().ApplyURI(cfg.MongoURL))
	if err != nil {
		panic(err)
	}
	app := &App{pg: pg, mongoClient: mongoClient, configs: mongoClient.Database(cfg.MongoDatabase).Collection("probe_configs"), cfg: cfg, client: secureHTTPClient()}
	if err := app.encryptLegacyAlertWebhooks(ctx); err != nil {
		panic(err)
	}
	app.scheduler = NewScheduler(app, ctx)
	if err := app.scheduler.Start(); err != nil {
		panic(err)
	}
	go app.runRetention(ctx)
	r := app.router()
	server := &http.Server{Addr: ":" + cfg.Port, Handler: r}
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			panic(err)
		}
	}()
	<-ctx.Done()
	app.scheduler.Stop()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdownCtx)
}

func runMigrations(ctx context.Context, pg *pgxpool.Pool) error {
	b, err := migrations.ReadFile("migrations/001_initial.sql")
	if err != nil {
		return err
	}
	_, err = pg.Exec(ctx, string(b))
	return err
}
func seedAdmin(ctx context.Context, pg *pgxpool.Pool, cfg Config) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(cfg.AdminPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = pg.Exec(ctx, `INSERT INTO users (email,password_hash,role) VALUES ($1,$2,'admin') ON CONFLICT (email) DO UPDATE SET role='admin'`, cfg.AdminEmail, string(hash))
	return err
}

func (a *App) router() *gin.Engine {
	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery(), cors())
	r.GET("/healthz", func(c *gin.Context) { c.JSON(200, gin.H{"status": "ok"}) })
	r.GET("/readyz", func(c *gin.Context) {
		if err := a.pg.Ping(c); err != nil {
			c.JSON(503, gin.H{"status": "unready"})
			return
		}
		c.JSON(200, gin.H{"status": "ready"})
	})
	r.GET("/metrics", func(c *gin.Context) {
		c.Header("Content-Type", "text/plain; version=0.0.4")
		c.String(200, "meridian_up 1\n")
	})
	r.POST("/auth/login", a.login)
	r.GET("/auth/oidc/config", a.oidcConfig)
	r.GET("/auth/oidc/login", a.oidcLogin)
	r.GET("/auth/oidc/callback", a.oidcCallback)
	r.POST("/auth/mfa/verify", a.verifyMFAChallenge)
	r.POST("/auth/password-reset/request", a.requestPasswordReset)
	r.POST("/auth/password-reset/confirm", a.confirmPasswordReset)
	r.POST("/webhooks/deployments", a.deploymentWebhook)
	agent := r.Group("/agent/v1")
	agent.Use(a.agentAuth())
	agent.POST("/heartbeat", a.agentHeartbeat)
	agent.GET("/assignments", a.agentAssignments)
	agent.POST("/runs", a.agentRun)
	api := r.Group("/")
	api.Use(a.auth())
	api.GET("/auth/me", a.me)
	api.POST("/auth/mfa/setup", a.mfaSetup)
	api.GET("/auth/mfa/status", a.mfaStatus)
	api.POST("/auth/mfa/confirm", a.mfaConfirm)
	api.POST("/auth/mfa/disable", a.mfaDisable)
	api.POST("/auth/logout", a.logout)
	api.GET("/auth/sessions", a.listSessions)
	api.DELETE("/auth/sessions/:id", a.revokeSession)
	api.POST("/users/:id/sessions/revoke", a.requireRoles("admin"), a.audit("user.sessions_revoked", "user", "Revoked all active user sessions"), a.revokeUserSessions)
	api.GET("/audit-events", a.requireRoles("admin"), a.listAuditEvents)
	api.GET("/operations/status", a.requireRoles("admin"), a.operationsStatus)
	api.POST("/operations/retention/run", a.requireRoles("admin"), a.audit("operations.retention_run", "operations", "Ran data retention cleanup"), a.runRetentionNow)
	api.GET("/users", a.requireRoles("admin"), a.listUsers)
	api.POST("/users", a.requireRoles("admin"), a.audit("user.created", "user", "Created a user"), a.createUser)
	api.DELETE("/users/:id", a.requireRoles("admin"), a.audit("user.deleted", "user", "Deleted a user"), a.deleteUser)
	api.GET("/api-tokens", a.requireRoles("admin"), a.listAPITokens)
	api.POST("/api-tokens", a.requireRoles("admin"), a.audit("api_token.created", "api_token", "Created an integration token"), a.createAPIToken)
	api.POST("/api-tokens/:id/revoke", a.requireRoles("admin"), a.audit("api_token.revoked", "api_token", "Revoked an integration token"), a.revokeAPIToken)
	api.GET("/agents", a.requireRoles("admin"), a.listAgents)
	api.POST("/agents", a.requireRoles("admin"), a.audit("agent.created", "agent", "Created a private-network agent"), a.createAgent)
	api.DELETE("/agents/:id", a.requireRoles("admin"), a.audit("agent.revoked", "agent", "Revoked a private-network agent"), a.revokeAgent)
	api.PUT("/targets/:id/agent", a.requireRoles("admin"), a.audit("target.agent_assigned", "target", "Updated private-agent assignment"), a.assignAgent)
	api.GET("/workflows", a.listWorkflows)
	api.POST("/workflows", a.requireRoles("admin"), a.audit("workflow.created", "workflow", "Created a transaction workflow"), a.createWorkflow)
	api.DELETE("/workflows/:id", a.requireRoles("admin"), a.audit("workflow.deleted", "workflow", "Deleted a transaction workflow"), a.deleteWorkflow)
	api.POST("/workflows/:id/run", a.requireRoles("admin", "operator"), a.runWorkflow)
	api.POST("/targets", a.requireRoles("admin"), a.audit("target.created", "target", "Created a target"), a.createTarget)
	api.GET("/targets", a.listTargets)
	api.GET("/targets/:id", a.getTarget)
	api.DELETE("/targets/:id", a.requireRoles("admin"), a.audit("target.deleted", "target", "Deleted a target"), a.deleteTarget)
	api.PUT("/targets/:id/config", a.requireRoles("admin"), a.audit("target.config_updated", "target", "Updated probe configuration"), a.putConfig)
	api.PUT("/targets/:id/schedule", a.requireRoles("admin"), a.audit("target.schedule_updated", "target", "Updated probe schedule"), a.putSchedule)
	api.POST("/targets/:id/pause", a.requireRoles("admin"), a.audit("target.paused", "target", "Paused scheduled probes"), a.pauseTarget)
	api.POST("/targets/:id/probe", a.requireProbeScope("probes:run"), a.audit("target.probe_started", "target", "Started a probe"), a.runProbe)
	api.POST("/targets/:id/gate", a.requireProbeScope("gates:run"), a.audit("target.gate_started", "target", "Started a release gate"), a.gate)
	api.GET("/targets/:id/runs", a.listRuns)
	api.GET("/runs/:id", a.getRun)
	api.GET("/incidents", a.listIncidents)
	api.POST("/incidents/:id/acknowledge", a.requireRoles("admin", "operator"), a.audit("incident.acknowledged", "incident", "Acknowledged an incident"), a.acknowledgeIncident)
	api.POST("/incidents/:id/resolve", a.requireRoles("admin", "operator"), a.audit("incident.resolved", "incident", "Resolved an incident"), a.resolveIncident)
	api.GET("/alert-rules", a.listAlertRules)
	api.GET("/alert-rules/:id/deliveries", a.requireRoles("admin"), a.listAlertDeliveries)
	api.POST("/alert-rules/:id/test", a.requireRoles("admin"), a.audit("alert_rule.tested", "alert_rule", "Sent an alert test"), a.testAlertRule)
	api.GET("/analytics", a.analytics)
	api.GET("/analytics/trends", a.analyticsTrends)
	api.GET("/analytics/layers", a.analyticsLayers)
	api.GET("/targets/:id/slo", a.getSLO)
	api.PUT("/targets/:id/slo", a.requireRoles("admin"), a.audit("target.slo_updated", "target", "Updated a service-level objective"), a.putSLO)
	api.POST("/alert-rules", a.requireRoles("admin"), a.audit("alert_rule.created", "alert_rule", "Created an alert rule"), a.createAlertRule)
	api.DELETE("/alert-rules/:id", a.requireRoles("admin"), a.audit("alert_rule.deleted", "alert_rule", "Deleted an alert rule"), a.deleteAlertRule)
	return r
}
// defaultCORSOrigins lists the dashboard addresses allowed to call the API when
// CORS_ORIGIN is unset. meridian.localhost is the primary local address;
// localhost stays allowed for compatibility.
const defaultCORSOrigins = "http://meridian.localhost:5173,http://localhost:5173"

// originAllowed reports whether origin exactly matches one entry in the
// comma-separated allowlist. An empty origin (non-browser request) never matches.
func originAllowed(origin, allowlist string) bool {
	if origin == "" {
		return false
	}
	for _, value := range strings.Split(allowlist, ",") {
		if strings.TrimRight(strings.TrimSpace(value), "/") == origin {
			return true
		}
	}
	return false
}

func cors() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Vary", "Origin")
		if origin := c.GetHeader("Origin"); originAllowed(origin, getenv("CORS_ORIGIN", defaultCORSOrigins)) {
			c.Header("Access-Control-Allow-Origin", origin)
		}
		c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		if c.Request.Method == http.MethodOptions {
			c.Status(204)
			c.Abort()
			return
		}
		c.Next()
	}
}

func (a *App) auth() gin.HandlerFunc {
	return func(c *gin.Context) {
		raw := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
		if strings.HasPrefix(raw, "meridian_") {
			hash := sha256.Sum256([]byte(raw))
			var id uuid.UUID; var name string; var targetID *uuid.UUID; var scopes []string
			err := a.pg.QueryRow(c, `SELECT id,name,target_id,scopes FROM api_tokens WHERE token_hash=$1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())`, hex.EncodeToString(hash[:])).Scan(&id,&name,&targetID,&scopes)
			if err != nil { c.JSON(401,gin.H{"error":"invalid, expired, or revoked API token"}); c.Abort(); return }
			_, _ = a.pg.Exec(c, `UPDATE api_tokens SET last_used_at=now() WHERE id=$1`, id)
			c.Set("actor_email", "integration: "+name); c.Set("actor_role", "integration"); c.Set("actor_id", ""); c.Set("token_scopes", scopes)
			if targetID != nil { c.Set("token_target_id", targetID.String()) }
			if c.Request.Method != http.MethodPost || (!strings.HasSuffix(c.Request.URL.Path, "/probe") && !strings.HasSuffix(c.Request.URL.Path, "/gate")) { c.JSON(403, gin.H{"error":"API tokens can only be used for their scoped probe or release-gate action"}); c.Abort(); return }
			c.Next(); return
		}
		token, err := jwt.Parse(raw, func(t *jwt.Token) (any, error) { return []byte(a.cfg.JWTSecret), nil }, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
		if err != nil || !token.Valid {
			c.JSON(401, gin.H{"error": "unauthorized"})
			c.Abort()
			return
		}
		claims, ok := token.Claims.(jwt.MapClaims)
		_, emailOK := claims["sub"].(string)
		_, roleOK := claims["role"].(string)
		id, idOK := claims["uid"].(string)
		sessionID, sessionOK := claims["sid"].(string)
		if !ok || !emailOK || !roleOK || !idOK || !sessionOK { c.JSON(401, gin.H{"error":"unauthorized"}); c.Abort(); return }
		userID, userErr := uuid.Parse(id); sessionUUID, sessionErr := uuid.Parse(sessionID)
		if userErr != nil || sessionErr != nil { c.JSON(401, gin.H{"error":"unauthorized"}); c.Abort(); return }
		var currentEmail, currentRole string
		err = a.pg.QueryRow(c, `SELECT u.email,u.role FROM user_sessions s JOIN users u ON u.id=s.user_id WHERE s.id=$1 AND s.user_id=$2 AND s.revoked_at IS NULL AND s.expires_at>now()`, sessionUUID, userID).Scan(&currentEmail,&currentRole)
		if err != nil { c.JSON(401, gin.H{"error":"session expired or revoked"}); c.Abort(); return }
		_, _ = a.pg.Exec(c, `UPDATE user_sessions SET last_seen_at=now() WHERE id=$1`, sessionUUID)
		c.Set("actor_email", currentEmail); c.Set("actor_role", currentRole); c.Set("actor_id", id); c.Set("session_id", sessionID)
		c.Next()
	}
}
func (s *Scheduler) Stats() (int,int) { s.mu.Lock();defer s.mu.Unlock();running:=0;for _,job:=range s.jobs{job.mu.Lock();if job.running{running++};job.mu.Unlock()};return len(s.jobs),running }

func (a *App) agentAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		key := strings.TrimSpace(c.GetHeader("X-Meridian-Agent-Key"))
		if !strings.HasPrefix(key, "meridian_agent_") { c.JSON(401,gin.H{"error":"invalid agent key"}); c.Abort(); return }
		sum := sha256.Sum256([]byte(key)); var id uuid.UUID
		if a.pg.QueryRow(c, `SELECT id FROM agents WHERE key_hash=$1 AND revoked_at IS NULL`, hex.EncodeToString(sum[:])).Scan(&id) != nil { c.JSON(401,gin.H{"error":"invalid or revoked agent key"}); c.Abort(); return }
		c.Set("agent_id", id.String()); c.Next()
	}
}

func (a *App) requireProbeScope(scope string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetString("actor_role") != "integration" {
			role := c.GetString("actor_role")
			if role != "admin" && role != "operator" { c.JSON(403, gin.H{"error":"your role does not have permission for this action"}); c.Abort(); return }
			c.Next(); return
		}
		scopes, _ := c.Get("token_scopes"); allowed := false
		for _, value := range scopes.([]string) { if value == scope { allowed = true } }
		if !allowed { c.JSON(403,gin.H{"error":"API token does not include the required scope"}); c.Abort(); return }
		if scopedTarget := c.GetString("token_target_id"); scopedTarget != "" && scopedTarget != c.Param("id") { c.JSON(403,gin.H{"error":"API token is not allowed for this target"}); c.Abort(); return }
		c.Next()
	}
}

func (a *App) requireRoles(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		role, _ := c.Get("actor_role")
		for _, allowed := range roles { if role == allowed { c.Next(); return } }
		c.JSON(403, gin.H{"error":"your role does not have permission for this action"}); c.Abort()
	}
}

func (a *App) audit(action, resourceType, summary string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		if c.Writer.Status() < 200 || c.Writer.Status() >= 300 { return }
		email, _ := c.Get("actor_email"); rawID, _ := c.Get("actor_id")
		resourceID := c.Param("id")
		_, _ = a.pg.Exec(c, `INSERT INTO audit_events(actor_id,actor_email,action,resource_type,resource_id,summary) VALUES (NULLIF($1,'')::uuid,$2,$3,$4,NULLIF($5,''),$6)`, fmt.Sprint(rawID), fmt.Sprint(email), action, resourceType, resourceID, summary)
	}
}

func (a *App) me(c *gin.Context) { c.JSON(200, gin.H{"id": c.GetString("actor_id"), "email": c.GetString("actor_email"), "role": c.GetString("actor_role")}) }

func (a *App) runRetention(ctx context.Context) { a.cleanupRetention(ctx); ticker:=time.NewTicker(24*time.Hour);defer ticker.Stop();for{select{case<-ctx.Done():return;case<-ticker.C:a.cleanupRetention(ctx)}} }
func (a *App) cleanupRetention(ctx context.Context) error {
	a.retentionMu.Lock();defer a.retentionMu.Unlock();tx,err:=a.pg.Begin(ctx);if err==nil{defer tx.Rollback(ctx);cutoff:=a.cfg.RetentionDays;for _,query:=range []string{`DELETE FROM incidents i USING probe_runs r WHERE i.run_id=r.id AND r.started_at < now()-make_interval(days=>$1)`,`DELETE FROM probe_runs WHERE started_at < now()-make_interval(days=>$1)`,`DELETE FROM transaction_runs WHERE finished_at < now()-make_interval(days=>$1)`,`DELETE FROM audit_events WHERE created_at < now()-make_interval(days=>$1)`,`DELETE FROM user_sessions WHERE expires_at < now()-make_interval(days=>$1)`,`DELETE FROM password_reset_tokens WHERE expires_at < now()-make_interval(days=>$1)`}{if _,err=tx.Exec(ctx,query,cutoff);err!=nil{break}};if err==nil{err=tx.Commit(ctx)}};a.lastRetentionAt=time.Now().UTC();if err!=nil{a.lastRetentionErr=err.Error()}else{a.lastRetentionErr=""};return err
}
func (a *App) runRetentionNow(c *gin.Context) { if err:=a.cleanupRetention(c);err!=nil{c.JSON(500,gin.H{"error":"retention cleanup failed"});return};c.JSON(200,gin.H{"status":"retention cleanup completed","retention_days":a.cfg.RetentionDays}) }
func (a *App) operationsStatus(c *gin.Context) { ctx,cancel:=context.WithTimeout(c,2*time.Second);defer cancel();database:="healthy";if a.pg.Ping(ctx)!=nil{database="unhealthy"};mongoStatus:="healthy";if a.mongoClient.Ping(ctx,nil)!=nil{mongoStatus="unhealthy"};scheduled,running:=a.scheduler.Stats();var targets,alerts,agents int;_ = a.pg.QueryRow(c,`SELECT count(*) FROM targets`).Scan(&targets);_ = a.pg.QueryRow(c,`SELECT count(*) FROM alert_rules WHERE enabled=true`).Scan(&alerts);_ = a.pg.QueryRow(c,`SELECT count(*) FROM agents WHERE revoked_at IS NULL`).Scan(&agents);a.retentionMu.RLock();lastAt,lastErr:=a.lastRetentionAt,a.lastRetentionErr;a.retentionMu.RUnlock();state:="healthy";if database!="healthy"||mongoStatus!="healthy"{state="degraded"};c.JSON(200,gin.H{"status":state,"database":database,"mongo":mongoStatus,"scheduler":gin.H{"scheduled_targets":scheduled,"active_probes":running},"alerts":gin.H{"enabled_rules":alerts,"smtp_configured":a.cfg.SMTPHost!=""&&a.cfg.SMTPFrom!=""},"agents":gin.H{"active":agents},"targets":targets,"retention":gin.H{"days":a.cfg.RetentionDays,"last_run_at":lastAt,"last_error":lastErr}}) }

func (a *App) oidcEnabled() bool { return a.cfg.OIDCAuthURL!="" && a.cfg.OIDCTokenURL!="" && a.cfg.OIDCUserInfoURL!="" && a.cfg.OIDCClientID!="" && a.cfg.OIDCClientSecret!="" && a.cfg.OIDCRedirectURL!="" }
func (a *App) oidcConfig(c *gin.Context) { c.JSON(200,gin.H{"enabled":a.oidcEnabled()}) }
func (a *App) oidcLogin(c *gin.Context) {
	if !a.oidcEnabled(){c.JSON(404,gin.H{"error":"SSO is not configured"});return};raw:=make([]byte,24);if _,err:=io.ReadFull(rand.Reader,raw);err!=nil{c.JSON(500,gin.H{"error":"could not start SSO"});return};state:=base64.RawURLEncoding.EncodeToString(raw);c.SetCookie("meridian_oidc_state",state,300,"/auth/oidc","",false,true);target,err:=url.Parse(a.cfg.OIDCAuthURL);if err!=nil{c.JSON(500,gin.H{"error":"SSO configuration is invalid"});return};query:=target.Query();query.Set("response_type","code");query.Set("client_id",a.cfg.OIDCClientID);query.Set("redirect_uri",a.cfg.OIDCRedirectURL);query.Set("scope","openid profile email");query.Set("state",state);target.RawQuery=query.Encode();c.Redirect(http.StatusFound,target.String())
}
func (a *App) oidcCallback(c *gin.Context) {
	stateCookie,err:=c.Cookie("meridian_oidc_state");if err!=nil||stateCookie==""||!hmac.Equal([]byte(stateCookie),[]byte(c.Query("state"))){c.Redirect(http.StatusFound,a.cfg.DashboardURL+"/?sso_error=state");return};c.SetCookie("meridian_oidc_state","",-1,"/auth/oidc","",false,true);if c.Query("error")!=""||c.Query("code")==""{c.Redirect(http.StatusFound,a.cfg.DashboardURL+"/?sso_error=cancelled");return};form:=url.Values{"grant_type":{"authorization_code"},"code":{c.Query("code")},"redirect_uri":{a.cfg.OIDCRedirectURL},"client_id":{a.cfg.OIDCClientID},"client_secret":{a.cfg.OIDCClientSecret}};req,err:=http.NewRequestWithContext(c,http.MethodPost,a.cfg.OIDCTokenURL,strings.NewReader(form.Encode()));if err!=nil{c.Redirect(http.StatusFound,a.cfg.DashboardURL+"/?sso_error=exchange");return};req.Header.Set("Content-Type","application/x-www-form-urlencoded");resp,err:=a.client.Do(req);if err!=nil||resp.StatusCode<200||resp.StatusCode>=300{if resp!=nil{resp.Body.Close()};c.Redirect(http.StatusFound,a.cfg.DashboardURL+"/?sso_error=exchange");return};var token struct{AccessToken string `json:"access_token"`};err=json.NewDecoder(io.LimitReader(resp.Body,1024*1024)).Decode(&token);resp.Body.Close();if err!=nil||token.AccessToken==""{c.Redirect(http.StatusFound,a.cfg.DashboardURL+"/?sso_error=identity");return};userReq,err:=http.NewRequestWithContext(c,http.MethodGet,a.cfg.OIDCUserInfoURL,nil);if err!=nil{c.Redirect(http.StatusFound,a.cfg.DashboardURL+"/?sso_error=identity");return};userReq.Header.Set("Authorization","Bearer "+token.AccessToken);userResp,err:=a.client.Do(userReq);if err!=nil||userResp.StatusCode<200||userResp.StatusCode>=300{if userResp!=nil{userResp.Body.Close()};c.Redirect(http.StatusFound,a.cfg.DashboardURL+"/?sso_error=identity");return};var profile struct{Email string `json:"email"`; EmailVerified bool `json:"email_verified"`};err=json.NewDecoder(io.LimitReader(userResp.Body,1024*1024)).Decode(&profile);userResp.Body.Close();email:=strings.ToLower(strings.TrimSpace(profile.Email));if err!=nil||email==""||!profile.EmailVerified{c.Redirect(http.StatusFound,a.cfg.DashboardURL+"/?sso_error=identity");return};var userID uuid.UUID;var role string;err=a.pg.QueryRow(c,`SELECT id,role FROM users WHERE lower(email)=lower($1)`,email).Scan(&userID,&role);if err!=nil{if !a.cfg.OIDCAutoProvision{c.Redirect(http.StatusFound,a.cfg.DashboardURL+"/?sso_error=access");return};role=a.cfg.OIDCDefaultRole;if role!="admin"&&role!="operator"&&role!="viewer"{role="viewer"};random:=make([]byte,32);_,_=io.ReadFull(rand.Reader,random);hash,_:=bcrypt.GenerateFromPassword(random,bcrypt.DefaultCost);if a.pg.QueryRow(c,`INSERT INTO users(email,password_hash,role) VALUES($1,$2,$3) RETURNING id`,email,string(hash),role).Scan(&userID)!=nil{c.Redirect(http.StatusFound,a.cfg.DashboardURL+"/?sso_error=access");return}};expiresAt:=time.Now().Add(time.Duration(a.cfg.SessionHours)*time.Hour);var sessionID uuid.UUID;if a.pg.QueryRow(c,`INSERT INTO user_sessions(user_id,expires_at) VALUES($1,$2) RETURNING id`,userID,expiresAt).Scan(&sessionID)!=nil{c.Redirect(http.StatusFound,a.cfg.DashboardURL+"/?sso_error=session");return};session:=jwt.NewWithClaims(jwt.SigningMethodHS256,jwt.MapClaims{"sub":email,"uid":userID.String(),"sid":sessionID.String(),"role":role,"exp":expiresAt.Unix()});signed,_:=session.SignedString([]byte(a.cfg.JWTSecret));c.Redirect(http.StatusFound,a.cfg.DashboardURL+"/?sso_token="+url.QueryEscape(signed))
}

func (a *App) listAuditEvents(c *gin.Context) {
	rows, err := a.pg.Query(c, `SELECT id,actor_email,action,resource_type,resource_id,summary,created_at FROM audit_events ORDER BY created_at DESC LIMIT 100`)
	if err != nil { c.JSON(500, gin.H{"error":"could not load audit history"}); return }; defer rows.Close()
	out := []gin.H{}
	for rows.Next() { var id uuid.UUID; var actor, action, resourceType, summary string; var resourceID *string; var at time.Time; if rows.Scan(&id,&actor,&action,&resourceType,&resourceID,&summary,&at)==nil { out=append(out,gin.H{"id":id,"actor_email":actor,"action":action,"resource_type":resourceType,"resource_id":resourceID,"summary":summary,"created_at":at}) } }
	c.JSON(200, out)
}

func (a *App) createUser(c *gin.Context) {
	var in struct { Email, Password, Role string }
	if c.ShouldBindJSON(&in)!=nil || strings.TrimSpace(in.Email)=="" || len(in.Password)<12 || (in.Role!="admin" && in.Role!="operator" && in.Role!="viewer") { c.JSON(400,gin.H{"error":"email, a password of at least 12 characters, and role admin, operator, or viewer are required"}); return }
	hash, err := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost); if err!=nil { c.JSON(500,gin.H{"error":"could not create user"}); return }
	var id uuid.UUID; err=a.pg.QueryRow(c,`INSERT INTO users(email,password_hash,role) VALUES($1,$2,$3) RETURNING id`,strings.TrimSpace(in.Email),string(hash),in.Role).Scan(&id); if err!=nil { c.JSON(409,gin.H{"error":"a user with that email already exists"}); return }; c.JSON(201,gin.H{"id":id,"email":strings.TrimSpace(in.Email),"role":in.Role})
}
func (a *App) listUsers(c *gin.Context) {
	rows, err := a.pg.Query(c, `SELECT id,email,role,created_at FROM users ORDER BY email`); if err != nil { c.JSON(500,gin.H{"error":"could not load users"}); return }; defer rows.Close()
	out:=[]gin.H{}; for rows.Next(){var id uuid.UUID;var email,role string;var created time.Time;if rows.Scan(&id,&email,&role,&created)==nil{out=append(out,gin.H{"id":id,"email":email,"role":role,"created_at":created})}};c.JSON(200,out)
}
func (a *App) deleteUser(c *gin.Context) {
	id, ok := parseID(c); if !ok { return }
	actorID, err := uuid.Parse(c.GetString("actor_id")); if err != nil { c.JSON(401,gin.H{"error":"unauthorized"}); return }
	tag, err := a.pg.Exec(c, `DELETE FROM users WHERE id=$1 AND id<>$2`, id, actorID)
	if err != nil { c.JSON(500,gin.H{"error":"could not delete user"}); return }
	if tag.RowsAffected()==0 { c.JSON(400,gin.H{"error":"you cannot delete your own account, or the user no longer exists"}); return }
	c.Status(204)
}
func (a *App) listAPITokens(c *gin.Context) {
	rows, err := a.pg.Query(c, `SELECT id,name,target_id,scopes,expires_at,revoked_at,last_used_at,created_at FROM api_tokens ORDER BY created_at DESC`); if err != nil { c.JSON(500,gin.H{"error":"could not load API tokens"}); return }; defer rows.Close()
	out:=[]gin.H{}; for rows.Next(){var id uuid.UUID;var name string;var targetID *uuid.UUID;var scopes []string;var expires,revoked,used *time.Time;var created time.Time;if rows.Scan(&id,&name,&targetID,&scopes,&expires,&revoked,&used,&created)==nil{out=append(out,gin.H{"id":id,"name":name,"target_id":targetID,"scopes":scopes,"expires_at":expires,"revoked_at":revoked,"last_used_at":used,"created_at":created})}};c.JSON(200,out)
}
func (a *App) listAgents(c *gin.Context) {
	rows, err := a.pg.Query(c, `SELECT a.id,a.name,a.last_seen_at,a.revoked_at,a.created_at,COUNT(t.id) FROM agents a LEFT JOIN targets t ON t.agent_id=a.id GROUP BY a.id ORDER BY a.created_at DESC`); if err != nil { c.JSON(500,gin.H{"error":"could not load agents"}); return }; defer rows.Close()
	out:=[]gin.H{};for rows.Next(){var id uuid.UUID;var name string;var seen,revoked *time.Time;var created time.Time;var targets int;if rows.Scan(&id,&name,&seen,&revoked,&created,&targets)==nil{out=append(out,gin.H{"id":id,"name":name,"last_seen_at":seen,"revoked_at":revoked,"created_at":created,"assigned_targets":targets})}};c.JSON(200,out)
}
func (a *App) createAgent(c *gin.Context) {
	var in struct { Name string `json:"name"` };if c.ShouldBindJSON(&in)!=nil||strings.TrimSpace(in.Name)==""{c.JSON(400,gin.H{"error":"agent name is required"});return}
	bytes:=make([]byte,32);if _,err:=io.ReadFull(rand.Reader,bytes);err!=nil{c.JSON(500,gin.H{"error":"could not generate agent key"});return};key:="meridian_agent_"+base64.RawURLEncoding.EncodeToString(bytes);sum:=sha256.Sum256([]byte(key));var id uuid.UUID;err:=a.pg.QueryRow(c,`INSERT INTO agents(name,key_hash) VALUES($1,$2) RETURNING id`,strings.TrimSpace(in.Name),hex.EncodeToString(sum[:])).Scan(&id);if err!=nil{c.JSON(409,gin.H{"error":"agent name is already in use"});return};c.JSON(201,gin.H{"id":id,"name":strings.TrimSpace(in.Name),"agent_key":key})
}
func (a *App) revokeAgent(c *gin.Context) { id,ok:=parseID(c);if !ok{return};tag,err:=a.pg.Exec(c,`UPDATE agents SET revoked_at=now() WHERE id=$1 AND revoked_at IS NULL`,id);if err!=nil{c.JSON(500,gin.H{"error":"could not revoke agent"});return};if tag.RowsAffected()==0{c.JSON(404,gin.H{"error":"active agent not found"});return};c.Status(204) }
func (a *App) assignAgent(c *gin.Context) { targetID,ok:=parseID(c);if !ok{return};var in struct{AgentID string `json:"agent_id"`};if c.ShouldBindJSON(&in)!=nil{c.JSON(400,gin.H{"error":"agent_id is required; use an empty value to unassign"});return};var agentID *uuid.UUID;if strings.TrimSpace(in.AgentID)!=""{parsed,err:=uuid.Parse(in.AgentID);if err!=nil{c.JSON(400,gin.H{"error":"agent_id must be a UUID"});return};var active bool;if a.pg.QueryRow(c,`SELECT EXISTS(SELECT 1 FROM agents WHERE id=$1 AND revoked_at IS NULL)`,parsed).Scan(&active)!=nil||!active{c.JSON(404,gin.H{"error":"active agent not found"});return};agentID=&parsed};var interval int;err:=a.pg.QueryRow(c,`UPDATE targets SET agent_id=$1 WHERE id=$2 RETURNING schedule_interval_seconds`,agentID,targetID).Scan(&interval);if err!=nil{c.JSON(404,gin.H{"error":"target not found"});return};if agentID!=nil{a.scheduler.Pause(targetID)}else{a.scheduler.Upsert(targetID,time.Duration(interval)*time.Second)};c.JSON(200,gin.H{"target_id":targetID,"agent_id":agentID}) }
func (a *App) agentHeartbeat(c *gin.Context) { id,_:=uuid.Parse(c.GetString("agent_id"));_,_ = a.pg.Exec(c,`UPDATE agents SET last_seen_at=now() WHERE id=$1`,id);c.JSON(200,gin.H{"status":"connected","agent_id":id}) }
func (a *App) agentAssignments(c *gin.Context) { id,_:=uuid.Parse(c.GetString("agent_id"));_,_ = a.pg.Exec(c,`UPDATE agents SET last_seen_at=now() WHERE id=$1`,id);rows,err:=a.pg.Query(c,`SELECT id,name,base_url,type,schedule_interval_seconds FROM targets WHERE agent_id=$1 ORDER BY name`,id);if err!=nil{c.JSON(500,gin.H{"error":"could not load assignments"});return};defer rows.Close();out:=[]gin.H{};for rows.Next(){var t Target;if rows.Scan(&t.ID,&t.Name,&t.BaseURL,&t.Type,&t.ScheduleIntervalSeconds)==nil{cfg,err:=a.getConfig(c,t.ID);if err==nil{out=append(out,gin.H{"target":t,"config":cfg})}}};c.JSON(200,gin.H{"agent_id":id,"assignments":out}) }
func (a *App) agentRun(c *gin.Context) {
	agentID, _ := uuid.Parse(c.GetString("agent_id"))
	var in struct { TargetID uuid.UUID `json:"target_id"`; StartedAt time.Time `json:"started_at"`; FinishedAt time.Time `json:"finished_at"`; OverallStatus string `json:"overall_status"`; Results []LayerResult `json:"results"` }
	if c.ShouldBindJSON(&in)!=nil || in.TargetID==uuid.Nil || (in.OverallStatus!="pass" && in.OverallStatus!="fail") || len(in.Results)!=4 { c.JSON(400,gin.H{"error":"target_id, pass/fail status, and four layer results are required"});return }
	var assigned bool;if a.pg.QueryRow(c,`SELECT EXISTS(SELECT 1 FROM targets WHERE id=$1 AND agent_id=$2)`,in.TargetID,agentID).Scan(&assigned)!=nil||!assigned{c.JSON(403,gin.H{"error":"target is not assigned to this agent"});return}
	if in.StartedAt.IsZero(){in.StartedAt=time.Now().UTC()};if in.FinishedAt.IsZero(){in.FinishedAt=time.Now().UTC()}
	var runID uuid.UUID;err:=a.pg.QueryRow(c,`INSERT INTO probe_runs(target_id,triggered_by,started_at,finished_at,overall_status) VALUES($1,$2,$3,$4,$5) RETURNING id`,in.TargetID,"agent:"+agentID.String(),in.StartedAt,in.FinishedAt,in.OverallStatus).Scan(&runID);if err!=nil{c.JSON(500,gin.H{"error":"could not record agent run"});return}
	for _, result := range in.Results { var diagnostics any;if result.Diagnostics!=nil{b,_:=json.Marshal(result.Diagnostics);diagnostics=string(b)};if _,err:=a.pg.Exec(c,`INSERT INTO probe_results(run_id,layer,status,latency_ms,error_msg,checked_at,diagnostics) VALUES($1,$2,$3,$4,$5,$6,$7)`,runID,result.Layer,result.Status,result.LatencyMS,result.ErrorMessage,result.CheckedAt,diagnostics);err!=nil{c.JSON(500,gin.H{"error":"could not record agent result"});return} }
	if in.OverallStatus=="fail"{for _,result:=range in.Results{if result.Status=="fail"{if incidentID,_,err:=a.attribute(c,in.TargetID,runID,result.Layer);err==nil{a.dispatchAlerts(c,incidentID)};break}}}else{_,_=a.pg.Exec(c,`UPDATE incidents SET status='resolved',resolved_at=$1,last_seen_at=$1 WHERE target_id=$2 AND status IN ('open','acknowledged')`,in.FinishedAt,in.TargetID)}
	_,_=a.pg.Exec(c,`UPDATE agents SET last_seen_at=now() WHERE id=$1`,agentID);c.JSON(201,gin.H{"id":runID})
}
type WorkflowStep struct { Name string `json:"name"`; Method string `json:"method"`; Path string `json:"path"`; Body string `json:"body"`; SaveAs string `json:"save_as"`; ExpectedStatus int `json:"expected_status"` }
func (a *App) listWorkflows(c *gin.Context) { rows,err:=a.pg.Query(c,`SELECT w.id,w.target_id,w.name,w.steps,w.created_at,t.name FROM transaction_workflows w JOIN targets t ON t.id=w.target_id ORDER BY w.created_at DESC`);if err!=nil{c.JSON(500,gin.H{"error":"could not load workflows"});return};defer rows.Close();out:=[]gin.H{};for rows.Next(){var id,tid uuid.UUID;var name,target string;var steps []byte;var at time.Time;if rows.Scan(&id,&tid,&name,&steps,&at,&target)==nil{out=append(out,gin.H{"id":id,"target_id":tid,"target_name":target,"name":name,"steps":json.RawMessage(steps),"created_at":at})}};c.JSON(200,out) }
func (a *App) createWorkflow(c *gin.Context) { var in struct{TargetID string `json:"target_id"`;Name string `json:"name"`;Steps []WorkflowStep `json:"steps"`};if c.ShouldBindJSON(&in)!=nil||strings.TrimSpace(in.Name)==""||len(in.Steps)==0{c.JSON(400,gin.H{"error":"target_id, name, and at least one step are required"});return};tid,err:=uuid.Parse(in.TargetID);if err!=nil{c.JSON(400,gin.H{"error":"target_id must be a UUID"});return};for _,s:=range in.Steps{if s.Path==""{c.JSON(400,gin.H{"error":"every workflow step needs a path"});return}};steps,_:=json.Marshal(in.Steps);var id uuid.UUID;err=a.pg.QueryRow(c,`INSERT INTO transaction_workflows(target_id,name,steps) VALUES($1,$2,$3) RETURNING id`,tid,strings.TrimSpace(in.Name),steps).Scan(&id);if err!=nil{c.JSON(500,gin.H{"error":"could not save workflow"});return};c.JSON(201,gin.H{"id":id}) }
func (a *App) deleteWorkflow(c *gin.Context) {id,ok:=parseID(c);if !ok{return};tag,err:=a.pg.Exec(c,`DELETE FROM transaction_workflows WHERE id=$1`,id);if err!=nil{c.JSON(500,gin.H{"error":"could not delete workflow"});return};if tag.RowsAffected()==0{c.JSON(404,gin.H{"error":"workflow not found"});return};c.Status(204)}
func (a *App) runWorkflow(c *gin.Context) { id,ok:=parseID(c);if !ok{return};var tid uuid.UUID;var raw []byte;if err:=a.pg.QueryRow(c,`SELECT target_id,steps FROM transaction_workflows WHERE id=$1`,id).Scan(&tid,&raw);err!=nil{c.JSON(404,gin.H{"error":"workflow not found"});return};var steps []WorkflowStep;if json.Unmarshal(raw,&steps)!=nil{c.JSON(500,gin.H{"error":"workflow is invalid"});return};t,err:=a.target(c,tid);if err!=nil{c.JSON(404,gin.H{"error":"target not found"});return};started:=time.Now().UTC();vars:=map[string]string{};results:=[]gin.H{};status:="pass";for i,s:=range steps{method:=s.Method;if method==""{method="GET"};path:=replaceVars(s.Path,vars);endpoint:=strings.TrimRight(t.BaseURL,"/")+"/"+strings.TrimLeft(path,"/");req,err:=http.NewRequestWithContext(c,method,endpoint,strings.NewReader(replaceVars(s.Body,vars)));if err!=nil{status="fail";results=append(results,gin.H{"step":i+1,"name":s.Name,"status":"fail","error":err.Error()});break};if s.Body!=""{req.Header.Set("Content-Type","application/json")};resp,err:=a.client.Do(req);if err!=nil{status="fail";results=append(results,gin.H{"step":i+1,"name":s.Name,"status":"fail","error":err.Error()});break};var data map[string]any;_ = json.NewDecoder(resp.Body).Decode(&data);resp.Body.Close();expected:=s.ExpectedStatus;if expected==0{expected=200};if resp.StatusCode!=expected{status="fail";results=append(results,gin.H{"step":i+1,"name":s.Name,"status":"fail","expected_status":expected,"actual_status":resp.StatusCode});break};if s.SaveAs!=""{for k,v:=range data{vars[s.SaveAs+"."+k]=fmt.Sprint(v)}};results=append(results,gin.H{"step":i+1,"name":s.Name,"status":"pass","status_code":resp.StatusCode})};finished:=time.Now().UTC();encoded,_:=json.Marshal(results);_,_=a.pg.Exec(c,`INSERT INTO transaction_runs(workflow_id,started_at,finished_at,status,results) VALUES($1,$2,$3,$4,$5)`,id,started,finished,status,encoded);c.JSON(201,gin.H{"workflow_id":id,"status":status,"started_at":started,"finished_at":finished,"results":results}) }
func replaceVars(value string, vars map[string]string) string { for key,item:=range vars{value=strings.ReplaceAll(value,"{{"+key+"}}",item)};return value }
func (a *App) createAPIToken(c *gin.Context) {
	var in struct { Name, TargetID, ExpiresAt string `json:"-"`; Scopes []string `json:"scopes"` }
	var raw map[string]any; if c.ShouldBindJSON(&raw)!=nil { c.JSON(400,gin.H{"error":"invalid API token"}); return }; in.Name,_=raw["name"].(string);in.TargetID,_=raw["target_id"].(string);in.ExpiresAt,_=raw["expires_at"].(string);if values,ok:=raw["scopes"].([]any);ok{for _,v:=range values{if value,ok:=v.(string);ok{in.Scopes=append(in.Scopes,value)}}}
	if strings.TrimSpace(in.Name)=="" || len(in.Scopes)==0 { c.JSON(400,gin.H{"error":"name and at least one scope are required"}); return }
	allowed:=map[string]bool{"probes:run":true,"gates:run":true};for _,scope:=range in.Scopes{if !allowed[scope]{c.JSON(400,gin.H{"error":"unsupported token scope"});return}}
	var targetID *uuid.UUID;if strings.TrimSpace(in.TargetID)!=""{parsed,err:=uuid.Parse(in.TargetID);if err!=nil{c.JSON(400,gin.H{"error":"target_id must be a UUID"});return};targetID=&parsed}
	var expiresAt *time.Time;if strings.TrimSpace(in.ExpiresAt)!=""{parsed,err:=time.Parse(time.RFC3339,in.ExpiresAt);if err!=nil||!parsed.After(time.Now()){c.JSON(400,gin.H{"error":"expires_at must be a future ISO timestamp"});return};expiresAt=&parsed}
	bytes:=make([]byte,32);if _,err:=io.ReadFull(rand.Reader,bytes);err!=nil{c.JSON(500,gin.H{"error":"could not generate API token"});return};plain:="meridian_"+base64.RawURLEncoding.EncodeToString(bytes);sum:=sha256.Sum256([]byte(plain));var id uuid.UUID;err:=a.pg.QueryRow(c,`INSERT INTO api_tokens(name,token_hash,target_id,scopes,expires_at,created_by) VALUES($1,$2,$3,$4,$5,NULLIF($6,'')::uuid) RETURNING id`,strings.TrimSpace(in.Name),hex.EncodeToString(sum[:]),targetID,in.Scopes,expiresAt,c.GetString("actor_id")).Scan(&id);if err!=nil{c.JSON(500,gin.H{"error":"could not create API token"});return};c.JSON(201,gin.H{"id":id,"name":strings.TrimSpace(in.Name),"token":plain,"scopes":in.Scopes,"target_id":targetID,"expires_at":expiresAt})
}
func (a *App) revokeAPIToken(c *gin.Context) { id,ok:=parseID(c);if !ok{return};tag,err:=a.pg.Exec(c,`UPDATE api_tokens SET revoked_at=now() WHERE id=$1 AND revoked_at IS NULL`,id);if err!=nil{c.JSON(500,gin.H{"error":"could not revoke API token"});return};if tag.RowsAffected()==0{c.JSON(404,gin.H{"error":"active API token not found"});return};c.JSON(200,gin.H{"status":"revoked"}) }
func (a *App) login(c *gin.Context) {
	var in struct {
		Email string `json:"email"`
		Password string `json:"password"`
	}
	if c.ShouldBindJSON(&in) != nil {
		c.JSON(400, gin.H{"error": "email and password are required"})
		return
	}
	var hash, role string; var mfaEnabled bool
	var userID uuid.UUID
	err := a.pg.QueryRow(c, `SELECT id,password_hash,role,mfa_enabled FROM users WHERE email=$1`, in.Email).Scan(&userID, &hash, &role,&mfaEnabled)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(hash), []byte(in.Password)) != nil {
		c.JSON(401, gin.H{"error": "invalid credentials"})
		return
	}
	if mfaEnabled { challenge:=jwt.NewWithClaims(jwt.SigningMethodHS256,jwt.MapClaims{"typ":"mfa","uid":userID.String(),"exp":time.Now().Add(5*time.Minute).Unix()});signed,_:=challenge.SignedString([]byte(a.cfg.JWTSecret));c.JSON(200,gin.H{"mfa_required":true,"challenge":signed});return }
	expiresAt := time.Now().Add(time.Duration(a.cfg.SessionHours) * time.Hour)
	var sessionID uuid.UUID
	if err := a.pg.QueryRow(c, `INSERT INTO user_sessions(user_id,expires_at) VALUES($1,$2) RETURNING id`, userID, expiresAt).Scan(&sessionID); err != nil { c.JSON(500, gin.H{"error":"could not create session"}); return }
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": in.Email, "uid": userID.String(), "sid": sessionID.String(), "role": role, "exp": expiresAt.Unix()})
	signed, _ := t.SignedString([]byte(a.cfg.JWTSecret))
	c.JSON(200, gin.H{"token": signed, "expires_at": expiresAt, "user": gin.H{"id":userID,"email":in.Email,"role":role}})
}

func mfaChallenge(token, secret string) (uuid.UUID, error) {
	parsed,err:=jwt.Parse(token,func(t *jwt.Token)(any,error){return []byte(secret),nil},jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}));if err!=nil||!parsed.Valid{return uuid.Nil,errors.New("invalid MFA challenge")};claims,ok:=parsed.Claims.(jwt.MapClaims);if !ok||claims["typ"]!="mfa"{return uuid.Nil,errors.New("invalid MFA challenge")};id,ok:=claims["uid"].(string);if !ok{return uuid.Nil,errors.New("invalid MFA challenge")};return uuid.Parse(id)
}

func randomRecoveryCode() (string,error) { bytes:=make([]byte,6);if _,err:=io.ReadFull(rand.Reader,bytes);err!=nil{return "",err};return strings.ToUpper(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(bytes)),nil }

func (a *App) verifyMFAForUser(ctx context.Context, userID uuid.UUID, code string) bool {
	var encrypted string;if a.pg.QueryRow(ctx,`SELECT mfa_secret FROM users WHERE id=$1 AND mfa_enabled=true`,userID).Scan(&encrypted)!=nil{return false};secret,err:=a.decryptMFASecret(encrypted);if err==nil&&validTOTP(secret,code){return true};sum:=sha256.Sum256([]byte(strings.ToUpper(strings.TrimSpace(code))));var id uuid.UUID;return a.pg.QueryRow(ctx,`UPDATE mfa_recovery_codes SET used_at=now() WHERE user_id=$1 AND code_hash=$2 AND used_at IS NULL RETURNING id`,userID,hex.EncodeToString(sum[:])).Scan(&id)==nil
}

func (a *App) verifyMFAChallenge(c *gin.Context) {
	var in struct{ Challenge string `json:"challenge"`; Code string `json:"code"` };if c.ShouldBindJSON(&in)!=nil{c.JSON(400,gin.H{"error":"challenge and authentication code are required"});return};userID,err:=mfaChallenge(in.Challenge,a.cfg.JWTSecret);if err!=nil||!a.verifyMFAForUser(c,userID,in.Code){c.JSON(401,gin.H{"error":"invalid or expired authentication code"});return};var email,role string;if a.pg.QueryRow(c,`SELECT email,role FROM users WHERE id=$1`,userID).Scan(&email,&role)!=nil{c.JSON(401,gin.H{"error":"invalid authentication challenge"});return};expiresAt:=time.Now().Add(time.Duration(a.cfg.SessionHours)*time.Hour);var sessionID uuid.UUID;if a.pg.QueryRow(c,`INSERT INTO user_sessions(user_id,expires_at) VALUES($1,$2) RETURNING id`,userID,expiresAt).Scan(&sessionID)!=nil{c.JSON(500,gin.H{"error":"could not create session"});return};session:=jwt.NewWithClaims(jwt.SigningMethodHS256,jwt.MapClaims{"sub":email,"uid":userID.String(),"sid":sessionID.String(),"role":role,"exp":expiresAt.Unix()});signed,_:=session.SignedString([]byte(a.cfg.JWTSecret));c.JSON(200,gin.H{"token":signed,"expires_at":expiresAt,"user":gin.H{"id":userID,"email":email,"role":role}})
}

func (a *App) mfaSetup(c *gin.Context) { bytes:=make([]byte,20);if _,err:=io.ReadFull(rand.Reader,bytes);err!=nil{c.JSON(500,gin.H{"error":"could not create MFA secret"});return};secret:=base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(bytes);encrypted,err:=a.encryptMFASecret(secret);if err!=nil{c.JSON(500,gin.H{"error":"could not protect MFA secret"});return};if _,err=a.pg.Exec(c,`UPDATE users SET mfa_secret=$1,mfa_enabled=false WHERE id=$2`,encrypted,c.GetString("actor_id"));err!=nil{c.JSON(500,gin.H{"error":"could not save MFA setup"});return};label:=url.QueryEscape("Meridian:"+c.GetString("actor_email"));c.JSON(200,gin.H{"secret":secret,"otpauth_url":"otpauth://totp/"+label+"?secret="+secret+"&issuer=Meridian&algorithm=SHA1&digits=6&period=30"}) }

func (a *App) mfaStatus(c *gin.Context) { var enabled bool;if a.pg.QueryRow(c,`SELECT mfa_enabled FROM users WHERE id=$1`,c.GetString("actor_id")).Scan(&enabled)!=nil{c.JSON(500,gin.H{"error":"could not load MFA status"});return};c.JSON(200,gin.H{"enabled":enabled}) }

func (a *App) mfaConfirm(c *gin.Context) { var in struct{Code string `json:"code"`};if c.ShouldBindJSON(&in)!=nil{c.JSON(400,gin.H{"error":"authentication code is required"});return};userID,_:=uuid.Parse(c.GetString("actor_id"));var encrypted string;if a.pg.QueryRow(c,`SELECT mfa_secret FROM users WHERE id=$1`,userID).Scan(&encrypted)!=nil{c.JSON(400,gin.H{"error":"start MFA setup first"});return};secret,err:=a.decryptMFASecret(encrypted);if err!=nil||!validTOTP(secret,in.Code){c.JSON(400,gin.H{"error":"invalid authentication code"});return};codes:=[]string{};tx,err:=a.pg.Begin(c);if err!=nil{c.JSON(500,gin.H{"error":"could not enable MFA"});return};defer tx.Rollback(c);if _,err=tx.Exec(c,`DELETE FROM mfa_recovery_codes WHERE user_id=$1`,userID);err!=nil{c.JSON(500,gin.H{"error":"could not enable MFA"});return};for i:=0;i<10;i++{code,err:=randomRecoveryCode();if err!=nil{c.JSON(500,gin.H{"error":"could not enable MFA"});return};sum:=sha256.Sum256([]byte(code));if _,err=tx.Exec(c,`INSERT INTO mfa_recovery_codes(user_id,code_hash) VALUES($1,$2)`,userID,hex.EncodeToString(sum[:]));err!=nil{c.JSON(500,gin.H{"error":"could not enable MFA"});return};codes=append(codes,code)};if _,err=tx.Exec(c,`UPDATE users SET mfa_enabled=true WHERE id=$1`,userID);err!=nil{c.JSON(500,gin.H{"error":"could not enable MFA"});return};if err=tx.Commit(c);err!=nil{c.JSON(500,gin.H{"error":"could not enable MFA"});return};c.JSON(200,gin.H{"status":"MFA enabled","recovery_codes":codes}) }

func (a *App) mfaDisable(c *gin.Context) { var in struct{Code string `json:"code"`};if c.ShouldBindJSON(&in)!=nil{c.JSON(400,gin.H{"error":"authentication code is required"});return};userID,_:=uuid.Parse(c.GetString("actor_id"));if !a.verifyMFAForUser(c,userID,in.Code){c.JSON(401,gin.H{"error":"invalid authentication code"});return};_,err:=a.pg.Exec(c,`UPDATE users SET mfa_enabled=false,mfa_secret=NULL WHERE id=$1`,userID);if err!=nil{c.JSON(500,gin.H{"error":"could not disable MFA"});return};_,_=a.pg.Exec(c,`DELETE FROM mfa_recovery_codes WHERE user_id=$1`,userID);c.JSON(200,gin.H{"status":"MFA disabled"}) }

func (a *App) sendEmail(to []string, subject, body string) error {
	if a.cfg.SMTPHost == "" || a.cfg.SMTPFrom == "" { return errors.New("SMTP is not configured") }
	message := fmt.Sprintf("To: %s\r\nFrom: %s\r\nSubject: %s\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s", strings.Join(to, ","), a.cfg.SMTPFrom, subject, body)
	var auth smtp.Auth
	if a.cfg.SMTPUsername != "" { auth = smtp.PlainAuth("", a.cfg.SMTPUsername, a.cfg.SMTPPassword, a.cfg.SMTPHost) }
	return smtp.SendMail(net.JoinHostPort(a.cfg.SMTPHost, a.cfg.SMTPPort), auth, a.cfg.SMTPFrom, to, []byte(message))
}

func (a *App) requestPasswordReset(c *gin.Context) {
	var in struct { Email string `json:"email"` }
	if c.ShouldBindJSON(&in) != nil || strings.TrimSpace(in.Email)=="" { c.JSON(400, gin.H{"error":"email is required"}); return }
	if a.cfg.SMTPHost=="" || a.cfg.SMTPFrom=="" { c.JSON(503, gin.H{"error":"password reset email is not configured"}); return }
	email := strings.ToLower(strings.TrimSpace(in.Email)); var userID uuid.UUID
	err := a.pg.QueryRow(c, `SELECT id FROM users WHERE lower(email)=lower($1)`, email).Scan(&userID)
	if err == nil {
		bytes := make([]byte,32); if _, err := io.ReadFull(rand.Reader,bytes); err != nil { c.JSON(500,gin.H{"error":"could not create password reset"}); return }
		plain := "meridian_reset_"+base64.RawURLEncoding.EncodeToString(bytes); sum:=sha256.Sum256([]byte(plain))
		_, _ = a.pg.Exec(c, `UPDATE password_reset_tokens SET used_at=now() WHERE user_id=$1 AND used_at IS NULL`, userID)
		_, err = a.pg.Exec(c, `INSERT INTO password_reset_tokens(user_id,token_hash,expires_at) VALUES($1,$2,now()+interval '30 minutes')`, userID, hex.EncodeToString(sum[:]))
		if err != nil { c.JSON(500,gin.H{"error":"could not create password reset"}); return }
		resetURL := a.cfg.DashboardURL+"/?reset_token="+url.QueryEscape(plain)
		if err = a.sendEmail([]string{email}, "Meridian password reset", "A password reset was requested for your Meridian account.\n\nSet a new password within 30 minutes:\n"+resetURL+"\n\nIf you did not request this, you can ignore this email."); err != nil { c.JSON(502,gin.H{"error":"could not deliver password reset email"}); return }
	}
	// Always use the same success response after SMTP is confirmed, preventing account enumeration.
	c.JSON(202, gin.H{"status":"If an account exists for that email, a reset link has been sent."})
}

func (a *App) confirmPasswordReset(c *gin.Context) {
	var in struct { Token string `json:"token"`; Password string `json:"password"` }
	if c.ShouldBindJSON(&in)!=nil || !strings.HasPrefix(in.Token,"meridian_reset_") || len(in.Password)<12 { c.JSON(400,gin.H{"error":"a valid reset token and a password of at least 12 characters are required"}); return }
	hash,err:=bcrypt.GenerateFromPassword([]byte(in.Password),bcrypt.DefaultCost); if err!=nil { c.JSON(500,gin.H{"error":"could not update password"}); return }
	tx,err:=a.pg.Begin(c); if err!=nil { c.JSON(500,gin.H{"error":"could not update password"}); return }; defer tx.Rollback(c)
	sum:=sha256.Sum256([]byte(in.Token)); var userID uuid.UUID
	err=tx.QueryRow(c, `UPDATE password_reset_tokens SET used_at=now() WHERE token_hash=$1 AND used_at IS NULL AND expires_at>now() RETURNING user_id`, hex.EncodeToString(sum[:])).Scan(&userID)
	if err != nil { c.JSON(400,gin.H{"error":"reset link is invalid or expired"}); return }
	if _,err=tx.Exec(c, `UPDATE users SET password_hash=$1 WHERE id=$2`,string(hash),userID);err!=nil { c.JSON(500,gin.H{"error":"could not update password"});return }
	if _,err=tx.Exec(c, `UPDATE user_sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL`,userID);err!=nil { c.JSON(500,gin.H{"error":"could not update password"});return }
	if err=tx.Commit(c);err!=nil { c.JSON(500,gin.H{"error":"could not update password"});return }
	c.JSON(200,gin.H{"status":"password updated; please sign in"})
}

func (a *App) logout(c *gin.Context) {
	sessionID, err := uuid.Parse(c.GetString("session_id")); if err != nil { c.JSON(401, gin.H{"error":"unauthorized"}); return }
	_, err = a.pg.Exec(c, `UPDATE user_sessions SET revoked_at=now() WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL`, sessionID, c.GetString("actor_id"))
	if err != nil { c.JSON(500, gin.H{"error":"could not end session"}); return }
	c.JSON(200, gin.H{"status":"signed out"})
}

func (a *App) listSessions(c *gin.Context) {
	rows, err := a.pg.Query(c, `SELECT id,created_at,expires_at,last_seen_at,revoked_at FROM user_sessions WHERE user_id=$1 ORDER BY created_at DESC LIMIT 20`, c.GetString("actor_id"))
	if err != nil { c.JSON(500, gin.H{"error":"could not load sessions"}); return }; defer rows.Close()
	items := []gin.H{}
	for rows.Next() { var id uuid.UUID; var createdAt, expiresAt, lastSeenAt time.Time; var revokedAt *time.Time; if rows.Scan(&id,&createdAt,&expiresAt,&lastSeenAt,&revokedAt)==nil { items=append(items,gin.H{"id":id,"created_at":createdAt,"expires_at":expiresAt,"last_seen_at":lastSeenAt,"revoked_at":revokedAt,"current":id.String()==c.GetString("session_id")}) } }
	c.JSON(200, items)
}

func (a *App) revokeSession(c *gin.Context) {
	id, ok := parseID(c); if !ok { return }
	tag, err := a.pg.Exec(c, `UPDATE user_sessions SET revoked_at=now() WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL`, id, c.GetString("actor_id"))
	if err != nil { c.JSON(500, gin.H{"error":"could not revoke session"}); return }; if tag.RowsAffected()==0 { c.JSON(404, gin.H{"error":"active session not found"}); return }
	c.JSON(200, gin.H{"status":"revoked"})
}

func (a *App) revokeUserSessions(c *gin.Context) {
	id, ok := parseID(c); if !ok { return }
	tag, err := a.pg.Exec(c, `UPDATE user_sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL`, id)
	if err != nil { c.JSON(500, gin.H{"error":"could not revoke user sessions"}); return }
	c.JSON(200, gin.H{"revoked":tag.RowsAffected()})
}

func parseID(c *gin.Context) (uuid.UUID, bool) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid UUID"})
		return uuid.Nil, false
	}
	return id, true
}
func (a *App) createTarget(c *gin.Context) {
	var in struct {
    Name    string `json:"name"`
    BaseURL string `json:"base_url"`
    Type    string `json:"type"`
}
	if c.ShouldBindJSON(&in) != nil || in.Name == "" || (in.Type != "rest" && in.Type != "graphql") {
		c.JSON(400, gin.H{"error": "name, base_url, and type (rest|graphql) are required"})
		return
	}
	parsed, err := url.ParseRequestURI(in.BaseURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		c.JSON(400, gin.H{"error": "base_url must be an absolute http(s) URL"})
		return
	}
	if err := validateOutboundURL(parsed); err != nil {
		c.JSON(400, gin.H{"error": "base_url is blocked by outbound security policy: " + err.Error()})
		return
	}
	var t Target
	err = a.pg.QueryRow(c, `INSERT INTO targets(name,base_url,type) VALUES($1,$2,$3) RETURNING id,name,base_url,type,schedule_interval_seconds,created_at`, in.Name, in.BaseURL, in.Type).Scan(&t.ID, &t.Name, &t.BaseURL, &t.Type, &t.ScheduleIntervalSeconds, &t.CreatedAt)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(201, t)
}
func (a *App) listTargets(c *gin.Context) {
	rows, err := a.pg.Query(c, `SELECT id,name,base_url,type,schedule_interval_seconds,created_at FROM targets ORDER BY created_at DESC`)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	out := []Target{}
	for rows.Next() {
		var t Target
		_ = rows.Scan(&t.ID, &t.Name, &t.BaseURL, &t.Type, &t.ScheduleIntervalSeconds, &t.CreatedAt)
		out = append(out, t)
	}
	c.JSON(200, out)
}
func (a *App) getTarget(c *gin.Context) {
	id, ok := parseID(c)
	if !ok {
		return
	}
	t, err := a.target(c, id)
	if err != nil {
		c.JSON(404, gin.H{"error": "target not found"})
		return
	}
	cfg, _ := a.getConfig(c, id)
	c.JSON(200, gin.H{"target": t, "config": cfg})
}
func (a *App) deleteTarget(c *gin.Context) {
	id, ok := parseID(c)
	if !ok {
		return
	}
	tx, err := a.pg.Begin(c)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer tx.Rollback(c)
	// Incidents retain foreign keys to targets and deployment events, so remove
	// them before deleting the target (the remaining probe data cascades).
	if _, err = tx.Exec(c, `DELETE FROM incidents WHERE target_id=$1`, id); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	result, err := tx.Exec(c, `DELETE FROM targets WHERE id=$1`, id)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if result.RowsAffected() == 0 {
		c.JSON(404, gin.H{"error": "target not found"})
		return
	}
	if err = tx.Commit(c); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	a.scheduler.Upsert(id, 0)
	if _, err = a.configs.DeleteOne(c, bson.M{"target_id": id.String()}); err != nil {
		c.JSON(500, gin.H{"error": "target deleted, but its probe configuration could not be removed: " + err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}
func (a *App) target(ctx context.Context, id uuid.UUID) (Target, error) {
	var t Target
	err := a.pg.QueryRow(ctx, `SELECT id,name,base_url,type,schedule_interval_seconds,created_at FROM targets WHERE id=$1`, id).Scan(&t.ID, &t.Name, &t.BaseURL, &t.Type, &t.ScheduleIntervalSeconds, &t.CreatedAt)
	return t, err
}
func (a *App) putSchedule(c *gin.Context) {
	id, ok := parseID(c)
	if !ok {
		return
	}
	var in struct {
		IntervalSeconds int `json:"interval_seconds"`
	}
	if c.ShouldBindJSON(&in) != nil || (in.IntervalSeconds != 0 && in.IntervalSeconds < 30) {
		c.JSON(400, gin.H{"error": "interval_seconds must be 0 (disabled) or at least 30"})
		return
	}
	var t Target
	var agentID *uuid.UUID
	err := a.pg.QueryRow(c, `UPDATE targets SET schedule_interval_seconds=$1 WHERE id=$2 RETURNING id,name,base_url,type,schedule_interval_seconds,created_at,agent_id`, in.IntervalSeconds, id).Scan(&t.ID, &t.Name, &t.BaseURL, &t.Type, &t.ScheduleIntervalSeconds, &t.CreatedAt, &agentID)
	if err != nil {
		c.JSON(404, gin.H{"error": "target not found"})
		return
	}
	if agentID == nil { a.scheduler.Upsert(t.ID, time.Duration(in.IntervalSeconds)*time.Second) } else { a.scheduler.Pause(t.ID) }
	c.JSON(200, t)
}
func (a *App) putConfig(c *gin.Context) {
	id, ok := parseID(c)
	if !ok {
		return
	}
	if _, err := a.target(c, id); err != nil {
		c.JSON(404, gin.H{"error": "target not found"})
		return
	}
	var cfg ProbeConfig
	if c.ShouldBindJSON(&cfg) != nil {
		c.JSON(400, gin.H{"error": "invalid probe configuration"})
		return
	}
	cfg.TargetID = id.String()
	if cfg.L1.TimeoutMS == 0 {
		cfg.L1.TimeoutMS = 3000
	}
	if cfg.L3.ExpectedStatus == 0 {
		cfg.L3.ExpectedStatus = 200
	}
	_, err := a.configs.ReplaceOne(c, bson.M{"target_id": cfg.TargetID}, cfg, options.Replace().SetUpsert(true))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, cfg)
}
func (a *App) getConfig(ctx context.Context, id uuid.UUID) (ProbeConfig, error) {
	var cfg ProbeConfig
	err := a.configs.FindOne(ctx, bson.M{"target_id": id.String()}).Decode(&cfg)
	return cfg, err
}

func (a *App) runProbe(c *gin.Context) {
	id, ok := parseID(c)
	if !ok {
		return
	}
	out, err := a.execute(c, id, "manual")
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	c.JSON(201, out)
}
func (a *App) gate(c *gin.Context) {
	id, ok := parseID(c)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(c, 30*time.Second)
	defer cancel()
	out, err := a.execute(ctx, id, "ci_gate")
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	status := 200
	if out.OverallStatus != "pass" {
		status = 409
	}
	c.JSON(status, out)
}

func (a *App) execute(ctx context.Context, targetID uuid.UUID, trigger string) (RunResponse, error) {
	t, err := a.target(ctx, targetID)
	if err != nil {
		return RunResponse{}, errors.New("target not found")
	}
	cfg, err := a.getConfig(ctx, targetID)
	if err != nil {
		return RunResponse{}, errors.New("target configuration not found")
	}
	started := time.Now().UTC()
	var runID uuid.UUID
	err = a.pg.QueryRow(ctx, `INSERT INTO probe_runs(target_id,triggered_by,started_at,overall_status) VALUES($1,$2,$3,'running') RETURNING id`, targetID, trigger, started).Scan(&runID)
	if err != nil {
		return RunResponse{}, err
	}
	results := []LayerResult{}
	response := map[string]any{}
	failed := false
	l1 := a.l1(ctx, t, cfg)
	results = append(results, l1)
	if l1.Status == "fail" {
		failed = true
	}
	if !failed {
		l2 := a.l2(ctx, t, cfg)
		results = append(results, l2)
		if l2.Status == "fail" {
			failed = true
		}
	} else {
		results = append(results, skipped(2), skipped(3), skipped(4))
	}
	if len(results) == 2 && !failed {
		l3, data := a.l3(ctx, t, cfg)
		results = append(results, l3)
		response = data
		if l3.Status == "fail" {
			failed = true
		}
	}
	if len(results) == 3 && !failed {
		l4 := a.l4(cfg, response)
		results = append(results, l4)
		if l4.Status == "fail" {
			failed = true
		}
	}
	for len(results) < 4 {
		results = append(results, skipped(len(results)+1))
	}
	for _, r := range results {
		var diagnostics any
		if r.Diagnostics != nil {
			b, _ := json.Marshal(r.Diagnostics)
			diagnostics = string(b)
		}
		_, err = a.pg.Exec(ctx, `INSERT INTO probe_results(run_id,layer,status,latency_ms,error_msg,checked_at,diagnostics) VALUES($1,$2,$3,$4,$5,$6,$7)`, runID, r.Layer, r.Status, r.LatencyMS, r.ErrorMessage, r.CheckedAt, diagnostics)
		if err != nil {
			return RunResponse{}, err
		}
	}
	status := "pass"
	if failed {
		status = "fail"
	}
	finished := time.Now().UTC()
	_, err = a.pg.Exec(ctx, `UPDATE probe_runs SET finished_at=$1,overall_status=$2 WHERE id=$3`, finished, status, runID)
	if err != nil {
		return RunResponse{}, err
	}
	out := RunResponse{ID: runID, TargetID: targetID, OverallStatus: status, StartedAt: started, FinishedAt: finished, Results: results}
	if failed {
		for _, r := range results {
			if r.Status == "fail" {
				iid, verdict, e := a.attribute(ctx, targetID, runID, r.Layer)
				if e == nil {
					a.dispatchAlerts(ctx, iid)
					out.IncidentID = &iid
					out.Verdict = verdict
				}
				break
			}
		}
	} else {
		_, _ = a.pg.Exec(ctx, `UPDATE incidents SET status='resolved',resolved_at=$1,last_seen_at=$1 WHERE target_id=$2 AND status IN ('open','acknowledged')`, finished, targetID)
	}
	return out, nil
}
func skipped(layer int) LayerResult {
	return LayerResult{Layer: layer, Status: "skip", CheckedAt: time.Now().UTC()}
}

func (a *App) l1(ctx context.Context, t Target, cfg ProbeConfig) LayerResult {
	start := time.Now()
	r := LayerResult{Layer: 1, Status: "pass", CheckedAt: start.UTC()}
	u, err := url.Parse(t.BaseURL)
	if err != nil {
		r.Status = "fail"
		r.ErrorMessage = "invalid target URL"
		return r
	}
	if err := validateOutboundURL(u); err != nil {
		r.Status = "fail"
		r.ErrorMessage = "connectivity blocked by outbound security policy: " + err.Error()
		return r
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	timeout := time.Duration(cfg.L1.TimeoutMS) * time.Millisecond
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	r.LatencyMS = int(time.Since(start).Milliseconds())
	if err != nil {
		r.Status = "fail"
		r.ErrorMessage = "connectivity failed: " + err.Error()
		return r
	}
	_ = conn.Close()
	return r
}
func (a *App) l2(ctx context.Context, t Target, cfg ProbeConfig) LayerResult {
	start := time.Now()
	r := LayerResult{Layer: 2, Status: "pass", CheckedAt: start.UTC()}
	if cfg.L2.AuthType == "" || cfg.L2.AuthType == "none" {
		r.ErrorMessage = "auth check not configured"
		return r
	}
	resp, _, err := a.request(ctx, t, cfg)
	r.LatencyMS = int(time.Since(start).Milliseconds())
	if err != nil {
		r.Status = "fail"
		r.ErrorMessage = "auth request failed: " + err.Error()
		return r
	}
	defer resp.Body.Close()
	expected := cfg.L2.ExpectedStatus
	if expected == 0 {
		expected = 200
	}
	if resp.StatusCode != expected {
		r.Status = "fail"
		r.ErrorMessage = fmt.Sprintf("expected auth status %d, got %d", expected, resp.StatusCode)
	}
	return r
}
func (a *App) l3(ctx context.Context, t Target, cfg ProbeConfig) (LayerResult, map[string]any) {
	start := time.Now()
	r := LayerResult{Layer: 3, Status: "pass", CheckedAt: start.UTC()}
	expected := cfg.L3.ExpectedStatus
	if expected == 0 {
		expected = 200
	}
	resp, body, err := a.request(ctx, t, cfg)
	r.LatencyMS = int(time.Since(start).Milliseconds())
	if err != nil {
		r.Status = "fail"
		r.ErrorMessage = "contract request failed: " + err.Error()
		r.Diagnostics = contractDiagnostics(expected, 0, cfg.L3.ExpectedShape, nil)
		return r, nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != expected {
		r.Status = "fail"
		r.ErrorMessage = fmt.Sprintf("expected status %d, got %d", expected, resp.StatusCode)
		r.Diagnostics = contractDiagnostics(expected, resp.StatusCode, cfg.L3.ExpectedShape, body)
		return r, nil
	}
	var data map[string]any
	if err := json.Unmarshal(body, &data); err != nil {
		r.Status = "fail"
		r.ErrorMessage = "response is not valid JSON"
		r.Diagnostics = contractDiagnostics(expected, resp.StatusCode, cfg.L3.ExpectedShape, body)
		return r, nil
	}
	if t.Type == "graphql" {
		if errs, ok := data["errors"]; ok && errs != nil {
			r.Status = "fail"
			r.ErrorMessage = "GraphQL response contains errors"
			r.Diagnostics = contractDiagnostics(expected, resp.StatusCode, cfg.L3.ExpectedShape, body)
			return r, data
		}
		if nested, ok := data["data"].(map[string]any); ok {
			data = nested
		}
	}
	if len(cfg.L3.ExpectedShape) > 0 && !matchesShape(data, cfg.L3.ExpectedShape) {
		r.Status = "fail"
		r.ErrorMessage = "response does not match expected shape"
		r.Diagnostics = contractDiagnostics(expected, resp.StatusCode, cfg.L3.ExpectedShape, body)
	}
	if r.Status == "pass" {
		captured, changes, err := a.compareBaseline(ctx, t.ID, data)
		if err == nil && (captured || len(changes) > 0) {
			r.Diagnostics = &ProbeDiagnostics{BaselineCaptured: captured, BaselineChanges: changes}
		}
	}
	return r, data
}
func responseShape(value any) map[string]string {
	out := map[string]string{}
	var walk func(any, string)
	walk = func(item any, path string) {
		switch value := item.(type) {
		case map[string]any:
			if path != "" { out[path] = "object" }
			for key, child := range value { next := key; if path != "" { next = path + "." + key }; walk(child, next) }
		case []any:
			out[path] = "array"
			if len(value) > 0 { walk(value[0], path+"[]") }
		case string: out[path] = "string"
		case float64: out[path] = "number"
		case bool: out[path] = "boolean"
		case nil: out[path] = "null"
		default: out[path] = fmt.Sprintf("%T", item)
		}
	}
	walk(value, "")
	return out
}
func (a *App) compareBaseline(ctx context.Context, targetID uuid.UUID, response map[string]any) (bool, []BaselineChange, error) {
	current := responseShape(response)
	var stored []byte
	err := a.pg.QueryRow(ctx, `SELECT shape FROM response_baselines WHERE target_id=$1`, targetID).Scan(&stored)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			shape, _ := json.Marshal(current)
			_, insertErr := a.pg.Exec(ctx, `INSERT INTO response_baselines(target_id,shape) VALUES($1,$2)`, targetID, shape)
			return insertErr == nil, nil, insertErr
		}
		return false, nil, err
	}
	baseline := map[string]string{}
	if err := json.Unmarshal(stored, &baseline); err != nil { return false, nil, err }
	changes := []BaselineChange{}
	for path, before := range baseline { if after, ok := current[path]; !ok { changes = append(changes, BaselineChange{Path:path,Change:"removed",Before:before}) } else if after != before { changes = append(changes, BaselineChange{Path:path,Change:"type_changed",Before:before,After:after}) } }
	for path, after := range current { if _, ok := baseline[path]; !ok { changes = append(changes, BaselineChange{Path:path,Change:"added",After:after}) } }
	sort.Slice(changes, func(i, j int) bool { return changes[i].Path < changes[j].Path })
	return false, changes, nil
}
func (a *App) pauseTarget(c *gin.Context) {
	id, ok := parseID(c)
	if !ok {
		return
	}
	var t Target
	err := a.pg.QueryRow(c, `UPDATE targets SET schedule_interval_seconds=0 WHERE id=$1 RETURNING id,name,base_url,type,schedule_interval_seconds,created_at`, id).Scan(&t.ID, &t.Name, &t.BaseURL, &t.Type, &t.ScheduleIntervalSeconds, &t.CreatedAt)
	if err != nil {
		c.JSON(404, gin.H{"error": "target not found"})
		return
	}
	a.scheduler.Pause(id)
	c.JSON(200, t)
}
func contractDiagnostics(expectedStatus, actualStatus int, expectedShape map[string]any, body []byte) *ProbeDiagnostics {
	return &ProbeDiagnostics{ExpectedStatus: expectedStatus, ActualStatus: actualStatus, ExpectedShape: expectedShape, ResponsePreview: safeResponsePreview(body)}
}
func safeResponsePreview(body []byte) any {
	const maxPreviewBytes = 12 * 1024
	if len(body) > maxPreviewBytes {
		body = body[:maxPreviewBytes]
	}
	var value any
	if json.Unmarshal(body, &value) == nil {
		return redactValue(value)
	}
	return "[non-JSON response preview omitted]"
}
func redactValue(value any) any {
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			lower := strings.ToLower(key)
			if strings.Contains(lower, "password") || strings.Contains(lower, "secret") || strings.Contains(lower, "token") || strings.Contains(lower, "authorization") || strings.Contains(lower, "api_key") || strings.Contains(lower, "apikey") || strings.Contains(lower, "cookie") || strings.Contains(lower, "credential") {
				out[key] = "[redacted]"
				continue
			}
			out[key] = redactValue(item)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = redactValue(item)
		}
		return out
	default:
		return value
	}
}
func (a *App) request(ctx context.Context, t Target, cfg ProbeConfig) (*http.Response, []byte, error) {
	endpoint := strings.TrimRight(t.BaseURL, "/")
	if cfg.L3.Path != "" {
		endpoint += "/" + strings.TrimLeft(cfg.L3.Path, "/")
	}
	parsedEndpoint, err := url.Parse(endpoint)
	if err != nil {
		return nil, nil, err
	}
	if err := validateOutboundURL(parsedEndpoint); err != nil {
		return nil, nil, errors.New("outbound request blocked by security policy: " + err.Error())
	}
	method := cfg.L3.Method
	if method == "" {
		method = http.MethodGet
	}
	var reader io.Reader
	if t.Type == "graphql" {
		method = http.MethodPost
		b, _ := json.Marshal(map[string]string{"query": cfg.L3.Query})
		reader = strings.NewReader(string(b))
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Accept", "application/json")
	if t.Type == "graphql" {
		req.Header.Set("Content-Type", "application/json")
	}
	if cfg.L2.AuthType == "bearer" || cfg.L2.AuthType == "header" {
		token := os.Getenv(cfg.L2.TokenEnvVar)
		if token == "" {
			return nil, nil, errors.New("configured token environment variable is empty")
		}
		if cfg.L2.AuthType == "bearer" {
			req.Header.Set("Authorization", "Bearer "+token)
		} else {
			header := cfg.L2.HeaderName
			if header == "" {
				return nil, nil, errors.New("header_name is required for header authentication")
			}
			req.Header.Set(header, token)
		}
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		resp.Body.Close()
		return nil, nil, err
	}
	resp.Body.Close()
	resp.Body = io.NopCloser(strings.NewReader(string(body)))
	return resp, body, nil
}
func (a *App) l4(cfg ProbeConfig, data map[string]any) LayerResult {
	r := LayerResult{Layer: 4, Status: "pass", CheckedAt: time.Now().UTC()}
	for _, as := range cfg.L4.Assertions {
		v, ok := jsonPath(data, as.Field)
		if !assertionOK(v, ok, as) {
			r.Status = "fail"
			r.ErrorMessage = "assertion failed: " + as.Field + " " + as.Rule
			break
		}
	}
	return r
}
func matchesShape(data map[string]any, shape map[string]any) bool {
	for k, want := range shape {
		got, ok := data[k]
		if !ok {
			return false
		}
		if nested, ok := want.(map[string]any); ok {
			m, ok := got.(map[string]any)
			if !ok || !matchesShape(m, nested) {
				return false
			}
		} else if typ, ok := want.(string); ok && typ != "" {
			if typ == "string" {
				if _, ok := got.(string); !ok {
					return false
				}
			}
			if typ == "number" {
				switch got.(type) {
				case float64, float32, int, int64:
				default:
					return false
				}
			}
			if typ == "boolean" {
				if _, ok := got.(bool); !ok {
					return false
				}
			}
		}
	}
	return true
}
func jsonPath(data map[string]any, path string) (any, bool) {
	var cur any = data
	for _, p := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[p]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}
func assertionOK(v any, exists bool, a Assertion) bool {
	switch a.Rule {
	case "exists":
		return exists
	case "non_empty":
		if !exists {
			return false
		}
		s, ok := v.(string)
		return ok && strings.TrimSpace(s) != ""
	case "equals":
		return exists && fmt.Sprint(v) == fmt.Sprint(a.Value)
	case "greater_than":
		f, e := strconv.ParseFloat(fmt.Sprint(v), 64)
		w, e2 := strconv.ParseFloat(fmt.Sprint(a.Value), 64)
		return e == nil && e2 == nil && f > w
	case "less_than":
		f, e := strconv.ParseFloat(fmt.Sprint(v), 64)
		w, e2 := strconv.ParseFloat(fmt.Sprint(a.Value), 64)
		return e == nil && e2 == nil && f < w
	}
	return false
}

func (a *App) attribute(ctx context.Context, targetID, runID uuid.UUID, layer int) (uuid.UUID, string, error) {
	classes := map[int]string{1: "network", 2: "auth", 3: "contract", 4: "data"}
	class := classes[layer]
	var deployID *uuid.UUID
	var deployedAt time.Time
	var id uuid.UUID
	err := a.pg.QueryRow(ctx, `SELECT id,deployed_at FROM deployment_events WHERE target_id=$1 AND deployed_at <= now() AND deployed_at >= now() - interval '30 minutes' ORDER BY deployed_at DESC LIMIT 1`, targetID).Scan(&id, &deployedAt)
	delta := 0
	verdict := fmt.Sprintf("%s failure; no deployment in the last 30 minutes", class)
	if err == nil {
		deployID = &id
		delta = int(time.Since(deployedAt).Minutes())
		verdict = fmt.Sprintf("%s failure correlated with deployment %s (%d minutes ago)", class, id.String(), delta)
	}
	var incidentID uuid.UUID
	updated, err := a.pg.Exec(ctx, `UPDATE incidents SET run_id=$1,attributed_to=$2,nearest_deploy_id=$3,deploy_delta_mins=$4,last_seen_at=now(),failure_count=failure_count+1 WHERE target_id=$5 AND failed_layer=$6 AND status='open'`, runID, class, deployID, delta, targetID, layer)
	if err != nil {
		return uuid.Nil, verdict, err
	}
	if updated.RowsAffected() > 0 {
		err = a.pg.QueryRow(ctx, `SELECT id FROM incidents WHERE target_id=$1 AND failed_layer=$2 AND status='open' ORDER BY last_seen_at DESC LIMIT 1`, targetID, layer).Scan(&incidentID)
		return incidentID, verdict, err
	}
	err = a.pg.QueryRow(ctx, `INSERT INTO incidents(target_id,run_id,failed_layer,attributed_to,nearest_deploy_id,deploy_delta_mins,created_at,first_seen_at,last_seen_at,failure_count) VALUES($1,$2,$3,$4,$5,$6,now(),now(),now(),1) RETURNING id`, targetID, runID, layer, class, deployID, delta).Scan(&incidentID)
	return incidentID, verdict, err
}

func (a *App) listRuns(c *gin.Context) {
	id, ok := parseID(c)
	if !ok {
		return
	}
	rows, err := a.pg.Query(c, `SELECT id,target_id,overall_status,started_at,finished_at FROM probe_runs WHERE target_id=$1 ORDER BY started_at DESC LIMIT 50`, id)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	out := []RunResponse{}
	for rows.Next() {
		var r RunResponse
		_ = rows.Scan(&r.ID, &r.TargetID, &r.OverallStatus, &r.StartedAt, &r.FinishedAt)
		out = append(out, r)
	}
	c.JSON(200, out)
}
func (a *App) getRun(c *gin.Context) {
	id, ok := parseID(c)
	if !ok {
		return
	}
	var r RunResponse
	err := a.pg.QueryRow(c, `SELECT id,target_id,overall_status,started_at,finished_at FROM probe_runs WHERE id=$1`, id).Scan(&r.ID, &r.TargetID, &r.OverallStatus, &r.StartedAt, &r.FinishedAt)
	if err != nil {
		c.JSON(404, gin.H{"error": "run not found"})
		return
	}
	rows, _ := a.pg.Query(c, `SELECT layer,status,latency_ms,COALESCE(error_msg,''),checked_at,COALESCE(diagnostics,'{}'::jsonb) FROM probe_results WHERE run_id=$1 ORDER BY layer`, id)
	defer rows.Close()
	for rows.Next() {
		var x LayerResult
		var diagnostics []byte
		_ = rows.Scan(&x.Layer, &x.Status, &x.LatencyMS, &x.ErrorMessage, &x.CheckedAt, &diagnostics)
		if len(diagnostics) > 0 && string(diagnostics) != "null" {
			_ = json.Unmarshal(diagnostics, &x.Diagnostics)
		}
		r.Results = append(r.Results, x)
	}
	c.JSON(200, r)
}
func (a *App) listIncidents(c *gin.Context) {
	rows, err := a.pg.Query(c, `SELECT i.id,i.target_id,i.run_id,i.failed_layer,i.attributed_to,i.nearest_deploy_id,i.deploy_delta_mins,i.created_at,i.status,i.first_seen_at,i.last_seen_at,i.resolved_at,i.failure_count,i.owner,i.acknowledged_at,i.acknowledgement_note,i.resolution_note,t.name FROM incidents i JOIN targets t ON t.id=i.target_id ORDER BY CASE WHEN i.status='resolved' THEN 1 ELSE 0 END,i.last_seen_at DESC LIMIT 100`)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	out := []gin.H{}
	for rows.Next() {
		var id, tid, rid uuid.UUID
		var layer, delta int
		var class, name string
		var dep *uuid.UUID
		var created, firstSeen, lastSeen time.Time
		var resolvedAt, acknowledgedAt *time.Time
		var owner, acknowledgementNote, resolutionNote *string
		var status string
		var failureCount int
		_ = rows.Scan(&id, &tid, &rid, &layer, &class, &dep, &delta, &created, &status, &firstSeen, &lastSeen, &resolvedAt, &failureCount, &owner, &acknowledgedAt, &acknowledgementNote, &resolutionNote, &name)
		out = append(out, gin.H{"id": id, "target_id": tid, "target_name": name, "run_id": rid, "failed_layer": layer, "attributed_to": class, "nearest_deploy_id": dep, "deploy_delta_mins": delta, "created_at": created, "status": status, "first_seen_at": firstSeen, "last_seen_at": lastSeen, "resolved_at": resolvedAt, "failure_count": failureCount, "owner": owner, "acknowledged_at": acknowledgedAt, "acknowledgement_note": acknowledgementNote, "resolution_note": resolutionNote})
	}
	c.JSON(200, out)
}
func secureHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = secureDialContext
	return &http.Client{Timeout: 30 * time.Second, Transport: transport, CheckRedirect: func(req *http.Request, _ []*http.Request) error { return validateOutboundURL(req.URL) }}
}
func secureDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil { return nil, err }
	ips, err := net.LookupIP(host)
	if err != nil { return nil, err }
	dialer := net.Dialer{}
	for _, ip := range ips {
		if !isBlockedIP(ip) { return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port)) }
	}
	return nil, errors.New("destination resolves only to blocked addresses")
}
func validateOutboundURL(u *url.URL) error {
	if u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" { return errors.New("only absolute http(s) URLs are allowed") }
	ips, err := net.LookupIP(u.Hostname())
	if err != nil { return fmt.Errorf("DNS lookup failed: %w", err) }
	for _, ip := range ips { if isBlockedIP(ip) { return fmt.Errorf("%s resolves to a blocked address", u.Hostname()) } }
	return nil
}
func isBlockedIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip); if !ok { return true }; addr = addr.Unmap()
	return addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() || addr.Is6() && addr.IsInterfaceLocalMulticast()
}
func (a *App) dispatchAlerts(ctx context.Context, incidentID uuid.UUID) {
	var targetID uuid.UUID
	var count int
	if a.pg.QueryRow(ctx, `SELECT target_id,failure_count FROM incidents WHERE id=$1`, incidentID).Scan(&targetID, &count) != nil { return }
	rows, err := a.pg.Query(ctx, `SELECT id,name,webhook_url,email_to FROM alert_rules WHERE target_id=$1 AND enabled=true AND min_failure_count=$2`, targetID, count)
	if err != nil { return }
	defer rows.Close()
	for rows.Next() {
		var ruleID uuid.UUID; var name, webhook string
		var emailTo *string
		if rows.Scan(&ruleID, &name, &webhook, &emailTo) != nil { continue }
		webhook, err = a.decryptAlertWebhook(webhook)
		if err != nil { continue }
		message := fmt.Sprintf("Meridian alert: %s has failed %d consecutive times. Open Meridian to investigate.", name, count)
		body, _ := json.Marshal(gin.H{
			"text": message, "incident_id": incidentID, "failure_count": count,
			"@type": "MessageCard", "@context": "https://schema.org/extensions", "summary": message,
			"themeColor": "E85D75", "title": "Meridian API alert",
			"sections": []gin.H{{"facts": []gin.H{{"name": "Rule", "value": name}, {"name": "Consecutive failures", "value": strconv.Itoa(count)}, {"name": "Incident", "value": incidentID.String()}}}},
		})
		go a.deliverWebhook(context.Background(),ruleID,&incidentID,webhook,body)
		if emailTo != nil && strings.TrimSpace(*emailTo) != "" { go a.deliverAlertEmail(context.Background(),ruleID,&incidentID,name,count,*emailTo) }
	}
}
func (a *App) recordAlertDelivery(ctx context.Context, ruleID uuid.UUID, incidentID *uuid.UUID, channel,status string, attempt,responseStatus int, message string) { _,_=a.pg.Exec(ctx,`INSERT INTO alert_deliveries(rule_id,incident_id,channel,status,attempt,response_status,error_message) VALUES($1,$2,$3,$4,$5,NULLIF($6,0),NULLIF($7,''))`,ruleID,incidentID,channel,status,attempt,responseStatus,message) }
func (a *App) deliverWebhook(ctx context.Context, ruleID uuid.UUID, incidentID *uuid.UUID, webhook string, body []byte) { var last string;for attempt:=1;attempt<=3;attempt++{req,err:=http.NewRequestWithContext(ctx,http.MethodPost,webhook,strings.NewReader(string(body)));if err==nil{req.Header.Set("Content-Type","application/json");var resp *http.Response;resp,err=a.client.Do(req);status:=0;if resp!=nil{status=resp.StatusCode;resp.Body.Close();if status>=200&&status<300{a.recordAlertDelivery(ctx,ruleID,incidentID,"webhook","sent",attempt,status,"");return};if err==nil{err=fmt.Errorf("webhook returned HTTP %d",status)}};last=fmt.Sprint(err);a.recordAlertDelivery(ctx,ruleID,incidentID,"webhook","failed",attempt,status,last)}else{last=err.Error();a.recordAlertDelivery(ctx,ruleID,incidentID,"webhook","failed",attempt,0,last)};if attempt<3{time.Sleep(time.Duration(attempt*2)*time.Second)}} }
func (a *App) deliverAlertEmail(ctx context.Context, ruleID uuid.UUID, incidentID *uuid.UUID, rule string, count int, recipients string) {
	if a.cfg.SMTPHost == "" || a.cfg.SMTPFrom == "" { a.recordAlertDelivery(ctx,ruleID,incidentID,"email","failed",1,0,"SMTP is not configured");return }
	to := strings.Split(recipients, ",")
	for i := range to { to[i] = strings.TrimSpace(to[i]) }
	incidentText:="test delivery";if incidentID!=nil{incidentText=incidentID.String()};message := fmt.Sprintf("To: %s\r\nFrom: %s\r\nSubject: Meridian API alert: %s\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s has failed %d consecutive times. Incident: %s\r\n", strings.Join(to, ","), a.cfg.SMTPFrom, rule, rule, count, incidentText)
	var auth smtp.Auth
	if a.cfg.SMTPUsername != "" { auth = smtp.PlainAuth("", a.cfg.SMTPUsername, a.cfg.SMTPPassword, a.cfg.SMTPHost) }
	var last string;for attempt:=1;attempt<=3;attempt++{err:=smtp.SendMail(net.JoinHostPort(a.cfg.SMTPHost,a.cfg.SMTPPort),auth,a.cfg.SMTPFrom,to,[]byte(message));if err==nil{a.recordAlertDelivery(ctx,ruleID,incidentID,"email","sent",attempt,0,"");return};last=err.Error();a.recordAlertDelivery(ctx,ruleID,incidentID,"email","failed",attempt,0,last);if attempt<3{time.Sleep(time.Duration(attempt*2)*time.Second)}}
}
func (a *App) acknowledgeIncident(c *gin.Context) {
	id, ok := parseID(c)
	if !ok { return }
	var in struct { Owner string `json:"owner"`; Note string `json:"note"` }
	if c.ShouldBindJSON(&in) != nil { c.JSON(400, gin.H{"error":"invalid acknowledgement"}); return }
	if strings.TrimSpace(in.Owner) == "" { c.JSON(400, gin.H{"error":"owner is required"}); return }
	tag, err := a.pg.Exec(c, `UPDATE incidents SET status='acknowledged',owner=$1,acknowledged_at=now(),acknowledgement_note=$2 WHERE id=$3 AND status IN ('open','acknowledged')`, strings.TrimSpace(in.Owner), strings.TrimSpace(in.Note), id)
	if err != nil { c.JSON(500, gin.H{"error":err.Error()}); return }
	if tag.RowsAffected() == 0 { c.JSON(409, gin.H{"error":"incident is already resolved or was not found"}); return }
	c.JSON(200, gin.H{"status":"acknowledged","id":id})
}
func (a *App) resolveIncident(c *gin.Context) {
	id, ok := parseID(c)
	if !ok { return }
	var in struct { Note string `json:"note"` }
	if c.ShouldBindJSON(&in) != nil { c.JSON(400, gin.H{"error":"invalid resolution"}); return }
	tag, err := a.pg.Exec(c, `UPDATE incidents SET status='resolved',resolved_at=now(),resolution_note=$1 WHERE id=$2 AND status IN ('open','acknowledged')`, strings.TrimSpace(in.Note), id)
	if err != nil { c.JSON(500, gin.H{"error":err.Error()}); return }
	if tag.RowsAffected() == 0 { c.JSON(409, gin.H{"error":"incident is already resolved or was not found"}); return }
	c.JSON(200, gin.H{"status":"resolved","id":id})
}
func (a *App) listAlertRules(c *gin.Context) {
	rows, err := a.pg.Query(c, `SELECT id,target_id,name,min_failure_count,webhook_url,email_to,enabled,created_at FROM alert_rules ORDER BY created_at DESC`)
	if err != nil { c.JSON(500, gin.H{"error":err.Error()}); return }
	defer rows.Close()
	out := []gin.H{}
	for rows.Next() {
		var id, targetID uuid.UUID
		var name, webhook string
		var emailTo *string
		var threshold int
		var enabled bool
		var created time.Time
		_ = rows.Scan(&id, &targetID, &name, &threshold, &webhook, &emailTo, &enabled, &created)
		hint := "configured"
		if plain, err := a.decryptAlertWebhook(webhook); err == nil { hint = alertWebhookHint(plain) }
		out = append(out, gin.H{"id": id, "target_id": targetID, "name": name, "min_failure_count": threshold, "webhook_configured": webhook != "", "webhook_hint": hint, "email_to": emailTo, "enabled": enabled, "created_at": created})
	}
	c.JSON(200,out)
}
func (a *App) listAlertDeliveries(c *gin.Context) { ruleID,ok:=parseID(c);if !ok{return};rows,err:=a.pg.Query(c,`SELECT id,incident_id,channel,status,attempt,response_status,error_message,created_at FROM alert_deliveries WHERE rule_id=$1 ORDER BY created_at DESC LIMIT 100`,ruleID);if err!=nil{c.JSON(500,gin.H{"error":"could not load alert deliveries"});return};defer rows.Close();out:=[]gin.H{};for rows.Next(){var id uuid.UUID;var incidentID *uuid.UUID;var channel,status string;var attempt int;var responseStatus *int;var message *string;var created time.Time;if rows.Scan(&id,&incidentID,&channel,&status,&attempt,&responseStatus,&message,&created)==nil{out=append(out,gin.H{"id":id,"incident_id":incidentID,"channel":channel,"status":status,"attempt":attempt,"response_status":responseStatus,"error_message":message,"created_at":created})}};c.JSON(200,out) }
func (a *App) testAlertRule(c *gin.Context) { ruleID,ok:=parseID(c);if !ok{return};var name,webhook string;var emailTo *string;if a.pg.QueryRow(c,`SELECT name,webhook_url,email_to FROM alert_rules WHERE id=$1`,ruleID).Scan(&name,&webhook,&emailTo)!=nil{c.JSON(404,gin.H{"error":"alert rule not found"});return};plain,err:=a.decryptAlertWebhook(webhook);if err!=nil{c.JSON(500,gin.H{"error":"could not prepare webhook"});return};message:="Meridian test alert: "+name+". Delivery configuration is being checked.";body,_:=json.Marshal(gin.H{"text":message,"@type":"MessageCard","@context":"https://schema.org/extensions","summary":message,"themeColor":"3B82F6","title":"Meridian test alert"});go a.deliverWebhook(context.Background(),ruleID,nil,plain,body);if emailTo!=nil&&strings.TrimSpace(*emailTo)!=""{go a.deliverAlertEmail(context.Background(),ruleID,nil,name,0,*emailTo)};c.JSON(202,gin.H{"status":"test delivery queued"}) }
func (a *App) analytics(c *gin.Context) {
	hours, _ := strconv.Atoi(c.DefaultQuery("hours", "24"))
	if hours != 24 && hours != 168 && hours != 720 { c.JSON(400, gin.H{"error":"hours must be 24, 168, or 720"}); return }
	rows, err := a.pg.Query(c, `SELECT t.id,t.name,COUNT(r.id),COUNT(r.id) FILTER (WHERE r.overall_status='pass'),COUNT(r.id) FILTER (WHERE r.overall_status='fail'),COALESCE(AVG(x.latency),0) FROM targets t LEFT JOIN probe_runs r ON r.target_id=t.id AND r.started_at >= now() - ($1 * interval '1 hour') LEFT JOIN LATERAL (SELECT SUM(latency_ms) AS latency FROM probe_results WHERE run_id=r.id) x ON true GROUP BY t.id,t.name ORDER BY t.name`, hours)
	if err != nil { c.JSON(500,gin.H{"error":err.Error()});return }
	defer rows.Close(); out:=[]gin.H{}
	for rows.Next(){var id uuid.UUID;var name string;var total,passed,failed int;var latency float64;_ = rows.Scan(&id,&name,&total,&passed,&failed,&latency);uptime:=float64(0);if total>0{uptime=float64(passed)*100/float64(total)};out=append(out,gin.H{"target_id":id,"target_name":name,"runs":total,"passed":passed,"failed":failed,"uptime_percent":uptime,"average_latency_ms":int(latency)})};c.JSON(200,gin.H{"hours":hours,"targets":out})
}
func (a *App) analyticsTrends(c *gin.Context) {
	hours,_:=strconv.Atoi(c.DefaultQuery("hours","24"));if hours!=24&&hours!=168&&hours!=720{c.JSON(400,gin.H{"error":"hours must be 24, 168, or 720"});return};bucket:="hour";if hours>=168{bucket="day"};targetID:=c.Query("target_id");if targetID!=""{if _,err:=uuid.Parse(targetID);err!=nil{c.JSON(400,gin.H{"error":"target_id must be a UUID"});return}}
	rows,err:=a.pg.Query(c,`SELECT date_trunc($1,started_at),COUNT(*),COUNT(*) FILTER (WHERE overall_status='pass'),COALESCE(AVG((SELECT SUM(latency_ms) FROM probe_results WHERE run_id=probe_runs.id)),0),COUNT(*) FILTER (WHERE overall_status='fail') FROM probe_runs WHERE started_at>=now()-($2*interval '1 hour') AND (NULLIF($3,'')::uuid IS NULL OR target_id=NULLIF($3,'')::uuid) GROUP BY 1 ORDER BY 1`,bucket,hours,targetID);if err!=nil{c.JSON(500,gin.H{"error":err.Error()});return};defer rows.Close();out:=[]gin.H{};for rows.Next(){var at time.Time;var total,pass,fail int;var latency float64;_ = rows.Scan(&at,&total,&pass,&latency,&fail);out=append(out,gin.H{"at":at,"uptime_percent":float64(pass)*100/float64(total),"average_latency_ms":int(latency),"failed":fail})};c.JSON(200,gin.H{"hours":hours,"target_id":targetID,"points":out})
}
func (a *App) analyticsLayers(c *gin.Context) {
	hours, _ := strconv.Atoi(c.DefaultQuery("hours", "24"))
	if hours != 24 && hours != 168 && hours != 720 {
		c.JSON(400, gin.H{"error": "hours must be 24, 168, or 720"})
		return
	}
	targetID := c.Query("target_id")
	if targetID != "" {
		if _, err := uuid.Parse(targetID); err != nil {
			c.JSON(400, gin.H{"error": "target_id must be a UUID"})
			return
		}
	}
	rows, err := a.pg.Query(c, `SELECT p.layer,COUNT(*) FROM probe_results p JOIN probe_runs r ON r.id=p.run_id WHERE p.status='fail' AND r.started_at>=now()-($1*interval '1 hour') AND (NULLIF($2,'')::uuid IS NULL OR r.target_id=NULLIF($2,'')::uuid) GROUP BY p.layer ORDER BY p.layer`, hours, targetID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	counts := map[int]int{1: 0, 2: 0, 3: 0, 4: 0}
	for rows.Next() {
		var layer, count int
		_ = rows.Scan(&layer, &count)
		counts[layer] = count
	}
	names := map[int]string{1: "L1 Connectivity", 2: "L2 Authentication", 3: "L3 Contract", 4: "L4 Data"}
	out := []gin.H{}
	for layer := 1; layer <= 4; layer++ {
		out = append(out, gin.H{"layer": layer, "name": names[layer], "failures": counts[layer]})
	}
	c.JSON(200, gin.H{"hours": hours, "target_id": targetID, "layers": out})
}
func (a *App) getSLO(c *gin.Context) {
	id, ok := parseID(c); if !ok { return }
	var target float64; var window int
	err := a.pg.QueryRow(c, `SELECT target_uptime_percent,window_hours FROM slo_targets WHERE target_id=$1`, id).Scan(&target,&window)
	if err != nil { c.JSON(404,gin.H{"error":"SLO not configured"}); return }
	var total, passed int
	_ = a.pg.QueryRow(c, `SELECT COUNT(*),COUNT(*) FILTER (WHERE overall_status='pass') FROM probe_runs WHERE target_id=$1 AND started_at >= now() - ($2 * interval '1 hour')`, id, window).Scan(&total,&passed)
	failed:=total-passed; actual:=float64(0); if total>0 { actual=float64(passed)*100/float64(total) }; allowed:=float64(total)*(100-target)/100; remaining:=allowed-float64(failed); state:="on_track"; if total==0 { state="no_data" } else if remaining<0 { state="breached" } else if allowed>0 && remaining/allowed<0.2 { state="at_risk" }
	c.JSON(200, gin.H{"target_id":id,"target_uptime_percent":target,"window_hours":window,"actual_uptime_percent":actual,"runs":total,"failed_runs":failed,"error_budget_allowed":allowed,"error_budget_remaining":remaining,"state":state})
}
func (a *App) putSLO(c *gin.Context) {
	id, ok := parseID(c); if !ok { return }
	var in struct { TargetUptimePercent float64 `json:"target_uptime_percent"`; WindowHours int `json:"window_hours"` }
	if c.ShouldBindJSON(&in) != nil || in.TargetUptimePercent <= 0 || in.TargetUptimePercent >= 100 || (in.WindowHours != 24 && in.WindowHours != 168 && in.WindowHours != 720) { c.JSON(400,gin.H{"error":"target_uptime_percent must be between 0 and 100; window_hours must be 24, 168, or 720"}); return }
	if _,err:=a.target(c,id);err!=nil { c.JSON(404,gin.H{"error":"target not found"});return }
	_,err:=a.pg.Exec(c,`INSERT INTO slo_targets(target_id,target_uptime_percent,window_hours,updated_at) VALUES($1,$2,$3,now()) ON CONFLICT(target_id) DO UPDATE SET target_uptime_percent=EXCLUDED.target_uptime_percent,window_hours=EXCLUDED.window_hours,updated_at=now()`,id,in.TargetUptimePercent,in.WindowHours)
	if err!=nil { c.JSON(500,gin.H{"error":err.Error()});return };c.JSON(200,gin.H{"target_id":id,"target_uptime_percent":in.TargetUptimePercent,"window_hours":in.WindowHours})
}
func (a *App) createAlertRule(c *gin.Context) {
	var in struct { TargetID, Name, WebhookURL, EmailTo string `json:"-"`; MinFailureCount int `json:"min_failure_count"`; Enabled bool `json:"enabled"` }
	var raw map[string]any
	if c.ShouldBindJSON(&raw) != nil { c.JSON(400,gin.H{"error":"invalid alert rule"}); return }
	in.TargetID,_ = raw["target_id"].(string); in.Name,_ = raw["name"].(string); in.WebhookURL,_ = raw["webhook_url"].(string); in.EmailTo,_ = raw["email_to"].(string); if n,ok:=raw["min_failure_count"].(float64);ok { in.MinFailureCount=int(n) }; if v,ok:=raw["enabled"].(bool);ok { in.Enabled=v } else { in.Enabled=true }
	targetID, err := uuid.Parse(in.TargetID); webhook, parseErr := url.ParseRequestURI(in.WebhookURL)
	if err != nil || parseErr != nil || webhook.Scheme!="https" || webhook.Host=="" || strings.TrimSpace(in.Name)=="" || in.MinFailureCount<1 { c.JSON(400,gin.H{"error":"name, target_id, HTTPS webhook_url, and a positive failure threshold are required"}); return }
	if err := validateOutboundURL(webhook); err != nil { c.JSON(400, gin.H{"error":"webhook_url is blocked by outbound security policy: " + err.Error()}); return }
	encryptedWebhook, err := a.encryptAlertWebhook(in.WebhookURL)
	if err != nil { c.JSON(503, gin.H{"error":"secure alert storage is unavailable; configure ALERT_WEBHOOK_ENCRYPTION_KEY"}); return }
	var id uuid.UUID
	err = a.pg.QueryRow(c,`INSERT INTO alert_rules(target_id,name,min_failure_count,webhook_url,email_to,enabled) VALUES($1,$2,$3,$4,$5,$6) RETURNING id`,targetID,strings.TrimSpace(in.Name),in.MinFailureCount,encryptedWebhook,strings.TrimSpace(in.EmailTo),in.Enabled).Scan(&id)
	if err != nil { c.JSON(500,gin.H{"error":err.Error()}); return }; c.JSON(201,gin.H{"id":id})
}
func (a *App) deleteAlertRule(c *gin.Context) { id,ok:=parseID(c); if !ok{return}; tag,err:=a.pg.Exec(c,`DELETE FROM alert_rules WHERE id=$1`,id); if err!=nil{c.JSON(500,gin.H{"error":err.Error()});return}; if tag.RowsAffected()==0{c.JSON(404,gin.H{"error":"alert rule not found"});return}; c.Status(204) }

func (a *App) deploymentWebhook(c *gin.Context) {
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid body"})
		return
	}
	sig := strings.TrimPrefix(c.GetHeader("X-Meridian-Signature"), "sha256=")
	mac := hmac.New(sha256.New, []byte(a.cfg.WebhookSecret))
	mac.Write(body)
	if !hmac.Equal([]byte(sig), []byte(hex.EncodeToString(mac.Sum(nil)))) {
		c.JSON(401, gin.H{"error": "invalid webhook signature"})
		return
	}
	var in struct {
		TargetID   string    `json:"target_id"`
		Version    string    `json:"version"`
		DeployedBy string    `json:"deployed_by"`
		Source     string    `json:"source"`
		DeliveryID string    `json:"delivery_id"`
		DeployedAt time.Time `json:"deployed_at"`
	}
	if json.Unmarshal(body, &in) != nil {
		c.JSON(400, gin.H{"error": "invalid deployment payload"})
		return
	}
	tid, err := uuid.Parse(in.TargetID)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid target_id"})
		return
	}
	if in.Version == "" || in.DeliveryID == "" {
		c.JSON(400, gin.H{"error": "version and delivery_id are required"})
		return
	}
	if in.DeployedAt.IsZero() {
		in.DeployedAt = time.Now().UTC()
	}
	if in.Source == "" {
		in.Source = "github"
	}
	_, err = a.pg.Exec(c, `INSERT INTO deployment_events(target_id,version,deployed_by,deployed_at,source,delivery_id) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT (delivery_id) DO NOTHING`, tid, in.Version, in.DeployedBy, in.DeployedAt, in.Source, in.DeliveryID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(202, gin.H{"status": "accepted"})
}
