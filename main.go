package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
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
}

type App struct {
	pg        *pgxpool.Pool
	configs   *mongo.Collection
	cfg       Config
	client    *http.Client
	scheduler *Scheduler
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
	Field, Rule string `bson:"field" json:"field"`
	Value       any    `bson:"value,omitempty" json:"value,omitempty"`
}
type LayerResult struct {
	Layer        int       `json:"layer"`
	Status       string    `json:"status"`
	LatencyMS    int       `json:"latency_ms"`
	ErrorMessage string    `json:"error_message,omitempty"`
	CheckedAt    time.Time `json:"checked_at"`
}
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
	return Config{Port: getenv("PORT", "8080"), DatabaseURL: getenv("DATABASE_URL", "postgres://meridian:meridian@postgres:5432/meridian?sslmode=disable"), MongoURL: getenv("MONGO_URL", "mongodb://mongo:27017"), MongoDatabase: getenv("MONGO_DATABASE", "meridian"), JWTSecret: getenv("JWT_SECRET", "change-me-in-production"), WebhookSecret: getenv("WEBHOOK_SECRET", "change-me-webhook"), AdminEmail: getenv("ADMIN_EMAIL", "admin@meridian.local"), AdminPassword: getenv("ADMIN_PASSWORD", "meridian-demo")}
}

type scheduledJob struct {
	cancel  context.CancelFunc
	mu      sync.Mutex
	running bool
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
	rows, err := s.app.pg.Query(s.ctx, `SELECT id,schedule_interval_seconds FROM targets WHERE schedule_interval_seconds > 0`)
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
	job.mu.Unlock()
	defer func() { job.mu.Lock(); job.running = false; job.mu.Unlock() }()
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	_, _ = s.app.execute(ctx, targetID, "scheduler")
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
	app := &App{pg: pg, configs: mongoClient.Database(cfg.MongoDatabase).Collection("probe_configs"), cfg: cfg, client: &http.Client{Timeout: 30 * time.Second}}
	app.scheduler = NewScheduler(app, ctx)
	if err := app.scheduler.Start(); err != nil {
		panic(err)
	}
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
	_, err = pg.Exec(ctx, `INSERT INTO users (email,password_hash) VALUES ($1,$2) ON CONFLICT (email) DO NOTHING`, cfg.AdminEmail, string(hash))
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
	r.POST("/webhooks/deployments", a.deploymentWebhook)
	api := r.Group("/")
	api.Use(a.auth())
	api.POST("/targets", a.createTarget)
	api.GET("/targets", a.listTargets)
	api.GET("/targets/:id", a.getTarget)
	api.PUT("/targets/:id/config", a.putConfig)
	api.PUT("/targets/:id/schedule", a.putSchedule)
	api.POST("/targets/:id/probe", a.runProbe)
	api.POST("/targets/:id/gate", a.gate)
	api.GET("/targets/:id/runs", a.listRuns)
	api.GET("/runs/:id", a.getRun)
	api.GET("/incidents", a.listIncidents)
	return r
}
func cors() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", getenv("CORS_ORIGIN", "http://localhost:5173"))
		c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS")
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
		token, err := jwt.Parse(raw, func(t *jwt.Token) (any, error) { return []byte(a.cfg.JWTSecret), nil })
		if err != nil || !token.Valid {
			c.JSON(401, gin.H{"error": "unauthorized"})
			c.Abort()
			return
		}
		c.Next()
	}
}
func (a *App) login(c *gin.Context) {
	var in struct {
		Email, Password string `json:"email"`
	}
	if c.ShouldBindJSON(&in) != nil {
		c.JSON(400, gin.H{"error": "email and password are required"})
		return
	}
	var hash string
	err := a.pg.QueryRow(c, `SELECT password_hash FROM users WHERE email=$1`, in.Email).Scan(&hash)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(hash), []byte(in.Password)) != nil {
		c.JSON(401, gin.H{"error": "invalid credentials"})
		return
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": in.Email, "exp": time.Now().Add(24 * time.Hour).Unix()})
	signed, _ := t.SignedString([]byte(a.cfg.JWTSecret))
	c.JSON(200, gin.H{"token": signed})
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
		Name, BaseURL, Type string `json:"name"`
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
	err := a.pg.QueryRow(c, `UPDATE targets SET schedule_interval_seconds=$1 WHERE id=$2 RETURNING id,name,base_url,type,schedule_interval_seconds,created_at`, in.IntervalSeconds, id).Scan(&t.ID, &t.Name, &t.BaseURL, &t.Type, &t.ScheduleIntervalSeconds, &t.CreatedAt)
	if err != nil {
		c.JSON(404, gin.H{"error": "target not found"})
		return
	}
	a.scheduler.Upsert(t.ID, time.Duration(in.IntervalSeconds)*time.Second)
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
		_, err = a.pg.Exec(ctx, `INSERT INTO probe_results(run_id,layer,status,latency_ms,error_msg,checked_at) VALUES($1,$2,$3,$4,$5,$6)`, runID, r.Layer, r.Status, r.LatencyMS, r.ErrorMessage, r.CheckedAt)
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
					out.IncidentID = &iid
					out.Verdict = verdict
				}
				break
			}
		}
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
	resp, body, err := a.request(ctx, t, cfg)
	r.LatencyMS = int(time.Since(start).Milliseconds())
	if err != nil {
		r.Status = "fail"
		r.ErrorMessage = "contract request failed: " + err.Error()
		return r, nil
	}
	defer resp.Body.Close()
	expected := cfg.L3.ExpectedStatus
	if expected == 0 {
		expected = 200
	}
	if resp.StatusCode != expected {
		r.Status = "fail"
		r.ErrorMessage = fmt.Sprintf("expected status %d, got %d", expected, resp.StatusCode)
		return r, nil
	}
	var data map[string]any
	if err := json.Unmarshal(body, &data); err != nil {
		r.Status = "fail"
		r.ErrorMessage = "response is not valid JSON"
		return r, nil
	}
	if t.Type == "graphql" {
		if errs, ok := data["errors"]; ok && errs != nil {
			r.Status = "fail"
			r.ErrorMessage = "GraphQL response contains errors"
			return r, data
		}
		if nested, ok := data["data"].(map[string]any); ok {
			data = nested
		}
	}
	if len(cfg.L3.ExpectedShape) > 0 && !matchesShape(data, cfg.L3.ExpectedShape) {
		r.Status = "fail"
		r.ErrorMessage = "response does not match expected shape"
	}
	return r, data
}
func (a *App) request(ctx context.Context, t Target, cfg ProbeConfig) (*http.Response, []byte, error) {
	endpoint := strings.TrimRight(t.BaseURL, "/")
	if cfg.L3.Path != "" {
		endpoint += "/" + strings.TrimLeft(cfg.L3.Path, "/")
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
	err = a.pg.QueryRow(ctx, `INSERT INTO incidents(target_id,run_id,failed_layer,attributed_to,nearest_deploy_id,deploy_delta_mins,created_at) VALUES($1,$2,$3,$4,$5,$6,now()) RETURNING id`, targetID, runID, layer, class, deployID, delta).Scan(&incidentID)
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
	rows, _ := a.pg.Query(c, `SELECT layer,status,latency_ms,COALESCE(error_msg,''),checked_at FROM probe_results WHERE run_id=$1 ORDER BY layer`, id)
	defer rows.Close()
	for rows.Next() {
		var x LayerResult
		_ = rows.Scan(&x.Layer, &x.Status, &x.LatencyMS, &x.ErrorMessage, &x.CheckedAt)
		r.Results = append(r.Results, x)
	}
	c.JSON(200, r)
}
func (a *App) listIncidents(c *gin.Context) {
	rows, err := a.pg.Query(c, `SELECT i.id,i.target_id,i.run_id,i.failed_layer,i.attributed_to,i.nearest_deploy_id,i.deploy_delta_mins,i.created_at,t.name FROM incidents i JOIN targets t ON t.id=i.target_id ORDER BY i.created_at DESC LIMIT 100`)
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
		var created time.Time
		_ = rows.Scan(&id, &tid, &rid, &layer, &class, &dep, &delta, &created, &name)
		out = append(out, gin.H{"id": id, "target_id": tid, "target_name": name, "run_id": rid, "failed_layer": layer, "attributed_to": class, "nearest_deploy_id": dep, "deploy_delta_mins": delta, "created_at": created})
	}
	c.JSON(200, out)
}

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
