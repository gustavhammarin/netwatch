package api

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"netwatch/bpf"
	imagescan "netwatch/internal/image-scan/scan"
	"netwatch/internal/network"
	syscalls "netwatch/internal/syscall"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Server exposes the Netwatch API and embedded web UI.
type Server struct {
	token      string
	unsafeAuth bool
	iface      string
	manager    *Manager
}

// Config configures the API server.
type Config struct {
	Token        string
	UnsafeNoAuth bool
	Interface    string
}

// New returns a configured API server.
func New(config Config) *Server {
	return &Server{
		token:      config.Token,
		unsafeAuth: config.UnsafeNoAuth,
		iface:      config.Interface,
		manager:    NewManager(config.Interface),
	}
}

// Handler builds the HTTP handler tree.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.Handle("/api/images", s.auth(http.HandlerFunc(s.handleImages)))
	mux.Handle("/api/scans", s.auth(http.HandlerFunc(s.handleScans)))
	mux.Handle("/api/scans/current", s.auth(http.HandlerFunc(s.handleCurrent)))
	mux.Handle("/api/scans/current/stop", s.auth(http.HandlerFunc(s.handleStop)))
	mux.Handle("/api/scans/current/clear", s.auth(http.HandlerFunc(s.handleClear)))
	mux.Handle("/api/scans/events", s.auth(http.HandlerFunc(s.handleEvents)))
	return mux
}

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.unsafeAuth {
			next.ServeHTTP(w, r)
			return
		}
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token == "" {
			token = r.URL.Query().Get("token")
		}
		if s.token == "" || token != s.token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleIndex(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(indexHTML))
}

func (s *Server) handleImages(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "docker", "images", "--format", "{{.Repository}}:{{.Tag}}").Output()
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Errorf("list docker images: %w", err))
		return
	}

	var images []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.Contains(line, "<none>") {
			continue
		}
		images = append(images, line)
	}
	writeJSON(w, http.StatusOK, map[string]any{"images": images})
}

func (s *Server) handleScans(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var request StartRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("decode request: %w", err))
		return
	}
	state, err := s.manager.Start(r.Context(), request)
	if err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	writeJSON(w, http.StatusAccepted, state)
}

func (s *Server) handleCurrent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, s.manager.State())
}

func (s *Server) handleStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.manager.Stop()
	writeJSON(w, http.StatusOK, s.manager.State())
}

func (s *Server) handleClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, s.manager.Clear())
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch, unsubscribe := s.manager.Subscribe()
	defer unsubscribe()

	for {
		select {
		case event := <-ch:
			data, err := json.Marshal(event)
			if err != nil {
				continue
			}
			_, _ = fmt.Fprintf(w, "event: %s\n", event.Type)
			_, _ = fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

// StartRequest starts a new scan session.
type StartRequest struct {
	Image           string   `json:"image"`
	Command         []string `json:"command,omitempty"`
	DurationSeconds int      `json:"durationSeconds,omitempty"`
}

// Event is a streamable UI/API event.
type Event struct {
	Type    string `json:"type"`
	Message string `json:"message,omitempty"`
	Data    any    `json:"data,omitempty"`
	Time    string `json:"time"`
}

// State is the current scan state.
type State struct {
	ID        string               `json:"id,omitempty"`
	Image     string               `json:"image,omitempty"`
	Status    string               `json:"status"`
	StartedAt string               `json:"startedAt,omitempty"`
	EndedAt   string               `json:"endedAt,omitempty"`
	Packages  any                  `json:"packages,omitempty"`
	Findings  any                  `json:"findings,omitempty"`
	Logs      []string             `json:"logs,omitempty"`
	Syscalls  []syscalls.Event     `json:"syscalls,omitempty"`
	Flows     []network.FlowRecord `json:"flows,omitempty"`
	Errors    []string             `json:"errors,omitempty"`
}

// Manager owns the single active scan session.
type Manager struct {
	mu          sync.Mutex
	iface       string
	state       State
	cancel      context.CancelFunc
	subscribers map[chan Event]struct{}
}

// NewManager creates a manager that permits one scan at a time.
func NewManager(iface string) *Manager {
	return &Manager{
		iface:       iface,
		state:       State{Status: "idle"},
		subscribers: make(map[chan Event]struct{}),
	}
}

// Start starts a scan if no scan is currently running.
func (m *Manager) Start(parent context.Context, request StartRequest) (State, error) {
	if strings.TrimSpace(request.Image) == "" {
		return State{}, fmt.Errorf("image is required")
	}
	duration := time.Duration(request.DurationSeconds) * time.Second
	if duration <= 0 {
		duration = 60 * time.Second
	}

	m.mu.Lock()
	if m.cancel != nil && (m.state.Status == "running" || m.state.Status == "starting") {
		m.mu.Unlock()
		return State{}, fmt.Errorf("a scan is already running")
	}

	ctx, cancel := context.WithTimeout(context.Background(), duration)
	id := newID()
	m.cancel = cancel
	m.state = State{
		ID:        id,
		Image:     request.Image,
		Status:    "starting",
		StartedAt: time.Now().Format(time.RFC3339),
	}
	state := m.state
	m.mu.Unlock()

	m.publish("status", "starting scan session", state)
	go m.run(ctx, cancel, request, duration)
	return state, nil
}

// Stop cancels the active scan if one exists.
func (m *Manager) Stop() {
	m.mu.Lock()
	cancel := m.cancel
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// Clear clears retained scan data. Active scans keep running, but their collected
// output is reset from this point forward.
func (m *Manager) Clear() State {
	m.mu.Lock()
	if m.cancel == nil {
		m.state = State{Status: "idle"}
	} else {
		m.state.Packages = nil
		m.state.Findings = nil
		m.state.Logs = nil
		m.state.Syscalls = nil
		m.state.Flows = nil
		m.state.Errors = nil
	}
	state := m.state
	m.mu.Unlock()

	m.publish("status", "cleared", state)
	return state
}

// State returns a snapshot of current state.
func (m *Manager) State() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state
}

// Subscribe registers for future events.
func (m *Manager) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, 128)
	m.mu.Lock()
	m.subscribers[ch] = struct{}{}
	m.mu.Unlock()

	return ch, func() {
		m.mu.Lock()
		delete(m.subscribers, ch)
		close(ch)
		m.mu.Unlock()
	}
}

func (m *Manager) run(ctx context.Context, cancel context.CancelFunc, request StartRequest, duration time.Duration) {
	m.setStatus("running")
	m.publish("status", fmt.Sprintf("observing container for up to %s", duration), nil)

	var wg sync.WaitGroup
	wg.Add(4)
	go func() {
		defer wg.Done()
		m.runImageScan(ctx, request.Image)
	}()
	go func() {
		defer wg.Done()
		m.runSyscalls(ctx)
	}()
	go func() {
		defer wg.Done()
		m.runNetwork(ctx)
	}()
	go func() {
		defer wg.Done()
		m.runContainer(ctx, cancel, request)
	}()

	<-ctx.Done()
	wg.Wait()

	m.mu.Lock()
	if len(m.state.Errors) > 0 && !errors.Is(ctx.Err(), context.Canceled) {
		m.state.Status = "completed_with_errors"
	} else if errors.Is(ctx.Err(), context.Canceled) {
		m.state.Status = "stopped"
	} else {
		m.state.Status = "completed"
	}
	m.state.EndedAt = time.Now().Format(time.RFC3339)
	m.cancel = nil
	state := m.state
	m.mu.Unlock()
	m.publish("status", state.Status, state)
}

func (m *Manager) runImageScan(ctx context.Context, image string) {
	result, err := imagescan.Image(ctx, image, func(message string) {
		m.publish("scan", message, nil)
	})
	if err != nil {
		m.addError(err)
		return
	}

	m.mu.Lock()
	m.state.Packages = result.Packages
	m.state.Findings = result.Findings
	m.mu.Unlock()
	m.publish("findings", "image filesystem analysis completed", result)
}

func (m *Manager) runSyscalls(ctx context.Context) {
	var objs bpf.SyscallObjects
	if err := bpf.LoadSyscallObjects(&objs, nil); err != nil {
		m.addError(fmt.Errorf("load syscall bpf objects: %w", err))
		return
	}
	defer objs.Close()

	events := make(chan syscalls.Event, 512)
	go func() {
		for event := range events {
			m.mu.Lock()
			m.state.Syscalls = appendBounded(m.state.Syscalls, event, 600)
			m.mu.Unlock()
			m.publish("syscall", event.Name, event)
		}
	}()

	err := syscalls.Watch(ctx, &objs, events, func(message string) {
		m.publish("ebpf", message, nil)
	})
	close(events)
	if err != nil {
		m.addError(err)
	}
}

func (m *Manager) runNetwork(ctx context.Context) {
	if m.iface == "" {
		m.publish("network", "network watcher disabled: no interface configured", nil)
		return
	}

	var objs bpf.NetObjects
	if err := bpf.LoadNetObjects(&objs, nil); err != nil {
		m.addError(fmt.Errorf("load network bpf objects: %w", err))
		return
	}
	defer objs.Close()

	attachCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		if err := network.AttachXDP(attachCtx, objs, m.iface); err != nil && ctx.Err() == nil {
			m.addError(err)
		}
	}()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			flows, err := network.Snapshot(&objs)
			if err != nil {
				m.addError(err)
				continue
			}
			m.mu.Lock()
			m.state.Flows = flows
			m.mu.Unlock()
			m.publish("network", "network flows updated", flows)
		case <-ctx.Done():
			return
		}
	}
}

func (m *Manager) runContainer(ctx context.Context, cancel context.CancelFunc, request StartRequest) {
	name := "netwatch-scan-" + m.State().ID
	args := []string{"run", "--rm", "--name", name}
	if len(request.Command) == 0 {
		args = append(args, request.Image)
	} else {
		args = append(args, request.Image)
		args = append(args, request.Command...)
	}

	cmd := exec.CommandContext(ctx, "docker", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		m.addError(fmt.Errorf("docker stdout: %w", err))
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		m.addError(fmt.Errorf("docker stderr: %w", err))
		return
	}

	if err := cmd.Start(); err != nil {
		m.addError(fmt.Errorf("start container: %w", err))
		return
	}
	m.publish("container", "container started", map[string]string{"name": name})

	var wg sync.WaitGroup
	wg.Add(2)
	go scanLines(&wg, stdout, func(line string) { m.addLog(line) })
	go scanLines(&wg, stderr, func(line string) { m.addLog(line) })

	done := make(chan error, 1)
	go func() {
		wg.Wait()
		done <- cmd.Wait()
	}()

	select {
	case err := <-done:
		if err != nil && ctx.Err() == nil {
			m.addError(fmt.Errorf("container exited: %w", err))
		}
		m.publish("container", "container exited", nil)
		cancel()
	case <-ctx.Done():
		stopCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = exec.CommandContext(stopCtx, "docker", "stop", name).Run()
		<-done
		m.publish("container", "container stopped", nil)
	}
}

func scanLines(wg *sync.WaitGroup, pipe any, emit func(string)) {
	defer wg.Done()
	reader, ok := pipe.(interface {
		Read([]byte) (int, error)
	})
	if !ok {
		return
	}
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		emit(scanner.Text())
	}
}

func (m *Manager) setStatus(status string) {
	m.mu.Lock()
	m.state.Status = status
	state := m.state
	m.mu.Unlock()
	m.publish("status", status, state)
}

func (m *Manager) addLog(line string) {
	m.mu.Lock()
	m.state.Logs = appendBounded(m.state.Logs, line, 500)
	m.mu.Unlock()
	m.publish("log", line, line)
}

func (m *Manager) addError(err error) {
	if err == nil {
		return
	}
	m.mu.Lock()
	m.state.Errors = appendBounded(m.state.Errors, err.Error(), 100)
	m.mu.Unlock()
	m.publish("error", err.Error(), nil)
}

func (m *Manager) publish(eventType string, message string, data any) {
	event := Event{
		Type:    eventType,
		Message: message,
		Data:    data,
		Time:    time.Now().Format(time.RFC3339),
	}
	m.mu.Lock()
	for subscriber := range m.subscribers {
		select {
		case subscriber <- event:
		default:
		}
	}
	m.mu.Unlock()
}

func appendBounded[T any](values []T, value T, limit int) []T {
	values = append(values, value)
	if len(values) > limit {
		return values[len(values)-limit:]
	}
	return values
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("write json response: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func newID() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

func tokenFromEnv() string {
	return os.Getenv("NETWATCH_TOKEN")
}

const indexHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Netwatch</title>
  <style>
    :root { color-scheme: dark; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #101412; color: #eef4ef; }
    * { box-sizing: border-box; }
    body { margin: 0; min-height: 100vh; background: #101412; }
    header { display: flex; align-items: center; justify-content: space-between; padding: 16px 24px; border-bottom: 1px solid #29332d; background: #151b18; position: sticky; top: 0; z-index: 2; }
    h1 { margin: 0; font-size: 20px; font-weight: 750; letter-spacing: 0; }
    main { padding: 18px 24px 32px; display: grid; gap: 16px; grid-template-columns: minmax(300px, 380px) minmax(0, 1fr); }
    label { display: block; font-size: 12px; color: #aab9ad; margin-bottom: 6px; }
    input, select { width: 100%; height: 38px; border: 1px solid #3a463f; background: #0d120f; color: #eef4ef; border-radius: 6px; padding: 0 10px; }
    button { height: 38px; border: 1px solid #6ea878; background: #2f7d44; color: white; border-radius: 6px; padding: 0 12px; font-weight: 650; cursor: pointer; }
    button:hover { filter: brightness(1.08); }
    button.secondary { background: #242c28; border-color: #46524b; }
    button.danger { background: #8c3434; border-color: #b44a4a; }
    .panel { border: 1px solid #29332d; border-radius: 8px; background: #151b18; min-width: 0; }
    .panel h2 { margin: 0; padding: 14px 14px 0; font-size: 14px; color: #dce7df; display: flex; justify-content: space-between; gap: 12px; }
    .panel .body { padding: 14px; }
    .stack { display: grid; gap: 12px; align-content: start; }
    .row { display: flex; gap: 8px; align-items: end; }
    .row > * { flex: 1; }
    .status { display: inline-flex; align-items: center; min-height: 28px; padding: 0 10px; border: 1px solid #3a463f; border-radius: 999px; color: #cfe2d2; background: #101512; font-size: 13px; white-space: nowrap; }
    .grid { display: grid; gap: 18px; grid-template-columns: repeat(2, minmax(0, 1fr)); }
    pre { margin: 0; white-space: pre-wrap; overflow-wrap: anywhere; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; line-height: 1.45; color: #d8e7dc; max-height: 340px; overflow: auto; }
    table { width: 100%; border-collapse: collapse; font-size: 12px; }
    th, td { text-align: left; padding: 9px 8px; border-bottom: 1px solid #29332d; vertical-align: top; overflow-wrap: anywhere; }
    th { color: #aab9ad; font-weight: 650; position: sticky; top: 0; background: #151b18; }
    .scroll { max-height: 380px; overflow: auto; }
    .metric { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; }
    .metric div { border: 1px solid #29332d; border-radius: 6px; padding: 10px; background: #101512; }
    .metric strong { display: block; font-size: 20px; }
    .metric span { color: #aab9ad; font-size: 12px; }
    .muted { color: #8fa095; }
    .vuln-title { font-weight: 700; color: #f0f6f1; margin-bottom: 5px; }
    .vuln-meta { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 7px; }
    .pill { display: inline-flex; align-items: center; min-height: 22px; padding: 0 8px; border-radius: 999px; background: #243028; border: 1px solid #3a463f; color: #d8e7dc; font-size: 11px; }
    .pill.high { background: #4a2424; border-color: #7d3737; color: #ffd6d6; }
    .pill.medium { background: #46381e; border-color: #766037; color: #ffe7b5; }
    .pill.low { background: #1f3b34; border-color: #38685c; color: #c8f3e5; }
    .empty { color: #8fa095; padding: 20px 8px; text-align: center; }
    .two-col { display: grid; gap: 16px; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); grid-column: 1 / -1; }
    .wide { grid-column: 1 / -1; }
    @media (max-width: 980px) { main, .grid { grid-template-columns: 1fr; } header { align-items: flex-start; gap: 10px; flex-direction: column; } }
    @media (max-width: 980px) { .two-col { grid-template-columns: 1fr; } .metric { grid-template-columns: repeat(2, 1fr); } }
  </style>
</head>
<body>
  <header>
    <h1>Netwatch</h1>
    <span id="status" class="status">idle</span>
  </header>
  <main>
    <section class="panel stack">
      <div class="body stack">
        <div>
          <label for="token">Bearer token</label>
          <input id="token" type="password" autocomplete="off">
        </div>
        <div>
          <label for="image">Image</label>
          <input id="image" list="images" placeholder="nginx:latest">
          <datalist id="images"></datalist>
        </div>
        <div class="row">
          <button id="refresh" class="secondary">Refresh</button>
          <button id="start">Start</button>
          <button id="stop" class="danger">Stop</button>
        </div>
        <button id="clear" class="secondary">Clear</button>
        <div class="metric">
          <div><strong id="findingCount">0</strong><span>findings</span></div>
          <div><strong id="packageCount">0</strong><span>packages</span></div>
          <div><strong id="syscallCount">0</strong><span>syscalls</span></div>
          <div><strong id="flowCount">0</strong><span>flows</span></div>
        </div>
      </div>
    </section>
    <section class="panel">
      <h2>Timeline</h2>
      <div class="body"><pre id="timeline"></pre></div>
    </section>
    <section class="panel wide">
      <h2>Vulnerabilities <span class="muted" id="vulnHint"></span></h2>
      <div class="body scroll"><table><thead><tr><th style="width: 28%;">Package</th><th style="width: 14%;">Severity</th><th>Finding</th></tr></thead><tbody id="findings"></tbody></table></div>
    </section>
    <section class="two-col">
      <div class="panel"><h2>Container Logs</h2><div class="body"><pre id="logs"></pre></div></div>
      <div class="panel"><h2>Syscalls</h2><div class="body scroll"><table><thead><tr><th>Category</th><th>Call</th><th>Process</th><th>Path</th></tr></thead><tbody id="syscalls"></tbody></table></div></div>
    </section>
    <section class="grid" style="grid-column: 1 / -1;">
      <div class="panel"><h2>Network</h2><div class="body scroll"><table><thead><tr><th>Source</th><th>Destination</th><th>Protocol</th><th>Bytes</th></tr></thead><tbody id="flows"></tbody></table></div></div>
      <div class="panel"><h2>Errors</h2><div class="body"><pre id="errors"></pre></div></div>
    </section>
  </main>
  <script>
    const token = document.querySelector('#token');
    const image = document.querySelector('#image');
    const statusEl = document.querySelector('#status');
    const timeline = document.querySelector('#timeline');
    const logs = document.querySelector('#logs');
    const errors = document.querySelector('#errors');
    const findings = document.querySelector('#findings');
    const syscalls = document.querySelector('#syscalls');
    const flows = document.querySelector('#flows');
    const auth = () => ({ Authorization: 'Bearer ' + token.value });
    token.value = localStorage.getItem('netwatchToken') || '';
    token.addEventListener('input', () => localStorage.setItem('netwatchToken', token.value));
    function line(message) { timeline.textContent = '[' + new Date().toLocaleTimeString() + '] ' + message + '\n' + timeline.textContent; }
    async function api(path, options = {}) {
      options.headers = { ...(options.headers || {}), ...auth() };
      const res = await fetch(path, options);
      if (!res.ok) throw new Error((await res.text()).trim());
      return res.json();
    }
    async function refreshImages() {
      const data = await api('/api/images');
      document.querySelector('#images').innerHTML = data.images.map(v => '<option value="' + v.replaceAll('"', '&quot;') + '"></option>').join('');
      line('images refreshed');
    }
    async function refreshState() {
      const state = await api('/api/scans/current');
      renderState(state);
    }
    function renderState(state) {
      statusEl.textContent = state.status || 'idle';
      logs.textContent = (state.logs || []).join('\n');
      errors.textContent = (state.errors || []).join('\n');
      document.querySelector('#findingCount').textContent = (state.findings || []).length;
      document.querySelector('#packageCount').textContent = (state.packages || []).length;
      document.querySelector('#syscallCount').textContent = (state.syscalls || []).length;
      document.querySelector('#flowCount').textContent = (state.flows || []).length;
      document.querySelector('#vulnHint').textContent = (state.packages || []).length ? (state.packages || []).length + ' packages analyzed' : '';
      renderFindings(state.findings || []);
      syscalls.innerHTML = rowsOrEmpty((state.syscalls || []).slice(-160).reverse().map(s => '<tr><td>' + pill(s.category) + '</td><td>' + esc(s.name) + '</td><td>' + esc(s.comm + " #" + s.pid) + '</td><td>' + esc(s.path || '') + '</td></tr>'), 4, 'No syscalls captured yet');
      flows.innerHTML = rowsOrEmpty((state.flows || []).map(f => '<tr><td>' + esc(f.src_ip) + '</td><td>' + esc(f.dst_ip + ":" + f.dst_port) + '</td><td>' + esc(f.protocol + " " + f.service) + '</td><td>' + esc(String(f.bytes)) + '</td></tr>'), 4, 'No network flows captured yet');
    }
    function renderFindings(items) {
      const rows = items.slice(-160).map(f => {
        const v = f.vulnerability || {};
        const sev = severity(v);
        const pkg = f.package || {};
        const aliases = Array.isArray(v.aliases) ? v.aliases.slice(0, 4).join(', ') : '';
        const modified = v.modified ? 'Modified ' + shortDate(v.modified) : '';
        const published = v.published ? 'Published ' + shortDate(v.published) : '';
        const summary = v.summary || v.details || '';
        const id = v.id || aliases || 'Unknown advisory';
        return '<tr><td><div class="vuln-title">' + esc(pkg.name || '') + '</div><div class="muted">' + esc([pkg.version, pkg.ecosystem, pkg.architecture].filter(Boolean).join(' · ')) + '</div></td><td>' + severityPill(sev) + '</td><td><div class="vuln-title">' + esc(id) + '</div><div>' + esc(v.summary || 'No summary available') + '</div><div class="vuln-meta">' + [aliases && pill(aliases), published && pill(published), modified && pill(modified)].filter(Boolean).join('') + '</div>' + (summary && summary !== v.summary ? '<details><summary class="muted">details</summary><pre>' + esc(summary) + '</pre></details>' : '') + '</td></tr>';
      });
      findings.innerHTML = rowsOrEmpty(rows, 3, 'No vulnerabilities found yet');
    }
    function severity(v) {
      const values = Array.isArray(v.severity) ? v.severity : [];
      for (const item of values) {
        const score = String(item.score || '').toUpperCase();
        if (score.includes('CRITICAL')) return 'critical';
        if (score.includes('HIGH')) return 'high';
        if (score.includes('MEDIUM')) return 'medium';
        if (score.includes('LOW')) return 'low';
        const n = Number(score.match(/[0-9.]+/)?.[0]);
        if (n >= 9) return 'critical';
        if (n >= 7) return 'high';
        if (n >= 4) return 'medium';
        if (n > 0) return 'low';
      }
      return 'unknown';
    }
    function severityPill(value) {
      const klass = value === 'critical' ? 'high' : value;
      return '<span class="pill ' + esc(klass) + '">' + esc(value) + '</span>';
    }
    function pill(value) { return '<span class="pill">' + esc(value) + '</span>'; }
    function rowsOrEmpty(rows, colspan, text) { return rows.length ? rows.join('') : '<tr><td class="empty" colspan="' + colspan + '">' + esc(text) + '</td></tr>'; }
    function shortDate(value) { const d = new Date(value); return Number.isNaN(d.valueOf()) ? value : d.toISOString().slice(0, 10); }
    function esc(v) { return String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
    document.querySelector('#refresh').onclick = () => refreshImages().catch(e => line(e.message));
    document.querySelector('#start').onclick = async () => {
      try {
        const state = await api('/api/scans', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ image: image.value }) });
        renderState(state);
        line('started ' + image.value);
      } catch (e) { line(e.message); }
    };
    document.querySelector('#stop').onclick = () => api('/api/scans/current/stop', { method: 'POST' }).then(renderState).catch(e => line(e.message));
    document.querySelector('#clear').onclick = () => {
      timeline.textContent = '';
      api('/api/scans/current/clear', { method: 'POST' }).then(renderState).then(() => line('cleared')).catch(e => line(e.message));
    };
    function connectEvents() {
      const source = new EventSource('/api/scans/events?token=' + encodeURIComponent(token.value));
      source.onmessage = event => line(event.data);
      ['status','scan','container','log','syscall','network','findings','error','ebpf'].forEach(type => {
        source.addEventListener(type, event => {
          const payload = JSON.parse(event.data);
          if (payload.message) line(payload.type + ': ' + payload.message);
          refreshState().catch(() => {});
        });
      });
      source.onerror = () => setTimeout(connectEvents, 2500);
    }
    connectEvents();
    refreshImages().catch(() => {});
    refreshState().catch(() => {});
  </script>
</body>
</html>`

// TokenFromEnv returns NETWATCH_TOKEN.
func TokenFromEnv() string {
	return tokenFromEnv()
}
