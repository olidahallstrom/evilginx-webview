# Phishlets Directory

## What are Phishlets?

Phishlets are configuration files that define how Evilginx2 should intercept and proxy requests for specific websites. They contain the rules for:

- **Proxy Hosts**: Which subdomains to proxy
- **Sub Filters**: Text replacement rules
- **Auth Tokens**: Which cookies/tokens to capture
- **Credentials**: Username and password field detection
- **Login Pages**: Where authentication happens

## ⚠️ Important Notice

This directory contains only **demonstration phishlets** for educational purposes. These examples are:

- **Non-functional**: They don't target real services
- **Educational**: Designed to show phishlet structure
- **Safe**: Won't cause harm when used

## File Structure

```
phishlets/
├── README.md           # This file
├── example.yaml        # Original example phishlet
├── demo-generic.yaml   # Generic demo phishlet
├── demo-simple.yaml    # Simple demo phishlet
└── demo-advanced.yaml  # Advanced demo phishlet
```

## Phishlet Format

### Basic Structure
```yaml
min_ver: '3.0.0'
proxy_hosts:
  - {phish_sub: 'login', orig_sub: 'login', domain: 'example.com', session: true, is_landing: true, auto_filter: true}
sub_filters:
  - {triggers_on: 'example.com', orig_sub: 'login', domain: 'example.com', search: 'pattern', replace: 'replacement', mimes: ['text/html']}
auth_tokens:
  - domain: '.example.com'
    keys: ['session_token', 'auth_cookie']
credentials:
  username:
    key: 'username'
    search: '(.*)'
    type: 'post'
  password:
    key: 'password'
    search: '(.*)'
    type: 'post'
login:
  domain: 'login.example.com'
  path: '/login'
```

### Configuration Options

#### Proxy Hosts
- `phish_sub`: Subdomain on your phishing domain
- `orig_sub`: Original subdomain of target site
- `domain`: Target domain
- `session`: Whether to track sessions
- `is_landing`: Landing page for victims
- `auto_filter`: Automatic content filtering

#### Sub Filters
- `triggers_on`: Domain that triggers the filter
- `orig_sub`: Original subdomain
- `domain`: Target domain
- `search`: Regex pattern to find
- `replace`: Replacement text
- `mimes`: MIME types to filter

#### Auth Tokens
- `domain`: Cookie domain
- `keys`: List of cookie names to capture

#### Credentials
- `username/password`: Field configurations
- `key`: Form field name
- `search`: Regex pattern for extraction
- `type`: 'post' or 'json'

## Usage Commands

### Loading Phishlets
```bash
# Load a phishlet
phishlets load demo-generic

# List available phishlets
phishlets

# Show phishlet details
phishlets show demo-generic
```

### Configuring Phishlets
```bash
# Set hostname
phishlets hostname demo-generic login.evil.com

# Enable phishlet
phishlets enable demo-generic

# Disable phishlet
phishlets disable demo-generic
```

### Managing Phishlets
```bash
# Hide phishlet (redirect all requests)
phishlets hide demo-generic

# Show phishlet (make accessible)
phishlets show demo-generic

# Get phishlet status
phishlets status demo-generic
```

## Creating Custom Phishlets

### 1. Analysis Phase
- Study the target website's structure
- Identify authentication flows
- Map subdomains and endpoints
- Analyze form submissions

### 2. Configuration Phase
- Define proxy hosts
- Set up sub filters for content replacement
- Configure auth token capture
- Define credential extraction rules

### 3. Testing Phase
- Test with developer mode
- Verify token capture
- Check content filtering
- Validate session handling

### 4. Deployment Phase
- Configure SSL certificates
- Set up DNS records
- Deploy to production environment
- Monitor for issues

## Security Considerations

### Legal Compliance
- Only use for authorized testing
- Get written permission
- Follow local laws
- Document authorized scope

### Technical Security
- Use HTTPS only
- Implement proper logging
- Monitor for abuse
- Regular security updates

### Ethical Guidelines
- Educational purposes only
- No unauthorized access
- Respect privacy
- Responsible disclosure

## Troubleshooting

### Common Issues

**Phishlet Won't Load**
```bash
# Check syntax
phishlets load demo-generic

# Verify file permissions
ls -la phishlets/

# Check logs
tail -f logs/evilginx.log
```

**Auth Tokens Not Captured**
```bash
# Verify token configuration
phishlets show demo-generic

# Check session data
sessions

# Review proxy logs
```

**Content Not Filtering**
```bash
# Check sub_filters configuration
# Verify MIME types
# Test with browser developer tools
```

## Examples

See the demo phishlets in this directory:
- `demo-generic.yaml` - Basic phishlet structure
- `demo-simple.yaml` - Simple login form
- `demo-advanced.yaml` - Advanced multi-step authentication

## Resources

- **Official Documentation**: https://help.evilginx.com
- **Phishlet Examples**: https://github.com/kgretzky/evilginx2
- **Training Course**: https://academy.breakdev.org/evilginx-mastery

## Disclaimer

These examples are for educational purposes only. Users must ensure they have proper authorization before using these tools against any targets. Unauthorized use is illegal and unethical.

**Use responsibly and ethically.** 