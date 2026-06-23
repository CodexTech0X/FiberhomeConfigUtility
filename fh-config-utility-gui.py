#!/usr/bin/env python3
"""
Fiberhome HG6145F1 Config Utility GUI
A standalone, zero-dependency, local desktop GUI (Tkinter) for Algérie Télécom Fiberhome ONTs.
Decrypts, extracts, and generates a beautiful, self-contained offline HTML5 report.
Also supports folder re-encryption, inline password AES cryptography, and Superuser password generation.
"""

import os
import sys
import io
import gzip
import tarfile
import random
import binascii
import json
import webbrowser
import base64
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

# Import PyCryptodome (AES for credentials)
try:
    from Crypto.Cipher import AES
    HAS_AES = True
except ImportError:
    HAS_AES = False

# Hardcoded keys
XOR_KEY = 0x2537
AES_KEY = b"ABCDEFGHIJKLMNOP"

def resource_path(relative_name: str) -> str:
    """
    Returns the absolute path to a bundled resource.
    - In development: uses the directory of this script.
    - In PyInstaller EXE: uses sys._MEIPASS (the temp extraction folder).
    This ensures icons and assets are found regardless of the installation path.
    """
    try:
        # PyInstaller sets this attribute when running as a frozen EXE
        base = sys._MEIPASS
    except AttributeError:
        base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, relative_name)

def xor_transform(data: bytes, key: int) -> bytes:
    size = len(data)
    out = bytearray(size)
    size_div_key = size // key
    for i, b in enumerate(data):
        transform_val = (size + key + i) - size_div_key
        out[i] = b ^ (transform_val & 0xFF)
    return bytes(out)

def decompress_if_needed(data: bytes) -> bytes:
    if data.startswith(b"\x1F\x8B"):
        return gzip.decompress(data)
    return data

def is_tar(data: bytes) -> bool:
    return len(data) > 262 and data[257:262] == b"ustar"

def fh_decrypt_string(cipher_hex: str) -> str:
    if not HAS_AES:
        return "[Error: PyCryptodome not installed]"
    try:
        cipher = AES.new(AES_KEY, AES.MODE_ECB)
        ciphertext = bytes.fromhex(cipher_hex.strip())
        plaintext = cipher.decrypt(ciphertext)
        return plaintext.rstrip(b"\x00").decode("utf-8", errors="ignore")
    except Exception as e:
        return f"[Decryption Error: {str(e)}]"

def fh_encrypt_string(plaintext: str) -> str:
    if not HAS_AES:
        return "[Error: PyCryptodome not installed]"
    try:
        cipher = AES.new(AES_KEY, AES.MODE_ECB)
        block_size = AES.block_size
        data = plaintext.encode("utf-8")
        padding = block_size - (len(data) % block_size)
        if padding != block_size:
            data += b"\x00" * padding
        ciphertext = cipher.encrypt(data)
        return binascii.hexlify(ciphertext).decode().upper()
    except Exception as e:
        return f"[Encryption Error: {str(e)}]"

def decrypt_if_encrypted(val: str) -> str:
    if not val or val == "UCI_NULL":
        return val
    if len(val) >= 32 and len(val) % 32 == 0:
        try:
            int(val, 16) # check if hex
            return fh_decrypt_string(val)
        except ValueError:
            return val
    return val

# MAC to Superuser Password algorithm ported from index.html (Algeria Telecom HG6145F1 RP4423 profile)
def calculate_super_password(mac: str) -> str:
    clean_mac = mac.replace(":", "").replace("-", "").replace(".", "").upper()
    if len(clean_mac) != 12:
        raise ValueError("MAC Address must be exactly 12 hex characters.")
    
    # Re-insert colons: expected format in JS MD5(mac + "AEJLY") is XX:XX:XX:XX:XX:XX
    formatted_mac = ":".join(clean_mac[i:i+2] for i in range(0, 12, 2))
    input_str = formatted_mac + "AEJLY"
    
    # Calculate MD5
    digest = hashlib.md5(input_str.encode("utf-8")).hexdigest()
    
    vals = []
    for i in range(20):
        c = digest[i]
        if c.isdigit():
            vals.append(ord(c) - 48)
        else:
            vals.append(ord(c) - 87)
            
    upper_chars = "ACDFGHJMNPRSTUWXY"
    lower_chars = "abcdfghjkmpstuwxy"
    digit_chars = "2345679"
    symbol_chars = "!@$&%"
    
    password = [''] * 16
    for i in range(16):
        v = vals[i]
        t = v % 4
        if t == 0:
            password[i] = upper_chars[(v * 2) % 17]
        elif t == 1:
            password[i] = lower_chars[(v * 2 + 1) % 17]
        elif t == 2:
            password[i] = digit_chars[6 - (v % 7)];
        else:
            password[i] = symbol_chars[4 - (v % 5)];
            
    def next_free(start, taken):
        p = start % 16
        while p in taken:
            p = (p + 1) % 16
        return p
        
    taken = set()
    p0 = next_free(vals[16] + 1, taken); taken.add(p0)
    p1 = next_free(vals[17] + 1, taken); taken.add(p1)
    p2 = next_free(vals[18] + 1, taken); taken.add(p2)
    p3 = next_free(vals[19] + 1, taken)
    
    password[p0] = upper_chars[(vals[16] * 2) % 17]
    password[p1] = lower_chars[(vals[17] * 2 + 1) % 17]
    password[p2] = digit_chars[6 - (vals[18] % 7)]
    password[p3] = symbol_chars[4 - (vals[19] % 5)]
    
    return "".join(password)

# UCI Parser & Serializer
def parse_uci(content: str):
    sections = []
    current_section = None
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("config "):
            parts = line.split(maxsplit=2)
            sec_type = parts[1]
            sec_name = parts[2].strip("'\"") if len(parts) > 2 else ""
            current_section = {
                "type": sec_type,
                "name": sec_name,
                "options": {}
            }
            sections.append(current_section)
        elif line.startswith("option ") and current_section is not None:
            parts = line.split(maxsplit=2)
            if len(parts) >= 3:
                opt_key = parts[1]
                opt_val = parts[2].strip("'\"")
                current_section["options"][opt_key] = opt_val
    return sections

# Extract and decrypt config
def extract_and_parse_config(file_bytes: bytes):
    decrypted_bytes = xor_transform(file_bytes, XOR_KEY)
    decompressed = decompress_if_needed(decrypted_bytes)
    
    config_text = ""
    
    if is_tar(decompressed):
        with tarfile.open(fileobj=io.BytesIO(decompressed), mode="r:*") as tar:
            for member in tar.getmembers():
                f_obj = tar.extractfile(member)
                if f_obj:
                    content = f_obj.read().decode("utf-8", errors="ignore")
                    if member.name == "usrconfig_conf":
                        config_text = content
    else:
        config_text = decompressed.decode("utf-8", errors="ignore")
        
    if not config_text:
        raise ValueError("Could not find configuration content (usrconfig_conf) inside file.")
        
    sections = parse_uci(config_text)
    
    # Structure credentials for HTML display
    internet = []
    wifi = []
    voip = []
    admin = []
    lan = {}
    
    for sec in sections:
        sec_name = sec["name"]
        options = sec["options"]
        
        # 1. Internet WAN PPPoE
        if "WANPPPConnection" in sec_name:
            vlan = options.get("VLANID", "")
            proto = options.get("AddressingType", "")
            service = options.get("X_FH_ServiceList", "")
            enc_user = options.get("Username", "")
            enc_pass = options.get("Password", "")
            
            internet.append({
                "section": sec_name,
                "vlan": vlan,
                "proto": proto,
                "service": service,
                "username_dec": decrypt_if_encrypted(enc_user),
                "username_raw": enc_user,
                "password_dec": decrypt_if_encrypted(enc_pass),
                "password_raw": enc_pass
            })
            
        # 2. WiFi Settings
        elif "WLANConfiguration" in sec_name or "BSSMode" in sec_name:
            ssid = options.get("SSID", "")
            pre_key = options.get("PreSharedKey", "")
            key_pass = options.get("KeyPassphrase", "")
            enable = options.get("Enable", "1")
            raw_key = key_pass if key_pass else pre_key
            
            if ssid:
                wifi.append({
                    "section": sec_name,
                    "ssid": ssid,
                    "enable": enable,
                    "password_dec": decrypt_if_encrypted(raw_key),
                    "password_raw": raw_key
                })
                
        # 3. Web Login Account
        elif "WebUserInfo" in sec_name:
            enc_pass = options.get("WebPassword", "")
            admin.append({
                "section": sec_name,
                "username": "admin / user",
                "password_dec": decrypt_if_encrypted(enc_pass),
                "password_raw": enc_pass
            })
            
        # 4. Voice VoIP Settings
        elif sec_name.endswith("__SIP__"):
            proxy = options.get("ProxyServer", "")
            standby = options.get("X_FH_Standby111ProxyServer", "")
            port = options.get("ProxyServerPort", "5060")
            if proxy or standby:
                voip.append({
                    "section": sec_name,
                    "proxy": proxy,
                    "standby": standby,
                    "port": port
                })
                
        # 5. LAN configuration
        elif sec_name.endswith("__LANHostConfigManagement__"):
            lan = {
                "section": sec_name,
                "ip": options.get("IPRouters", "192.168.1.1"),
                "subnet": options.get("SubnetMask", "255.255.255.0"),
                "dhcp_start": options.get("MinAddress", ""),
                "dhcp_end": options.get("MaxAddress", ""),
                "dns": options.get("DNSServers", "")
            }
            
    if not lan:
        for sec in sections:
            if "LANHostConfigManagement__IPInterface" in sec["name"]:
                lan = {
                    "section": sec["name"],
                    "ip": sec["options"].get("IPInterfaceIPAddress", "192.168.1.1"),
                    "subnet": sec["options"].get("IPInterfaceSubnetMask", "255.255.255.0"),
                    "dhcp_start": "",
                    "dhcp_end": "",
                    "dns": ""
                }
                break

    # Read base64 icon to inject in HTML
    icon_b64 = ""
    icon_png_path = resource_path("icon.png")
    if os.path.exists(icon_png_path):
        try:
            with open(icon_png_path, "rb") as f_icon:
                icon_b64 = base64.b64encode(f_icon.read()).decode("utf-8")
        except Exception:
            pass

    return {
        "raw_config_text": config_text,
        "icon_b64": icon_b64,
        "extracted": {
            "internet": internet,
            "wifi": wifi,
            "voip": voip,
            "admin": admin,
            "lan": lan
        }
    }

# HTML Template
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Fiberhome HG6145F1 Config Report</title>
    <link id="favicon-link" rel="icon" type="image/png" href="" />
    <style>
        :root {
            --bg-color: #0b0f19;
            --card-bg: rgba(22, 28, 45, 0.45);
            --border-color: rgba(255, 255, 255, 0.08);
            --primary: #3b82f6;
            --primary-glow: rgba(59, 130, 246, 0.4);
            --success: #10b981;
            --success-glow: rgba(16, 185, 129, 0.3);
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            transition: all 0.25s ease;
        }

        body {
            background-color: var(--bg-color);
            background-image: radial-gradient(circle at top left, #1e1b4b 0%, #090716 100%);
            color: var(--text-main);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            padding: 40px 20px;
        }

        .container {
            width: 100%;
            max-width: 1000px;
            display: flex;
            flex-direction: column;
            gap: 25px;
        }

        header {
            text-align: center;
            margin-bottom: 5px;
        }

        header h1 {
            font-size: 2.2rem;
            font-weight: 800;
            background: linear-gradient(135deg, #60a5fa, #3b82f6, #818cf8);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 8px;
            letter-spacing: -0.5px;
        }

        header p {
            color: var(--text-muted);
            font-size: 1rem;
        }

        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            margin-top: 10px;
            background: rgba(16, 185, 129, 0.15);
            color: #34d399;
            border: 1px solid rgba(16, 185, 129, 0.3);
        }

        .glass-card {
            background: var(--card-bg);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 30px;
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.4);
        }

        /* Tabs Navigation */
        .tabs {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 10px;
            margin-bottom: 10px;
        }
        .tab-btn {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid var(--border-color);
            color: var(--text-muted);
            padding: 10px 18px;
            border-radius: 8px;
            font-weight: 600;
            font-size: 0.9rem;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .tab-btn:hover {
            background: rgba(255, 255, 255, 0.1);
            color: var(--text-main);
        }
        .tab-btn.active {
            background: var(--primary);
            color: #ffffff;
            border-color: var(--primary);
            box-shadow: 0 0 12px var(--primary-glow);
        }

        /* Tab Content panels */
        .tab-content {
            display: none;
            flex-direction: column;
            gap: 20px;
            margin-top: 10px;
        }
        .tab-content.active {
            display: flex;
        }

        .section-header {
            font-size: 1.25rem;
            font-weight: 700;
            border-left: 4px solid var(--primary);
            padding-left: 10px;
            margin-bottom: 15px;
            color: #ffffff;
        }

        .settings-grid {
            display: grid;
            grid-template-columns: 1fr;
            gap: 20px;
        }
        @media(min-width: 768px) {
            .settings-grid {
                grid-template-columns: 1fr 1fr;
            }
        }

        .input-group {
            display: flex;
            flex-direction: column;
            gap: 8px;
            background: rgba(255, 255, 255, 0.01);
            border: 1px solid rgba(255, 255, 255, 0.03);
            padding: 15px;
            border-radius: 10px;
        }
        .input-group label {
            font-size: 0.82rem;
            font-weight: 600;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .field-row {
            display: flex;
            gap: 8px;
        }
        .field-row input {
            flex: 1;
            background: rgba(0, 0, 0, 0.35);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 10px 12px;
            color: #ffffff;
            font-size: 0.95rem;
            font-family: monospace;
        }
        .field-row input:focus {
            border-color: var(--primary);
            outline: none;
        }

        /* Action Buttons */
        .btn-icon {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid var(--border-color);
            color: var(--text-main);
            width: 38px;
            height: 38px;
            border-radius: 6px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .btn-icon:hover {
            background: rgba(255, 255, 255, 0.15);
        }
        .btn-icon svg {
            width: 18px;
            height: 18px;
            stroke: currentColor;
            fill: none;
        }

        .btn-action-container {
            display: flex;
            justify-content: flex-end;
            gap: 12px;
            margin-top: 15px;
        }

        .btn {
            padding: 12px 24px;
            border-radius: 8px;
            font-weight: 700;
            font-size: 0.95rem;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            border: none;
            text-decoration: none;
        }
        .btn-primary {
            background: linear-gradient(135deg, #2563eb, #1d4ed8);
            color: #ffffff;
            box-shadow: 0 4px 15px var(--primary-glow);
        }
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(37, 99, 235, 0.6);
        }

        .raw-textarea {
            width: 100%;
            height: 400px;
            background: rgba(0, 0, 0, 0.4);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 15px;
            color: #34d399;
            font-family: monospace;
            font-size: 0.9rem;
            resize: vertical;
            white-space: pre;
            overflow: auto;
        }

        .toast {
            position: fixed;
            bottom: 25px;
            right: 25px;
            background: rgba(16, 185, 129, 0.9);
            color: #ffffff;
            padding: 12px 24px;
            border-radius: 8px;
            font-weight: 600;
            box-shadow: 0 4px 15px var(--success-glow);
            display: none;
            z-index: 100;
        }

        .search-bar {
            width: 100%;
            background: rgba(0, 0, 0, 0.2);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 12px 15px;
            color: #ffffff;
            font-size: 0.95rem;
            margin-bottom: 15px;
        }
        .search-bar:focus {
            border-color: var(--primary);
            outline: none;
        }
    </style>
</head>
<body>

<div class="container">
    <header>
        <div style="display: flex; align-items: center; justify-content: center; gap: 15px; margin-bottom: 12px;">
            <img id="html-logo" src="" style="width: 48px; height: 48px; border-radius: 8px; display: none;" />
            <h1>Fiberhome HG6145F1 Config Report</h1>
        </div>
        <p>Offline decrypted configuration summary</p>
        <span class="badge">Algérie Télécom Profile</span>
    </header>

    <div class="glass-card">
        <div class="tabs">
            <button class="tab-btn active" onclick="showTab('tab-wan')">Internet (WAN)</button>
            <button class="tab-btn" onclick="showTab('tab-wifi')">Wi-Fi Network</button>
            <button class="tab-btn" onclick="showTab('tab-admin')">ONT Admin</button>
            <button class="tab-btn" onclick="showTab('tab-voip')">VoIP (SIP)</button>
            <button class="tab-btn" onclick="showTab('tab-lan')">LAN & DNS</button>
            <button class="tab-btn" onclick="showTab('tab-super')">Superuser Pass</button>
            <button class="tab-btn" onclick="showTab('tab-raw')">Raw Config</button>
        </div>

        <input type="text" class="search-bar" id="search-filter" placeholder="Search settings..." onkeyup="filterSettings()">
        
        <!-- Tab: WAN -->
        <div class="tab-content active" id="tab-wan">
            <div class="section-header">PPPoE Internet Configurations</div>
            <div class="settings-grid" id="wan-container"></div>
        </div>

        <!-- Tab: WiFi -->
        <div class="tab-content" id="tab-wifi">
            <div class="section-header">Wireless SSID & Keys</div>
            <div class="settings-grid" id="wifi-container"></div>
        </div>

        <!-- Tab: Admin -->
        <div class="tab-content" id="tab-admin">
            <div class="section-header">ONT Web Console Access</div>
            <div class="settings-grid" id="admin-container"></div>
        </div>

        <!-- Tab: VoIP -->
        <div class="tab-content" id="tab-voip">
            <div class="section-header">SIP Settings</div>
            <div class="settings-grid" id="voip-container"></div>
        </div>

        <!-- Tab: LAN & DNS -->
        <div class="tab-content" id="tab-lan">
            <div class="section-header">LAN & DHCP Servers</div>
            <div class="settings-grid" id="lan-container"></div>
        </div>

        <!-- Tab: Superuser -->
        <div class="tab-content" id="tab-super">
            <div class="section-header">Web Superuser Password Generator</div>
            <div class="input-group" style="grid-column: 1/-1">
                <label for="mac-input-rep">MAC Address</label>
                <div class="field-row" style="margin-bottom:12px; gap:10px;">
                    <input type="text" id="mac-input-rep" placeholder="A8:5A:F3:00:11:22" maxlength="17" autocomplete="off" style="font-family: monospace;">
                    <button class="btn btn-primary" id="btn-gen-rep" onclick="generateSuperReport()" style="padding:10px 20px;">GENERATE</button>
                </div>
                <label>Generated Superuser Password</label>
                <div class="field-row">
                    <input type="password" id="pw-display-rep" readonly>
                    <button class="btn-icon" onclick="togglePassVisibility('pw-display-rep')">
                        <svg viewBox="0 0 24 24" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                    </button>
                    <button class="btn-icon" onclick="copyText('pw-display-rep')">
                        <svg viewBox="0 0 24 24" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                    </button>
                </div>
            </div>
        </div>

        <!-- Tab: Raw -->
        <div class="tab-content" id="tab-raw">
            <div class="section-header">UCI Text Representation (usrconfig_conf)</div>
            <textarea class="raw-textarea" id="raw-config-text" readonly></textarea>
        </div>
        
        <!-- Global Action Bar -->
        <div class="btn-action-container">
            <button class="btn btn-primary" onclick="exportTxtBackup()">
                Export Text Summary Backup
            </button>
        </div>
    </div>
</div>

<div class="toast" id="toast">Notification text</div>

<script>
    // Embedded decrypted JSON data loaded statically
    /* __DATA_PLACEHOLDER__ */

    function showToast(text, duration = 3000) {
        const toast = document.getElementById('toast');
        toast.innerText = text;
        toast.style.display = 'block';
        setTimeout(() => {
            toast.style.display = 'none';
        }, duration);
    }

    function showTab(tabId) {
        document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
        
        event.currentTarget.classList.add('active');
        document.getElementById(tabId).classList.add('active');
    }

    function copyText(inputId) {
        const el = document.getElementById(inputId);
        el.select();
        document.execCommand('copy');
        showToast("Copied value to clipboard!");
    }

    function togglePassVisibility(inputId) {
        const el = document.getElementById(inputId);
        el.type = el.type === "password" ? "text" : "password";
    }

    function filterSettings() {
        const query = document.getElementById('search-filter').value.toLowerCase();
        document.querySelectorAll('.input-group').forEach(group => {
            const content = group.getAttribute('data-search') ? group.getAttribute('data-search').toLowerCase() : '';
            const inputs = Array.from(group.querySelectorAll('input')).map(input => input.value.toLowerCase()).join(' ');
            if (content.includes(query) || inputs.includes(query)) {
                group.style.display = 'flex';
            } else {
                group.style.display = 'none';
            }
        });
    }

    // ── Bundled MD5 ──
    function MD5(str) {
      function safeAdd(x,y){var lsw=(x&0xFFFF)+(y&0xFFFF),msw=(x>>16)+(y>>16)+(lsw>>16);return(msw<<16)|(lsw&0xFFFF)}
      function rol(n,c){return(n<<c)|(n>>>(32-c))}
      function cmn(q,a,b,x,s,t){return safeAdd(rol(safeAdd(safeAdd(a,q),safeAdd(x,t)),s),b)}
      function ff(a,b,c,d,x,s,t){return cmn((b&c)|(~b&d),a,b,x,s,t)}
      function gg(a,b,c,d,x,s,t){return cmn((b&d)|(c&~d),a,b,x,s,t)}
      function hh(a,b,c,d,x,s,t){return cmn(b^c^d,a,b,x,s,t)}
      function ii(a,b,c,d,x,s,t){return cmn(c^(b|~d),a,b,x,s,t)}
      function blks(s){
        var i,nb=((s.length+8)>>6)+1,w=new Array(nb*16);
        for(i=0;i<nb*16;i++)w[i]=0;
        for(i=0;i<s.length;i++)w[i>>2]|=s.charCodeAt(i)<<((i%4)*8);
        w[i>>2]|=0x80<<((i%4)*8);
        w[nb*16-2]=s.length*8;
        return w;
      }
      var w=blks(str),a=1732584193,b=-271733879,c=-1732584194,d=271733878;
      for(var i=0;i<w.length;i+=16){
        var oa=a,ob=b,oc=c,od=d;
        a=ff(a,b,c,d,w[i+0],7,-680876936);   d=ff(d,a,b,c,w[i+1],12,-389564586);  c=ff(c,d,a,b,w[i+2],17,606105819);    b=ff(b,c,d,a,w[i+3],22,-1044525330);
        a=ff(a,b,c,d,w[i+4],7,-176418897);   d=ff(d,a,b,c,w[i+5],12,1200080426);  c=ff(c,d,a,b,w[i+6],17,-1473231341);  b=ff(b,c,d,a,w[i+7],22,-45705983);
        a=ff(a,b,c,d,w[i+8],7,1770035416);   d=ff(d,a,b,c,w[i+9],12,-1958414417); c=ff(c,d,a,b,w[i+10],17,-42063);      b=ff(b,c,d,a,w[i+11],22,-1990404162);
        a=ff(a,b,c,d,w[i+12],7,1804603682);  d=ff(d,a,b,c,w[i+13],12,-40341101);  c=ff(c,d,a,b,w[i+14],17,-1502002290); b=ff(b,c,d,a,w[i+15],22,1236535329);
        a=gg(a,b,c,d,w[i+1],5,-165796510);   d=gg(d,a,b,c,w[i+6],9,-1069501632);  c=gg(c,d,a,b,w[i+11],14,643717713);   b=gg(b,c,d,a,w[i+0],20,-373897302);
        a=gg(a,b,c,d,w[i+5],5,-701558691);   d=gg(d,a,b,c,w[i+10],9,38016083);    c=gg(c,d,a,b,w[i+15],14,-660478335);  b=gg(b,c,d,a,w[i+4],20,-405537848);
        a=gg(a,b,c,d,w[i+9],5,568446438);    d=gg(d,a,b,c,w[i+14],9,-1019803690); c=gg(c,d,a,b,w[i+3],14,-187363961);   b=gg(b,c,d,a,w[i+8],20,1163531501);
        a=gg(a,b,c,d,w[i+13],5,-1444681467); d=gg(d,a,b,c,w[i+2],9,-51403784);    c=gg(c,d,a,b,w[i+7],14,1735328473);   b=gg(b,c,d,a,w[i+12],20,-1926607734);
        a=hh(a,b,c,d,w[i+5],4,-378558);      d=hh(d,a,b,c,w[i+8],11,-2022574463); c=hh(c,d,a,b,w[i+11],16,1839030562);  b=hh(b,c,d,a,w[i+14],23,-35309556);
        a=hh(a,b,c,d,w[i+1],4,-1530992060); d=hh(d,a,b,c,w[i+4],11,1272893353);  c=hh(c,d,a,b,w[i+7],16,-155497632);   b=hh(b,c,d,a,w[i+10],23,-1094730640);
        a=hh(a,b,c,d,w[i+13],4,681279174);   d=hh(d,a,b,c,w[i+0],11,-358537222);  c=hh(c,d,a,b,w[i+3],16,-722521979);   b=hh(b,c,d,a,w[i+6],23,76029189);
        a=hh(a,b,c,d,w[i+9],4,-640364487);   d=hh(d,a,b,c,w[i+12],11,-421815835); c=hh(c,d,a,b,w[i+15],16,530742520);   b=hh(b,c,d,a,w[i+2],23,-995338651);
        a=ii(a,b,c,d,w[i+0],6,-198630844);   d=ii(d,a,b,c,w[i+7],10,1126891415);  c=ii(c,d,a,b,w[i+14],15,-1416354905); b=ii(b,c,d,a,w[i+5],21,-57434055);
        a=ii(a,b,c,d,w[i+12],6,1700485571);  d=ii(d,a,b,c,w[i+3],10,-1894986606); c=ii(c,d,a,b,w[i+10],15,-1051523);    b=ii(b,c,d,a,w[i+1],21,-2054922799);
        a=ii(a,b,c,d,w[i+8],6,1873313359);   d=ii(d,a,b,c,w[i+15],10,-30611744);  c=ii(c,d,a,b,w[i+6],15,-1560198380);  b=ii(b,c,d,a,w[i+13],21,1309151649);
        a=ii(a,b,c,d,w[i+4],6,-145523070);   d=ii(d,a,b,c,w[i+11],10,-1120210379);c=ii(c,d,a,b,w[i+2],15,718787259);    b=ii(b,c,d,a,w[i+9],21,-343485551);
        a=safeAdd(a,oa);b=safeAdd(b,ob);c=safeAdd(c,oc);d=safeAdd(d,od);
      }
      var s='';for(var j=0;j<4;j++)s+=('0'+((a>>>(j*8))&0xFF).toString(16)).slice(-2);
      var s2='';for(var j=0;j<4;j++)s2+=('0'+((b>>>(j*8))&0xFF).toString(16)).slice(-2);
      var s3='';for(var j=0;j<4;j++)s3+=('0'+((c>>>(j*8))&0xFF).toString(16)).slice(-2);
      var s4='';for(var j=0;j<4;j++)s4+=('0'+((d>>>(j*8))&0xFF).toString(16)).slice(-2);
      return s+s2+s3+s4;
    }

    var UPPER  = "ACDFGHJMNPRSTUWXY";
    var LOWER  = "abcdfghjkmpstuwxy";
    var DIGIT  = "2345679";
    var SYMBOL = "!@$&%";

    function macToPass(mac) {
      var digest = MD5(mac + "AEJLY");
      var vals = [];
      for (var i = 0; i < 20; i++) {
        var c = digest[i];
        if (c >= '0' && c <= '9') vals.push(c.charCodeAt(0) - 48);
        else vals.push(c.charCodeAt(0) - 87);
      }
      var password = new Array(16).fill('');
      for (var i = 0; i < 16; i++) {
        var v = vals[i], t = v % 4;
        if (t === 0) password[i] = UPPER[(v * 2) % 17];
        else if (t === 1) password[i] = LOWER[(v * 2 + 1) % 17];
        else if (t === 2) password[i] = DIGIT[6 - (v % 7)];
        else              password[i] = SYMBOL[4 - (v % 5)];
      }
      function nextFree(start, taken) {
        var p = start % 16;
        while (taken.has(p)) p = (p + 1) % 16;
        return p;
      }
      var taken = new Set();
      var p0 = nextFree(vals[16] + 1, taken); taken.add(p0);
      var p1 = nextFree(vals[17] + 1, taken); taken.add(p1);
      var p2 = nextFree(vals[18] + 1, taken); taken.add(p2);
      var p3 = nextFree(vals[19] + 1, taken);
      password[p0] = UPPER[(vals[16] * 2) % 17];
      password[p1] = LOWER[(vals[17] * 2 + 1) % 17];
      password[p2] = DIGIT[6 - (vals[18] % 7)];
      password[p3] = SYMBOL[4 - (vals[19] % 5)];
      return password.join('');
    }

    function generateSuperReport() {
        const input = document.getElementById('mac-input-rep');
        const raw = input.value.trim();
        let clean = raw.replace(/[:\-.]/g, "").toUpperCase();
        if (clean.length !== 12 || !/^[0-9A-F]+$/.test(clean)) {
            alert("Invalid MAC address - expected 12 hexadecimal characters.");
            return;
        }
        let formatted = clean.match(/.{2}/g).join(":");
        const pass = macToPass(formatted);
        
        const pwDisplay = document.getElementById('pw-display-rep');
        pwDisplay.value = pass;
    }

    // Populate data inside HTML
    document.addEventListener("DOMContentLoaded", () => {
        // Auto-colon formatting in HTML report
        const macInput = document.getElementById('mac-input-rep');
        if (macInput) {
            macInput.addEventListener('input', () => {
                let v = macInput.value.replace(/[^0-9A-Fa-f:]/g, '');
                let digits = v.replace(/:/g, '');
                if (digits.length > 12) digits = digits.slice(0, 12);
                let formatted = digits.match(/.{1,2}/g);
                if (formatted) {
                    macInput.value = formatted.join(':').toUpperCase();
                } else {
                    macInput.value = '';
                }
            });
        }

        // Set Favicon and Logo
        if (configData.icon_b64) {
            document.getElementById('favicon-link').href = "data:image/png;base64," + configData.icon_b64;
            const logoEl = document.getElementById('html-logo');
            logoEl.src = "data:image/png;base64," + configData.icon_b64;
            logoEl.style.display = "block";
        } else {
            document.getElementById('favicon-link').href = "icon.png";
            const logoEl = document.getElementById('html-logo');
            logoEl.src = "icon.png";
            logoEl.style.display = "block";
        }

        const ext = configData.extracted;
        
        // Populate Raw Config Text
        document.getElementById('raw-config-text').value = configData.raw_config_text;

        // 1. WAN Internet
        const wanContainer = document.getElementById('wan-container');
        wanContainer.innerHTML = '';
        ext.internet.forEach((item, idx) => {
            wanContainer.innerHTML += `
                <div class="input-group" data-search="${item.service} ${item.username_dec} ${item.vlan}">
                    <label>VLAN Service (${item.service})</label>
                    <div class="field-row" style="margin-bottom:10px;">
                        <input type="text" id="wan-vlan-${idx}" value="${item.vlan}" readonly>
                    </div>
                    <label>PPPoE Username</label>
                    <div class="field-row" style="margin-bottom:10px;">
                        <input type="text" id="wan-user-${idx}" value="${item.username_dec}" readonly>
                        <button class="btn-icon" onclick="copyText('wan-user-${idx}')">
                            <svg viewBox="0 0 24 24" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                        </button>
                    </div>
                    <label>PPPoE Password</label>
                    <div class="field-row">
                        <input type="password" id="wan-pass-${idx}" value="${item.password_dec}" readonly>
                        <button class="btn-icon" onclick="togglePassVisibility('wan-pass-${idx}')">
                            <svg viewBox="0 0 24 24" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                        </button>
                        <button class="btn-icon" onclick="copyText('wan-pass-${idx}')">
                            <svg viewBox="0 0 24 24" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                        </button>
                    </div>
                    <div style="font-size:0.75rem;color:var(--text-muted);word-break:break-all;margin-top:5px;">
                        Raw Hex: ${item.password_raw}
                    </div>
                </div>
            `;
        });

        // 2. WiFi
        const wifiContainer = document.getElementById('wifi-container');
        wifiContainer.innerHTML = '';
        ext.wifi.forEach((item, idx) => {
            wifiContainer.innerHTML += `
                <div class="input-group" data-search="${item.ssid}">
                    <label>SSID Name</label>
                    <div class="field-row" style="margin-bottom:10px;">
                        <input type="text" id="wifi-ssid-${idx}" value="${item.ssid}" readonly>
                        <button class="btn-icon" onclick="copyText('wifi-ssid-${idx}')">
                            <svg viewBox="0 0 24 24" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                        </button>
                    </div>
                    <label>Wi-Fi Security Key</label>
                    <div class="field-row" style="margin-bottom:10px;">
                        <input type="password" id="wifi-pass-${idx}" value="${item.password_dec}" readonly>
                        <button class="btn-icon" onclick="togglePassVisibility('wifi-pass-${idx}')">
                            <svg viewBox="0 0 24 24" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                        </button>
                        <button class="btn-icon" onclick="copyText('wifi-pass-${idx}')">
                            <svg viewBox="0 0 24 24" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                        </button>
                    </div>
                    <label>Status (Enabled = 1)</label>
                    <div class="field-row">
                        <input type="text" value="${item.enable}" readonly>
                    </div>
                    <div style="font-size:0.75rem;color:var(--text-muted);word-break:break-all;margin-top:5px;">
                        Raw Hex: ${item.password_raw}
                    </div>
                </div>
            `;
        });

        // 3. Admin Accounts
        const adminContainer = document.getElementById('admin-container');
        adminContainer.innerHTML = '';
        ext.admin.forEach((item, idx) => {
            adminContainer.innerHTML += `
                <div class="input-group" data-search="${item.username}">
                    <label>Login Profile (${item.username})</label>
                    <div class="field-row" style="margin-bottom:10px;">
                        <input type="password" id="admin-pass-${idx}" value="${item.password_dec}" readonly>
                        <button class="btn-icon" onclick="togglePassVisibility('admin-pass-${idx}')">
                            <svg viewBox="0 0 24 24" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                        </button>
                        <button class="btn-icon" onclick="copyText('admin-pass-${idx}')">
                            <svg viewBox="0 0 24 24" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                        </button>
                    </div>
                    <div style="font-size:0.75rem;color:var(--text-muted);word-break:break-all;margin-top:5px;">
                        Raw Hex: ${item.password_raw}
                    </div>
                </div>
            `;
        });

        // 4. VoIP (SIP)
        const voipContainer = document.getElementById('voip-container');
        voipContainer.innerHTML = '';
        if(ext.voip.length === 0) {
            voipContainer.innerHTML = `<div style="grid-column:1/-1;text-align:center;color:var(--text-muted)">No active VoIP parameters found.</div>`;
        }
        ext.voip.forEach((item, idx) => {
            voipContainer.innerHTML += `
                <div class="input-group" data-search="${item.proxy} ${item.standby}">
                    <label>SIP Proxy Server</label>
                    <div class="field-row" style="margin-bottom:10px;">
                        <input type="text" value="${item.proxy}" readonly>
                    </div>
                    <label>Secondary / Standby Proxy</label>
                    <div class="field-row" style="margin-bottom:10px;">
                        <input type="text" value="${item.standby}" readonly>
                    </div>
                    <label>Proxy Server Port</label>
                    <div class="field-row">
                        <input type="text" value="${item.port}" readonly>
                    </div>
                </div>
            `;
        });

        // 5. LAN & DNS
        const lanContainer = document.getElementById('lan-container');
        lanContainer.innerHTML = '';
        if(!ext.lan.ip) {
            lanContainer.innerHTML = `<div style="grid-column:1/-1;text-align:center;color:var(--text-muted)">No LAN configuration found.</div>`;
        } else {
            lanContainer.innerHTML = `
                <div class="input-group" data-search="${ext.lan.ip} ${ext.lan.dns}" style="grid-column: 1/-1">
                    <label>Router LAN IP Address</label>
                    <div class="field-row" style="margin-bottom:12px;">
                        <input type="text" value="${ext.lan.ip}" readonly>
                    </div>
                    <label>Subnet Mask</label>
                    <div class="field-row" style="margin-bottom:12px;">
                        <input type="text" value="${ext.lan.subnet}" readonly>
                    </div>
                    <label>DHCP Start & End IP Range</label>
                    <div class="field-row" style="margin-bottom:12px; gap:15px;">
                        <input type="text" value="${ext.lan.dhcp_start}" placeholder="Start IP" readonly>
                        <input type="text" value="${ext.lan.dhcp_end}" placeholder="End IP" readonly>
                    </div>
                    <label>Static DNS Servers (comma separated)</label>
                    <div class="field-row">
                        <input type="text" value="${ext.lan.dns}" readonly>
                    </div>
                </div>
            `;
        }
    });

    function exportTxtBackup() {
        const ext = configData.extracted;
        let txt = "===================================================\\n";
        txt += " FIBERHOME HG6145F1 CONFIG BACKUP SUMMARY\\n";
        txt += "===================================================\\n\\n";
        
        txt += "--- INTERNET (WAN PPPoE) CONFIGURATIONS ---\\n";
        ext.internet.forEach((item, idx) => {
            txt += `VLAN ID: ${item.vlan} (Service: ${item.service})\\n`;
            txt += `Username: ${item.username_dec}\\n`;
            txt += `Password: ${item.password_dec}\\n\\n`;
        });
        
        txt += "--- WIRELESS NETWORKS (WI-FI) ---\\n";
        ext.wifi.forEach((item, idx) => {
            txt += `SSID Name: ${item.ssid}\\n`;
            txt += `Security Password: ${item.password_dec}\\n`;
            txt += `Status: ${item.enable === '1' ? 'Enabled' : 'Disabled'}\\n\\n`;
        });

        txt += "--- ONT ADMINISTRATIVE ACCOUNT ---\\n";
        ext.admin.forEach((item, idx) => {
            txt += `Username: ${item.username}\\n`;
            txt += `Password: ${item.password_dec}\\n\\n`;
        });

        txt += "--- VoIP SIP SERVER CONFIGURATIONS ---\\n";
        ext.voip.forEach((item, idx) => {
            txt += `Proxy Server IP: ${item.proxy}\\n`;
            txt += `Secondary Proxy: ${item.standby}\\n`;
            txt += `Port: ${item.port}\\n\\n`;
        });

        txt += "--- LAN & DHCP ROUTER SETTINGS ---\\n";
        if(ext.lan.ip) {
            txt += `Router Gateway IP: ${ext.lan.ip}\\n`;
            txt += `Subnet Mask: ${ext.lan.subnet}\\n`;
            txt += `DHCP Start/End Range: ${ext.lan.dhcp_start} - ${ext.lan.dhcp_end}\\n`;
            txt += `Static DNS Servers: ${ext.lan.dns}\\n`;
        }

        const blob = new Blob([txt], { type: "text/plain;charset=utf-8" });
        const link = document.createElement("a");
        link.href = URL.createObjectURL(blob);
        link.download = "fiberhome_config_backup.txt";
        link.click();
        showToast("Backup text summary exported!");
    }
</script>
</body>
</html>
"""

# Tkinter GUI Class
class ConfigUtilityApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Fiberhome HG6145F1 Utility (Algeria Telecom)")
        self.root.geometry("800x580")
        self.root.resizable(False, False)
        
        # Load Window Favicon (icon.ico) - works in both script and EXE
        icon_ico_path = resource_path("icon.ico")
        if os.path.exists(icon_ico_path):
            try:
                self.root.iconbitmap(icon_ico_path)
            except Exception:
                pass

        # Apply index.html Color Palette Theme to GUI
        self.root.configure(bg="#090d16")
        
        # Configure TTK styles
        self.style = ttk.Style()
        self.style.theme_use("clam")
        
        # Style Notebook (Tabs Container)
        self.style.configure("TNotebook", background="#090d16", borderwidth=0)
        self.style.configure("TNotebook.Tab", 
                             background="#0f172a", 
                             foreground="#10b981", 
                             font=("Arial", 9, "bold"),
                             padding=[10, 6],
                             borderwidth=0)
        
        self.style.map("TNotebook.Tab",
                       background=[("selected", "#10b981")],
                       foreground=[("selected", "#ffffff")])

        # Style standard ttk.Frame
        self.style.configure("TFrame", background="#111928")
        
        # Title Banner (matches header of HTML report)
        title_frame = tk.Frame(root, bg="#090d16", bd=0)
        title_frame.pack(fill="x")
        
        # Load PNG icon next to title name - works in both script and EXE
        self.logo_img = None
        icon_png_path = resource_path("icon.png")
        if os.path.exists(icon_png_path):
            try:
                raw_img = tk.PhotoImage(file=icon_png_path)
                width = raw_img.width()
                if width > 64:
                    factor = width // 40
                    if factor > 1:
                        self.logo_img = raw_img.subsample(factor, factor)
                    else:
                        self.logo_img = raw_img
                else:
                    self.logo_img = raw_img
            except Exception as e:
                print("Error loading PNG logo:", e)

        # Pack Logo if loaded successfully
        if self.logo_img:
            logo_label = tk.Label(title_frame, image=self.logo_img, bg="#090d16")
            logo_label.pack(side="left", padx=(20, 10), pady=15)
            
        # Text Header Container
        text_frame = tk.Frame(title_frame, bg="#090d16")
        text_frame.pack(side="left", fill="both", expand=True, pady=15)
        
        title_label = tk.Label(text_frame, text="Fiberhome HG6145F1 Utility", bg="#090d16", fg="#f3f4f6", font=("Arial", 14, "bold"), anchor="w")
        title_label.pack(fill="x")
        subtitle_label = tk.Label(text_frame, text="Algeria Telecom Edition - HG6145F1 Profile", bg="#090d16", fg="#9ca3af", font=("Arial", 9), anchor="w")
        subtitle_label.pack(fill="x")

        # Tab Control Container
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True, padx=15, pady=15)

        # Tab 1: Decrypter
        self.tab_decrypt = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_decrypt, text=" Decrypt ")
        self.setup_decrypt_tab()

        # Tab 2: Encrypter
        self.tab_encrypt = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_encrypt, text=" Re-encrypt ")

        # Tab 3: Password AES Crypt Helper
        self.tab_helper = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_helper, text=" AES Helper ")
        self.setup_helper_tab()

        # Tab 4: Superuser Password Generator
        self.tab_super = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_super, text=" Superuser ")
        self.setup_super_tab()
        self.setup_encrypt_tab()

        # Tab 5: About
        self.tab_about = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_about, text=" About ")
        self.setup_about_tab()

    def log(self, message):
        # Logging to console (no UI log box)
        print(f"[+] {message}")

    def setup_about_tab(self):
        container = tk.Frame(self.tab_about, bg="#111928")
        container.pack(fill="both", expand=True, padx=30, pady=25)

        # ── App Title ─────────────────────────────────────────────
        title_lbl = tk.Label(
            container,
            text="Fiberhome HG6145F1 Config Utility",
            bg="#111928", fg="#f3f4f6",
            font=("Arial", 13, "bold")
        )
        title_lbl.pack(anchor="w", pady=(0, 2))

        sub_lbl = tk.Label(
            container,
            text="Algeria Telecom Edition  —  Firmware RP4423",
            bg="#111928", fg="#9ca3af",
            font=("Arial", 9)
        )
        sub_lbl.pack(anchor="w", pady=(0, 20))

        # ── Separator ─────────────────────────────────────────────
        sep1 = tk.Frame(container, bg="#10b981", height=1)
        sep1.pack(fill="x", pady=(0, 20))

        # ── Credit Block: Tool Author ──────────────────────────────
        tk.Label(
            container,
            text="🔧  Core Tool & Algorithm",
            bg="#111928", fg="#9ca3af",
            font=("Arial", 8, "bold")
        ).pack(anchor="w")

        tk.Label(
            container,
            text="Adel / NumberOneDZ",
            bg="#111928", fg="#f3f4f6",
            font=("Arial", 11, "bold")
        ).pack(anchor="w", pady=(2, 0))

        link_adel = tk.Label(
            container,
            text="t.me/numberonedz",
            bg="#111928", fg="#10b981",
            font=("Arial", 10, "underline"),
            cursor="hand2"
        )
        link_adel.pack(anchor="w", pady=(2, 18))
        link_adel.bind("<Button-1>", lambda e: webbrowser.open("https://t.me/numberonedz"))

        # ── Credit Block: GUI Author ───────────────────────────────
        tk.Label(
            container,
            text="🖥️  GUI Design & Modifications",
            bg="#111928", fg="#9ca3af",
            font=("Arial", 8, "bold")
        ).pack(anchor="w")

        tk.Label(
            container,
            text="CodexTech",
            bg="#111928", fg="#f3f4f6",
            font=("Arial", 11, "bold")
        ).pack(anchor="w", pady=(2, 0))

        link_codex = tk.Label(
            container,
            text="t.me/codextech0x",
            bg="#111928", fg="#10b981",
            font=("Arial", 10, "underline"),
            cursor="hand2"
        )
        link_codex.pack(anchor="w", pady=(2, 18))
        link_codex.bind("<Button-1>", lambda e: webbrowser.open("https://t.me/codextech0x"))

        # ── Separator ─────────────────────────────────────────────
        sep2 = tk.Frame(container, bg="#1e293b", height=1)
        sep2.pack(fill="x", pady=(0, 15))

        # ── Disclaimer ────────────────────────────────────────────
        disclaimer = tk.Label(
            container,
            text="This tool is provided for educational and personal use only.\n"
                 "Use responsibly and only on devices you own or have permission to access.",
            bg="#111928", fg="#6b7280",
            font=("Arial", 8),
            justify="left",
            wraplength=540
        )
        disclaimer.pack(anchor="w")


    def setup_decrypt_tab(self):
        desc = ("Decrypter Section:\n\n"
                "Select the encrypted configuration binary downloaded from your ONT.\n\n"
                "This will:\n"
                "1. Decrypt & unpack files to a new folder in the same directory.\n"
                "2. Generate a gorgeous, interactive offline HTML dashboard.")
        
        # Frame container
        container = tk.Frame(self.tab_decrypt, bg="#111928")
        container.pack(fill="both", expand=True, padx=20, pady=20)
        
        lbl_desc = tk.Label(container, text=desc, justify="left", font=("Arial", 10), bg="#111928", fg="#f3f4f6", anchor="w")
        lbl_desc.pack(anchor="w", pady=10)
        
        btn_border1 = tk.Frame(container, bg="#10b981", padx=1, pady=1)
        btn_border1.pack(pady=25, fill="x")
        btn_decrypt = tk.Button(btn_border1, text="Select Encrypted Config File & Decrypt",
                                bg="#0f172a", fg="#10b981", font=("Arial", 11, "bold"),
                                relief="flat", activebackground="#111928", activeforeground="#059669",
                                cursor="hand2", command=self.action_decrypt, height=2, bd=0)
        btn_decrypt.pack(fill="x")
        
        info_label = tk.Label(container, text="Note: The static HTML report will open automatically in your web browser.", 
                              bg="#111928", fg="#9ca3af", font=("Arial", 9, "italic"))
        info_label.pack(pady=10)

    def setup_encrypt_tab(self):
        desc = ("Encrypter Section:\n\n"
                "Packs and encrypts a previously extracted configuration folder back to binary.\n\n"
                "Important:\n"
                "The folder must contain the mandatory 'usrconfig_conf' file.\n"
                "If you edited variables (like passwords), make sure to encrypt them\n"
                "using the 'AES Password Helper' tab before saving them in the text file.")
        
        container = tk.Frame(self.tab_encrypt, bg="#111928")
        container.pack(fill="both", expand=True, padx=20, pady=20)
        
        lbl_desc = tk.Label(container, text=desc, justify="left", font=("Arial", 10), bg="#111928", fg="#f3f4f6", anchor="w")
        lbl_desc.pack(anchor="w", pady=10)
        
        btn_border2 = tk.Frame(container, bg="#10b981", padx=1, pady=1)
        btn_border2.pack(pady=25, fill="x")
        btn_encrypt = tk.Button(btn_border2, text="Select Folder to Re-encrypt",
                                bg="#0f172a", fg="#10b981", font=("Arial", 11, "bold"),
                                relief="flat", activebackground="#111928", activeforeground="#059669",
                                cursor="hand2", command=self.action_encrypt, height=2, bd=0)
        btn_encrypt.pack(fill="x")

    def setup_helper_tab(self):
        desc = ("AES Password Helper:\n\n"
                "Allows you to encrypt plaintext passwords into the AES-128 hex block format\n"
                "needed for the configuration file, or decrypt existing ones.")
        
        container = tk.Frame(self.tab_helper, bg="#111928")
        container.pack(fill="both", expand=True, padx=20, pady=15)
        
        lbl_desc = tk.Label(container, text=desc, justify="left", font=("Arial", 10), bg="#111928", fg="#f3f4f6", anchor="w")
        lbl_desc.pack(anchor="w", pady=5)
        
        # Grid input
        grid_frame = tk.Frame(container, bg="#111928")
        grid_frame.pack(fill="x", pady=10)
        
        tk.Label(grid_frame, text="Input Text (Plaintext or Encrypted Hex):", bg="#111928", fg="#9ca3af", font=("Arial", 9, "bold")).pack(anchor="w", pady=5)
        
        self.entry_input = tk.Entry(grid_frame, bg="#0f172a", fg="#f3f4f6", insertbackground="#f3f4f6", font=("Consolas", 10), bd=1, relief="solid", highlightbackground="#1e293b", highlightcolor="#10b981", highlightthickness=1)
        self.entry_input.pack(fill="x", ipady=5, pady=5)
        
        # Crypto buttons
        btn_frame = tk.Frame(container, bg="#111928")
        btn_frame.pack(fill="x", pady=15)
        
        enc_border = tk.Frame(btn_frame, bg="#10b981", padx=1, pady=1)
        enc_border.pack(side="left", padx=5, expand=True, fill="x")
        btn_enc = tk.Button(enc_border, text="Encrypt to Router Hex", bg="#0f172a", fg="#10b981",
                            relief="flat", command=self.helper_encrypt, cursor="hand2",
                            activebackground="#111928", activeforeground="#059669",
                            font=("Arial", 10, "bold"), height=2, bd=0)
        btn_enc.pack(fill="x")

        dec_border = tk.Frame(btn_frame, bg="#10b981", padx=1, pady=1)
        dec_border.pack(side="left", padx=5, expand=True, fill="x")
        btn_dec = tk.Button(dec_border, text="Decrypt from Hex", bg="#0f172a", fg="#10b981",
                            relief="flat", command=self.helper_decrypt, cursor="hand2",
                            activebackground="#111928", activeforeground="#059669",
                            font=("Arial", 10, "bold"), height=2, bd=0)
        btn_dec.pack(fill="x")

        # Result field
        res_frame = tk.Frame(container, bg="#111928")
        res_frame.pack(fill="x", pady=5)
        
        tk.Label(res_frame, text="Result Output:", bg="#111928", fg="#9ca3af", font=("Arial", 9, "bold")).pack(anchor="w", pady=5)
        
        self.entry_result = tk.Entry(res_frame, bg="#0f172a", fg="#10b981", insertbackground="#f3f4f6", font=("Consolas", 10), bd=1, relief="solid", highlightbackground="#1e293b", highlightcolor="#10b981", highlightthickness=1)
        self.entry_result.pack(fill="x", ipady=5, pady=5)

    def setup_super_tab(self):
        desc = ("Superuser Password Generator:\n\n"
                "Generates the default admin superuser password for Algeria Telecom\n"
                "Fiberhome HG6145F1 ONTs (Firmware RP4423) using the MAC address.")
        
        container = tk.Frame(self.tab_super, bg="#111928")
        container.pack(fill="both", expand=True, padx=20, pady=15)
        
        lbl_desc = tk.Label(container, text=desc, justify="left", font=("Arial", 10), bg="#111928", fg="#f3f4f6", anchor="w")
        lbl_desc.pack(anchor="w", pady=5)
        
        # Grid input
        grid_frame = tk.Frame(container, bg="#111928")
        grid_frame.pack(fill="x", pady=10)
        
        tk.Label(grid_frame, text="MAC Address (e.g. A8:5A:F3:00:11:22):", bg="#111928", fg="#9ca3af", font=("Arial", 9, "bold")).pack(anchor="w", pady=5)
        
        self.entry_mac = tk.Entry(grid_frame, bg="#0f172a", fg="#f3f4f6", insertbackground="#f3f4f6", font=("Consolas", 10), bd=1, relief="solid", highlightbackground="#1e293b", highlightcolor="#10b981", highlightthickness=1)
        self.entry_mac.pack(fill="x", ipady=5, pady=5)
        
        # Bind keyrelease event to auto-format colons
        self.entry_mac.bind("<KeyRelease>", self.format_mac)
        
        # Generate button
        gen_border = tk.Frame(container, bg="#10b981", padx=1, pady=1)
        gen_border.pack(fill="x", pady=15)
        btn_gen = tk.Button(gen_border, text="GENERATE PASSWORD", bg="#0f172a", fg="#10b981",
                            relief="flat", command=self.helper_gen_super, cursor="hand2",
                            activebackground="#111928", activeforeground="#059669",
                            font=("Arial", 10, "bold"), height=2, bd=0)
        btn_gen.pack(fill="x")
        
        # Result output
        res_frame = tk.Frame(container, bg="#111928")
        res_frame.pack(fill="x", pady=5)
        
        tk.Label(res_frame, text="Generated Superuser Password:", bg="#111928", fg="#9ca3af", font=("Arial", 9, "bold")).pack(anchor="w", pady=5)
        
        self.entry_super_pass = tk.Entry(res_frame, bg="#0f172a", fg="#10b981", insertbackground="#f3f4f6", font=("Consolas", 10), bd=1, relief="solid", highlightbackground="#1e293b", highlightcolor="#10b981", highlightthickness=1)
        self.entry_super_pass.pack(fill="x", ipady=5, pady=5)
        
        # Copy button
        copy_border = tk.Frame(container, bg="#10b981", padx=1, pady=1)
        copy_border.pack(pady=5)
        btn_copy = tk.Button(copy_border, text="  Copy Password  ", bg="#0f172a", fg="#10b981",
                             relief="flat", command=self.helper_copy_super, cursor="hand2",
                             activebackground="#111928", activeforeground="#059669",
                             font=("Arial", 9, "bold"), height=1, bd=0)
        btn_copy.pack(fill="x")

    def format_mac(self, event):
        if event.keysym in ("BackSpace", "Delete", "Left", "Right"):
            return
        
        raw_val = self.entry_mac.get()
        # Clean anything not hex
        clean = raw_val.replace(":", "").replace("-", "").replace(".", "").upper()
        digits = "".join(c for c in clean if c in "0123456789ABCDEF")[:12]
        
        # Reformat XX:XX:XX:XX:XX:XX
        formatted = ":".join(digits[i:i+2] for i in range(0, len(digits), 2))
        
        self.entry_mac.delete(0, tk.END)
        self.entry_mac.insert(0, formatted)

    def helper_gen_super(self):
        mac = self.entry_mac.get().strip()
        if not mac:
            return
        
        clean = mac.replace(":", "").replace("-", "").replace(".", "")
        if len(clean) != 12:
            self.log("[ERROR] MAC Address must be exactly 12 hex characters.")
            messagebox.showerror("Invalid MAC", "MAC Address must be exactly 12 hexadecimal characters.")
            return
            
        try:
            super_pass = calculate_super_password(mac)
            self.entry_super_pass.delete(0, tk.END)
            self.entry_super_pass.insert(0, super_pass)
            self.log(f"Generated superuser password for MAC: {mac}")
        except Exception as e:
            self.log(f"[ERROR] Failed to calculate password: {str(e)}")
            messagebox.showerror("Error", f"Failed to calculate superuser password: {str(e)}")

    def helper_copy_super(self):
        val = self.entry_super_pass.get().strip()
        if not val:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(val)
        self.log("Superuser password copied to clipboard!")
        messagebox.showinfo("Copied", "Superuser password copied to clipboard!")

    def action_decrypt(self):
        file_path = filedialog.askopenfilename(
            title="Open Encrypted Fiberhome Config File",
            filetypes=[("Fiberhome Configuration", "*usrconfig*"), ("All Files", "*.*")]
        )
        if not file_path:
            return
        
        self.log(f"Selected config file for decryption: {os.path.basename(file_path)}")
        
        try:
            with open(file_path, "rb") as f:
                encrypted_data = f.read()
                
            # XOR decrypt
            dec_bytes = xor_transform(encrypted_data, XOR_KEY)
            decompressed = decompress_if_needed(dec_bytes)
            
            # Extract folder path
            parent_dir = os.path.dirname(os.path.abspath(file_path))
            base_name = os.path.basename(file_path)
            extracted_folder_name = base_name + "_extracted"
            out_dir = os.path.join(parent_dir, extracted_folder_name)
            
            os.makedirs(out_dir, exist_ok=True)
            
            # Unpack TAR
            usrconfig_text = ""
            
            if is_tar(decompressed):
                with tarfile.open(fileobj=io.BytesIO(decompressed), mode="r:*") as tar:
                    if hasattr(tarfile, 'data_filter'):
                        tar.extractall(out_dir, filter='data')
                    else:
                        tar.extractall(out_dir)
                self.log(f"Extracted archive contents to folder: {extracted_folder_name}")
                
                # Load extracted usrconfig_conf
                conf_path = os.path.join(out_dir, "usrconfig_conf")
                if os.path.exists(conf_path):
                    with open(conf_path, "r", encoding="utf-8", errors="ignore") as f_conf:
                        usrconfig_text = f_conf.read()
            else:
                usrconfig_text = decompressed.decode("utf-8", errors="ignore")
                with open(os.path.join(out_dir, "usrconfig_conf"), "w", encoding="utf-8") as f_conf:
                    f_conf.write(usrconfig_text)
                self.log(f"Extracted raw text configuration file directly.")
            
            # Parse settings and generate report
            parsed = extract_and_parse_config(encrypted_data)
            
            # Inject data into HTML report
            json_data = json.dumps(parsed)
            html_content = HTML_TEMPLATE.replace("/* __DATA_PLACEHOLDER__ */", f"const configData = {json_data};")
            
            report_name = base_name + "_report.html"
            report_path = os.path.join(parent_dir, report_name)
            
            with open(report_path, "w", encoding="utf-8") as f_rep:
                f_rep.write(html_content)
                
            self.log(f"Report generated: {report_name}")
            messagebox.showinfo("Success", f"Decryption complete!\n\n1. Extracted folder created: {extracted_folder_name}\n2. HTML report created: {report_name}\n\nOpening report in browser...")
            
            # Auto open report in browser
            webbrowser.open("file://" + os.path.abspath(report_path))
            
        except Exception as e:
            self.log(f"Decryption failed: {str(e)}")
            messagebox.showerror("Error", f"Failed to decrypt and process configuration:\n{str(e)}")

    def action_encrypt(self):
        folder_path = filedialog.askdirectory(title="Select Extracted Config Folder")
        if not folder_path:
            return
        
        self.log(f"Selected folder for encryption: {os.path.basename(folder_path)}")
        
        mandatory_file = "usrconfig_conf"
        optional_file = "voice_digitmap_conf"
        
        m_path = os.path.join(folder_path, mandatory_file)
        if not os.path.exists(m_path):
            self.log(f"[ERROR] Mandatory file '{mandatory_file}' not found in folder.")
            messagebox.showerror("Error", f"The folder must contain the '{mandatory_file}' file.")
            return

        files_to_add = [m_path]
        o_path = os.path.join(folder_path, optional_file)
        if os.path.exists(o_path):
            files_to_add.append(o_path)
            
        try:
            # Compress TAR
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
                for f_path in files_to_add:
                    tar.add(f_path, arcname=os.path.basename(f_path))
            
            compressed_data = buffer.getvalue()
            
            # XOR encrypt
            encrypted_data = xor_transform(compressed_data, XOR_KEY)
            
            # Save dialog
            random_id = random.randint(10000, 99999)
            save_path = filedialog.asksaveasfilename(
                title="Save Encrypted Config File",
                initialfile=f"usrconfig_fh-{random_id}",
                filetypes=[("Fiberhome Configuration File", "*")]
            )
            
            if not save_path:
                return
                
            with open(save_path, "wb") as f:
                f.write(encrypted_data)
                
            self.log(f"Successfully encrypted and saved to: {os.path.basename(save_path)}")
            messagebox.showinfo("Success", f"Folder packed and encrypted successfully!\nSaved to: {os.path.basename(save_path)}")
            
        except Exception as e:
            self.log(f"Encryption failed: {str(e)}")
            messagebox.showerror("Error", f"Failed to package and encrypt configuration:\n{str(e)}")

    def helper_encrypt(self):
        val = self.entry_input.get().strip()
        if not val:
            return
        if not HAS_AES:
            messagebox.showwarning("AES Missing", "PyCryptodome library is not installed. Encryption is unavailable.")
            return
        enc = fh_encrypt_string(val)
        self.entry_result.delete(0, tk.END)
        self.entry_result.insert(0, enc)

    def helper_decrypt(self):
        val = self.entry_input.get().strip()
        if not val:
            return
        if not HAS_AES:
            messagebox.showwarning("AES Missing", "PyCryptodome library is not installed. Decryption is unavailable.")
            return
        # check hex format
        try:
            int(val, 16)
        except ValueError:
            messagebox.showerror("Invalid Input", "AES ciphertext must be a valid hexadecimal string.")
            return
        dec = fh_decrypt_string(val)
        self.entry_result.delete(0, tk.END)
        self.entry_result.insert(0, dec)

def main():
    root = tk.Tk()
    app = ConfigUtilityApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
