# FiberhomeConfigUtility
**A graphical user interface for the Fiberhome HG6145F1 config utility**   **Tested on Algeria Telecom HG6145F1 ONT · Firmware RP4423**
<div align="center">

<img src="icon.png" width="80" height="80" alt="Fiberhome Config Utility Icon" />

# Fiberhome HG6145F1 Config Utility — GUI Edition

**A graphical user interface for the Fiberhome HG6145F1 config utility**  
**Tested on Algeria Telecom HG6145F1 ONT · Firmware RP4423**

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat-square)](https://github.com)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Based On](https://img.shields.io/badge/Based%20On-numberonedz%2Ffiberhome--config--utility-orange?style=flat-square)](https://github.com/numberonedz/fiberhome-config-utility)

</div>
<img width="802" height="612" alt="image" src="https://github.com/user-attachments/assets/1b7a1390-7bea-4967-8d39-c2f480bdf442" />
<img width="1366" height="1154" alt="image" src="https://github.com/user-attachments/assets/a2f073ea-eb9e-46c1-994a-1b7c1929a545" />

---

> [!IMPORTANT]
> This is a **GUI wrapper** of the original CLI tool by **[Adel / NumberOneDZ](https://github.com/numberonedz/fiberhome-config-utility)**.  
> All core algorithms and reverse-engineering work belong to the original author.  
> This project simply provides a user-friendly desktop interface on top of that work, along with the integration of the Superuser password feature.

---

## 📖 Overview

This tool provides a simple, standalone desktop application (built with Python Tkinter) for working with **Algeria Telecom Fiberhome HG6145F1 ONT** configuration files.  

No command line knowledge needed — everything is done through a clean, dark-themed GUI with labeled tabs.

---

## 🖥️ GUI Tabs & Features

### 🔓 Decrypt Tab
Select the encrypted configuration binary downloaded from your ONT's web interface.  
The tool will:
1. Decrypt and unpack the file into a new folder in the same directory
2. Automatically generate an **interactive offline HTML5 report** and open it in your browser

The HTML report displays all extracted settings organized in tabs:

| Report Tab | What it shows |
|------------|--------------|
| 🌐 Internet (WAN) | PPPoE username & password, VLAN ID |
| 📶 Wi-Fi Network | SSID names and Wi-Fi passwords |
| 🔐 ONT Admin | Web console admin/user account passwords |
| 📞 VoIP (SIP) | SIP proxy server and port |
| 🖧 LAN & DNS | Router IP, subnet, DHCP range, DNS servers |
| 🛡️ Superuser Pass | Built-in MAC-based password generator |
| 📄 Raw Config | Full raw text of the config file |

All passwords in the report have **show/hide** and **copy to clipboard** buttons.

---

### 🔒 Re-encrypt Tab
Packs and encrypts a previously extracted config folder back to binary format, ready to be uploaded back to the router.

> The folder must contain the `usrconfig_conf` file.  
> Use the **AES Helper** tab to re-encrypt any passwords you edited before saving.

---

### 🔑 AES Helper Tab
Encrypt or decrypt individual password strings using the same AES-128 ECB format that the router uses internally.

- **Encrypt** → convert a plaintext password to the hex format used in the config file
- **Decrypt** → convert an existing hex string back to readable plaintext

---

### 🛡️ Superuser Tab
Generate the default hidden `superadmin` password for Algeria Telecom Fiberhome HG6145F1 ONTs.

- Input: the router's **MAC address** (found on the label on the back of the device)
- Output: the generated superuser password
- One-click **Copy to Clipboard** button
### Option A — Download Ready-to-Use EXE (Windows)

No Python needed. Download the pre-built executable directly:

👉 **[Download Latest Release](https://github.com/CodexTech0X/FiberhomeConfigUtility/releases/tag/Release)**

---
### Option B — Run from Source
## 🚀 Getting Started

### Requirements
- Python 3.8+
- [PyCryptodome](https://pypi.org/project/pycryptodome/)

### Install & Run

```bash
pip install -r requirements.txt
python fh-config-utility-gui.py
```

---

## 📦 Build Standalone EXE (Windows)

```bash
pip install pyinstaller
pyinstaller FiberhomeConfigUtility.spec
```

Output will be in the `dist/` folder.

---

## ⚠️ Disclaimer

This tool is provided for **educational and personal use only**.  
Use it responsibly and only on devices you own or have permission to access.

---

## 👥 Credits

All credit for the original tool, the reverse-engineering of the config file format, and the core decryption algorithms goes to:

**Adel / NumberOneDZ**  
🔗 [github.com/numberonedz/fiberhome-config-utility](https://github.com/numberonedz/fiberhome-config-utility)  
💬 [t.me/numberonedz](https://t.me/numberonedz)

This repository only adds a graphical user interface and integrates the Superuser password generator as a convenience feature.

---

## 📄 License

[MIT License](LICENSE)
