# Joomla-Mass-LFI-Scanner
A high-speed, Python-based **mass Local File Inclusion (LFI) vulnerability scanner** for **Joomla CMS**.

This tool aggressively targets Joomla installations with **70+ public LFI exploit methods** to download the sensitive `configuration.php` file.  
It then **automatically extracts all database, FTP, and secret keys** from compromised sites and attempts remote MySQL login using the found credentials—delivering a full impact analysis for each target.

---

## Features

- 🚀 **70+ LFI vectors** for maximum Joomla attack surface
- 💾 **Downloads `configuration.php`** if vulnerable, extracting all DB, FTP, and secret info
- 🗝️ **Auto remote MySQL login test** with found credentials (checks if remote DB access is possible)
- ⚡ **Mass, multi-threaded scanning** (50+ threads for speed)
- 📑 **Detailed result and success logs**
- 🛠️ **Easily customizable, open-source**

---

## How It Works

1. **Scans each target** with 70+ known LFI paths specific to Joomla extensions, plugins, and components.
2. **Downloads and parses `configuration.php`** if LFI succeeds, extracting:
    - MySQL DB host, user, password, name
    - FTP host, user, password (if any)
    - Secret keys and other sensitive config
3. **Attempts remote MySQL login** with the harvested credentials (tries public IP if host is localhost/127.0.0.1).
4. **Logs full findings** to `results_joomla.txt` (all results) and `success_joomla.txt` (vulnerable only).

---

## Usage

**Requirements:**  
- Python 3.x  
- `requests`, `pymysql`  
  *(install dependencies with: `pip install -r requirements.txt`)*

### Scan a list of sites

```bash
python joomscan.py lfi sites.txt
