#!/usr/bin/env python3
import sys
import os
import subprocess
import time

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

CHECK_MARK = f"{Colors.OKGREEN}[OK]{Colors.RESET}"
CROSS_MARK = f"{Colors.FAIL}[XX]{Colors.RESET}"
INFO_MARK = f"{Colors.OKCYAN}[i]{Colors.RESET}"

print(f"{Colors.BOLD}{Colors.OKRED if hasattr(Colors, 'OKRED') else Colors.FAIL}")
print("==================================================")
print("       Van Helsing DoS - Pre-Flight Setup")
print("==================================================")
print(f"{Colors.RESET}")

def report_status(task, success, detail=""):
    mark = CHECK_MARK if success else CROSS_MARK
    msg = f" {mark} {task:<45}"
    if detail:
        msg += f"- {detail}"
    print(msg)
    time.sleep(0.1)
    return success

def check_python_version():
    is_valid = sys.version_info >= (3, 8)
    msg = f"v{sys.version_info.major}.{sys.version_info.minor}"
    report_status("Python Version (>= 3.8)", is_valid, msg)
    if not is_valid:
        print(f"\n{Colors.FAIL}Error: Van Helsing DoS requires Python 3.8 or higher.{Colors.RESET}")
        sys.exit(1)
    return True

def install_requirements():
    print(f"\n{INFO_MARK} Auto-Installing missing Python packages...")
    
    # Pre-install OS dependencies on Linux if needed
    if sys.platform == 'linux' or sys.platform == 'linux2':
        print(f"{INFO_MARK} Installing Linux Build Essentials (sudo) for uvloop/impacket...")
        try:
            subprocess.check_call(['sudo', 'apt-get', 'update', '-qq'])
            subprocess.check_call(['sudo', 'apt-get', 'install', '-y', '-qq', 'python3-dev', 'python3-pip', 'libssl-dev', 'libffi-dev', 'build-essential'])
        except Exception:
            pass # Non-fatal, just try to continue
            
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "-r", "requirements.txt"])
        return True
    except Exception as e:
        print(f"\n{Colors.FAIL}Failed to install requirements: {e}{Colors.RESET}")
        return False

def check_requirements():
    try:
        if not os.path.exists('requirements.txt'):
             report_status("Core Dependencies (PIP)", True, "Skipped (requirements.txt missing)")
             return True
             
        import pkg_resources
        
        with open('requirements.txt', 'r', encoding='utf-8') as f:
            lines = f.readlines()
            
        reqs = []
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#'):
                # Handle platform specific markers
                if ';' in line:
                    if 'linux' not in sys.platform and 'linux' in line:
                         continue # Skip linux reqs on windows
                    line = line.split(';')[0].strip()
                reqs.append(line)
        
        # This will raise pkg_resources.VersionConflict if a version is mismatched
        # or pkg_resources.DistributionNotFound if it's entirely missing
        pkg_resources.require(reqs)
        
        report_status("Core Dependencies (PIP)", True, "Installed and Up-to-date")
        return True
    except Exception as e:
        # Catch both DistributionNotFound and VersionConflict
        err_msg = type(e).__name__ 
        report_status("Core Dependencies (PIP)", False, f"Mismatch/Missing ({err_msg})")
        return install_requirements()

def check_playwright_browsers():
    try:
        # Check if browsers are installed
        from playwright._impl._driver import compute_driver_executable
        from playwright.sync_api import sync_playwright
        
        # Test basic chromium availability without full heavy launch
        # Just importing and having requirements is often not enough, user must run playwright install
        # To be safe, try silent query
        cmd = [sys.executable, "-m", "playwright", "install", "chromium", "--with-deps"]
        # Skip checking deep binary paths, just trigger update nicely if needed
        # Since this is an installer, we can just run it quickly and let it skip if exists
        report_status("Headless Browser Binaries", False, "Checking/Installing...")
        print(f"{INFO_MARK} Ensuring Chromium Headless is installed for Cloudflare Bypass...")
        subprocess.check_call(cmd)
        report_status("Headless Browser Binaries", True, "Ready")
        return True
    except Exception as e:
        report_status("Headless Browser Binaries", False, "Failed")
        print(f"{Colors.FAIL}Notice: Could not auto-install playwright browser: {e}. Please run 'playwright install chromium' manually.{Colors.RESET}")
        return False

def check_kali_optimizations():
    if sys.platform != "linux" and sys.platform != "linux2":
        report_status("Kali/Linux TCP Optimizations", True, "Skipped (Not Linux)")
        return True
        
    setup_file = "setup_kali.sh"
    if not os.path.exists(setup_file):
        report_status("Kali/Linux TCP Optimizations", False, "setup_kali.sh missing")
        return True # Non-fatal
        
    try:
        # Check an easy optimization marker: file descriptor limits
        import resource
        soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft >= 100000:
             report_status("Kali/Linux TCP Optimizations", True, f"High FD Limit detected ({soft})")
             return True
        else:
             report_status("Kali/Linux TCP Optimizations", False, f"Low FD Limit ({soft})")
             
             print(f"\n{INFO_MARK} Do you want to apply Kali Linux Ulimit/TCP Optimizations now? (Requires sudo)")
             print("   This is HIGHLY RECOMMENDED for maximum attack throughput.")
             ans = input("   [Y/n]: ").strip().lower()
             if ans != 'n':
                 try:
                     os.chmod(setup_file, 0o755)
                     subprocess.check_call(["sudo", "./" + setup_file])
                     report_status("Kali/Linux TCP Optimizations", True, "Applied")
                 except Exception as e:
                     print(f"{Colors.FAIL}Failed to apply TCP Optimizations: {e}{Colors.RESET}")
             return True
    except ImportError:
         report_status("Kali/Linux TCP Optimizations", False, "Unknown state")
         return True


def main():
    print(f"{INFO_MARK} Starting Pre-Flight System Checks...\n")
    
    check_python_version()
    req_ok = check_requirements()
    pw_ok = check_playwright_browsers()
    check_kali_optimizations()
    
    print("\n==================================================")
    if req_ok and pw_ok:
        print(f"{CHECK_MARK} {Colors.BOLD}ALL SYSTEMS GO! Starting Van_HelsingDoS...{Colors.RESET}\n")
        time.sleep(1)
        # Execute the menu logic directly or run it as subprocess
        os.system(f"{sys.executable} menu.py")
    else:
        print(f"{CROSS_MARK} {Colors.WARNING}Some components failed to install. Please check errors above.{Colors.RESET}\n")
        sys.exit(1)

if __name__ == "__main__":
    main()
