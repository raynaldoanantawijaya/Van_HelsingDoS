import asyncio
import platform
from time import sleep

class TurnstileDispenser:
    @staticmethod
    def solve_challenge(url: str, headless: bool = None):
        """
        Solve Cloudflare Turnstile challenge using Playwright.
        
        On Linux/Kali: defaults to headless=True (no display needed)
        On Windows: defaults to headless=False (needs visible browser)
        
        Set DISPLAY env var on Linux if using headless=False.
        """
        if headless is None:
            headless = platform.system() == "Linux"
        
        print(f"[*] Executing Playwright Solver for {url} (headless={headless})...")
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            print("[!] Playwright is not installed.")
            print("[!] Run: pip install playwright && playwright install chromium")
            return None, None
        
        # Use a modern Linux User-Agent when running on Linux
        if platform.system() == "Linux":
            ua = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36'
        else:
            ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36'
        
        with sync_playwright() as p:
            # On Kali Linux, chromium might need --no-sandbox
            launch_args = []
            if platform.system() == "Linux":
                launch_args = ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage']
            
            browser = p.chromium.launch(
                headless=headless,
                args=launch_args
            )
            context = browser.new_context(
                viewport={'width': 1920, 'height': 1080},
                user_agent=ua,
                locale='en-US',
            )
            page = context.new_page()
            
            print("[*] Navigating to target to trigger challenge...")
            try:
                page.goto(url, wait_until="networkidle", timeout=15000)
            except Exception:
                pass
                
            print("[*] Computing JS Challenge... (Waiting 12 seconds)")
            sleep(12)  # Let CF compute PoW (slightly longer for headless)
            
            cookies = context.cookies()
            cf_clearance = None
            for c in cookies:
                if c['name'] == 'cf_clearance':
                    cf_clearance = c['value']
                    
            browser.close()
            
            if cf_clearance:
                print(f"[+] Successfully extracted cf_clearance: {cf_clearance[:10]}*********")
                # Save to file for auto-pickup by attack engine
                try:
                    from pathlib import Path
                    clearance_path = Path(__file__).parent / "files" / "cf_clearance.txt"
                    clearance_path.write_text(cf_clearance)
                    print(f"[+] Saved to {clearance_path}")
                except Exception as e:
                    print(f"[-] Could not save clearance file: {e}")
                return cf_clearance, ua
            else:
                print("[-] Failed to bypass Cloudflare. No clearance cookie found.")
                return None, None

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        url = sys.argv[1]
        headless_flag = "--headless" in sys.argv
        TurnstileDispenser.solve_challenge(url, headless=headless_flag if "--headless" in sys.argv else None)
    else:
        print("Usage: python turnstile_dispenser.py <url> [--headless]")
