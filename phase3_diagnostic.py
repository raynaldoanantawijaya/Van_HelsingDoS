#!/usr/bin/env python3
"""
CHAOS V36 Phase 3 — Full System Diagnostic
Tests: TargetProfiler, dox_origin_ip, QUIC readiness, Proxy pipeline, Turnstile daemon
Against 8 diverse real-world targets.
"""
import sys, os, socket, time, json, io

# Force utf-8
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

import requests
import urllib3
urllib3.disable_warnings()

# ── Colour helpers ──
class C:
    G = '\033[92m'; R = '\033[91m'; Y = '\033[93m'; B = '\033[94m'
    M = '\033[95m'; C = '\033[96m'; W = '\033[97m'; X = '\033[0m'

TARGETS = [
    "https://www.cloudflare.com",       # 1. Behind Cloudflare (obviously)
    "https://www.microsoft.com",        # 2. Akamai / Azure Front Door
    "https://wordpress.org",            # 3. WordPress CMS
    "https://www.apache.org",           # 4. Apache HTTPD (bare metal)
    "https://nginx.org",                # 5. Nginx origin
    "https://shopee.co.id",             # 6. Indonesian e-commerce (CDN heavy)
    "https://kemenag.go.id",            # 7. Indonesian .go.id target
    "https://detik.com",                # 8. Indonesian news (Cloudflare or Akamai)
]

# ═══════════════════════════════════════════════
# TEST 1: TargetProfiler (from start.py)
# ═══════════════════════════════════════════════
def test_profiler():
    print(f"\n{C.M}{'═'*70}")
    print(f"  TEST 1: TargetProfiler — WAF / CMS / Server Detection")
    print(f"{'═'*70}{C.X}")
    
    try:
        from start import TargetProfiler
        profiler_ok = True
    except Exception as e:
        print(f"  {C.R}[FAIL] Cannot import TargetProfiler: {e}{C.X}")
        profiler_ok = False
    
    results = []
    for url in TARGETS:
        row = {"url": url, "server": "?", "waf": "?", "cms": "?", "methods": []}
        
        if profiler_ok:
            try:
                p = TargetProfiler.profile(url)
                row["server"] = p.get("server", "?")
                row["waf"]    = p.get("waf") or "None"
                row["cms"]    = p.get("cms") or "-"
                row["methods"]= p.get("methods", [])[:3]
            except Exception as e:
                row["server"] = f"ERR: {e}"
        else:
            # Fallback: manual header check
            try:
                r = requests.get(url, timeout=8, verify=False, allow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/136.0.0.0 Safari/537.36"})
                row["server"] = r.headers.get("server", "Unknown")
                if r.headers.get("cf-ray"):
                    row["waf"] = "Cloudflare"
                elif "akamai" in str(r.headers).lower():
                    row["waf"] = "Akamai"
                else:
                    row["waf"] = "None"
            except Exception as e:
                row["server"] = f"TIMEOUT ({e})"
        
        waf_color = C.R if row["waf"] not in ["None", "-", "?"] else C.G
        print(f"  {C.B}{url:<40}{C.X} Server: {C.C}{row['server']:<20}{C.X} WAF: {waf_color}{row['waf']:<18}{C.X} CMS: {row['cms']}")
        results.append(row)
    
    return results

# ═══════════════════════════════════════════════
# TEST 2: dox_origin_ip (Pre-Flight Doxing)
# ═══════════════════════════════════════════════
def test_doxing():
    print(f"\n{C.M}{'═'*70}")
    print(f"  TEST 2: Pre-Flight Origin Doxing (Subdomain Leak)")
    print(f"{'═'*70}{C.X}")
    
    from urllib.parse import urlparse
    
    SUBDOMAINS = ['mail', 'direct', 'ftp', 'cpanel', 'webmail', 'dev', 'admin', 'forum', 'staging', 'api', 'cdn', 'ns1', 'ns2']
    CF_RANGES = ("104.", "172.", "162.159.", "188.114.", "141.101.")
    
    dox_results = {}
    for url in TARGETS:
        domain = urlparse(url).netloc.split(':')[0]
        found_origin = None
        tested = 0
        
        for sub in SUBDOMAINS:
            try:
                sub_domain = f"{sub}.{domain}"
                ip = socket.gethostbyname(sub_domain)
                tested += 1
                if not any(ip.startswith(r) for r in CF_RANGES):
                    found_origin = f"{ip} (via {sub}.)"
                    break
            except Exception:
                pass
        
        if found_origin:
            print(f"  {C.G}[HIT] {domain:<30} → Origin IP: {found_origin}{C.X}")
        else:
            print(f"  {C.Y}[---] {domain:<30} → No origin leaked (tested {tested} subdomains){C.X}")
        dox_results[domain] = found_origin
    
    return dox_results

# ═══════════════════════════════════════════════
# TEST 3: HTTP/3 QUIC Readiness
# ═══════════════════════════════════════════════
def test_quic_readiness():
    print(f"\n{C.M}{'═'*70}")
    print(f"  TEST 3: HTTP/3 QUIC Module Readiness")
    print(f"{'═'*70}{C.X}")
    
    # Check if aioquic is installed
    try:
        import aioquic
        print(f"  {C.G}[OK] aioquic installed: v{aioquic.__version__}{C.X}")
        quic_ready = True
    except ImportError:
        print(f"  {C.R}[FAIL] aioquic NOT installed. Run: pip install aioquic{C.X}")
        quic_ready = False
    
    # Check if targets advertise HTTP/3 via Alt-Svc header
    print(f"\n  Checking Alt-Svc (HTTP/3 advertisement) on targets:")
    for url in TARGETS:
        try:
            r = requests.get(url, timeout=8, verify=False, allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 Chrome/136"})
            alt_svc = r.headers.get("alt-svc", "")
            if "h3" in alt_svc.lower():
                print(f"  {C.G}[H3] {url:<40} Alt-Svc: {alt_svc[:60]}{C.X}")
            else:
                als = alt_svc[:50] if alt_svc else "Not advertised"
                print(f"  {C.Y}[--] {url:<40} Alt-Svc: {als}{C.X}")
        except Exception as e:
            print(f"  {C.R}[ERR] {url:<40} {e}{C.X}")
    
    return quic_ready

# ═══════════════════════════════════════════════
# TEST 4: Proxy Pipeline Health
# ═══════════════════════════════════════════════
def test_proxy_pipeline():
    print(f"\n{C.M}{'═'*70}")
    print(f"  TEST 4: Proxy Pipeline Health (Sample 10 sources)")
    print(f"{'═'*70}{C.X}")
    
    try:
        with open("config.json", "r") as f:
            cfg = json.load(f)
        sources = cfg.get("proxy-providers", [])
    except Exception:
        sources = []
    
    print(f"  Total sources in config.json: {len(sources)}")
    
    # Test 10 random sources
    import random
    sample = random.sample(sources, min(10, len(sources)))
    alive = 0
    dead = 0
    total_proxies = 0
    
    for src in sample:
        url = src["url"]
        try:
            r = requests.get(url, timeout=8, verify=False)
            count = len([l for l in r.text.strip().splitlines() if l.strip()])
            if count > 0:
                alive += 1
                total_proxies += count
                print(f"  {C.G}[LIVE] Type {src['type']}: {count:>5} proxies ← {url.split('/')[-1]}{C.X}")
            else:
                dead += 1
                print(f"  {C.R}[DEAD] Type {src['type']}: empty    ← {url.split('/')[-1]}{C.X}")
        except Exception as e:
            dead += 1
            print(f"  {C.R}[FAIL] Type {src['type']}: {str(e)[:30]} ← {url.split('/')[-1]}{C.X}")
    
    print(f"\n  Summary: {C.G}{alive} alive{C.X} / {C.R}{dead} dead{C.X} / {total_proxies:,} proxies from sample")
    return alive, dead, total_proxies

# ═══════════════════════════════════════════════
# TEST 5: Turnstile Daemon Module Check
# ═══════════════════════════════════════════════
def test_turnstile():
    print(f"\n{C.M}{'═'*70}")
    print(f"  TEST 5: Turnstile Daemon Module Integrity")
    print(f"{'═'*70}{C.X}")
    
    try:
        from turnstile_dispenser import TurnstileDispenser
        import inspect
        sig = inspect.signature(TurnstileDispenser.solve_challenge)
        params = list(sig.parameters.keys())
        
        has_daemon = "daemon" in params
        print(f"  {C.G if has_daemon else C.R}[{'OK' if has_daemon else 'FAIL'}] Daemon parameter: {'Present' if has_daemon else 'MISSING'}{C.X}")
        print(f"  Parameters: {params}")
        
    except Exception as e:
        print(f"  {C.R}[FAIL] Cannot import TurnstileDispenser: {e}{C.X}")

# ═══════════════════════════════════════════════
# TEST 6: AsyncQuicFlood Class Exists
# ═══════════════════════════════════════════════
def test_quic_class():
    print(f"\n{C.M}{'═'*70}")
    print(f"  TEST 6: AsyncQuicFlood Class Registration")
    print(f"{'═'*70}{C.X}")
    
    try:
        from start import AsyncQuicFlood, Methods
        print(f"  {C.G}[OK] AsyncQuicFlood class imported successfully{C.X}")
        
        if "H3_QUIC" in Methods.LAYER7_METHODS:
            print(f"  {C.G}[OK] H3_QUIC registered in Methods.LAYER7_METHODS{C.X}")
        else:
            print(f"  {C.R}[FAIL] H3_QUIC NOT in Methods.LAYER7_METHODS{C.X}")
            
    except ImportError as e:
        print(f"  {C.R}[FAIL] Cannot import AsyncQuicFlood: {e}{C.X}")
    except Exception as e:
        print(f"  {C.Y}[WARN] Partial import error (may be OK): {e}{C.X}")

# ═══════════════════════════════════════════════
# TEST 7: Sentinel Escalation Logic Check
# ═══════════════════════════════════════════════
def test_sentinel_logic():
    print(f"\n{C.M}{'═'*70}")
    print(f"  TEST 7: Sentinel Auto-Escalation Logic (Code Check)")
    print(f"{'═'*70}{C.X}")
    
    try:
        with open("menu.py", "r", encoding="utf-8") as f:
            content = f.read()
        
        checks = {
            "consecutive_up": "Escalation counter variable",
            "SENTINEL": "Sentinel label in output",
            "mutation_gen": "Smart mutation generation tracker",
            "MUTATION_POOL": "Method rotation pool",
            "p.poll()": "Active process polling loop",
        }
        
        for keyword, desc in checks.items():
            if keyword in content:
                print(f"  {C.G}[OK] {desc} ({keyword}){C.X}")
            else:
                print(f"  {C.R}[MISSING] {desc} ({keyword}){C.X}")
                
    except Exception as e:
        print(f"  {C.R}[FAIL] Cannot read menu.py: {e}{C.X}")

# ═══════════════════════════════════════════════
# TEST 8: Hot-Swap Cookie Reload in start.py
# ═══════════════════════════════════════════════
def test_hotswap():
    print(f"\n{C.M}{'═'*70}")
    print(f"  TEST 8: CF Clearance Hot-Swap Logic (Code Check)")
    print(f"{'═'*70}{C.X}")
    
    try:
        with open("start.py", "r", encoding="utf-8") as f:
            content = f.read()
        
        checks = {
            "loop_counter": "Loop counter for periodic check",
            "Hot Swapping": "Hot-swap comment marker",
            "cf_clearance.txt": "Clearance file path reference",
            "new_clearance": "Fresh cookie variable",
        }
        
        for keyword, desc in checks.items():
            if keyword in content:
                print(f"  {C.G}[OK] {desc}{C.X}")
            else:
                print(f"  {C.R}[MISSING] {desc}{C.X}")
                
    except Exception as e:
        print(f"  {C.R}[FAIL] Cannot read start.py: {e}{C.X}")


# ═══════════════════════════════════════════════
# MAIN RUNNER
# ═══════════════════════════════════════════════
if __name__ == "__main__":
    print(f"\n{C.R}{'▓'*70}")
    print(f"  CHAOS V36 — PHASE 3 FULL DIAGNOSTIC")
    print(f"  Testing 8 targets + all new modules")
    print(f"{'▓'*70}{C.X}")
    
    t0 = time.time()
    
    profiler_results = test_profiler()
    dox_results = test_doxing()
    quic_ready = test_quic_readiness()
    proxy_alive, proxy_dead, proxy_total = test_proxy_pipeline()
    test_turnstile()
    test_quic_class()
    test_sentinel_logic()
    test_hotswap()
    
    elapsed = time.time() - t0
    
    # ── FINAL VERDICT ──
    print(f"\n{C.M}{'═'*70}")
    print(f"  DIAGNOSTIC COMPLETE — {elapsed:.1f}s elapsed")
    print(f"{'═'*70}{C.X}")
    
    issues = []
    
    # Analyze profiler results
    waf_detected = sum(1 for r in profiler_results if r["waf"] not in ["None", "-", "?"])
    print(f"  WAF Detection  : {waf_detected}/8 targets identified WAF")
    if waf_detected < 3:
        issues.append("WAF detection rate is low — TargetProfiler may need more signatures")
    
    # Analyze doxing
    dox_hits = sum(1 for v in dox_results.values() if v)
    print(f"  Origin Doxing   : {dox_hits}/8 origin IPs leaked")
    if dox_hits == 0:
        issues.append("No origin IPs found — consider adding DNS history API (SecurityTrails/Censys)")
    
    # QUIC
    print(f"  QUIC Module     : {'Ready' if quic_ready else 'NOT INSTALLED'}")
    if not quic_ready:
        issues.append("aioquic not installed — H3_QUIC vector is non-functional")
    
    # Proxy
    print(f"  Proxy Sources   : {proxy_alive} alive / {proxy_dead} dead from sample")
    if proxy_dead > proxy_alive:
        issues.append("More dead proxy sources than alive — needs cleanup")
    
    if issues:
        print(f"\n  {C.Y}⚠  ISSUES FOUND:{C.X}")
        for i, issue in enumerate(issues, 1):
            print(f"  {C.Y}  {i}. {issue}{C.X}")
    else:
        print(f"\n  {C.G}✓  ALL SYSTEMS NOMINAL — READY FOR COMBAT{C.X}")
    
    print()
