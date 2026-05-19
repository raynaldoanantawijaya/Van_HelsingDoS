#!/usr/bin/env python3
import sys, os, io, time
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

TARGETS = [
    "https://www.konisolo.com/",
    "https://puskesjaten1.karanganyarkab.go.id/",
    "https://hardosoloplast.com/",
    "https://surakarta.go.id/",
    "https://raynaldotech.my.id",
    "https://uns.ac.id/",
    "https://www.ums.ac.id/",
    "https://satudata.karanganyarkab.go.id/"
]

def run_diagnostic():
    print(f"\n{'='*60}")
    print(f" TARGET DIAGNOSTIC (V36 BATTLE READINESS)")
    print(f"{'='*60}")
    
    try:
        from start import TargetProfiler
    except Exception as e:
        print(f"Failed to load profiler: {e}")
        return

    for url in TARGETS:
        print(f"\n[+] Analyzing: {url}")
        res = TargetProfiler.profile(url)
        print(f"    Server : {res.get('server')}")
        print(f"    WAF    : {res.get('waf') or 'None'}")
        print(f"    CMS    : {res.get('cms') or 'Unknown'}")
        print(f"    Alt-Svc: {res.get('alt_svc') or 'None'}")
        print(f"    Ports  : {res.get('open_ports')}")
        print(f"    Methods: {', '.join(res.get('methods')[:4])}")

if __name__ == "__main__":
    run_diagnostic()
