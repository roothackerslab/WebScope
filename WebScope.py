#!/usr/bin/env python3
from __future__ import annotations
"""
 ██╗    ██╗███████╗██████╗ ███████╗ ██████╗ ██████╗ ██████╗ ███████╗
 ██║    ██║██╔════╝██╔══██╗██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
 ██║ █╗ ██║█████╗  ██████╔╝███████╗██║     ██║   ██║██████╔╝█████╗  
 ██║███╗██║██╔══╝  ██╔══██╗╚════██║██║     ██║   ██║██╔═══╝ ██╔══╝  
 ╚███╔███╔╝███████╗██████╔╝███████║╚██████╗╚██████╔╝██║     ███████╗
  ╚══╝╚══╝ ╚══════╝╚═════╝ ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝
                    See Beyond The Surface
                    By: Mughal__Hacker | RootHackersLab
                    v2.3 — All in One Analyzer
"""
import requests, socket, json, sys, os, argparse, time, re, random, logging, threading, warnings
from datetime import datetime
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
from functools import wraps
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib3.exceptions import InsecureRequestWarning   # ✅ BUG 1 FIXED

warnings.filterwarnings('ignore', category=InsecureRequestWarning)

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

init(autoreset=True)

# ── LOGGING ────────────────────────────────────────────────────────────────
logging.basicConfig(
    filename='webscope.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    force=True
)
logger = logging.getLogger(__name__)

# ── CONFIG ─────────────────────────────────────────────────────────────────
MAX_THREADS       = 50
PORT_TIMEOUT      = 0.5
REQUEST_TIMEOUT   = 7
SUBDOMAIN_TIMEOUT = 3.0

# ── USER AGENTS ────────────────────────────────────────────────────────────
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
]

def get_random_headers():
    return {
        'User-Agent': random.choice(USER_AGENTS),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'DNT': '1',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1'
    }

def create_session(retries: int = 2) -> requests.Session:
    """Session with retry logic"""
    session = requests.Session()
    retry = Retry(
        total=retries,
        backoff_factor=0.3,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=['GET', 'HEAD', 'OPTIONS']
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

# ── THREAD-SAFE RATE LIMITER ───────────────────────────────────────────────
def rate_limit(calls_per_second: float = 2.0):
    """Thread-safe rate limiter with Lock"""       # ✅ v2.2 improvement kept
    min_interval = 1.0 / calls_per_second
    last_called  = [0.0]
    lock         = threading.Lock()
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            with lock:
                elapsed = time.time() - last_called[0]
                left    = min_interval - elapsed
                if left > 0:
                    time.sleep(left)
                ret = func(*args, **kwargs)
                last_called[0] = time.time()
                return ret
        return wrapper
    return decorator

COMMON_SUBDOMAINS = [
    'www','mail','ftp','localhost','webmail','smtp','pop','ns1','webdisk',
    'ns2','cpanel','whm','autodiscover','autoconfig','m','imap','test',
    'ns','blog','pop3','dev','www2','admin','forum','news','vpn',
    'ns3','mail2','new','mysql','old','lists','support','mobile','mx',
    'static','docs','beta','shop','sql','secure','demo','cp','calendar',
    'wiki','web','media','email','images','img','www1','intranet',
    'portal','video','sip','dns2','api','cdn','stats','dns1','ns4',
    'www3','dns','search','staging','server','mx1','chat','wap','my',
    'svn','mail1','sites','proxy','ads','host','crm','cms','backup',
    'mx2','lyncdiscover','info','apps','download','remote','db','forums',
    'git','gitlab','jenkins','jira','confluence','kibana','grafana',
    'prometheus','elastic','mongo','redis','vault','docker','k8s',
]

SENSITIVE_FILES = [
    'robots.txt','sitemap.xml','security.txt','.well-known/security.txt',
    '.git/config','.git/HEAD','.env','.env.local','.env.production',
    'wp-config.php','config.php','configuration.php','settings.php',
    '.htaccess','.htpasswd','web.config','crossdomain.xml',
    'phpinfo.php','info.php','test.php','backup.sql','database.sql',
    'dump.sql','backup.zip','backup.tar.gz','admin.php','login.php',
    'administrator/','admin/','phpmyadmin/','cpanel/','wp-admin/',
    '.DS_Store','composer.json','package.json','yarn.lock','package-lock.json',
    '.svn/entries','Dockerfile','docker-compose.yml',
]

COMMON_PORTS = {
    21:'FTP', 22:'SSH', 23:'Telnet', 25:'SMTP', 53:'DNS',
    80:'HTTP', 110:'POP3', 143:'IMAP', 443:'HTTPS', 445:'SMB',
    3306:'MySQL', 3389:'RDP', 5432:'PostgreSQL', 5900:'VNC',
    6379:'Redis', 8080:'HTTP-Proxy', 8443:'HTTPS-Alt',
    27017:'MongoDB', 9200:'Elasticsearch',
}

# ── STARTUP ANIMATION ──────────────────────────────────────────────────────
def scan_startup_animation(target: str, domain: str) -> None:
    """Professional hacker-style startup animation"""
    os.system('cls' if os.name == 'nt' else 'clear')
    G  = Fore.GREEN + Style.BRIGHT
    C  = Fore.CYAN  + Style.BRIGHT
    Y  = Fore.YELLOW
    W  = Fore.WHITE + Style.BRIGHT
    R  = Style.RESET_ALL
    DG = Fore.GREEN
    DM = Fore.GREEN + Style.DIM

    # Matrix rain burst
    chars = '01アイウエオカキクケコサシスセソタチツテト'
    print()
    for _ in range(3):
        line = ''
        for _ in range(68):
            if random.random() > 0.7:
                line += G + random.choice(chars) + R
            else:
                line += DM + random.choice('01') + R
        print(f"  {line}")
        time.sleep(0.05)
    print()

    # Animated border draw
    sys.stdout.write(f"  {DG}")
    for _ in range(66):
        sys.stdout.write('─')
        sys.stdout.flush()
        time.sleep(0.003)
    sys.stdout.write(R + '\n')
    time.sleep(0.1)

    # Title typewriter
    title = "[ WEBSCOPE PRO v2.3 — INITIALIZING ]"
    sys.stdout.write(f"  {G}")
    for ch in title:
        sys.stdout.write(ch)
        sys.stdout.flush()
        time.sleep(0.03)
    sys.stdout.write(R + '\n')

    sys.stdout.write(f"  {DG}")
    for _ in range(66):
        sys.stdout.write('─')
        sys.stdout.flush()
        time.sleep(0.003)
    sys.stdout.write(R + '\n\n')
    time.sleep(0.15)

    # Target info reveal
    fields = [
        ('TARGET',    target),
        ('DOMAIN',    domain),
        ('TIMESTAMP', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
        ('THREADS',   f'{MAX_THREADS} parallel workers'),
        ('ENGINE',    'WebScope Pro v2.3 / RootHackersLab'),
    ]
    for label, value in fields:
        sys.stdout.write(f"  {DG}◈{R}  {Fore.WHITE}{label:<14}{R} {C}")
        time.sleep(0.08)
        for ch in str(value):
            sys.stdout.write(ch)
            sys.stdout.flush()
            time.sleep(0.012)
        sys.stdout.write(R + '\n')
    print()

    # Module loading bars
    modules = [
        'WHOIS Lookup','DNS Records','IP & Geo-Location',
        'Subdomain Discovery','Tech Stack Detection',
        'Security Headers','HTTP Analysis','Exposed Files','Port Scanner',
    ]
    sys.stdout.write(f"  {DG}{'─'*66}{R}\n")
    sys.stdout.write(f"  {W}Loading Modules:{R}\n\n")
    for mod in modules:
        sys.stdout.write(f"  {DG}  ▸{R} {Fore.WHITE}{mod:<28}{R} {DG}[")
        sys.stdout.flush()
        time.sleep(0.06)
        for _ in range(18):
            sys.stdout.write('█')
            sys.stdout.flush()
            time.sleep(0.018)
        sys.stdout.write(f"]{R} {G}READY{R}\n")
    print()
    sys.stdout.write(f"  {DG}{'─'*66}{R}\n")

    # Countdown
    for i in range(3, 0, -1):
        sys.stdout.write(f"\r  {Y}[ Scan starting in {G}{i}{Y} ]   {R}")
        sys.stdout.flush()
        time.sleep(0.7)
    sys.stdout.write(f"\r  {G}[ SCAN LAUNCHED — GO GO GO! ]{R}            \n\n")
    time.sleep(0.3)


# ── INTERACTIVE MENU HELPERS ───────────────────────────────────────────────
def _print_menu_header() -> None:
    G  = Fore.GREEN + Style.BRIGHT
    C  = Fore.CYAN  + Style.BRIGHT
    R  = Style.RESET_ALL
    DG = Fore.GREEN
    print(f"""
{G}
 ██╗    ██╗███████╗██████╗ ███████╗ ██████╗ ██████╗ ██████╗ ███████╗
 ██║    ██║██╔════╝██╔══██╗██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
 ██║ █╗ ██║█████╗  ██████╔╝███████╗██║     ██║   ██║██████╔╝█████╗  
 ██║███╗██║██╔══╝  ██╔══██╗╚════██║██║     ██║   ██║██╔═══╝ ██╔══╝  
 ╚███╔███╔╝███████╗██████╔╝███████║╚██████╗╚██████╔╝██║     ███████╗
  ╚══╝╚══╝ ╚══════╝╚═════╝ ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝
{R}""")
    print(f"  {DG}{'─'*66}{R}")
    print(f"  {DG}◈{R}  {'Author':<12} {Fore.WHITE}Mughal__Hacker{R}")
    print(f"  {DG}◈{R}  {'Community':<12} {C}RootHackersLab{R}")
    print(f"  {DG}◈{R}  {'Version':<12} {Fore.WHITE}v2.3 (All in One Analyzer){R}")
    print(f"  {DG}{'─'*66}{R}")
    print(f"\n  {Fore.WHITE + Style.BRIGHT}Modules:{R}")
    for m in [
        'WHOIS Lookup','DNS Records','IP & Geo-Location',
        'Subdomain Discovery (Threaded)','Technology Stack Detection',
        'Security Headers Analysis','HTTP Response Analysis',
        'Exposed Files Detection (Threaded)','Port Scanning (Threaded)',
    ]:
        print(f"    {DG}▸{R} {m}")
    print(f"\n  {DG}{'─'*66}{R}")


def _pick_output_format() -> str:
    """Numbered menu for output format"""
    G  = Fore.GREEN + Style.BRIGHT
    Y  = Fore.YELLOW
    C  = Fore.CYAN
    W  = Fore.WHITE + Style.BRIGHT
    R  = Style.RESET_ALL
    DG = Fore.GREEN
    fmt_map = {'1':'html','2':'json','3':'both'}
    while True:
        print(f"\n  {DG}┌{'─'*40}┐{R}")
        print(f"  {DG}│{R}  {W}SELECT OUTPUT FORMAT{R}{'':>21}{DG}│{R}")
        print(f"  {DG}├{'─'*40}┤{R}")
        print(f"  {DG}│{R}  {G} [1]{R}  HTML Report  {Fore.WHITE}(browser viewer){R}{'':>5}{DG}│{R}")
        print(f"  {DG}│{R}  {C} [2]{R}  JSON Report  {Fore.WHITE}(raw data){R}{'':>9}{DG}│{R}")
        print(f"  {DG}│{R}  {Y} [3]{R}  Both         {Fore.WHITE}(recommended){R}{'':>7}{DG}│{R}")
        print(f"  {DG}└{'─'*40}┘{R}")
        choice = input(f"\n  {Y}[?]{R} Enter choice {DG}[1/2/3]{R}: ").strip()
        if choice in fmt_map:
            label = {'1':'HTML','2':'JSON','3':'HTML + JSON'}[choice]
            print(f"  {DG}[✓]{R} Output format → {G}{label}{R}")
            return fmt_map[choice]
        print(f"  {Fore.RED}[-]{R} Invalid — enter {G}1{R}, {C}2{R}, or {Y}3{R}")


def _confirm_scan(target: str, fmt: str) -> bool:
    """Numbered confirmation before scan"""
    G  = Fore.GREEN + Style.BRIGHT
    Y  = Fore.YELLOW
    R  = Style.RESET_ALL
    DG = Fore.GREEN
    while True:
        print(f"\n  {DG}┌{'─'*46}┐{R}")
        print(f"  {DG}│{R}  {Fore.WHITE + Style.BRIGHT}SCAN CONFIGURATION{R}{'':>28}{DG}│{R}")
        print(f"  {DG}├{'─'*46}┤{R}")
        print(f"  {DG}│{R}  {Fore.WHITE}Target  :{R}  {Fore.CYAN}{target[:32]:<32}{R}  {DG}│{R}")
        print(f"  {DG}│{R}  {Fore.WHITE}Output  :{R}  {G}{fmt.upper():<32}{R}  {DG}│{R}")
        print(f"  {DG}├{'─'*46}┤{R}")
        print(f"  {DG}│{R}  {G} [1]{R}  Launch Scan 🚀{'':>29}{DG}│{R}")
        print(f"  {DG}│{R}  {Fore.RED} [2]{R}  Cancel{R}{'':>38}{DG}│{R}")
        print(f"  {DG}└{'─'*46}┘{R}")
        choice = input(f"\n  {Y}[?]{R} Enter choice {DG}[1/2]{R}: ").strip()
        if choice == '1': return True
        if choice == '2': return False
        print(f"  {Fore.RED}[-]{R} Enter {G}1{R} to scan or {Fore.RED}2{R} to cancel")


# ── MAIN CLASS ─────────────────────────────────────────────────────────────
class WebScopePro:
    def __init__(self, target: str, verbose: bool = False, output: str = 'both',
                 skip_ssl: bool = False, no_color: bool = False,
                 allowlist: list | None = None, dry_run: bool = False):
        self.target   = self._clean_url(target)
        parsed        = urlparse(self.target)
        self.domain   = (parsed.netloc or parsed.path).split(':')[0]
        self.verbose  = verbose
        self.output   = output
        self.skip_ssl = skip_ssl
        self.no_color = no_color
        self.allowlist= allowlist or []
        self.dry_run  = dry_run
        self.session  = create_session()

        # ✅ BUG 5 FIXED: Color shortcuts set ONCE cleanly — no more inline ternaries
        NC      = no_color
        self.R  = '' if NC else Style.RESET_ALL
        self.G  = '' if NC else Fore.GREEN
        self.GB = '' if NC else Fore.GREEN + Style.BRIGHT
        self.C  = '' if NC else Fore.CYAN
        self.CB = '' if NC else Fore.CYAN  + Style.BRIGHT
        self.Y  = '' if NC else Fore.YELLOW
        self.W  = '' if NC else Fore.WHITE
        self.WB = '' if NC else Fore.WHITE + Style.BRIGHT
        self.RE = '' if NC else Fore.RED

        self.results = {
            'target': self.target, 'domain': self.domain,
            'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'whois': {}, 'dns': {}, 'subdomains': [],
            'technologies': {}, 'security': {}, 'http_info': {},
            'ports': [], 'exposed_files': [], 'ip_info': {}, 'robots_txt': '',
        }
        self.report_dir = 'WebScope_Reports'
        os.makedirs(self.report_dir, exist_ok=True)

    def _clean_url(self, url: str) -> str:
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url

    def _is_private_ip(self, hostname: str) -> bool:
        """Check if hostname resolves to private/internal IP"""
        try:
            ip = socket.gethostbyname(hostname)
            return ip.startswith((
                '10.','192.168.','127.','0.',
                '172.16.','172.17.','172.18.','172.19.','172.20.',
                '172.21.','172.22.','172.23.','172.24.','172.25.',
                '172.26.','172.27.','172.28.','172.29.','172.30.','172.31.',
            ))
        except socket.gaierror:
            return False

    def _domain_allowed(self, domain: str) -> bool:
        """✅ BUG 7 FIXED: Proper subdomain matching, not just exact match"""
        if not self.allowlist:
            return True
        return any(domain == d or domain.endswith('.' + d) for d in self.allowlist)

    def _ok (self, m): print(f"  {self.G}[+]{self.R} {m}")
    def _err(self, m): print(f"  {self.RE}[-]{self.R} {m}")
    def _wrn(self, m): print(f"  {self.Y}[!]{self.R} {m}")
    def _inf(self, m): print(f"  {self.C}[*]{self.R} {m}")

    def _phase(self, num: int, name: str) -> None:
        bar = self.G + '─'*68 + self.R
        tag = f"[0{num}]" if num < 10 else f"[{num}]"
        print(f"\n{bar}")
        print(f"  {self.G}{tag}{self.R}  {self.WB}{name}{self.R}")
        print(bar)

    def print_banner(self) -> None:
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"""
{self.GB}
 ██╗    ██╗███████╗██████╗ ███████╗ ██████╗ ██████╗ ██████╗ ███████╗
 ██║    ██║██╔════╝██╔══██╗██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
 ██║ █╗ ██║█████╗  ██████╔╝███████╗██║     ██║   ██║██████╔╝█████╗  
 ██║███╗██║██╔══╝  ██╔══██╗╚════██║██║     ██║   ██║██╔═══╝ ██╔══╝  
 ╚███╔███╔╝███████╗██████╔╝███████║╚██████╗╚██████╔╝██║     ███████╗
  ╚══╝╚══╝ ╚══════╝╚═════╝ ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝
{self.R}""")
        print(f"  {self.G}{'─'*66}{self.R}")
        print(f"  {self.G}◈{self.R}  {'Author':<18} {self.W}Mughal__Hacker{self.R}")
        print(f"  {self.G}◈{self.R}  {'Community':<18} {self.C}RootHackersLab{self.R}")
        print(f"  {self.G}◈{self.R}  {'Version':<18} {self.W}v2.3 (Merged + All Bugs Fixed){self.R}")
        print(f"  {self.G}◈{self.R}  {'Target':<18} {self.C}{self.target}{self.R}")
        print(f"  {self.G}◈{self.R}  {'Domain':<18} {self.C}{self.domain}{self.R}")
        print(f"  {self.G}◈{self.R}  {'Scan Started':<18} {self.W}{self.results['scan_time']}{self.R}")
        print(f"  {self.G}{'─'*66}{self.R}")
        modules = [
            ('WHOIS Lookup','DNS Records','IP & Geo-Location'),
            ('Subdomain Discovery','Tech Stack Detection','Security Headers'),
            ('HTTP Analysis','Exposed Files','Port Scanning'),
        ]
        print(f"\n  {self.WB}Active Modules:{self.R}")
        for row in modules:
            line = ''.join(f"  {self.G}▸{self.R} {self.W}{m:<26}{self.R}" for m in row)
            print(f"  {line}")
        print(f"  {self.G}{'─'*66}{self.R}\n")

    # ── PHASE 1: WHOIS ────────────────────────────────────────────────────
    def whois_lookup(self) -> None:
        self._phase(1, 'WHOIS Information')
        if not WHOIS_AVAILABLE:
            self._wrn('python-whois not installed  →  pip install python-whois'); return
        try:
            w = whois.whois(self.domain)
            def s(v): return str(v[0] if isinstance(v,list) else v) if v else 'N/A'
            self.results['whois'] = {
                'registrar':s(w.registrar),'creation_date':s(w.creation_date),
                'expiration_date':s(w.expiration_date),'updated_date':s(getattr(w,'updated_date',None)),
                'name_servers':list(w.name_servers or []),'status':w.status or [],
            }
            r = self.results['whois']
            self._ok(f"Registrar        : {r['registrar']}")
            self._ok(f"Created          : {r['creation_date']}")
            self._ok(f"Expires          : {r['expiration_date']}")
            self._ok(f"Updated          : {r['updated_date']}")
            for ns in r['name_servers'][:3]:
                self._inf(f"Nameserver       : {ns}")
        except Exception as e:
            self._err(f"WHOIS failed: {e}")
            logger.error(f"WHOIS lookup error: {e}")

    # ── PHASE 2: DNS ──────────────────────────────────────────────────────
    def dns_lookup(self) -> None:
        self._phase(2, 'DNS Records')
        if not DNS_AVAILABLE:
            self._wrn('dnspython not installed  →  pip install dnspython'); return
        for rtype in ['A','AAAA','MX','NS','TXT','CNAME','SOA']:
            try:
                answers = dns.resolver.resolve(self.domain, rtype, lifetime=5)
                records = [str(r) for r in answers]
                self.results['dns'][rtype] = records
                self._ok(f"{rtype:<6} → {len(records)} record(s)")
                for r in records[:2]:
                    print(f"          {self.W}{r[:80]}{self.R}")
            except dns.resolver.NoAnswer:
                self.results['dns'][rtype] = []
            except dns.resolver.NXDOMAIN:
                self._err('Domain does not exist (NXDOMAIN)'); break
            except Exception as e:
                self.results['dns'][rtype] = []
                logger.debug(f"DNS {rtype} query failed: {e}")

    # ── PHASE 3: IP & GEO ─────────────────────────────────────────────────
    def ip_information(self) -> None:
        self._phase(3, 'IP & Geo-Location')
        try:
            ip = socket.gethostbyname(self.domain)
            self.results['ip_info']['ip'] = ip
            self._ok(f"IP Address       : {self.C}{ip}{self.R}")
            r = self.session.get(f"http://ip-api.com/json/{ip}", timeout=5)
            if r.status_code == 200:
                d = r.json()
                if d.get('status') == 'success':
                    geo = {k:d.get(v,'N/A') for k,v in {
                        'country':'country','country_code':'countryCode',
                        'region':'regionName','city':'city','zip':'zip',
                        'lat':'lat','lon':'lon','timezone':'timezone',
                        'isp':'isp','org':'org','as':'as',
                    }.items()}
                    self.results['ip_info']['geo'] = geo
                    self._ok(f"Location         : {geo['city']}, {geo['region']}, {geo['country']}")
                    self._ok(f"Coordinates      : {geo['lat']}, {geo['lon']}")
                    self._ok(f"Timezone         : {geo['timezone']}")
                    self._ok(f"ISP              : {geo['isp']}")
                    self._ok(f"Organization     : {geo['org']}")
                    self._ok(f"AS Number        : {geo['as']}")
        except Exception as e:
            self._err(f"IP lookup failed: {e}")
            logger.error(f"IP information error: {e}")

    # ── PHASE 4: SUBDOMAINS ───────────────────────────────────────────────
    def subdomain_enum(self) -> None:
        self._phase(4, 'Subdomain Discovery')
        self._inf(f"Testing {len(COMMON_SUBDOMAINS)} subdomains with {MAX_THREADS} threads …")
        found = []

        def _check(sub: str):
            host = f"{sub}.{self.domain}"
            try:
                # ✅ BUG 6 FIXED: Simple gethostbyname — no pointless socket object
                socket.setdefaulttimeout(SUBDOMAIN_TIMEOUT)
                socket.gethostbyname(host)
                return host
            except Exception:
                return None

        with ThreadPoolExecutor(max_workers=MAX_THREADS) as ex:
            futures = {ex.submit(_check, s): s for s in COMMON_SUBDOMAINS}
            for fut in as_completed(futures):
                result = fut.result()
                if result:
                    found.append(result)
                    self._ok(f"Found  → {self.C}{result}{self.R}")

        self.results['subdomains'] = sorted(found)
        print(f"\n  {self.G}Total Subdomains Found : {len(found)}{self.R}")

    # ── PHASE 5: TECH DETECTION ───────────────────────────────────────────
    def technology_detection(self) -> None:
        self._phase(5, 'Technology Stack Detection')
        try:
            logger.info(f"Detecting technology stack for {self.target}")
            resp = self.session.get(self.target, headers=get_random_headers(),
                                    timeout=REQUEST_TIMEOUT, verify=not self.skip_ssl,
                                    allow_redirects=True)
        except Exception as e:
            self._err(f"Request failed: {e}"); logger.error(f"Tech detection failed: {e}"); return

        tech = self.results['technologies']
        tech['server']     = resp.headers.get('Server','Unknown')
        tech['powered_by'] = resp.headers.get('X-Powered-By','Unknown')
        self._ok(f"Server           : {tech['server']}")
        if tech['powered_by'] != 'Unknown':
            self._ok(f"Powered By       : {tech['powered_by']}")

        soup = BeautifulSoup(resp.text, 'html.parser')
        cms  = self._detect_cms(soup, resp.text, resp.headers)
        if cms != 'Unknown':
            tech['cms'] = cms; self._ok(f"CMS              : {self.C}{cms}{self.R}")
        fws  = self._detect_frameworks(resp.text, resp.headers)
        if fws:
            tech['frameworks'] = fws; self._ok(f"Frameworks       : {self.C}{', '.join(fws)}{self.R}")
        libs = self._detect_js_libraries(soup)
        if libs:
            tech['js_libraries'] = libs; self._ok(f"JS Libraries     : {self.C}{', '.join(libs[:6])}{self.R}")
        analytics = self._detect_analytics(resp.text)
        if analytics:
            tech['analytics'] = analytics; self._ok(f"Analytics        : {self.C}{', '.join(analytics)}{self.R}")

    def _detect_cms(self, soup, html, headers):
        sigs = {
            'WordPress':['/wp-content/','/wp-includes/','wp-json'],
            'Joomla':['/components/com_','Joomla'],'Drupal':['/sites/default/','Drupal'],
            'Magento':['Mage.Cookies','/skin/frontend/'],'Shopify':['cdn.shopify.com','myshopify.com'],
            'Wix':['wix.com','_wix'],'Squarespace':['squarespace','sqsp.com'],
            'Ghost':['ghost','/ghost/'],'PrestaShop':['prestashop'],
            'OpenCart':['catalog/view/theme'],'TYPO3':['typo3'],
        }
        h = html.lower(); hs = str(headers).lower()
        for cms, patterns in sigs.items():
            if any(p.lower() in h or p.lower() in hs for p in patterns):
                return cms
        return 'Unknown'

    def _detect_frameworks(self, html, headers):
        sigs = {
            'React':'__react','Angular':'ng-version','Vue.js':'__vue__',
            'Next.js':'_next','Nuxt.js':'__nuxt','Laravel':'laravel_session',
            'Django':'csrftoken','Flask':'flask','ASP.NET':'__viewstate',
            'Spring':'jsessionid','Ruby on Rails':'csrf-token','Symfony':'symfony',
        }
        h = html.lower(); hs = str(headers).lower()
        return [fw for fw,p in sigs.items() if p in h or p in hs]

    def _detect_js_libraries(self, soup):
        patterns = {
            'jQuery':'jquery','Bootstrap':'bootstrap','Font Awesome':'fontawesome',
            'Chart.js':'chart','D3.js':'/d3.','Three.js':'three',
            'Lodash':'lodash','Moment.js':'moment','Axios':'axios','GSAP':'gsap','Swiper':'swiper',
        }
        found = []
        for tag in soup.find_all('script', src=True):
            src = tag['src'].lower()
            for lib, pat in patterns.items():
                if pat in src and lib not in found:
                    found.append(lib)
        return found

    def _detect_analytics(self, html):
        sigs = {
            'Google Analytics':'google-analytics.com','Google Tag Manager':'googletagmanager.com',
            'Facebook Pixel':'fbevents.js','Hotjar':'hotjar.com','Mixpanel':'mixpanel.com',
            'Matomo':'matomo','Yandex Metrica':'metrica.yandex',
        }
        h = html.lower()
        return [tool for tool,p in sigs.items() if p in h]

    # ── PHASE 6: SECURITY HEADERS ─────────────────────────────────────────
    def security_analysis(self) -> None:
        self._phase(6, 'Security Headers Analysis')
        try:
            logger.info(f"Analyzing security headers for {self.target}")
            resp = self.session.get(self.target, headers=get_random_headers(),
                                    timeout=REQUEST_TIMEOUT, verify=not self.skip_ssl)
        except Exception as e:
            self._err(f"Request failed: {e}"); logger.error(f"Security analysis failed: {e}"); return

        checks = {
            'Strict-Transport-Security':'HSTS','Content-Security-Policy':'CSP',
            'X-Frame-Options':'Clickjacking Protection','X-Content-Type-Options':'MIME Sniffing Protection',
            'X-XSS-Protection':'XSS Protection','Referrer-Policy':'Referrer Policy',
            'Permissions-Policy':'Permissions Policy','X-Permitted-Cross-Domain-Policies':'Cross-Domain Policy',
        }
        present, missing = [], []
        for header, desc in checks.items():
            if header in resp.headers:
                present.append({'header':header,'description':desc,'value':resp.headers[header]})
                self._ok(f"{desc:<37} {self.G}✓ Present{self.R}")
            else:
                missing.append({'header':header,'description':desc})
                self._wrn(f"{desc:<37} {self.RE}✗ Missing{self.R}")

        score = (len(present)/len(checks))*100
        grade = self._grade(score)
        ssl   = self.target.startswith('https')
        self.results['security'] = {
            'score':f"{score:.0f}%",'grade':grade,'present_headers':present,
            'missing_headers':missing,'ssl_enabled':ssl,'total_headers':len(checks),
            'present_count':len(present),'missing_count':len(missing),
        }
        flag = f"{self.G}✓ Enabled{self.R}" if ssl else f"{self.RE}✗ Disabled{self.R}"
        print(f"\n  {self.C}Security Score   : {score:.0f}%  (Grade: {grade}){self.R}")
        print(f"  {self.C}SSL/TLS          : {flag}")

    def _grade(self, score: float) -> str:
        return 'A+' if score>=90 else 'A' if score>=80 else 'B' if score>=70 \
          else 'C' if score>=60 else 'D' if score>=50 else 'F'

    # ── PHASE 7: HTTP ─────────────────────────────────────────────────────
    def http_analysis(self) -> None:
        self._phase(7, 'HTTP Response Analysis')
        try:
            logger.info(f"Analyzing HTTP response for {self.target}")
            resp = self.session.get(self.target, headers=get_random_headers(),
                                    timeout=REQUEST_TIMEOUT, verify=not self.skip_ssl,
                                    allow_redirects=True)
            self.results['http_info'] = {
                'status_code':resp.status_code,'status_text':resp.reason,
                'content_type':resp.headers.get('Content-Type','Unknown'),
                'content_length':resp.headers.get('Content-Length','Unknown'),
                'encoding':resp.encoding,'cookies':len(resp.cookies),
                'redirects':len(resp.history),'final_url':resp.url,
                'response_time':f"{resp.elapsed.total_seconds():.2f}",
            }
            i = self.results['http_info']
            self._ok(f"Status           : {i['status_code']} {i['status_text']}")
            self._ok(f"Content-Type     : {i['content_type']}")
            self._ok(f"Response Time    : {i['response_time']}s")
            self._ok(f"Cookies          : {i['cookies']}")
            self._ok(f"Redirects        : {i['redirects']}")
            self._ok(f"Final URL        : {i['final_url']}")
            self._ok(f"Encoding         : {i['encoding']}")
        except Exception as e:
            self._err(f"HTTP analysis failed: {e}"); logger.error(f"HTTP analysis error: {e}")

    # ── PHASE 8: EXPOSED FILES ────────────────────────────────────────────
    def check_exposed_files(self) -> None:
        self._phase(8, 'Exposed Files Detection')
        self._inf(f"Testing {len(SENSITIVE_FILES)} paths with {MAX_THREADS} threads …")
        logger.info(f"Checking {len(SENSITIVE_FILES)} exposed files")
        found = []

        # ✅ BUG 2 FIXED: rate_limit NOT on the inner _check — threads work freely
        def _check(path: str):
            url = f"{self.target.rstrip('/')}/{path}"
            try:
                r = self.session.get(url, headers=get_random_headers(),
                                     timeout=3, verify=not self.skip_ssl,
                                     allow_redirects=False)
                if r.status_code == 200:
                    logger.warning(f"Exposed file found: {url}")
                    return {'file':path,'url':url,'status':r.status_code,'size':len(r.content)}
            except Exception as e:
                logger.debug(f"File check failed for {path}: {e}")
            return None

        with ThreadPoolExecutor(max_workers=MAX_THREADS) as ex:
            futures = {ex.submit(_check, p): p for p in SENSITIVE_FILES}
            for fut in as_completed(futures):
                res = fut.result()
                if res:
                    found.append(res)
                    self._wrn(f"EXPOSED → {self.RE}{res['file']}{self.R}  ({res['size']} bytes)")

        for f in found:
            if f['file'] == 'robots.txt':
                try:
                    r = self.session.get(f['url'], timeout=3, verify=not self.skip_ssl)
                    self.results['robots_txt'] = r.text[:2000]
                except Exception as e:
                    logger.debug(f"Failed to fetch robots.txt: {e}")

        self.results['exposed_files'] = found
        if not found:
            self._ok('No common sensitive files exposed')
        else:
            print(f"\n  {self.RE}Total Exposed Files: {len(found)}{self.R}")

    # ── PHASE 9: PORT SCAN ────────────────────────────────────────────────
    def port_scan(self) -> None:
        self._phase(9, 'Port Scanning')
        try:
            ip = socket.gethostbyname(self.domain)
            self._inf(f"Scanning {ip}  ({len(COMMON_PORTS)} ports, timeout={PORT_TIMEOUT}s) …")
        except Exception as e:
            self._err(f"DNS resolution failed: {e}"); return

        open_ports = []

        def _scan(port: int):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(PORT_TIMEOUT)
                    if s.connect_ex((ip, port)) == 0:
                        return port
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=MAX_THREADS) as ex:
            futures = {ex.submit(_scan, p): p for p in COMMON_PORTS}
            for fut in as_completed(futures):
                p = fut.result()
                if p is not None:
                    open_ports.append({'port':p,'service':COMMON_PORTS[p],'state':'open'})
                    self._ok(f"Port {p:<6} ({COMMON_PORTS[p]:<16}) {self.G}OPEN{self.R}")

        self.results['ports'] = sorted(open_ports, key=lambda x: x['port'])
        if not open_ports:
            self._inf('No common ports detected as open')
        else:
            print(f"\n  {self.C}Total Open Ports: {len(open_ports)}{self.R}")

    # ── HTML REPORT ───────────────────────────────────────────────────────
    def generate_html_report(self) -> str:
        ts    = datetime.now().strftime('%Y%m%d_%H%M%S')
        fn    = f"{self.report_dir}/WebScope_{self.domain.replace('.','_')}_{ts}.html"
        grade = self.results['security'].get('grade','F')
        gc    = {'A+':'#00ff41','A':'#39ff14','B':'#aaff00','C':'#ffcc00','D':'#ff6600','F':'#ff0000'}.get(grade,'#ff0000')

        def badge(text, color):
            return f'<span class="badge" style="background:{color};color:#000">{text}</span>'

        dns_rows     = ''.join(f'<tr><td class="rec-type">{rt}</td><td>{"<br>".join(rs) if rs else "<span class=na>N/A</span>"}</td></tr>' for rt,rs in self.results['dns'].items())
        sub_items    = ''.join(f'<li>&#x25B8; {s}</li>' for s in self.results['subdomains']) or '<li class="na">No subdomains found</li>'
        port_rows    = ''.join(f'<tr><td>{p["port"]}</td><td>{p["service"]}</td><td>{badge("OPEN","#00ff41")}</td></tr>' for p in self.results['ports']) or '<tr><td colspan="3" class="na">No open ports detected</td></tr>'
        file_rows    = ''.join(f'<tr><td class="danger-txt">{f["file"]}</td><td>{badge(str(f["status"]),"#ff0000")}</td><td>{f["size"]} B</td></tr>' for f in self.results['exposed_files']) or '<tr><td colspan="3" class="ok-txt">No sensitive files exposed ✓</td></tr>'
        present_rows = ''.join(f'<tr><td>{h["description"]}</td><td class="muted">{h["value"][:55]}</td><td>{badge("PRESENT","#00ff41")}</td></tr>' for h in self.results['security'].get('present_headers',[]))
        missing_rows = ''.join(f'<tr><td>{h["description"]}</td><td class="na">—</td><td>{badge("MISSING","#ff0000")}</td></tr>' for h in self.results['security'].get('missing_headers',[]))

        tech      = self.results['technologies']
        tech_tags = ''
        for k in ('cms','server','powered_by'):
            v = tech.get(k,'')
            if v and v != 'Unknown': tech_tags += f'<span class="tag">{k.upper()}: {v}</span>'
        for fw  in tech.get('frameworks',[]): tech_tags += f'<span class="tag">{fw}</span>'
        for lib in tech.get('js_libraries',[]): tech_tags += f'<span class="tag tag-lib">{lib}</span>'
        for an  in tech.get('analytics',[]): tech_tags += f'<span class="tag tag-an">{an}</span>'
        if not tech_tags: tech_tags = '<span class="na">No technologies detected</span>'

        geo     = self.results['ip_info'].get('geo',{})
        ssl_ok  = self.results['security'].get('ssl_enabled',False)
        ssl_txt = '<span class="ok-txt">✓ HTTPS</span>' if ssl_ok else '<span class="danger-txt">✗ HTTP Only</span>'
        i       = self.results['http_info']

        HTML = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WebScope :: {self.domain}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&display=swap');
:root{{--bg:#020c02;--bg2:#0a180a;--bg3:#0f220f;--green:#00ff41;--green2:#00cc33;--green3:#003d0f;--cyan:#00e5ff;--red:#ff0000;--yellow:#ffd700;--text:#c0ffc0;--muted:#4a7a4a;--border:#1a3a1a;--glow:0 0 10px #00ff41,0 0 22px #00ff41;--glow-sm:0 0 6px #00ff41;}}
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Share Tech Mono',monospace;background:var(--bg);color:var(--text);min-height:100vh;overflow-x:hidden}}
body::before{{content:'';position:fixed;inset:0;z-index:9999;pointer-events:none;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,255,65,.025) 2px,rgba(0,255,65,.025) 4px)}}
.hdr{{background:linear-gradient(180deg,#000 0%,var(--bg2) 100%);border-bottom:2px solid var(--green);padding:42px 20px 32px;text-align:center;position:relative;overflow:hidden}}
.hdr::after{{content:'';position:absolute;inset:0;background:radial-gradient(ellipse at 50% 0%,rgba(0,255,65,.07) 0%,transparent 70%);pointer-events:none}}
.logo{{font-family:'Orbitron',monospace;font-size:clamp(1.4rem,3.5vw,2.8rem);font-weight:900;color:var(--green);text-shadow:var(--glow);letter-spacing:5px;margin-bottom:4px}}
.tagline{{color:var(--muted);font-size:.78rem;letter-spacing:4px;margin-bottom:22px}}
.meta-grid{{display:inline-grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:10px;background:rgba(0,255,65,.04);border:1px solid var(--border);padding:16px 24px;border-radius:3px;text-align:left;max-width:860px;width:100%}}
.mi{{display:flex;gap:10px;font-size:.8rem}}.mi .lbl{{color:var(--muted);min-width:76px}}.mi .val{{color:var(--cyan)}}
.nav{{display:flex;flex-wrap:wrap;gap:1px;background:#000;border-bottom:1px solid var(--border);padding:0 18px;position:sticky;top:0;z-index:100}}
.nav a{{color:var(--muted);text-decoration:none;padding:9px 14px;font-size:.74rem;letter-spacing:1px;transition:.2s;border-bottom:2px solid transparent}}
.nav a:hover{{color:var(--green);border-bottom-color:var(--green);text-shadow:var(--glow-sm)}}
.dash{{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:14px;padding:28px 28px 0}}
.card{{background:var(--bg2);border:1px solid var(--border);border-top:3px solid var(--green);padding:22px 18px;border-radius:3px;transition:.3s;position:relative;overflow:hidden}}
.card::before{{content:'';position:absolute;inset:0;background:radial-gradient(circle at 50% 0%,rgba(0,255,65,.05) 0%,transparent 60%);pointer-events:none}}
.card:hover{{border-color:var(--green);box-shadow:var(--glow-sm);transform:translateY(-2px)}}
.card .cv{{font-family:'Orbitron',monospace;font-size:2.2rem;font-weight:700;color:var(--green);text-shadow:var(--glow-sm);margin:7px 0 3px}}
.card .cl{{color:var(--muted);font-size:.7rem;letter-spacing:2px;text-transform:uppercase}}
.card .cs{{color:var(--text);font-size:.76rem;margin-top:3px}}
.card.danger{{border-top-color:var(--red)}}.card.danger .cv{{color:var(--red);text-shadow:0 0 6px var(--red)}}
.card.warn{{border-top-color:var(--yellow)}}.card.warn .cv{{color:var(--yellow);text-shadow:0 0 6px var(--yellow)}}
.wrap{{padding:28px}}
.sec{{background:var(--bg2);border:1px solid var(--border);border-radius:3px;margin-bottom:22px;overflow:hidden}}
.sh{{background:var(--bg3);border-bottom:1px solid var(--border);padding:13px 18px;font-family:'Orbitron',monospace;font-size:.78rem;font-weight:700;color:var(--green);letter-spacing:2px;display:flex;align-items:center;gap:10px}}
.sb{{padding:18px}}
.ig{{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:10px}}
.ii{{background:rgba(0,255,65,.03);border:1px solid var(--border);padding:10px 14px;border-radius:2px;border-left:3px solid var(--green)}}
.ii .k{{color:var(--muted);font-size:.68rem;letter-spacing:1px;margin-bottom:3px}}.ii .v{{color:var(--cyan);font-size:.84rem;word-break:break-all}}
table{{width:100%;border-collapse:collapse;font-size:.8rem}}
th{{background:var(--bg3);color:var(--green);padding:9px 13px;text-align:left;letter-spacing:1px;font-size:.7rem;border-bottom:1px solid var(--border)}}
td{{padding:8px 13px;border-bottom:1px solid rgba(26,58,26,.4);color:var(--text)}}
tr:hover td{{background:rgba(0,255,65,.03)}}tr:last-child td{{border-bottom:none}}
.rec-type{{color:var(--cyan);font-weight:700}}
.sub-list{{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:7px;list-style:none}}
.sub-list li{{background:rgba(0,229,255,.04);border:1px solid rgba(0,229,255,.15);border-left:3px solid var(--cyan);padding:7px 11px;font-size:.8rem;color:var(--cyan);border-radius:2px}}
.tag{{display:inline-block;background:rgba(0,255,65,.09);border:1px solid var(--green2);color:var(--green);padding:4px 11px;margin:3px;border-radius:2px;font-size:.75rem;letter-spacing:1px}}
.tag-lib{{background:rgba(0,229,255,.07);border-color:var(--cyan);color:var(--cyan)}}
.tag-an{{background:rgba(255,215,0,.07);border-color:var(--yellow);color:var(--yellow)}}
.score-wrap{{display:flex;align-items:center;gap:28px;flex-wrap:wrap}}
.score-circle{{width:120px;height:120px;border-radius:50%;border:4px solid {gc};box-shadow:0 0 18px {gc},inset 0 0 18px rgba(0,255,65,.04);display:flex;flex-direction:column;align-items:center;justify-content:center;font-family:'Orbitron',monospace;flex-shrink:0}}
.score-circle .gr{{font-size:2.2rem;font-weight:900;color:{gc};text-shadow:0 0 10px {gc}}}.score-circle .pc{{font-size:.72rem;color:var(--muted);margin-top:1px}}
.badge{{display:inline-block;padding:2px 9px;border-radius:2px;font-size:.7rem;font-weight:700;letter-spacing:1px}}
.na{{color:var(--muted);font-style:italic}}.ok-txt{{color:var(--green)}}.danger-txt{{color:var(--red)}}.warn-txt{{color:var(--yellow)}}.muted{{color:var(--muted)}}
.robots{{background:#000;border:1px solid var(--border);padding:12px;border-radius:2px;font-size:.74rem;color:var(--muted);max-height:180px;overflow-y:auto;white-space:pre-wrap;word-break:break-all;margin-top:10px}}
.ftr{{background:#000;border-top:1px solid var(--border);padding:28px;text-align:center}}
.ftr .fl{{font-family:'Orbitron',monospace;color:var(--green);font-size:1rem;font-weight:700;letter-spacing:4px;text-shadow:var(--glow-sm);margin-bottom:6px}}
.ftr p{{color:var(--muted);font-size:.75rem;margin:3px 0}}.ftr .author{{color:var(--cyan)}}
::-webkit-scrollbar{{width:5px}}::-webkit-scrollbar-track{{background:#000}}::-webkit-scrollbar-thumb{{background:var(--green3);border-radius:3px}}::-webkit-scrollbar-thumb:hover{{background:var(--green2)}}
</style></head><body>
<div class="hdr">
  <div class="logo">&#x25C6; WEBSCOPE PRO &#x25C6;</div>
  <div class="tagline">SEE BEYOND THE SURFACE</div>
  <div class="meta-grid">
    <div class="mi"><span class="lbl">TARGET</span><span class="val">{self.target}</span></div>
    <div class="mi"><span class="lbl">DOMAIN</span><span class="val">{self.domain}</span></div>
    <div class="mi"><span class="lbl">IP</span><span class="val">{self.results['ip_info'].get('ip','N/A')}</span></div>
    <div class="mi"><span class="lbl">SCAN TIME</span><span class="val">{self.results['scan_time']}</span></div>
    <div class="mi"><span class="lbl">SSL</span><span class="val">{ssl_txt}</span></div>
    <div class="mi"><span class="lbl">GRADE</span><span class="val" style="color:{gc};text-shadow:0 0 6px {gc}">{grade}</span></div>
  </div>
</div>
<nav class="nav">
  <a href="#sum">SUMMARY</a><a href="#ip">IP/GEO</a><a href="#whois">WHOIS</a>
  <a href="#dns">DNS</a><a href="#tech">TECH</a><a href="#sec">SECURITY</a>
  <a href="#sub">SUBDOMAINS</a><a href="#ports">PORTS</a><a href="#files">FILES</a><a href="#http">HTTP</a>
</nav>
<div class="dash" id="sum">
  <div class="card {'danger' if self.results['exposed_files'] else ''}">
    <div class="cl">SECURITY SCORE</div><div class="cv">{self.results['security'].get('score','N/A')}</div>
    <div class="cs">Grade: <span style="color:{gc}">{grade}</span></div>
  </div>
  <div class="card {'warn' if self.results['subdomains'] else ''}">
    <div class="cl">SUBDOMAINS</div><div class="cv">{len(self.results['subdomains'])}</div><div class="cs">Discovered</div>
  </div>
  <div class="card {'warn' if self.results['ports'] else ''}">
    <div class="cl">OPEN PORTS</div><div class="cv">{len(self.results['ports'])}</div><div class="cs">Detected</div>
  </div>
  <div class="card {'danger' if self.results['exposed_files'] else ''}">
    <div class="cl">EXPOSED FILES</div><div class="cv">{len(self.results['exposed_files'])}</div>
    <div class="cs">{'⚠ Risk Detected' if self.results['exposed_files'] else 'All Clear'}</div>
  </div>
  <div class="card">
    <div class="cl">SEC HEADERS</div>
    <div class="cv">{self.results['security'].get('present_count',0)}<span style="font-size:.9rem;color:var(--muted)">/{self.results['security'].get('total_headers',8)}</span></div>
    <div class="cs">Present</div>
  </div>
  <div class="card">
    <div class="cl">RESPONSE TIME</div>
    <div class="cv" style="font-size:1.5rem">{i.get('response_time','N/A')}<span style="font-size:.85rem;color:var(--muted)">s</span></div>
    <div class="cs">HTTP</div>
  </div>
</div>
<div class="wrap">
  <div class="sec" id="ip"><div class="sh"><span>&#x1F310;</span> IP &amp; GEO-LOCATION</div>
    <div class="sb"><div class="ig">
      <div class="ii"><div class="k">IP ADDRESS</div><div class="v">{self.results['ip_info'].get('ip','N/A')}</div></div>
      <div class="ii"><div class="k">CITY</div><div class="v">{geo.get('city','N/A')}</div></div>
      <div class="ii"><div class="k">REGION</div><div class="v">{geo.get('region','N/A')}</div></div>
      <div class="ii"><div class="k">COUNTRY</div><div class="v">{geo.get('country','N/A')} ({geo.get('country_code','N/A')})</div></div>
      <div class="ii"><div class="k">COORDINATES</div><div class="v">{geo.get('lat','N/A')}, {geo.get('lon','N/A')}</div></div>
      <div class="ii"><div class="k">TIMEZONE</div><div class="v">{geo.get('timezone','N/A')}</div></div>
      <div class="ii"><div class="k">ISP</div><div class="v">{geo.get('isp','N/A')}</div></div>
      <div class="ii"><div class="k">ORGANIZATION</div><div class="v">{geo.get('org','N/A')}</div></div>
      <div class="ii"><div class="k">AS NUMBER</div><div class="v">{geo.get('as','N/A')}</div></div>
    </div></div>
  </div>
  <div class="sec" id="whois"><div class="sh"><span>&#x1F4CB;</span> WHOIS INFORMATION</div>
    <div class="sb"><div class="ig">
      <div class="ii"><div class="k">REGISTRAR</div><div class="v">{self.results['whois'].get('registrar','N/A')}</div></div>
      <div class="ii"><div class="k">CREATED</div><div class="v">{self.results['whois'].get('creation_date','N/A')}</div></div>
      <div class="ii"><div class="k">EXPIRES</div><div class="v">{self.results['whois'].get('expiration_date','N/A')}</div></div>
      <div class="ii"><div class="k">UPDATED</div><div class="v">{self.results['whois'].get('updated_date','N/A')}</div></div>
      <div class="ii"><div class="k">NAME SERVERS</div><div class="v">{"<br>".join(list(self.results['whois'].get('name_servers',[]))[:3]) or 'N/A'}</div></div>
    </div></div>
  </div>
  <div class="sec" id="dns"><div class="sh"><span>&#x1F30D;</span> DNS RECORDS</div>
    <div class="sb"><table><thead><tr><th>TYPE</th><th>RECORDS</th></tr></thead><tbody>{dns_rows}</tbody></table></div>
  </div>
  <div class="sec" id="tech"><div class="sh"><span>&#x1F527;</span> TECHNOLOGY STACK</div><div class="sb">{tech_tags}</div></div>
  <div class="sec" id="sec"><div class="sh"><span>&#x1F512;</span> SECURITY ANALYSIS</div>
    <div class="sb">
      <div class="score-wrap">
        <div class="score-circle"><div class="gr">{grade}</div><div class="pc">{self.results['security'].get('score','N/A')}</div></div>
        <div>
          <p style="font-size:.85rem">{self.results['security'].get('present_count',0)} of {self.results['security'].get('total_headers',8)} security headers present</p>
          <p style="color:var(--muted);font-size:.78rem;margin-top:5px">SSL/TLS: {ssl_txt}</p>
        </div>
      </div>
      <table style="margin-top:18px"><thead><tr><th>HEADER</th><th>VALUE</th><th>STATUS</th></tr></thead>
        <tbody>{present_rows}{missing_rows}</tbody></table>
    </div>
  </div>
  <div class="sec" id="sub"><div class="sh"><span>&#x1F50D;</span> SUBDOMAINS ({len(self.results['subdomains'])})</div>
    <div class="sb"><ul class="sub-list">{sub_items}</ul></div>
  </div>
  <div class="sec" id="ports"><div class="sh"><span>&#x1F513;</span> OPEN PORTS ({len(self.results['ports'])})</div>
    <div class="sb"><table><thead><tr><th>PORT</th><th>SERVICE</th><th>STATE</th></tr></thead><tbody>{port_rows}</tbody></table></div>
  </div>
  <div class="sec" id="files"><div class="sh"><span>&#x26A0;</span> EXPOSED FILES ({len(self.results['exposed_files'])})</div>
    <div class="sb">
      {'<p class="warn-txt" style="margin-bottom:10px;font-size:.8rem">&#x26A0; Warning: Sensitive files are publicly accessible.</p>' if self.results['exposed_files'] else ''}
      <table><thead><tr><th>FILE PATH</th><th>STATUS</th><th>SIZE</th></tr></thead><tbody>{file_rows}</tbody></table>
      {f'<div class="robots"><strong style="color:var(--green)">robots.txt:</strong><br>{self.results["robots_txt"]}</div>' if self.results.get('robots_txt') else ''}
    </div>
  </div>
  <div class="sec" id="http"><div class="sh"><span>&#x1F4E1;</span> HTTP RESPONSE INFO</div>
    <div class="sb"><div class="ig">
      <div class="ii"><div class="k">STATUS</div><div class="v">{i.get('status_code','N/A')} {i.get('status_text','')}</div></div>
      <div class="ii"><div class="k">CONTENT-TYPE</div><div class="v">{i.get('content_type','N/A')}</div></div>
      <div class="ii"><div class="k">RESPONSE TIME</div><div class="v">{i.get('response_time','N/A')}s</div></div>
      <div class="ii"><div class="k">ENCODING</div><div class="v">{i.get('encoding','N/A')}</div></div>
      <div class="ii"><div class="k">COOKIES</div><div class="v">{i.get('cookies',0)}</div></div>
      <div class="ii"><div class="k">REDIRECTS</div><div class="v">{i.get('redirects',0)}</div></div>
      <div class="ii"><div class="k">FINAL URL</div><div class="v">{i.get('final_url','N/A')}</div></div>
      <div class="ii"><div class="k">CONTENT LENGTH</div><div class="v">{i.get('content_length','N/A')}</div></div>
    </div></div>
  </div>
</div>
<div class="ftr">
  <div class="fl">&#x25C6; WEBSCOPE PRO &#x25C6;</div>
  <p>See Beyond The Surface</p>
  <p style="margin-top:7px">By <span class="author">Mughal__Hacker</span> &nbsp;|&nbsp; <span style="color:#2ecc71">RootHackersLab</span> &nbsp;|&nbsp; v2.3</p>
  <p style="margin-top:12px;font-size:.68rem;color:#1e3a1e">
    &#x26A0; For educational and authorized security testing only.<br>
    Always obtain written permission before scanning any target.<br>
    Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
  </p>
</div>
</body></html>"""

        with open(fn, 'w', encoding='utf-8') as f:
            f.write(HTML)
        return fn

    # ── JSON REPORT ───────────────────────────────────────────────────────
    def generate_json_report(self) -> str:
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        fn = f"{self.report_dir}/WebScope_{self.domain.replace('.','_')}_{ts}.json"
        with open(fn, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False, default=str)  # ✅ v2.2: default=str fixes datetime crash
        return fn

    # ── MAIN SCAN ─────────────────────────────────────────────────────────
    def run_scan(self) -> None:
        try:
            # ✅ BUG 7 FIXED: proper subdomain-aware allowlist check
            if not self._domain_allowed(self.domain):
                self._err(f"Target '{self.domain}' not in allowlist. Use --allowlist")
                return

            # ✅ v2.2: Private IP warning
            if self._is_private_ip(self.domain):
                self._wrn("Target resolves to private/internal IP — ensure you have authorization.")

            if self.dry_run:
                self._inf(f"[DRY RUN] Would scan: {self.target}")
                self._inf("[DRY RUN] Modules: WHOIS, DNS, IP, Subdomains, Tech, Security, HTTP, Files, Ports")
                return

            # ✅ Animation only when colors enabled
            if not self.no_color:
                scan_startup_animation(self.target, self.domain)

            self.print_banner()

            logger.info('='*80)
            logger.info(f"Starting WebScope v2.3 scan for: {self.target}")
            logger.info(f"Domain: {self.domain} | SSL verify: {not self.skip_ssl}")
            logger.info('='*80)

            t0 = time.time()

            self.whois_lookup()
            self.dns_lookup()
            self.ip_information()
            self.subdomain_enum()
            self.technology_detection()
            self.security_analysis()
            self.http_analysis()
            self.check_exposed_files()
            self.port_scan()

            elapsed = time.time() - t0

            print(f"\n  {self.Y}{'─'*66}{self.R}")
            print(f"  {self.WB}Generating Reports …{self.R}")

            if self.output in ('html','both'):
                hf = self.generate_html_report()
                self._ok(f"HTML  →  {hf}")

            if self.output in ('json','both'):
                jf = self.generate_json_report()
                self._ok(f"JSON  →  {jf}")

            sec = self.results['security']
            exp = len(self.results['exposed_files'])
            print(f"""
{self.G}{'═'*68}
  ✓  SCAN COMPLETE  —  {elapsed:.1f}s
{'═'*68}{self.R}
  {self.W}Security Score  {self.G}{sec.get('score','N/A')}{self.R}  Grade {self.G}{sec.get('grade','F')}{self.R}
  {self.W}Subdomains      {self.C}{len(self.results['subdomains'])}{self.R}
  {self.W}Open Ports      {self.C}{len(self.results['ports'])}{self.R}
  {self.W}Exposed Files   {self.RE if exp>0 else self.G}{exp}{self.R}
  {self.W}Sec Headers     {self.C}{sec.get('present_count',0)}/{sec.get('total_headers',8)}{self.R}
  {self.Y}Open HTML report in browser for full hacker-style view!{self.R}
{self.G}{'═'*68}{self.R}
""")
        except KeyboardInterrupt:
            print(f"\n\n  {self.RE}[!] Interrupted by user{self.R}")
            sys.exit(0)
        except Exception as e:
            print(f"\n  {self.RE}[!] Critical error: {e}{self.R}")
            import traceback; traceback.print_exc()
            logger.exception("Critical error during scan")


# ── CLI ENTRY POINT ────────────────────────────────────────────────────────
def main() -> None:
    p = argparse.ArgumentParser(
        description='WebScope Pro v2.3 — Merged + All Bugs Fixed',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com
  %(prog)s https://target.com -o json --skip-ssl
  %(prog)s example.com --no-color -o json | tee scan.log
  %(prog)s example.com --dry-run
  %(prog)s sub.example.com --allowlist example.com

⚠  Only scan systems you own or have explicit written permission to test.
        """
    )
    p.add_argument('target',   nargs='?',  help='Target URL or domain')
    p.add_argument('-o','--output', choices=['html','json','both'], default='both')
    p.add_argument('-v','--verbose', action='store_true')
    p.add_argument('--skip-ssl',  action='store_true', help='Skip SSL verification')
    p.add_argument('--no-color',  action='store_true', help='Disable colored output')
    p.add_argument('--allowlist', nargs='+', metavar='DOMAIN', help='Restrict to these domains')
    p.add_argument('--dry-run',   action='store_true', help='Preview scan without executing')
    args = p.parse_args()

    if not args.target:
        os.system('cls' if os.name == 'nt' else 'clear')
        if not args.no_color:
            _print_menu_header()

        while True:
            target = input(f"\n  {Fore.YELLOW}[?]{Style.RESET_ALL} Target URL or domain: ").strip()
            if not target:
                print(f"  {Fore.RED}[-]{Style.RESET_ALL} Please enter a valid target"); continue

            fmt = _pick_output_format()           # ✅ Numbered [1/2/3] menu

            if _confirm_scan(target, fmt):        # ✅ Numbered [1/2] confirm
                args.target = target
                args.output = fmt
                break
            else:
                print(f"  {Fore.RED}[-]{Style.RESET_ALL} Scan cancelled.")
                sys.exit(0)

    WebScopePro(
        target   = args.target,
        verbose  = args.verbose,
        output   = args.output,
        skip_ssl = args.skip_ssl,
        no_color = args.no_color,
        allowlist= args.allowlist,
        dry_run  = args.dry_run,
    ).run_scan()

if __name__ == '__main__':
    main()
