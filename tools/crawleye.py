# tools/crawleye.py
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from collections import deque

COMMON_SENSITIVE_PATHS = [
    "/admin",
    "/admin_old",
    "/login",
    "/dashboard",
    "/backup",
    "/backup.zip",
    "/config.php",
    "/config.php~",
    "/.git",
    "/test",
    "/uploads",
]


class CrawlEye:
    def __init__(self, base_url, max_pages=50):
        if not base_url.startswith("http"):
            base_url = "http://" + base_url

        self.base_url = base_url.rstrip("/")
        self.domain = urlparse(self.base_url).netloc
        self.max_pages = max_pages

        self.visited = set()
        self.queue = deque([self.base_url])
        self.discovered = set()

        self.robots_paths = []
        self.sitemap_urls = []
        self.sensitive_hits = []

    # ================= ROBOTS.TXT =================
    def parse_robots(self):
        robots_url = urljoin(self.base_url, "/robots.txt")
        try:
            r = requests.get(robots_url, timeout=5)
            if r.status_code == 200:
                for line in r.text.splitlines():
                    if line.lower().startswith("disallow"):
                        path = line.split(":")[1].strip()
                        if path:
                            self.robots_paths.append(path)
        except Exception:
            pass

    # ================= SITEMAP.XML =================
    def parse_sitemap(self):
        sitemap_url = urljoin(self.base_url, "/sitemap.xml")
        try:
            r = requests.get(sitemap_url, timeout=5)
            if r.status_code == 200 and "<urlset" in r.text:
                soup = BeautifulSoup(r.text, "xml")
                for loc in soup.find_all("loc"):
                    self.sitemap_urls.append(loc.text.strip())
        except Exception:
            pass

    # ================= SENSITIVE PATHS =================
    def check_sensitive_paths(self):
        for path in COMMON_SENSITIVE_PATHS:
            full = self.base_url + path
            try:
                r = requests.get(full, timeout=4)
                if r.status_code in (200, 401, 403):
                    self.sensitive_hits.append({
                        "path": path,
                        "status": r.status_code
                    })
            except Exception:
                pass

    # ================= PAGE CRAWLING =================
    def crawl(self):
        self.parse_robots()
        self.parse_sitemap()
        self.check_sensitive_paths()

        while self.queue and len(self.visited) < self.max_pages:
            current = self.queue.popleft()
            if current in self.visited:
                continue

            try:
                r = requests.get(current, timeout=5)
                if r.status_code != 200:
                    continue
            except Exception:
                continue

            self.visited.add(current)
            self.discovered.add(current)

            soup = BeautifulSoup(r.text, "html.parser")

            for a in soup.find_all("a", href=True):
                href = a["href"]
                url = urljoin(current, href)
                parsed = urlparse(url)

                if parsed.netloc == self.domain:
                    clean = parsed.scheme + "://" + parsed.netloc + parsed.path
                    if clean not in self.visited:
                        self.queue.append(clean)

        return {
            "base_url": self.base_url,
            "total_pages": len(self.discovered),
            "urls": sorted(self.discovered),
            "robots": sorted(set(self.robots_paths)),
            "sitemap": sorted(set(self.sitemap_urls)),
            "sensitive": self.sensitive_hits
        }
