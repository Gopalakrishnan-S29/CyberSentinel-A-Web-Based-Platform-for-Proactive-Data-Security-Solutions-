# tools/bannerhunter.py
import socket
from datetime import datetime
from typing import List, Dict, Any, Optional
import re

from packaging.version import parse as parse_version  # pip install packaging

DEFAULT_PORTS = [21, 22, 23, 25, 80, 110, 143, 443, 3306, 5432]
DEFAULT_TIMEOUT = 2.5
MAX_READ = 1500
MAX_PORTS = 20

FINGERPRINTS = [
    (re.compile(r"Apache/?\s*([0-9]+\.[0-9]+\.[0-9]+)"), ("Apache HTTPD", 1, "2.4.49")),
    (re.compile(r"nginx/?\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)"), ("nginx", 1, "1.19.0")),
    (re.compile(r"OpenSSH[_-]?([0-9]+\.[0-9]+(?:p[0-9]+)?)"), ("OpenSSH", 1, "7.6")),
    (re.compile(r"vsftpd/?\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)"), ("vsftpd", 1, "3.0.3")),
    (re.compile(r"Exim\s+([0-9]+\.[0-9]+)"), ("Exim", 1, "4.92")),
    (re.compile(r"Microsoft-IIS/?\s*([0-9]+\.[0-9]+)"), ("Microsoft IIS", 1, None)),
    (re.compile(r"Apache-Coyote/([0-9]+\.[0-9]+)"), ("Apache Tomcat (Coyote)", 1, None)),
    (re.compile(r"mysql.*?Ver\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.I), ("MySQL", 1, "5.7")),
    (re.compile(r"PostgreSQL.*?([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.I), ("PostgreSQL", 1, "9.6")),
]


def _sanitize_ports(port_list: Optional[List[int]]) -> List[int]:
    if not port_list:
        return DEFAULT_PORTS.copy()
    cleaned = []
    for p in port_list:
        try:
            pi = int(p)
            if 1 <= pi <= 65535:
                cleaned.append(pi)
        except Exception:
            continue
        if len(cleaned) >= MAX_PORTS:
            break
    return cleaned or DEFAULT_PORTS.copy()


class BannerHunter:
    def __init__(self, target: str, ports: Optional[List[int]] = None, timeout: float = DEFAULT_TIMEOUT):
        self.target = target.strip()
        self.timeout = float(timeout)
        self.ports = _sanitize_ports(ports)

    def _looks_like_ip(self, s: str) -> bool:
        try:
            socket.inet_aton(s)
            return True
        except Exception:
            return False

    def resolve(self) -> Dict[str, Any]:
        if self._looks_like_ip(self.target):
            return {"hostname": self.target, "ips": [self.target], "aliases": []}
        try:
            hostname, aliases, ips = socket.gethostbyname_ex(self.target)
            return {"hostname": hostname, "aliases": aliases, "ips": ips}
        except Exception as e:
            return {"error": f"DNS resolution failed: {e}"}

    def _gentle_probe(self, s: socket.socket, port: int):
        try:
            if port in (80, 8080, 8000, 8888):
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: example\r\n\r\n")
            elif port in (25, 587, 110, 143):
                s.sendall(b"\r\n")
            else:
                s.sendall(b"\r\n")
        except Exception:
            pass

    def grab_banner(self, ip: str, port: int) -> Dict[str, Any]:
        res = {"ip": ip, "port": port, "success": False, "raw": "", "product": None, "version": None, "risk": "unknown", "error": None}
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((ip, port))

                try:
                    data = s.recv(MAX_READ)
                except socket.timeout:
                    data = b""
                except Exception:
                    data = b""

                if not data:
                    try:
                        self._gentle_probe(s, port)
                        data = s.recv(MAX_READ)
                    except Exception:
                        data = b""

                raw = data.decode(errors="replace").strip() if data else ""
                res["raw"] = raw
                res["success"] = True

                if raw:
                    product, version, risk = self._fingerprint(raw)
                    res["product"] = product
                    res["version"] = version
                    res["risk"] = risk
                else:
                    res["product"] = None
                    res["version"] = None
                    res["risk"] = "unknown"

                return res

        except Exception as e:
            res["error"] = str(e)
            return res

    def _fingerprint(self, banner: str):
        banner_clean = banner.strip()
        for patt, (product_name, ver_group, threshold) in FINGERPRINTS:
            m = patt.search(banner_clean)
            if m:
                try:
                    version_raw = m.group(ver_group)
                except Exception:
                    try:
                        version_raw = m.group(1)
                    except Exception:
                        version_raw = None
                if version_raw:
                    ver_norm = re.sub(r"[^0-9\.]", "", version_raw)
                    risk = "unknown"
                    if threshold:
                        try:
                            if parse_version(ver_norm) <= parse_version(str(threshold)):
                                risk = "potentially_outdated"
                            else:
                                risk = "ok"
                        except Exception:
                            risk = "unknown"
                    else:
                        risk = "unknown"
                    return product_name, ver_norm, risk
                else:
                    return product_name, None, "unknown"
        return None, None, "unknown"

    def scan(self) -> Dict[str, Any]:
        out = {"target": self.target, "scanned_at": datetime.utcnow().isoformat() + "Z", "dns": None, "entries": []}
        resolved = self.resolve()
        out["dns"] = resolved
        ip_list = []
        if isinstance(resolved, dict) and resolved.get("ips"):
            ip_list = resolved["ips"]
        elif isinstance(resolved, dict) and resolved.get("error"):
            ip_list = [self.target] if self._looks_like_ip(self.target) else []

        if not ip_list:
            out["note"] = "no-resolvable-ip"
            return out

        for ip in ip_list:
            for port in self.ports:
                e = self.grab_banner(ip, port)
                out["entries"].append(e)

        return out
