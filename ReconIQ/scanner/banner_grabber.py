import socket
import logging
import datetime
import concurrent.futures
import re
from typing import List, Dict

logger = logging.getLogger("RECONIQ.BannerGrabber")

SERVICE_PROBES = {
    21:    b"",
    22:    b"",
    23:    b"",
    25:    b"EHLO reconiq\r\n",
    80:    b"HEAD / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n",
    110:   b"",
    143:   b"",
    443:   b"HEAD / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n",
    445:   b"",
    3306:  b"",
    5432:  b"",
    6379:  b"INFO\r\n",
    8080:  b"HEAD / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n",
    8443:  b"HEAD / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n",
    9200:  b"GET / HTTP/1.0\r\n\r\n",
    27017: b"",
}

VERSION_PATTERNS = {
    "SSH":        r"SSH-[\d.]+-([^\s\r\n]+)",
    "Apache":     r"Apache/([\d.]+)",
    "nginx":      r"nginx/([\d.]+)",
    "OpenSSH":    r"OpenSSH_([\d.]+)",
    "MySQL":      r"([\d.]+)-MariaDB|mysql_native|[\x00-\xff]{4}([\d.]+)",
    "FTP":        r"(vsFTPd|ProFTPD|FileZilla)[^\r\n]*([\d.]+)?",
    "Postfix":    r"Postfix",
    "Exim":       r"Exim ([\d.]+)",
    "Redis":      r"redis_version:([\d.]+)",
    "Elasticsearch": r'"version"\s*:\s*\{[^}]*"number"\s*:\s*"([^\"]+)"',
}

class BannerGrabber:
    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout
        self.logger = logging.getLogger("RECONIQ.BannerGrabber")

    def grab(self, target: str, port: int) -> Dict:
        result = {
            "port": port,
            "banner": None,
            "service": None,
            "version": None,
            "raw_banner": None,
            "grabbed_at": datetime.datetime.utcnow().isoformat()
        }
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            sock.settimeout(2.0)
            try:
                initial = sock.recv(1024)
                if initial:
                    result["raw_banner"] = initial.decode(errors="ignore").strip()
            except socket.timeout:
                pass

            probe = SERVICE_PROBES.get(port, b"HEAD / HTTP/1.0\r\n\r\n")
            if probe and not result["raw_banner"]:
                sock.sendall(probe)
                sock.settimeout(self.timeout)
                try:
                    data = sock.recv(2048)
                    if data:
                        result["raw_banner"] = data.decode(errors="ignore").strip()
                except socket.timeout:
                    pass

            sock.close()

            if result["raw_banner"]:
                banner = result["raw_banner"][:500]
                result["banner"] = banner
                result["service"] = self._identify_service(banner, port)
                result["version"] = self._extract_version(banner)
                self.logger.info(
                    f"Port {port} → {result['service']} "
                    f"v{result['version'] or 'unknown'}"
                )
            else:
                result["banner"] = "No banner received"

        except socket.timeout:
            result["banner"] = "Timeout"
        except ConnectionRefusedError:
            result["banner"] = "Connection refused"
        except Exception as e:
            result["banner"] = f"Error: {str(e)}"

        return result

    def _identify_service(self, banner: str, port: int) -> str:
        b = banner.lower()
        checks = [
            ("ssh",        "SSH"),
            ("openssh",    "OpenSSH"),
            ("http/",      "HTTP"),
            ("html",       "HTTP"),
            ("nginx",      "nginx"),
            ("apache",     "Apache"),
            ("iis",        "IIS"),
            ("ftp",        "FTP"),
            ("vsftpd",     "vsFTPd"),
            ("proftpd",    "ProFTPD"),
            ("smtp",       "SMTP"),
            ("postfix",    "Postfix"),
            ("exim",       "Exim"),
            ("pop3",       "POP3"),
            ("imap",       "IMAP"),
            ("mysql",      "MySQL"),
            ("mariadb",    "MariaDB"),
            ("postgresql", "PostgreSQL"),
            ("redis",      "Redis"),
            ("mongodb",    "MongoDB"),
            ("elasticsearch", "Elasticsearch"),
        ]
        for keyword, name in checks:
            if keyword in b:
                return name
        from scanner.tcp_scanner import SERVICE_MAP
        return SERVICE_MAP.get(port, "Unknown")

    def _extract_version(self, banner: str) -> str:
        for svc, pattern in VERSION_PATTERNS.items():
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                groups = [g for g in match.groups() if g]
                if groups:
                    return groups[0]
        match = re.search(r"([\d]+\.[\d]+\.[\d]+)", banner)
        if match:
            return match.group(1)
        return None

    def grab_multiple(self, target: str, ports: List[int]) -> List[Dict]:
        self.logger.info(f"Banner grabbing {len(ports)} ports on {target}")
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = {
                executor.submit(self.grab, target, port): port
                for port in ports
            }
            for future in concurrent.futures.as_completed(futures):
                try:
                    results.append(future.result())
                except Exception as e:
                    self.logger.error(f"Banner grab error: {e}")
        results.sort(key=lambda x: x["port"])
        return results
