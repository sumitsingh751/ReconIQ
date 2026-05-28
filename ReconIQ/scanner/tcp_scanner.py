import socket
import logging
import concurrent.futures
import datetime
from typing import List, Dict

logger = logging.getLogger("RECONIQ.TCPScanner")

SERVICE_MAP = {
    20: "FTP-Data", 21: "FTP",
    22: "SSH", 23: "Telnet",
    25: "SMTP", 110: "POP3", 143: "IMAP", 465: "SMTPS",
    587: "SMTP-Submit", 993: "IMAPS", 995: "POP3S",
    53: "DNS",
    80: "HTTP", 443: "HTTPS", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 8000: "HTTP-Dev", 8888: "HTTP-Dev",
    3000: "HTTP-Dev", 5000: "HTTP-Dev",
    135: "RPC", 137: "NetBIOS-NS", 138: "NetBIOS-DG",
    139: "NetBIOS-SSN", 445: "SMB", 3389: "RDP",
    1433: "MSSQL", 1434: "MSSQL-Monitor",
    3306: "MySQL", 5432: "PostgreSQL",
    6379: "Redis", 27017: "MongoDB", 27018: "MongoDB",
    5984: "CouchDB", 9200: "Elasticsearch", 9300: "Elasticsearch",
    5900: "VNC", 5901: "VNC-1", 5902: "VNC-2",
    111: "RPC-Portmap", 512: "Rexec", 513: "Rlogin",
    514: "RSH/Syslog", 515: "LPD-Print",
    2049: "NFS", 4045: "NFS-Lockd",
    79: "Finger", 113: "Ident",
    119: "NNTP", 123: "NTP",
    161: "SNMP", 162: "SNMP-Trap",
    389: "LDAP", 636: "LDAPS",
    1099: "Java-RMI", 4848: "GlassFish",
    8009: "AJP", 8080: "Tomcat", 8181: "GlassFish",
    5672: "RabbitMQ", 15672: "RabbitMQ-Mgmt",
    9092: "Kafka", 2181: "Zookeeper",
    2375: "Docker", 2376: "Docker-TLS",
    6443: "Kubernetes-API", 10250: "Kubelet",
    500: "IKE-VPN", 1194: "OpenVPN",
    1723: "PPTP", 4500: "IPSec-NAT",
    4444: "Metasploit", 1524: "Ingreslock-Backdoor",
    6200: "Bindshell", 31337: "BackOrifice",
    631: "IPP-Print", 873: "Rsync",
    3128: "Squid-Proxy", 8118: "Privoxy",
    9050: "Tor-SOCKS", 1080: "SOCKS-Proxy",
}

RISK_MAP = {
    "CRITICAL": {21, 23, 512, 513, 514, 1524, 4444, 6200, 31337, 1099},
    "HIGH":     {25, 53, 111, 135, 137, 138, 139, 445, 1433, 3306,
                 5432, 5900, 3389, 27017, 6379, 2049, 2375, 2376},
    "MEDIUM":   {22, 80, 110, 143, 161, 389, 443, 873, 1080, 3128,
                 5672, 8080, 9200, 9092},
    "LOW":      {8443, 8000, 8888, 3000, 5000, 993, 995, 465, 587},
}

def get_risk_level(port: int) -> str:
    for level, ports in RISK_MAP.items():
        if port in ports:
            return level
    return "INFO"

class TCPScanner:
    def __init__(self, timeout: float = 2.0, max_threads: int = 150):
        self.timeout = timeout
        self.max_threads = max_threads
        self.logger = logging.getLogger("RECONIQ.TCPScanner")

    def _scan_port(self, target: str, port: int) -> Dict:
        result = {
            "port": port,
            "state": "closed",
            "service": SERVICE_MAP.get(port, "unknown"),
            "risk": get_risk_level(port),
            "response_time_ms": None,
            "scanned_at": datetime.datetime.utcnow().isoformat()
        }
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            start = datetime.datetime.utcnow()
            connection = sock.connect_ex((target, port))
            elapsed = (datetime.datetime.utcnow() - start).total_seconds() * 1000
            result["response_time_ms"] = round(elapsed, 2)

            if connection == 0:
                result["state"] = "open"
                self.logger.debug(f"Port {port} OPEN on {target} ({result['service']})")
            else:
                result["state"] = "closed"
            sock.close()

        except socket.timeout:
            result["state"] = "filtered"
            result["note"] = "Timeout — firewall may be dropping packets"
        except socket.gaierror:
            result["state"] = "error"
            result["note"] = "DNS resolution failed"
        except OSError as e:
            result["state"] = "error"
            result["note"] = str(e)
        return result

    def scan(self, target: str, ports: List[int]) -> List[Dict]:
        self.logger.info(
            f"TCP scan → {target} | {len(ports)} ports | "
            f"threads={self.max_threads} | timeout={self.timeout}s"
        )
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {
                executor.submit(self._scan_port, target, port): port
                for port in ports
            }
            for future in concurrent.futures.as_completed(futures):
                try:
                    results.append(future.result())
                except Exception as e:
                    self.logger.error(f"Thread error: {e}")

        results.sort(key=lambda x: x["port"])
        open_count = sum(1 for r in results if r["state"] == "open")
        filtered_count = sum(1 for r in results if r["state"] == "filtered")
        self.logger.info(
            f"TCP scan complete → {open_count} open, {filtered_count} filtered"
        )
        return results
