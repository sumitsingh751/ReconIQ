import os
import sys
import socket
import logging
import datetime
import contextlib
from typing import Dict, List

logging.getLogger("scapy").setLevel(logging.CRITICAL)
logging.getLogger("scapy.runtime").setLevel(logging.CRITICAL)

@contextlib.contextmanager
def suppress_output():
    with open(os.devnull, 'w') as devnull:
        old_stderr = sys.stderr
        try:
            sys.stderr = devnull
            yield
        finally:
            sys.stderr = old_stderr

from scapy.all import IP, ICMP, TCP, sr1, RandShort, conf
conf.verb = 0

logger = logging.getLogger("RECONIQ.OSFingerprint")

INITIAL_TTL_MAP = [
    (32,  "Windows 9x / ME"),
    (64,  "Linux / macOS / FreeBSD / iOS / Android"),
    (128, "Windows NT/XP/Vista/7/8/10/11"),
    (255, "Cisco IOS / Solaris / AIX / HP-UX"),
]

WINDOW_OS_MAP = {
    65535: "macOS / FreeBSD / NetBSD",
    8192:  "Windows Vista / 7 / Server 2008",
    64240: "Linux Kernel 4.x / 5.x",
    29200: "Linux Kernel 3.x",
    14600: "Linux Kernel 2.6",
    5840:  "Linux Kernel 2.4",
    65392: "Cisco IOS",
    16384: "OpenBSD",
    32768: "Linux / Solaris",
    65160: "Linux Kernel 5.x (newer)",
}

WINDOWS_PORTS  = {135, 139, 445, 3389, 1433, 5985}
LINUX_PORTS    = {22, 111, 2049, 512, 513, 514}
NETWORK_PORTS  = {161, 162, 23, 179}

BANNER_OS_SIGNATURES = {
    "windows": ["microsoft", "iis", "windows", "win32", "ntlm", "ms-sql"],
    "linux":   ["ubuntu", "debian", "centos", "fedora", "redhat", "linux",
                "apache", "nginx", "openssh", "vsftpd", "postfix"],
    "cisco":   ["cisco", "ios", "catalyst"],
    "freebsd": ["freebsd", "netbsd", "openbsd"],
}

class OSFingerprint:
    def __init__(self, timeout: float = 2.0):
        self.timeout = timeout
        self.logger = logging.getLogger("RECONIQ.OSFingerprint")

    def _is_localhost(self, target: str) -> bool:
        try:
            resolved = socket.gethostbyname(target)
            return resolved in ("127.0.0.1", "::1", "0.0.0.0") or resolved.startswith("127.")
        except Exception:
            return target in ("localhost", "127.0.0.1", "::1")

    def _normalize_ttl(self, ttl: int) -> int:
        for initial in [32, 64, 128, 255]:
            if ttl <= initial:
                return initial
        return 255

    def _ttl_to_os(self, ttl: int) -> str:
        normalized = self._normalize_ttl(ttl)
        for threshold, os_name in INITIAL_TTL_MAP:
            if normalized <= threshold:
                return os_name
        return "Unknown"

    def _window_to_os(self, window: int) -> str:
        if window in WINDOW_OS_MAP:
            return WINDOW_OS_MAP[window]
        closest = min(WINDOW_OS_MAP.keys(), key=lambda x: abs(x - window))
        if abs(closest - window) < 2000:
            return f"{WINDOW_OS_MAP[closest]} (approx)"
        return f"Unknown ({window})"

    def _icmp_probe(self, target: str) -> dict:
        result = {"ttl": None, "os_hint": None}
        try:
            pkt = IP(dst=target) / ICMP()
            with suppress_output():
                resp = sr1(pkt, timeout=self.timeout, verbose=0)
            if resp and resp.haslayer(IP):
                ttl = resp[IP].ttl
                result["ttl"] = ttl
                result["normalized_ttl"] = self._normalize_ttl(ttl)
                result["os_hint"] = self._ttl_to_os(ttl)
        except Exception as e:
            self.logger.debug(f"ICMP probe failed: {e}")
        return result

    def _socket_ttl_probe(self, target: str, port: int) -> dict:
        result = {"ttl": None, "os_hint": None}
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 64)
            conn = sock.connect_ex((target, port))
            if conn == 0:
                try:
                    ttl = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
                    result["ttl"] = ttl
                    result["normalized_ttl"] = self._normalize_ttl(ttl)
                    result["os_hint"] = self._ttl_to_os(ttl)
                except Exception:
                    pass
            sock.close()
        except Exception as e:
            self.logger.debug(f"Socket TTL probe failed: {e}")
        return result

    def _tcp_syn_probe(self, target: str, port: int) -> dict:
        result = {"window_size": None, "os_hint": None, "mss": None,
                  "wscale": None, "timestamp": False, "sack": False}
        try:
            pkt = IP(dst=target) / TCP(
                sport=RandShort(), dport=port, flags="S",
                options=[("MSS", 1460), ("SAckOK", b""),
                         ("Timestamp", (0, 0)), ("NOP", None), ("WScale", 6)]
            )
            with suppress_output():
                resp = sr1(pkt, timeout=self.timeout, verbose=0)
            if resp and resp.haslayer(TCP):
                flags = resp[TCP].flags
                if flags in (0x12, 0x14, 0x04):
                    window = resp[TCP].window
                    result["window_size"] = window
                    result["os_hint"] = self._window_to_os(window)
                    for opt in resp[TCP].options:
                        if isinstance(opt, tuple):
                            if opt[0] == "MSS":       result["mss"] = opt[1]
                            elif opt[0] == "WScale":  result["wscale"] = opt[1]
                            elif opt[0] == "Timestamp": result["timestamp"] = True
                            elif opt[0] == "SAckOK":  result["sack"] = True
                    rst = IP(dst=target)/TCP(sport=pkt[TCP].sport, dport=port, flags="R")
                    with suppress_output():
                        sr1(rst, timeout=1, verbose=0)
        except Exception as e:
            self.logger.debug(f"TCP SYN probe port {port} failed: {e}")
        return result

    def _port_signature_detect(self, open_ports: List[int]) -> dict:
        result = {"os_hint": None, "evidence": []}
        if not open_ports:
            return result
        port_set = set(open_ports)

        windows_score = len(port_set & WINDOWS_PORTS)
        linux_score   = len(port_set & LINUX_PORTS)
        network_score = len(port_set & NETWORK_PORTS)

        if windows_score > 0:
            matched = port_set & WINDOWS_PORTS
            result["os_hint"] = "Windows NT/XP/Vista/7/8/10/11"
            result["evidence"].append(
                f"Windows port signatures found: {sorted(matched)} "
                f"(RPC/SMB/RDP/MSSQL)"
            )
        elif linux_score > 0:
            matched = port_set & LINUX_PORTS
            result["os_hint"] = "Linux / macOS / FreeBSD / iOS / Android"
            result["evidence"].append(
                f"Linux port signatures found: {sorted(matched)} "
                f"(SSH/NFS/RPC)"
            )
        elif network_score > 0:
            result["os_hint"] = "Cisco IOS / Solaris / AIX / HP-UX"
            result["evidence"].append("Network device port signatures found")

        return result

    def _banner_detect(self, banners: list) -> dict:
        result = {"os_hint": None, "evidence": []}
        if not banners:
            return result

        all_banners = " ".join(
            (b.get("banner", "") or "") + " " + (b.get("service", "") or "")
            for b in banners
        ).lower()

        scores = {}
        for os_name, keywords in BANNER_OS_SIGNATURES.items():
            score = sum(1 for kw in keywords if kw in all_banners)
            if score > 0:
                scores[os_name] = score

        if scores:
            winner = max(scores, key=scores.get)
            os_map = {
                "windows": "Windows NT/XP/Vista/7/8/10/11",
                "linux":   "Linux / macOS / FreeBSD / iOS / Android",
                "cisco":   "Cisco IOS / Solaris / AIX / HP-UX",
                "freebsd": "macOS / FreeBSD / NetBSD",
            }
            result["os_hint"] = os_map.get(winner, winner)
            result["evidence"].append(
                f"Banner analysis → {winner.upper()} signatures detected"
            )

        return result

    def _localhost_detect(self) -> dict:
        import platform
        system = platform.system()
        version = platform.version()
        machine = platform.machine()
        os_map = {
            "Windows": "Windows NT/XP/Vista/7/8/10/11",
            "Linux":   "Linux / macOS / FreeBSD / iOS / Android",
            "Darwin":  "macOS / FreeBSD / NetBSD",
        }
        detected = os_map.get(system, system)
        return {
            "os_hint": detected,
            "evidence": [
                f"Localhost detected → {system} {version} ({machine})"
            ],
            "ttl": 128 if system == "Windows" else 64,
            "confidence_boost": 40
        }

    def _combine_evidence(self, probes: list) -> dict:
        votes = {}
        evidence = []

        for probe in probes:
            if not probe:
                continue
            hint = probe.get("os_hint")
            weight = probe.get("weight", 1)
            boost = probe.get("confidence_boost", 0)

            if hint:
                votes[hint] = votes.get(hint, 0) + weight + boost
            evidence.extend(probe.get("evidence", []))

            if probe.get("ttl"):
                ttl = probe["ttl"]
                norm = probe.get("normalized_ttl", self._normalize_ttl(ttl))
                evidence.append(f"TTL={ttl} (normalized→{norm})")

            if probe.get("window_size"):
                evidence.append(
                    f"TCP Window={probe['window_size']} → {probe.get('os_hint','?')}"
                )

            if probe.get("timestamp") and probe.get("sack"):
                votes["Linux / macOS / FreeBSD / iOS / Android"] = \
                    votes.get("Linux / macOS / FreeBSD / iOS / Android", 0) + 2
                evidence.append("TCP options: Timestamp+SACK → Linux pattern")
            if probe.get("mss") == 1460:
                evidence.append("MSS=1460 (standard Ethernet MTU)")

        if votes:
            winner = max(votes, key=votes.get)
            total  = sum(votes.values())
            pct    = min(int((votes[winner] / total) * 100), 95) if total else 0
            level  = "HIGH" if pct >= 70 else "MEDIUM" if pct >= 40 else "LOW"
            return {
                "os_detected": winner,
                "confidence_level": level,
                "confidence_percent": pct,
                "votes": votes,
                "evidence": list(dict.fromkeys(evidence))
            }

        return {
            "os_detected": "Unknown",
            "confidence_level": "LOW",
            "confidence_percent": 0,
            "votes": {},
            "evidence": evidence or ["Insufficient data"]
        }

    def detect(self, target: str,
               open_ports: List[int] = None,
               banners: list = None) -> dict:

        result = {
            "host": target,
            "os_detected": "Unknown",
            "confidence_level": "LOW",
            "confidence_percent": 0,
            "ttl": None,
            "normalized_ttl": None,
            "window_size": None,
            "tcp_options": None,
            "mss": None,
            "wscale": None,
            "timestamp_support": False,
            "sack_support": False,
            "evidence": [],
            "probes_run": [],
            "timestamp": datetime.datetime.utcnow().isoformat()
        }

        self.logger.info(f"OS detection → {target}")
        all_probes = []

        if self._is_localhost(target):
            self.logger.info("Localhost detected — using platform detection")
            local = self._localhost_detect()
            local["weight"] = 5
            all_probes.append(local)
            result["probes_run"].append("Platform Detection (localhost)")
            result["ttl"] = local.get("ttl")
            result["normalized_ttl"] = local.get("ttl")

        else:
            icmp = self._icmp_probe(target)
            icmp["weight"] = 2
            all_probes.append(icmp)
            result["probes_run"].append("ICMP TTL")
            if icmp.get("ttl"):
                result["ttl"] = icmp["ttl"]
                result["normalized_ttl"] = icmp.get("normalized_ttl")

            probe_ports = list(dict.fromkeys(
                (open_ports or [])[:3] + [80, 443, 22, 135, 8080]
            ))[:5]

            for port in probe_ports:
                tcp = self._tcp_syn_probe(target, port)
                if tcp.get("window_size"):
                    tcp["weight"] = 3
                    all_probes.append(tcp)
                    result["probes_run"].append(f"TCP SYN port {port}")
                    if not result["window_size"]:
                        result["window_size"]       = tcp["window_size"]
                        result["mss"]               = tcp.get("mss")
                        result["wscale"]            = tcp.get("wscale")
                        result["timestamp_support"] = tcp.get("timestamp", False)
                        result["sack_support"]      = tcp.get("sack", False)

        if open_ports:
            port_sig = self._port_signature_detect(open_ports)
            if port_sig.get("os_hint"):
                port_sig["weight"] = 3
                all_probes.append(port_sig)
                result["probes_run"].append("Port Signatures")

        if banners:
            banner_sig = self._banner_detect(banners)
            if banner_sig.get("os_hint"):
                banner_sig["weight"] = 2
                all_probes.append(banner_sig)
                result["probes_run"].append("Banner Analysis")

        combined = self._combine_evidence(all_probes)
        result.update(combined)

        self.logger.info(
            f"OS result → {result['os_detected']} "
            f"({result['confidence_level']} {result['confidence_percent']}%)\n"
        )
        return result