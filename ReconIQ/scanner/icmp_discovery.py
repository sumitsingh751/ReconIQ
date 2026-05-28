import os
import sys
import socket
import logging
import datetime
import contextlib

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

TCP_FALLBACK_PORTS = [80, 443, 22, 135, 445, 8080, 3389, 21]

class ICMPDiscovery:
    def __init__(self, timeout: float = 2.0, retries: int = 2):
        self.timeout = timeout
        self.retries = retries
        self.logger = logging.getLogger("RECONIQ.ICMPDiscovery")

    def _is_localhost(self, target: str) -> bool:
        try:
            resolved = socket.gethostbyname(target)
            return resolved.startswith("127.") or resolved == "::1"
        except Exception:
            return target in ("localhost", "127.0.0.1", "::1")

    def _localhost_ping(self, target: str) -> dict:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            start = datetime.datetime.utcnow()
            sock.connect_ex(("127.0.0.1", 135))
            elapsed = (datetime.datetime.utcnow() - start).total_seconds() * 1000
            sock.close()
        except Exception:
            elapsed = 0.1
        return {
            "is_up": True,
            "method": "Localhost (loopback)",
            "ttl": 128,
            "latency_ms": round(elapsed, 2),
            "adaptive_note": "Target is localhost — using direct platform detection."
        }

    def _icmp_ping(self, target: str) -> dict:
        for attempt in range(1, self.retries + 1):
            try:
                packet = IP(dst=target) / ICMP()
                start = datetime.datetime.utcnow()
                with suppress_output():
                    response = sr1(packet, timeout=self.timeout, verbose=0)
                elapsed = (datetime.datetime.utcnow() - start).total_seconds() * 1000
                if response and response.haslayer(IP):
                    return {
                        "is_up": True,
                        "method": "ICMP Echo",
                        "ttl": response[IP].ttl,
                        "latency_ms": round(elapsed, 2),
                    }
            except PermissionError:
                return {"is_up": None, "error": "admin_required"}
            except Exception as e:
                self.logger.debug(f"ICMP attempt {attempt}: {e}")
        return {"is_up": False, "method": "ICMP Echo"}

    def _tcp_ping(self, target: str) -> dict:
        for port in TCP_FALLBACK_PORTS:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                start = datetime.datetime.utcnow()
                result = sock.connect_ex((target, port))
                elapsed = (datetime.datetime.utcnow() - start).total_seconds() * 1000
                sock.close()
                if result == 0:
                    return {
                        "is_up": True,
                        "method": f"TCP Connect (port {port})",
                        "latency_ms": round(elapsed, 2),
                        "ttl": None,
                    }
            except Exception:
                continue
        return {"is_up": False, "method": "TCP Connect"}

    def _syn_ping(self, target: str) -> dict:
        for port in [80, 443, 22]:
            try:
                pkt = IP(dst=target) / TCP(sport=RandShort(), dport=port, flags="S")
                start = datetime.datetime.utcnow()
                with suppress_output():
                    resp = sr1(pkt, timeout=self.timeout, verbose=0)
                elapsed = (datetime.datetime.utcnow() - start).total_seconds() * 1000
                if resp and resp.haslayer(TCP):
                    return {
                        "is_up": True,
                        "method": f"TCP SYN (port {port})",
                        "ttl": resp[IP].ttl,
                        "latency_ms": round(elapsed, 2),
                    }
            except Exception:
                continue
        return {"is_up": False, "method": "TCP SYN"}

    def ping(self, target: str) -> dict:
        result = {
            "host": target,
            "is_up": False,
            "method": None,
            "ttl": None,
            "latency_ms": None,
            "adaptive_note": None,
            "all_methods_tried": [],
            "timestamp": datetime.datetime.utcnow().isoformat()
        }

        self.logger.info(f"Host discovery → {target}")

        if self._is_localhost(target):
            local = self._localhost_ping(target)
            result.update(local)
            result["all_methods_tried"].append("Localhost")
            return result

        icmp = self._icmp_ping(target)
        result["all_methods_tried"].append("ICMP Echo")

        if icmp.get("error") == "admin_required":
            result["adaptive_note"] = (
                "Raw sockets need Administrator privileges. "
                "Switching to TCP discovery."
            )
        elif icmp.get("is_up"):
            result.update({
                "is_up": True,
                "method": icmp["method"],
                "ttl": icmp.get("ttl"),
                "latency_ms": icmp.get("latency_ms"),
            })
            return result

        tcp = self._tcp_ping(target)
        result["all_methods_tried"].append("TCP Connect")

        if tcp.get("is_up"):
            result.update({
                "is_up": True,
                "method": tcp["method"],
                "latency_ms": tcp.get("latency_ms"),
                "adaptive_note": (
                    f"ICMP blocked. Host confirmed UP via {tcp['method']}."
                )
            })
            return result

        syn = self._syn_ping(target)
        result["all_methods_tried"].append("TCP SYN")

        if syn.get("is_up"):
            result.update({
                "is_up": True,
                "method": syn["method"],
                "ttl": syn.get("ttl"),
                "latency_ms": syn.get("latency_ms"),
                "adaptive_note": (
                    f"ICMP blocked. Host confirmed UP via {syn['method']}."
                )
            })
            return result

        result["adaptive_note"] = (
            "All discovery methods failed. "
            "Host may be firewalled. Scanning ports anyway (-Pn mode)."
        )
        return result