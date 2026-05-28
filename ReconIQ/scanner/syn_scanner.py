import os
import sys
import logging
import datetime
import contextlib
import concurrent.futures
from typing import List, Dict
from scapy.all import IP, TCP, sr1, RandShort, conf

logging.getLogger("scapy").setLevel(logging.CRITICAL)
logging.getLogger("scapy.runtime").setLevel(logging.CRITICAL)
conf.verb = 0

@contextlib.contextmanager
def suppress_output():
    with open(os.devnull, 'w') as devnull:
        old_stderr = sys.stderr
        try:
            sys.stderr = devnull
            yield
        finally:
            sys.stderr = old_stderr

from scanner.tcp_scanner import SERVICE_MAP, get_risk_level

class SYNScanner:
    def __init__(self, timeout: float = 1.5, max_threads: int = 100):
        self.timeout = timeout
        self.max_threads = max_threads
        self.logger = logging.getLogger("RECONIQ.SYNScanner")

    def _syn_probe(self, target: str, port: int) -> Dict:
        result = {
            "port": port,
            "state": "unknown",
            "service": SERVICE_MAP.get(port, "unknown"),
            "risk": get_risk_level(port),
            "scan_type": "SYN",
            "ttl": None,
            "window_size": None,
            "scanned_at": datetime.datetime.utcnow().isoformat()
        }
        try:
            src_port = int(RandShort())
            packet = IP(dst=target) / TCP(sport=src_port, dport=port, flags="S")
            with suppress_output():
                response = sr1(packet, timeout=self.timeout, verbose=0)

            if response is None:
                result["state"] = "filtered"
                result["note"] = "No response — firewall dropping packets"
            elif response.haslayer(TCP):
                flags = response[TCP].flags
                result["ttl"] = response[IP].ttl
                result["window_size"] = response[TCP].window
                if flags == 0x12:
                    result["state"] = "open"
                    rst = IP(dst=target) / TCP(sport=src_port, dport=port, flags="R", seq=response[TCP].ack)
                    with suppress_output():
                        sr1(rst, timeout=1, verbose=0)
                elif flags in (0x14, 0x04):
                    result["state"] = "closed"
            elif response.haslayer("ICMP"):
                if response["ICMP"].type == 3:
                    result["state"] = "filtered"
                    result["note"] = "ICMP unreachable — filtered"
        except PermissionError:
            result["state"] = "error"
            result["note"] = "Run as Administrator/root for SYN scan"
        except Exception as e:
            result["state"] = "error"
            result["note"] = str(e)
        return result

    def scan(self, target: str, ports: List[int]) -> List[Dict]:
        self.logger.info(f"SYN scan → {target} | {len(ports)} ports")
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self._syn_probe, target, port): port for port in ports}
            for future in concurrent.futures.as_completed(futures):
                try:
                    results.append(future.result())
                except Exception as e:
                    self.logger.error(f"SYN thread error: {e}")
        results.sort(key=lambda x: x["port"])
        open_count = sum(1 for r in results if r["state"] == "open")
        self.logger.info(f"SYN scan complete → {open_count} open ports")
        return results