import requests
import logging
import datetime
import json
from typing import Dict

logger = logging.getLogger("RECONIQ.AI")

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "llama3"

SYSTEM_PROMPT = """You are RECONIQ's AI security analyst — a senior penetration tester with 15 years of experience.

Analyze reconnaissance scan data and provide:
- Specific, actionable findings (not generic advice)
- Clear risk ratings per finding (CRITICAL/HIGH/MEDIUM/LOW)
- Exact CVEs or vulnerability classes where relevant
- Next attack steps a pentester should take
- Signs of misconfigurations or exposed services
- Evidence-based OS and service analysis

Format your response with clear sections using these headers:
[HOST STATUS] [OPEN PORTS & RISK] [VULNERABILITY ASSESSMENT] [OS ANALYSIS] [NEXT STEPS] [RISK SUMMARY]

Be technical, specific, and concise. No generic disclaimers."""

class ReasoningEngine:
    def __init__(self, model: str = MODEL, ollama_url: str = OLLAMA_URL):
        self.model = model
        self.ollama_url = ollama_url
        self.logger = logging.getLogger("RECONIQ.AI")

    def _build_prompt(self, target: str, scan_data: Dict) -> str:
        
        ports = scan_data.get("ports", [])
        open_ports = [p for p in ports if p.get("state") == "open"]
        host = scan_data.get("host_discovery", {})
        os_data = scan_data.get("os_detection", {})
        banners = scan_data.get("banners", [])

        open_summary = ", ".join(
            f"{p['port']}/{p.get('service','?')}" for p in open_ports
        ) or "None found"

        banner_summary = "\n".join(
            f"  Port {b['port']}: {b.get('service','?')} "
            f"v{b.get('version','?')} — {str(b.get('banner',''))[:100]}"
            for b in banners if b.get("banner") and b["banner"] not in ("No banner received", "Timeout")
        ) or "  No banners captured"

        return f"""
RECONIQ Scan Report
===================
Target   : {target}
Time     : {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}

HOST STATUS:
  Up      : {host.get('is_up', 'Unknown')}
  Method  : {host.get('method', 'N/A')}
  Latency : {host.get('latency_ms', 'N/A')} ms
  TTL     : {host.get('ttl', 'N/A')}

OPEN PORTS ({len(open_ports)} found):
  {open_summary}

BANNER INFORMATION:
{banner_summary}

OS DETECTION:
  OS      : {os_data.get('os_detected', 'Unknown')}
  TTL     : {os_data.get('ttl', 'N/A')} (normalized: {os_data.get('normalized_ttl', 'N/A')})
  Window  : {os_data.get('window_size', 'N/A')}
  MSS     : {os_data.get('mss', 'N/A')}
  SACK    : {os_data.get('sack_support', 'N/A')}
  Confidence: {os_data.get('confidence_level', 'N/A')} ({os_data.get('confidence_percent', 0)}%)

FULL PORT DATA:
{json.dumps([p for p in open_ports], indent=2)}

Analyze this and provide your security assessment.
"""

    def analyze(self, target: str, scan_data: Dict) -> Dict:
        result = {
            "model": self.model,
            "target": target,
            "analysis": None,
            "analyzed_at": datetime.datetime.utcnow().isoformat(),
            "status": "pending"
        }
        try:
            self.logger.info(f"AI analysis → {target}")
            payload = {
                "model": self.model,
                "prompt": self._build_prompt(target, scan_data),
                "system": SYSTEM_PROMPT,
                "stream": False,
                "options": {
                    "temperature": 0.2,
                    "top_p": 0.9,
                    "num_predict": 2000,
                    "repeat_penalty": 1.1,
                }
            }
            response = requests.post(
                self.ollama_url, json=payload, timeout=300
            )
            response.raise_for_status()
            raw = response.json()
            result["analysis"] = raw.get("response", "").strip()
            result["status"] = "completed"
            result["tokens_used"] = raw.get("eval_count", 0)
            self.logger.info(
                f"AI complete → {result['tokens_used']} tokens used"
            )
        except requests.exceptions.ConnectionError:
            result["status"] = "failed"
            result["error"] = "Ollama not running — start with: ollama serve"
        except requests.exceptions.Timeout:
            result["status"] = "failed"
            result["error"] = "AI timed out — try --no-ai for faster scan"
        except Exception as e:
            result["status"] = "failed"
            result["error"] = str(e)
        return result