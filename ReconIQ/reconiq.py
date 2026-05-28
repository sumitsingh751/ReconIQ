import os
import sys
import io

_stderr = sys.stderr
sys.stderr = io.StringIO()
try:
    import scapy
finally:
    sys.stderr = _stderr

import argparse
import datetime
import json

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich import box
from rich.rule import Rule
from rich.text import Text
from rich.theme import Theme

from scanner.tcp_scanner import TCPScanner
from scanner.syn_scanner import SYNScanner
from scanner.icmp_discovery import ICMPDiscovery
from scanner.banner_grabber import BannerGrabber
from scanner.os_fingerprint import OSFingerprint
from ai.reasoning_engine import ReasoningEngine

theme = Theme({
    "info":     "bold cyan",
    "success":  "bold green",
    "warning":  "bold yellow",
    "danger":   "bold red",
    "critical": "bold red on white",
    "ai":       "bold magenta",
    "dim":      "dim white",
    "target":   "bold white",
    "flag":     "bold yellow",
})
console = Console(theme=theme)

RISK_COLORS = {
    "CRITICAL": "[bold red]CRITICAL[/bold red]",
    "HIGH":     "[red]HIGH[/red]",
    "MEDIUM":   "[yellow]MEDIUM[/yellow]",
    "LOW":      "[green]LOW[/green]",
    "INFO":     "[dim]INFO[/dim]",
}

def print_banner():
    banner = """[bold cyan]
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗ ██████╗ 
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██║██╔═══██╗
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║██║██║   ██║
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██║██║▄▄ ██║
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║╚██████╔╝
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝ ╚══▀▀═╝[/bold cyan]"""
    console.print(banner)
    console.print(Panel(
        "[bold white]  Adaptive AI Reconnaissance Framework  [/bold white]\n"
        "[dim cyan]  Intelligent scanning · AI reasoning · Adaptive strategies  [/dim cyan]",
        border_style="cyan", padding=(0, 4)
    ))
    console.print()

def print_colored_help():
    console.print(Rule("[bold cyan]RECONIQ — Usage Guide[/bold cyan]"))
    console.print()
    table = Table(
        show_header=True, header_style="bold cyan",
        box=box.ROUNDED, border_style="dim cyan", padding=(0, 2)
    )
    table.add_column("FLAG",        style="bold yellow", width=8)
    table.add_column("LONG FLAG",   style="cyan",        width=14)
    table.add_column("DESCRIPTION", style="white",       width=38)
    table.add_column("EXAMPLE",     style="dim",         width=28)

    table.add_row("-t", "--target",    "[bold]Target IP or hostname[/bold]",    "-t 192.168.1.1")
    table.add_row("-p", "--ports",     "Port range or list",                    "-p 1-1024  or  -p 22,80,443")
    table.add_row("-s", "--scan",      "Scan type: tcp / syn",                  "-s syn")
    table.add_row("-o", "--output",    "Save report to JSON",                   "-o report.json")
    table.add_row("-v", "--verbose",   "Show closed ports too",                 "-v")
    table.add_row("",   "--no-ai",     "[dim]Skip AI analysis (faster)[/dim]",  "--no-ai")
    table.add_row("",   "--no-banner", "[dim]Skip banner grabbing[/dim]",        "--no-banner")
    table.add_row("",   "--no-os",     "[dim]Skip OS detection[/dim]",           "--no-os")
    console.print(table)
    console.print()

    console.print(Rule("[bold cyan]Examples[/bold cyan]"))
    examples = [
        ("Quick scan",       "python reconiq.py [bold yellow]-t[/bold yellow] 192.168.1.1 [bold yellow]-p[/bold yellow] 1-1024 [bold yellow]-s[/bold yellow] tcp"),
        ("Full + save",      "python reconiq.py [bold yellow]-t[/bold yellow] 192.168.1.1 [bold yellow]-p[/bold yellow] 1-1024 [bold yellow]-o[/bold yellow] report.json"),
        ("SYN stealth",      "python reconiq.py [bold yellow]-t[/bold yellow] 192.168.1.1 [bold yellow]-p[/bold yellow] 1-1024 [bold yellow]-s[/bold yellow] syn"),
        ("Fast no AI",       "python reconiq.py [bold yellow]-t[/bold yellow] 192.168.1.1 [bold yellow]-p[/bold yellow] 1-1024 --no-ai"),
        ("Localhost scan",   "python reconiq.py [bold yellow]-t[/bold yellow] 127.0.0.1   [bold yellow]-p[/bold yellow] 1-1024 --no-ai"),
        ("Top ports",        "python reconiq.py [bold yellow]-t[/bold yellow] 192.168.1.1 [bold yellow]-p[/bold yellow] 21,22,80,135,443,445,3306,3389"),
    ]
    for name, cmd in examples:
        console.print(f"  [bold cyan]{name:18}[/bold cyan]  {cmd}")
    console.print()

def parse_args():
    parser = argparse.ArgumentParser(
        prog="reconiq",
        description="RECONIQ — Adaptive AI Recon Framework",
        add_help=False
    )
    parser.add_argument("-t", "--target")
    parser.add_argument("-p", "--ports",   default="1-1024")
    parser.add_argument("-s", "--scan",    default="tcp", choices=["tcp", "syn"])
    parser.add_argument("--no-ai",         action="store_true")
    parser.add_argument("--no-banner",     action="store_true")
    parser.add_argument("--no-os",         action="store_true")
    parser.add_argument("-o", "--output")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-h", "--help",    action="store_true")
    return parser.parse_args()

def parse_ports(port_str: str):
    ports = []
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            s, e = part.split("-")
            ports.extend(range(int(s), int(e) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))

def print_scan_config(target, ports, scan_type, flags):
    console.print(Rule("[bold cyan]Scan Configuration[/bold cyan]"))
    table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
    table.add_column(style="bold yellow", width=20)
    table.add_column(style="bold white")

    output_val = flags.output if flags.output else "[dim]None[/dim]"

    table.add_row("-t  Target",    f"[bold white]{target}[/bold white]")
    table.add_row("-p  Ports",     f"[cyan]{len(ports)} ports  ({ports[0]}–{ports[-1]})[/cyan]")
    table.add_row("-s  Scan Type", f"[bold magenta]{scan_type.upper()}[/bold magenta]")
    table.add_row("-o  Output",    f"[cyan]{output_val}[/cyan]")
    table.add_row("    AI",        "[green]ON[/green]"  if not flags.no_ai     else "[dim]OFF[/dim]")
    table.add_row("    Banner",    "[green]ON[/green]"  if not flags.no_banner else "[dim]OFF[/dim]")
    table.add_row("    OS Detect", "[green]ON[/green]"  if not flags.no_os     else "[dim]OFF[/dim]")
    table.add_row("    Started",   datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    console.print(table)
    console.print()

def print_host_status(result: dict):
    console.print(Rule("[bold cyan]Host Discovery[/bold cyan]"))
    if result["is_up"]:
        line = "  [success][+][/success] Host [success]UP[/success]"
        if result.get("latency_ms"):
            line += f"  [dim]latency: {result['latency_ms']}ms[/dim]"
        if result.get("ttl"):
            line += f"  [dim]TTL: {result['ttl']}[/dim]"
        if result.get("method"):
            line += f"  [dim]via {result['method']}[/dim]"
        console.print(line)
    else:
        console.print("  [warning][!][/warning] Host [warning]NOT responding[/warning]")
    if result.get("adaptive_note"):
        console.print(f"\n  [ai][ADAPTIVE][/ai] [cyan]{result['adaptive_note']}[/cyan]")
    console.print()

def print_port_results(results: list, verbose: bool = False, banners: list = None):
    console.print(Rule("[bold cyan]Port Scan Results[/bold cyan]"))

    banner_map = {}
    if banners:
        for b in banners:
            version = f" v{b['version']}" if b.get("version") else ""
            svc  = b.get("service") or ""
            info = f"{svc}{version}"
            raw  = b.get("banner", "")
            if raw and raw not in ("No banner received", "Timeout", "Connection refused"):
                first_line = raw.split("\n")[0][:55]
                info = f"{info} — {first_line}" if info else first_line
            banner_map[b["port"]] = info.strip(" —")

    table = Table(
        show_header=True, header_style="bold cyan",
        box=box.ROUNDED, border_style="dim cyan", padding=(0, 1)
    )
    table.add_column("PORT",    style="bold white", width=7)
    table.add_column("STATE",                       width=12)
    table.add_column("SERVICE", style="cyan",       width=14)
    table.add_column("RISK",                        width=10)
    table.add_column("INFO",    style="dim",        width=48)

    open_count = filtered_count = 0
    for r in results:
        state = r["state"]
        risk  = r.get("risk", "INFO")
        if state == "open":
            open_count += 1
            state_str = "[success]OPEN[/success]"
        elif state == "filtered":
            filtered_count += 1
            state_str = "[warning]FILTERED[/warning]"
        elif state == "closed":
            if not verbose:
                continue
            state_str = "[dim]CLOSED[/dim]"
        else:
            state_str = "[danger]ERROR[/danger]"

        info = banner_map.get(r["port"], r.get("note", "-"))
        if info and len(info) > 55:
            info = info[:52] + "..."

        table.add_row(
            str(r["port"]), state_str,
            r.get("service", "unknown"),
            RISK_COLORS.get(risk, risk),
            info or "-"
        )

    console.print(table)
    summary = Text("\n  ")
    summary.append(f"[+] {open_count} open", style="bold green")
    summary.append("  |  ", style="dim")
    summary.append(f"{filtered_count} filtered", style="yellow")
    summary.append("  |  ", style="dim")
    summary.append(f"{len(results)-open_count-filtered_count} closed", style="dim")
    console.print(summary)
    console.print()
    return open_count

def print_os_result(result: dict):
    console.print(Rule("[bold cyan]OS Detection[/bold cyan]"))
    pct   = result.get("confidence_percent", 0)
    lvl   = result.get("confidence_level", "LOW")
    color = "green" if pct >= 70 else "yellow" if pct >= 40 else "red"

    table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
    table.add_column(style="bold cyan", width=22)
    table.add_column(style="white")

    table.add_row("OS Detected",
        f"[bold white]{result.get('os_detected','Unknown')}[/bold white]")
    table.add_row("Confidence",
        f"[{color}]{lvl} ({pct}%)[/{color}]")
    table.add_row("TTL",
        f"{result.get('ttl','N/A')}  [dim](initial: {result.get('normalized_ttl','N/A')})[/dim]")
    table.add_row("Window Size",    str(result.get("window_size",    "N/A")))
    table.add_row("MSS",            str(result.get("mss",            "N/A")))
    table.add_row("WScale",         str(result.get("wscale",         "N/A")))
    table.add_row("SACK Support",   str(result.get("sack_support",   "N/A")))
    table.add_row("Timestamp",      str(result.get("timestamp_support","N/A")))
    table.add_row("Methods Used",   ", ".join(result.get("probes_run", [])))
    console.print(table)

    if result.get("evidence"):
        console.print("  [dim cyan]Evidence:[/dim cyan]")
        for ev in result["evidence"]:
            console.print(f"    [dim]• {ev}[/dim]")
    console.print()

def print_ai_analysis(result: dict):
    console.print(Rule("[bold magenta]AI Reasoning Engine[/bold magenta]"))
    if result["status"] == "completed":
        tokens = result.get("tokens_used", 0)
        console.print(Panel(
            result["analysis"],
            title=f"[bold magenta]RECONIQ AI — Llama 3[/bold magenta]  [dim]({tokens} tokens)[/dim]",
            border_style="magenta", padding=(1, 2)
        ))
    else:
        console.print(
            f"  [danger][!][/danger] AI failed: [dim]{result.get('error','Unknown')}[/dim]"
        )
    console.print()

def print_summary(target, open_count, os_result, start_time):
    elapsed = (datetime.datetime.now() - start_time).total_seconds()
    console.print(Rule("[bold cyan]Scan Summary[/bold cyan]"))
    table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
    table.add_column(style="bold cyan", width=22)
    table.add_column(style="white")
    table.add_row("Target",        f"[bold white]{target}[/bold white]")
    table.add_row("Open Ports",    f"[bold green]{open_count}[/bold green]")
    table.add_row("OS Detected",   os_result.get("os_detected","Unknown") if os_result else "N/A")
    table.add_row("Scan Duration", f"{elapsed:.1f} seconds")
    table.add_row("Completed At",  datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    console.print(table)
    console.print()

def save_report(data: dict, filepath: str):
    with open(filepath, "w") as f:
        json.dump(data, f, indent=2)
    console.print(f"  [success][+][/success] Report saved → [cyan]{filepath}[/cyan]\n")

def main():
    print_banner()
    args = parse_args()

    if args.help or not args.target:
        print_colored_help()
        sys.exit(0)

    ports      = parse_ports(args.ports)
    start_time = datetime.datetime.now()
    report = {
        "tool": "RECONIQ", "version": "2.1",
        "target": args.target, "scan_type": args.scan,
        "started_at": start_time.isoformat(), "results": {}
    }

    print_scan_config(args.target, ports, args.scan, args)

    with Progress(SpinnerColumn(style="cyan"),
                  TextColumn("[cyan]{task.description}"),
                  TimeElapsedColumn(), transient=True) as p:
        p.add_task("Host discovery (ICMP + TCP fallback)...")
        discovery  = ICMPDiscovery()
        host_result = discovery.ping(args.target)

    print_host_status(host_result)
    report["results"]["host_discovery"] = host_result

    scan_label = f"{args.scan.upper()} scan → {len(ports)} ports"
    with Progress(SpinnerColumn(style="cyan"),
                  TextColumn(f"[cyan]{scan_label}"),
                  BarColumn(style="cyan"),
                  TimeElapsedColumn(), transient=True) as p:
        p.add_task(scan_label, total=None)
        scanner      = SYNScanner() if args.scan == "syn" else TCPScanner()
        port_results = scanner.scan(args.target, ports)

    report["results"]["ports"] = port_results
    open_ports = [p for p in port_results if p["state"] == "open"]

    banners = []
    if not args.no_banner and open_ports:
        with Progress(SpinnerColumn(style="cyan"),
                      TextColumn(f"[cyan]Banner grabbing {len(open_ports)} open ports..."),
                      TimeElapsedColumn(), transient=True) as p:
            p.add_task("Banners...")
            grabber = BannerGrabber()
            banners = grabber.grab_multiple(
                args.target, [p["port"] for p in open_ports]
            )
        report["results"]["banners"] = banners

    open_count = print_port_results(port_results, args.verbose, banners)

    os_result = None
    if not args.no_os:
        with Progress(SpinnerColumn(style="cyan"),
                      TextColumn("[cyan]OS fingerprinting..."),
                      TimeElapsedColumn(), transient=True) as p:
            p.add_task("OS detect...")
            os_fp     = OSFingerprint()
            os_result = os_fp.detect(
                args.target,
                open_ports=[p["port"] for p in open_ports],
                banners=banners
            )
        print_os_result(os_result)
        report["results"]["os_detection"] = os_result

    if not args.no_ai:
        with Progress(SpinnerColumn(style="magenta"),
                      TextColumn("[magenta]AI reasoning with Llama 3 (1-2 min)..."),
                      TimeElapsedColumn(), transient=True) as p:
            p.add_task("AI...")
            ai        = ReasoningEngine()
            ai_result = ai.analyze(args.target, report["results"])
        print_ai_analysis(ai_result)
        report["ai_analysis"] = ai_result

    print_summary(args.target, open_count, os_result, start_time)

    if args.output:
        save_report(report, args.output)

    console.print(Rule("[bold cyan]Done[/bold cyan]"))

if __name__ == "__main__":
    main()