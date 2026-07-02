import argparse
from datetime import datetime
from colorama import init
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.columns import Columns

from scanner import scan_url
from scoring import calculate_risk
from reporter import save_json_report
from virustotal import check_virustotal
from html_reporter import save_html_report
from whois_lookup import lookup_whois
from ssl_checker import check_ssl_certificate
from dns_lookup import lookup_dns
from ip_lookup import lookup_ip
from screenshotter import capture_screenshot
from threat_summary import generate_threat_summary

init(autoreset=True)
console = Console()
VERSION = "1.0.0"


ASCII_LOGO = r"""
██████╗ ██╗      █████╗  ██████╗██╗  ██╗████████╗███████╗██████╗ ███╗   ███╗
██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝╚══██╔══╝██╔════╝██╔══██╗████╗ ████║
██████╔╝██║     ███████║██║     █████╔╝    ██║   █████╗  ██████╔╝██╔████╔██║
██╔══██╗██║     ██╔══██║██║     ██╔═██╗    ██║   ██╔══╝  ██╔══██╗██║╚██╔╝██║
██████╔╝███████╗██║  ██║╚██████╗██║  ██╗   ██║   ███████╗██║  ██║██║ ╚═╝ ██║
╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝
"""


def get_verdict(score):
    if score < 25:
        return "LOW", "green", "HIGH"
    if score < 60:
        return "MEDIUM", "yellow", "MEDIUM"
    return "HIGH", "red", "LOW"


def module_status(name, status):
    return f"[green]✓[/green] {name:<30} [cyan]{status}[/cyan]"


def scan_target(url, no_screenshot=False):
    scan_started = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    result = scan_url(url)
    score, reasons = calculate_risk(url)

    vt_result = check_virustotal(result["final_url"])
    whois_result = lookup_whois(result["domain"])
    ssl_result = check_ssl_certificate(result["domain"])
    dns_result = lookup_dns(result["domain"])
    ip_result = lookup_ip(result["domain"])

    screenshot_result = {
        "enabled": False,
        "screenshot_path": None,
        "error": "Screenshot disabled",
    }

    if not no_screenshot:
        screenshot_result = capture_screenshot(result["final_url"], result["domain"])

    if vt_result.get("malicious", 0) > 0:
        score += 30
        reasons.append(f"VirusTotal malicious detections: {vt_result['malicious']}")

    if vt_result.get("suspicious", 0) > 0:
        score += 15
        reasons.append(f"VirusTotal suspicious detections: {vt_result['suspicious']}")

    if ssl_result.get("error"):
        score += 10
        reasons.append("SSL certificate check failed")

    if screenshot_result.get("error") and not no_screenshot:
        reasons.append("Website screenshot capture failed")

    score = min(score, 100)
    threat_level, risk_color, confidence = get_verdict(score)

    threat_summary = generate_threat_summary(
        url, result, score, reasons, vt_result, whois_result,
        ssl_result, dns_result, ip_result, screenshot_result
    )

    json_report = save_json_report(
        url, result, score, reasons, vt_result, whois_result,
        ssl_result, dns_result, ip_result, screenshot_result, threat_summary
    )

    html_report = save_html_report(
        url, result, score, reasons, vt_result, whois_result,
        ssl_result, dns_result, ip_result, screenshot_result, threat_summary
    )

    vt_total = (
        vt_result.get("malicious", 0)
        + vt_result.get("suspicious", 0)
        + vt_result.get("harmless", 0)
        + vt_result.get("undetected", 0)
    )

    modules = "\n".join([
        module_status("URL Validation", "PASSED" if result["valid"] else "FAILED"),
        module_status("VirusTotal Intelligence", "CLEAN" if vt_result.get("malicious", 0) == 0 else "DETECTED"),
        module_status("WHOIS Intelligence", "COMPLETE" if not whois_result.get("error") else "FAILED"),
        module_status("SSL Certificate", "VALID" if ssl_result.get("is_valid") else "INVALID"),
        module_status("DNS Intelligence", "RESOLVED" if dns_result.get("a_records") or dns_result.get("aaaa_records") else "FAILED"),
        module_status("IP Intelligence", "RESOLVED" if ip_result.get("ip_address") else "FAILED"),
        module_status("Website Screenshot", "CAPTURED" if screenshot_result.get("screenshot_path") else "SKIPPED"),
        module_status("AI Threat Summary", "GENERATED"),
        module_status("JSON Report", "SAVED"),
        module_status("HTML Report", "SAVED"),
    ])

    overview = Table.grid(padding=(0, 2))
    overview.add_column(style="cyan")
    overview.add_column()
    overview.add_row("Target", url)
    overview.add_row("Scan Started", scan_started)
    overview.add_row("Engine", "BlackTerm Intelligence Engine")
    overview.add_row("Version", VERSION)
    overview.add_row("Risk", f"[{risk_color}]{threat_level}[/{risk_color}]")
    overview.add_row("Confidence", confidence)

    intel = Table.grid(padding=(0, 2))
    intel.add_column(style="cyan")
    intel.add_column()
    intel.add_row("Target IP", str(ip_result.get("ip_address")))
    intel.add_row("ASN", str(ip_result.get("asn_description")))
    intel.add_row("Domain Age", f"{whois_result.get('domain_age_days')} days")
    intel.add_row("SSL Status", "VALID" if ssl_result.get("is_valid") else "INVALID")
    intel.add_row("VT Detection", f"{vt_result.get('malicious', 0)} / {vt_total}")

    reports = Table.grid(padding=(0, 2))
    reports.add_column(style="green")
    reports.add_column()
    reports.add_row("JSON", str(json_report))
    reports.add_row("HTML", str(html_report))
    reports.add_row("PNG", str(screenshot_result.get("screenshot_path")))

    console.print(Panel(ASCII_LOGO, title="[bold red]BLACKTERM PHISHSCAN v1.0[/bold red]", subtitle="Offensive Intelligence & Threat Scanner", border_style="red"))
    console.print(Columns([
        Panel(overview, title="Scan Overview", border_style="cyan"),
        Panel(intel, title="Intelligence", border_style="green"),
    ]))
    console.print(Panel(modules, title="Modules", border_style="red"))
    console.print(Panel(f"[{risk_color}]Risk Score: {score}/100\nThreat Level: {threat_level}\nConfidence: {confidence}[/{risk_color}]", title="Assessment", border_style=risk_color))
    console.print(Panel(threat_summary, title="AI Threat Summary", border_style="cyan"))
    console.print(Panel(reports, title="Reports", border_style="green"))


def main():
    parser = argparse.ArgumentParser(
        prog="blackterm",
        description="BlackTerm PhishScan - phishing URL intelligence scanner",
    )

    subparsers = parser.add_subparsers(dest="command")
    scan_parser = subparsers.add_parser("scan", help="Scan a URL")
    scan_parser.add_argument("url", help="URL or domain to scan")
    scan_parser.add_argument("--no-screenshot", action="store_true")

    args = parser.parse_args()

    if args.command == "scan":
        scan_target(args.url, args.no_screenshot)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()