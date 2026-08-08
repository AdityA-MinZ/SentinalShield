"""
Command line interface. Run "sentinel-shield --help" to see the commands:

    sentinel-shield proxy       run the reverse proxy in front of an app
    sentinel-shield admin       start the admin API (stats, IP control)
    sentinel-shield dashboard   start the web dashboard
    sentinel-shield report      print a summary of a log file
    sentinel-shield status      show the current configuration
    sentinel-shield rules       list the loaded detection rules
"""

import asyncio
import json
import signal
from collections import Counter
from pathlib import Path

import click
import uvicorn

from ..core.config import Config
from ..api.server import create_api
from ..proxy.proxy_server import ProxyServer


@click.group()
@click.version_option(version="1.0.0", prog_name="sentinel-shield")
def cli():
    """SentinelShield - Advanced Intrusion Detection & Web Protection"""


@cli.command()
@click.option("--config", "-c", default=None, help="Path to config file")
@click.option("--host", default=None, help="Bind host")
@click.option("--port", default=None, type=int, help="Bind port")
@click.option("--upstream", "-u", default=None, help="Upstream URL")
def proxy(config, host, port, upstream):
    """Run as standalone reverse proxy (for Juice Shop demo)"""
    cfg = _load_config(config)
    if host:
        cfg.set("server", "host", host)
    if port:
        cfg.set("server", "port", port)
    if upstream:
        cfg.set("server", "upstream", upstream)

    server = ProxyServer(cfg)

    async def _serve():
        runner = await server.start()
        stop = asyncio.Future()

        def _shutdown(*_args):
            if not stop.done():
                stop.set_result(None)

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                asyncio.get_event_loop().add_signal_handler(sig, _shutdown)
            except (NotImplementedError, RuntimeError):
                signal.signal(sig, _shutdown)

        await stop
        await runner.cleanup()

    try:
        asyncio.run(_serve())
    except KeyboardInterrupt:
        pass


@cli.command()
@click.option("--config", "-c", default=None, help="Path to config file")
@click.option("--app", "-a", default="app:app", help="WSGI application")
@click.option("--host", default=None, help="Bind host")
@click.option("--port", default=None, type=int, help="Bind port")
def wrap(config, app, host, port):
    """Wrap an existing WSGI app with SentinelShield"""
    click.echo("Wrap mode requires integrating into your WSGI app directly.")
    click.echo()
    click.echo("  from sentinel_shield import SentinelShield")
    click.echo("  from flask import Flask")
    click.echo()
    click.echo("  app = Flask(__name__)")
    click.echo("  app.wsgi_app = SentinelShield(app.wsgi_app)")
    click.echo()
    click.echo("For non-Python apps (like Juice Shop), use proxy command:")
    click.echo()
    click.echo("  sentinel-shield proxy --upstream http://localhost:3000")


@cli.command()
@click.option("--config", "-c", default=None, help="Path to config file")
@click.option("--host", default="0.0.0.0", help="Admin API bind host")
@click.option("--port", default=9090, type=int, help="Admin API bind port")
def admin(config, host, port):
    """Start the admin API server"""
    cfg = _load_config(config)
    cfg.set("admin_api", "host", host)
    cfg.set("admin_api", "port", port)

    from ..detection.rules_engine import RulesEngine
    from ..protection.rate_limiter import RateLimiter
    from ..protection.ip_reputation import IPReputation
    from ..monitor.traffic_analyzer import TrafficAnalyzer

    eng = RulesEngine(cfg.rules_dir)
    rl = RateLimiter(cfg.rate_limiter)
    ipr = IPReputation(cfg.ip_reputation)
    ta = TrafficAnalyzer(cfg.traffic_analyzer)

    app = create_api(cfg, eng, rl, ipr, ta)

    click.echo(f"Admin API starting on {host}:{port}")
    uvicorn.run(app, host=host, port=port)


@cli.command()
@click.option("--config", "-c", default=None, help="Path to config file")
@click.option("--host", default="0.0.0.0", help="Dashboard bind host")
@click.option("--port", default=9091, type=int, help="Dashboard bind port")
@click.option("--log-file", default=None, help="Path to log file")
def dashboard(config, host, port, log_file):
    """Start the web dashboard"""
    cfg = _load_config(config)
    if log_file:
        cfg.set("logging", "file", log_file)

    from ..dashboard.server import create_app
    app = create_app(cfg)

    click.echo(f"Dashboard starting on http://{host}:{port}")
    from werkzeug.serving import run_simple
    run_simple(host, port, app, use_reloader=False, use_debugger=False)


@cli.command()
@click.option("--config", "-c", default=None, help="Path to config file")
@click.option("--log-file", default=None, help="Path to log file to analyze")
@click.option("--format", "-f", "output_format", default="table",
              type=click.Choice(["table", "json", "markdown"]),
              help="Output format")
def report(config, log_file, output_format):
    """Generate security summary report from log file"""
    cfg = _load_config(config)
    if not log_file:
        log_file = cfg.logging.get("file", "sentinel-shield.log")

    log_path = Path(log_file)
    if not log_path.exists():
        click.echo(f"Log file not found: {log_path}", err=True)
        raise SystemExit(1)

    summary = _analyze_log(log_path)

    if output_format == "json":
        _report_json(summary)
    elif output_format == "markdown":
        _report_markdown(summary)
    else:
        _report_table(summary)


def _analyze_log(log_path):
    """Read a JSONL log file and count requests, attacks and IPs."""
    total_requests = 0
    security_events = []
    ip_requests = Counter()
    attack_types = Counter()

    with open(log_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                ip = entry.get("client_ip", "unknown")
                ip_requests[ip] += 1

                event = entry.get("event", "")
                if event == "access":
                    total_requests += 1
                elif event in ("block", "detection"):
                    attack_type = entry.get("attack_type", "") or entry.get("reason_type", "")
                    if attack_type:
                        attack_types[attack_type] += 1
                    security_events.append(entry)
            except (json.JSONDecodeError, KeyError):
                continue

    return {
        "total_requests": total_requests,
        "total_blocks": len(security_events),
        "attack_types": attack_types,
        "top_ips": ip_requests.most_common(10),
        "security_events": security_events,
    }


def _report_table(summary):
    attack_types = summary["attack_types"]
    top_ips = summary["top_ips"]
    events = summary["security_events"]

    click.echo("\nSentinelShield Security Report")
    click.echo("=" * 50)
    click.echo(f"Total requests analyzed: {summary['total_requests']}")
    click.echo(f"Blocked/detected events: {summary['total_blocks']}")
    click.echo()
    click.echo("Attack Distribution:")
    click.echo("-" * 30)
    for atype, count in attack_types.most_common():
        click.echo(f"  {atype:<20} {count}")
    click.echo()
    click.echo("Top IPs:")
    click.echo("-" * 30)
    for ip, count in top_ips:
        click.echo(f"  {ip:<20} {count} requests")
    click.echo()
    click.echo("Recent Blocks:")
    click.echo("-" * 30)
    for e in events[-5:]:
        ts = e.get("timestamp", "")[11:19] if e.get("timestamp") else ""
        ip = e.get("client_ip", "")
        atype = e.get("attack_type", "") or e.get("reason_type", "")
        click.echo(f"  {ts} {ip} {atype}")


def _report_json(summary):
    recent = []
    for e in summary["security_events"][-20:]:
        recent.append({
            "timestamp": e.get("timestamp", ""),
            "client_ip": e.get("client_ip", ""),
            "event": e.get("event", ""),
            "attack_type": e.get("attack_type", "") or e.get("reason_type", ""),
            "rule_id": e.get("rule_id", ""),
        })
    data = {
        "total_requests": summary["total_requests"],
        "total_blocks": summary["total_blocks"],
        "attack_distribution": dict(summary["attack_types"].most_common()),
        "top_ips": [{"ip": ip, "count": count} for ip, count in summary["top_ips"]],
        "recent_events": recent,
    }
    click.echo(json.dumps(data, indent=2))


def _report_markdown(summary):
    attack_types = summary["attack_types"]
    top_ips = summary["top_ips"]
    events = summary["security_events"]

    click.echo("# SentinelShield Security Report\n")
    click.echo(f"- **Total requests:** {summary['total_requests']}")
    click.echo(f"- **Blocked/detected:** {summary['total_blocks']}\n")
    click.echo("## Attack Distribution\n")
    click.echo("| Attack Type | Count |")
    click.echo("|------------|-------|")
    for atype, count in attack_types.most_common():
        click.echo(f"| {atype} | {count} |")
    click.echo("\n## Top IPs\n")
    click.echo("| IP | Requests |")
    click.echo("|----|----------|")
    for ip, count in top_ips:
        click.echo(f"| {ip} | {count} |")
    click.echo("\n## Recent Security Events\n")
    click.echo("| Time | IP | Type | Rule |")
    click.echo("|------|----|------|------|")
    for e in events[-10:]:
        ts = e.get("timestamp", "")[11:19] if e.get("timestamp") else ""
        ip = e.get("client_ip", "")
        atype = e.get("attack_type", "") or e.get("reason_type", "")
        rid = e.get("rule_id", "") or e.get("reason", "")[:30]
        click.echo(f"| {ts} | {ip} | {atype} | {rid} |")


@cli.command()
@click.option("--config", "-c", default=None, help="Path to config file")
def status(config):
    """Check current SentinelShield status"""
    cfg = _load_config(config)
    rules_dir = cfg.rules_dir

    from ..detection.rules_engine import RulesEngine
    rules_engine = RulesEngine(rules_dir)

    click.echo("SentinelShield Status")
    click.echo("=" * 40)
    click.echo(f"Detection mode: {cfg.detection.get('mode', 'log')}")
    click.echo(f"Rules loaded: {len(rules_engine.rules)}")
    click.echo(f"Rate limiter: {'enabled' if cfg.rate_limiter.get('enabled') else 'disabled'}")
    click.echo(f"IP reputation: {'enabled' if cfg.ip_reputation.get('enabled') else 'disabled'}")
    click.echo(f"Upstream: {cfg.server.get('upstream', 'N/A')}")
    click.echo(f"Server port: {cfg.server.get('port', 8080)}")
    click.echo(f"Admin API: {'enabled' if cfg.admin_api.get('enabled') else 'disabled'}")
    log_file = cfg.logging.get("file", "sentinel-shield.log")
    log_path = Path(log_file)
    log_size = log_path.stat().st_size if log_path.exists() else 0
    click.echo(f"Log file: {log_file} ({_fmt_size(log_size)})")


@cli.command()
@click.option("--config", "-c", default=None, help="Path to config file")
@click.argument("rule_id", required=False)
def rules(config, rule_id):
    """List detection rules"""
    cfg = _load_config(config)
    from ..detection.rules_engine import RulesEngine
    rules_engine = RulesEngine(cfg.rules_dir)

    if not rules_engine.rules:
        click.echo("No rules loaded.")
        return

    if rule_id:
        for r in rules_engine.rules:
            if r["id"].lower() == rule_id.lower():
                click.echo(f"ID:       {r['id']}")
                click.echo(f"Name:     {r.get('name', 'N/A')}")
                click.echo(f"Type:     {r.get('attack_type', 'N/A')}")
                click.echo(f"Severity: {r.get('severity', 'medium')}")
                click.echo(f"Action:   {r.get('action', 'block')}")
                click.echo(f"Locations: {', '.join(r.get('locations', []))}")
                click.echo(f"Patterns ({len(r.get('patterns', []))}):")
                for p in r.get("patterns", []):
                    click.echo(f"  - {p}")
                return
        click.echo(f"Rule {rule_id} not found.")
        return

    click.echo(f"{'ID':<20} {'Name':<35} {'Type':<15} {'Severity':<10}")
    click.echo("-" * 80)
    for r in rules_engine.rules:
        click.echo(
            f"{r['id']:<20} "
            f"{r.get('name', 'N/A'):<35} "
            f"{r.get('attack_type', 'N/A'):<15} "
            f"{r.get('severity', 'medium'):<10}"
        )
    click.echo(f"\nTotal: {len(rules_engine.rules)} rules")


def _load_config(config_path):
    if config_path:
        return Config(Path(config_path))
    return Config()


def _fmt_size(size: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{size:.1f}{unit}"
        size /= 1024
    return f"{size:.1f}TB"


if __name__ == "__main__":
    cli()
