#!/usr/bin/env python3
"""
xray-check
Parses Xray configs from a subscription URL and checks IP/domain info via ip-api.com

Usage:
  xray-check                                      # interactive URL input
  xray-check --url <sub_url>                       # non-interactive
  xray-check --url <sub_url> --lang ru             # Russian output
  xray-check --try-all                             # try all UA presets, pick best
  xray-check --ua clash                            # override UA
"""

import argparse
import base64
import sys
import json
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

console = Console()

# ── Defaults ──────────────────────────────────────────────────────────────

DEFAULT_UA = "Happ/5.0.0"
DEFAULT_LANG = "en"

UA_PRESETS = {
    "clash":        "clash-meta/1.18.0",
    "v2rayng":      "V2RayNG/1.8.20",
    "neko":         "NekoBox/1.2.9",
    "hiddify":      "HiddifyNext/0.1.0",
    "sagernet":     "SagerNet/0.20.0",
    "streisand":    "Streisand/1.4.0",
    "happ":         "Happ/5.0.0",
    "incy":         "Incy/1.0.0",
    "shadowrocket": "Shadowrocket/840",
    "quantumult":   "Quantumult%20X/1.0.0",
    "surfboard":    "Surfboard/4.1.1",
    "singbox":      "SFI/1.8.0",
}


def resolve_ua(name: str) -> str:
    key = name.strip().lower()
    return UA_PRESETS.get(key, name.strip())


# ── Protocol parsers (share links) ────────────────────────────────────────

def parse_vmess(link: str) -> dict | None:
    try:
        raw = link.replace("vmess://", "")
        padded = raw + "=" * (-len(raw) % 4)
        data = json.loads(base64.b64decode(padded))
        return {
            "protocol": "vmess",
            "address": data.get("add", ""),
            "port": str(data.get("port", "")),
            "name": data.get("ps", ""),
            "network": data.get("net", "tcp"),
        }
    except Exception:
        return None


def parse_vless(link: str) -> dict | None:
    try:
        raw = link.replace("vless://", "")
        main, fragment = (raw.split("#") + [""])[:2]
        _, rest = main.split("@", 1)
        address_port, _, query_str = rest.partition("?")
        address, _, port = address_port.rpartition(":")
        return {
            "protocol": "vless",
            "address": address,
            "port": port,
            "name": urllib.parse.unquote(fragment) if fragment else "",
            "network": urllib.parse.parse_qs(query_str).get("type", ["tcp"])[0],
        }
    except Exception:
        return None


def parse_trojan(link: str) -> dict | None:
    try:
        raw = link.replace("trojan://", "")
        main, fragment = (raw.split("#") + [""])[:2]
        _, rest = main.split("@", 1)
        address_port, _, _ = rest.partition("?")
        address, _, port = address_port.rpartition(":")
        return {
            "protocol": "trojan",
            "address": address,
            "port": port,
            "name": urllib.parse.unquote(fragment) if fragment else "",
            "network": "tcp",
        }
    except Exception:
        return None


def parse_ss(link: str) -> dict | None:
    try:
        raw = link.replace("ss://", "")
        main, fragment = (raw.split("#") + [""])[:2]
        if "@" in main:
            _, rest = main.split("@", 1)
            address, _, port = rest.rpartition(":")
        else:
            padded = main + "=" * (-len(main) % 4)
            decoded = base64.b64decode(padded).decode()
            _, rest = decoded.split("@", 1)
            address, _, port = rest.rpartition(":")
        return {
            "protocol": "ss",
            "address": address,
            "port": port,
            "name": urllib.parse.unquote(fragment) if fragment else "",
            "network": "tcp",
        }
    except Exception:
        return None


def parse_ssr(link: str) -> dict | None:
    try:
        raw = link.replace("ssr://", "")
        padded = raw + "=" * (-len(raw) % 4)
        decoded = base64.b64decode(padded).decode()
        parts = decoded.split("/")
        server_port = parts[0]
        server, _, port = server_port.rpartition(":")
        name = ""
        if len(parts) > 1 and "?" in parts[1]:
            qs = parts[1].split("?", 1)[1]
            for pair in qs.split("&"):
                k, _, v = pair.partition("=")
                if k == "remarks":
                    pv = v + "=" * (-len(v) % 4)
                    name = base64.b64decode(pv).decode()
        return {
            "protocol": "ssr",
            "address": server,
            "port": port,
            "name": name,
            "network": "tcp",
        }
    except Exception:
        return None


def parse_hysteria2(link: str) -> dict | None:
    try:
        raw = link.replace("hysteria2://", "").replace("hy2://", "")
        main, fragment = (raw.split("#") + [""])[:2]
        _, rest = main.split("@", 1)
        address_port, _, _ = rest.partition("?")
        address, _, port = address_port.rpartition(":")
        return {
            "protocol": "hy2",
            "address": address,
            "port": port,
            "name": urllib.parse.unquote(fragment) if fragment else "",
            "network": "udp",
        }
    except Exception:
        return None


PARSERS = {
    "vmess://": parse_vmess,
    "vless://": parse_vless,
    "trojan://": parse_trojan,
    "ss://": parse_ss,
    "ssr://": parse_ssr,
    "hysteria2://": parse_hysteria2,
    "hy2://": parse_hysteria2,
}


def parse_config(link: str) -> dict | None:
    for prefix, parser in PARSERS.items():
        if link.startswith(prefix):
            return parser(link)
    return None


# ── JSON subscription parser ────────────────────────────────────────────

def _safe_get(d, *keys, default=None):
    for k in keys:
        if not isinstance(d, dict):
            return default
        d = d.get(k)
        if d is None:
            return default
    return d


def _parse_json_outbound(obj: dict, fallback_name: str = "") -> dict | None:
    protocol = (obj.get("protocol") or "").lower()
    name = obj.get("name") or fallback_name
    settings = obj.get("settings", {})
    stream = obj.get("streamSettings", {})
    network = stream.get("network", "tcp")
    address = port = None

    vnext = _safe_get(settings, "vnext")
    if isinstance(vnext, list) and vnext:
        address = vnext[0].get("address", "")
        port = vnext[0].get("port", "")

    if not address:
        servers = _safe_get(settings, "servers")
        if isinstance(servers, list) and servers:
            address = servers[0].get("address", "")
            port = servers[0].get("port", "")

    if not address:
        address = _safe_get(settings, "address")
        port = _safe_get(settings, "port")

    if not address:
        return None

    proto_map = {
        "vmess": "vmess", "vless": "vless", "trojan": "trojan",
        "shadowsocks": "ss", "shadowsocksr": "ssr",
        "socks": "socks", "http": "http",
        "hysteria2": "hy2", "hysteria": "hy1",
        "tuic": "tuic", "wireguard": "wg",
    }
    return {
        "protocol": proto_map.get(protocol, protocol),
        "address": str(address),
        "port": str(port) if port else "",
        "name": name,
        "network": network,
    }


def parse_json_subscription(text: str) -> list[dict] | None:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None

    outbounds = []
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                name = item.get("remarks") or _safe_get(item, "meta", "serverDescription", default="")
                if not isinstance(name, str):
                    name = ""
                if "outbounds" in item:
                    outbounds.extend((obj, name) for obj in item["outbounds"])
                elif "protocol" in item or "settings" in item:
                    outbounds.append((item, name))
    elif isinstance(data, dict):
        name = data.get("remarks") or _safe_get(data, "meta", "serverDescription", default="")
        if not isinstance(name, str):
            name = ""
        if "outbounds" in data:
            outbounds = [(obj, name) for obj in data["outbounds"]]
        elif "protocol" in data or "settings" in data:
            outbounds = [(data, name)]

    configs = []
    for obj, name in outbounds:
        if isinstance(obj, dict):
            cfg = _parse_json_outbound(obj, fallback_name=name)
            if cfg:
                configs.append(cfg)
    return configs if configs else None


# ── Subscription fetch ───────────────────────────────────────────────────

def _try_parse_body(body: str) -> tuple[list[str], list[dict]] | None:
    body = body.strip()
    if not body:
        return None
    json_cfgs = parse_json_subscription(body)
    if json_cfgs:
        return ([], json_cfgs)
    try:
        padded = body + "=" * (-len(body) % 4)
        decoded = base64.b64decode(padded).decode("utf-8")
        json_cfgs = parse_json_subscription(decoded)
        if json_cfgs:
            return ([], json_cfgs)
        lines = [l.strip() for l in decoded.splitlines() if l.strip()]
    except Exception:
        lines = [l.strip() for l in body.splitlines() if l.strip()]
    return (lines, []) if lines else None


def _count_valid(links: list[str], json_cfgs: list[dict]) -> int:
    if json_cfgs:
        return sum(1 for c in json_cfgs if c.get("address"))
    return sum(1 for l in links if parse_config(l))


def fetch_subscription(url: str, ua: str, timeout: int = 15) -> tuple[list[str], list[dict]]:
    headers = {"User-Agent": ua, "Accept": "*/*"}
    console.print(f"\n[bold cyan]Fetching subscription...[/]", end=" ")
    resp = requests.get(url, headers=headers, timeout=timeout)
    resp.raise_for_status()

    result = _try_parse_body(resp.text)
    if result is None:
        console.print("[red]empty response[/]")
        return ([], [])

    links, json_cfgs = result
    if json_cfgs:
        console.print(f"[green]{len(json_cfgs)} JSON configs found[/]")
    else:
        console.print(f"[green]{len(links)} share-link configs found[/]")
    return (links, json_cfgs)


def fetch_try_all(url: str, timeout: int = 15) -> tuple[list[str], list[dict], str]:
    console.print(f"\n[bold bright_yellow]Trying all {len(UA_PRESETS)} UA presets...[/]")
    best_count = 0
    best_result = ([], [])
    best_name = ""

    tbl = Table(box=box.SIMPLE, header_style="bold bright_cyan", border_style="dim", padding=(0, 1))
    tbl.add_column("Preset", style="white", width=16)
    tbl.add_column("User-Agent", style="dim", max_width=30)
    tbl.add_column("Valid", width=8, justify="center")
    tbl.add_column("Format", width=8, justify="center")

    for name, ua in UA_PRESETS.items():
        try:
            headers = {"User-Agent": ua, "Accept": "*/*"}
            resp = requests.get(url, headers=headers, timeout=timeout)
            resp.raise_for_status()
            result = _try_parse_body(resp.text)
            if result is None:
                tbl.add_row(name, ua, Text("0", style="dim"), Text("—", style="dim"))
                continue
            links, json_cfgs = result
            count = _count_valid(links, json_cfgs)
            fmt = "JSON" if json_cfgs else "links"
            style = "bold bright_green" if count > best_count else "white"
            tbl.add_row(name, ua, Text(str(count), style=style), Text(fmt, style=style))
            if count > best_count:
                best_count = count
                best_result = (links, json_cfgs)
                best_name = name
        except Exception as e:
            tbl.add_row(name, ua, Text("ERR", style="red"), Text(str(e)[:15], style="red"))

    console.print(tbl)
    if best_count == 0:
        console.print("[red]No UA returned any valid configs.[/]")
        return ([], [], "")
    console.print(f"[bold bright_green]Best: {best_name}[/] — [bold]{best_count}[/] valid configs\n")
    return (best_result[0], best_result[1], best_name)


# ── ip-api.com lookup ────────────────────────────────────────────────────

def lookup_ip(address: str, lang: str = "en") -> dict:
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{address}"
            f"?fields=status,message,country,city,isp,as,query&lang={lang}",
            timeout=10,
        )
        data = resp.json()
        if data.get("status") == "success":
            return {
                "ip": data.get("query", address),
                "country": data.get("country", "N/A"),
                "city": data.get("city", "N/A"),
                "isp": data.get("isp", "N/A"),
                "asn": data.get("as", "N/A"),
                "ok": True,
            }
        else:
            return {"ip": address, "ok": False, "error": data.get("message", "Unknown error")}
    except Exception as e:
        return {"ip": address, "ok": False, "error": str(e)}


# ── Colors ────────────────────────────────────────────────────────────────

PROTO_STYLE = {
    "vmess": "bold bright_cyan", "vless": "bold bright_green",
    "trojan": "bold bright_red", "ss": "bold bright_yellow",
    "ssr": "bold bright_magenta", "hy2": "bold bright_blue",
    "hy1": "bold blue", "tuic": "bold bright_magenta",
    "wg": "bold bright_cyan", "socks": "bold white", "http": "bold white",
}


def _ps(proto: str) -> str:
    return PROTO_STYLE.get(proto, "bold white")


# ── Main ──────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="xray-check: Xray subscription IP checker")
    ap.add_argument("--url", help="Subscription URL (skip interactive prompt)")
    ap.add_argument("--ua", default=DEFAULT_UA, help=f"User-Agent string (default: {DEFAULT_UA})")
    ap.add_argument("--lang", default=DEFAULT_LANG, choices=["en", "ru"],
                     help="ip-api.com response language (default: en)")
    ap.add_argument("--try-all", action="store_true", help="Try all UA presets, auto-pick best")
    args = ap.parse_args()

    console.print(Panel(
        "[bold]xray-check[/]\n"
        "Paste your subscription URL to check IP/domain info via ip-api.com",
        title=":globe_with_meridians:  xray-check",
        border_style="bright_blue",
        box=box.DOUBLE,
    ))

    # URL
    if args.url:
        url = args.url.strip()
    else:
        url = console.input("\n[bold bright_white]Subscription URL: [/]").strip()
    if not url:
        console.print("[red]No URL provided. Exiting.[/]")
        sys.exit(1)

    # Fetch
    try:
        if args.try_all:
            links, json_cfgs, _ = fetch_try_all(url)
        else:
            links, json_cfgs = fetch_subscription(url, ua=args.ua)
    except Exception as e:
        console.print(f"[red]Failed to fetch subscription: {e}[/]")
        sys.exit(1)

    # Parse
    configs = []
    failed_parse = 0
    if json_cfgs:
        configs = [c for c in json_cfgs if c.get("address")]
        failed_parse = len(json_cfgs) - len(configs)
    else:
        for link in links:
            cfg = parse_config(link)
            if cfg and cfg.get("address"):
                configs.append(cfg)
            else:
                failed_parse += 1

    if failed_parse:
        console.print(f"[yellow]Skipped {failed_parse} unrecognized/invalid configs[/]")
    if not configs:
        console.print("[red]No valid configs found. Exiting.[/]")
        sys.exit(1)

    # Deduplicate
    seen = set()
    unique = []
    for cfg in configs:
        key = (cfg["protocol"], cfg["address"], cfg["port"])
        if key not in seen:
            seen.add(key)
            unique.append(cfg)

    total = len(unique)
    console.print(f"[bold]{total} unique configs to check[/]\n")

    # Lookup
    BATCH = 40
    results = [None] * total
    lang = args.lang

    with console.status("[bold bright_yellow]Querying ip-api.com...[/]", spinner="dots"):
        for batch_start in range(0, total, BATCH):
            batch_end = min(batch_start + BATCH, total)
            with ThreadPoolExecutor(max_workers=10) as pool:
                futs = {}
                for idx in range(batch_start, batch_end):
                    f = pool.submit(lookup_ip, unique[idx]["address"], lang)
                    futs[f] = idx
                for f in as_completed(futs):
                    results[futs[f]] = f.result()
            if batch_end < total:
                console.print(f"  [dim]Rate-limit pause (62 s)...[/]")
                time.sleep(62)

    # Table
    table = Table(
        title="\n:mag:  Check Results",
        box=box.ROUNDED, show_lines=True,
        title_style="bold bright_white",
        header_style="bold bright_cyan",
        border_style="bright_blue",
        padding=(0, 1),
    )
    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("Proto", width=7, justify="center")
    table.add_column("Name", style="white", max_width=26, no_wrap=True)
    table.add_column("Address", style="bright_white", max_width=24)
    table.add_column("Port", style="dim", width=6, justify="center")
    table.add_column("Country", width=18)
    table.add_column("City", width=16)
    table.add_column("ISP", max_width=28)
    table.add_column("ASN", max_width=22)
    table.add_column("Status", min_width=12, justify="center")

    for i, (cfg, info) in enumerate(zip(unique, results), 1):
        proto = cfg["protocol"]
        name = cfg.get("name", "") or "—"
        addr = cfg["address"]
        port = cfg["port"]

        if info and info.get("ok"):
            country_txt = Text(info["country"], style="bright_yellow")
            city_txt = Text(info["city"], style="bright_white")
            isp_txt = Text(info["isp"], style="bright_cyan")
            asn_txt = Text(info["asn"], style="dim")
            status_txt = Text("  OK  ", style="bold on green")
            if addr != info["ip"]:
                addr_d = Text(addr, style="bright_white") + Text(f"\n({info['ip']})", style="dim")
            else:
                addr_d = Text(addr, style="bright_white")
        else:
            country_txt = Text("N/A", style="dim")
            city_txt = Text("N/A", style="dim")
            isp_txt = Text("N/A", style="dim")
            asn_txt = Text("N/A", style="dim")
            addr_d = Text(addr, style="bright_white")
            err_msg = (info.get("error") or "failed") if info else "no data"
            err_msg = err_msg[:20]
            status_txt = Text(f" FAIL ", style="bold on red")

        table.add_row(
            Text(str(i), style="dim"),
            Text(proto.upper(), style=_ps(proto)),
            Text(name, style="white"),
            addr_d,
            Text(port, style="dim"),
            country_txt, city_txt, isp_txt, asn_txt,
            status_txt,
        )

    console.print()
    console.print(table)

    # Summary
    ok_count = sum(1 for r in results if r and r.get("ok"))
    fail_count = total - ok_count
    countries = {r["country"] for r in results if r and r.get("ok")}

    console.print()
    s = Text()
    s.append("Summary: ", style="bold bright_white")
    s.append(f"{total} configs  ", style="bold")
    s.append(f"|  [green]{ok_count} OK[/]  ")
    if fail_count:
        s.append(f"|  [red]{fail_count} failed[/]  ")
    s.append(f"|  {len(countries)} countries: ", style="bold")
    s.append(", ".join(sorted(countries)), style="bright_yellow")
    console.print(Panel(s, border_style="bright_green", box=box.SIMPLE))


if __name__ == "__main__":
    main()
