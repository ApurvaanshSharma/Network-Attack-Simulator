"""
main.py
=======
Entry point for the Network Attack Simulator.

Starts the web GUI automatically, then runs the interactive CLI.
Both interfaces share the same VirtualNetwork and SimulatorLogger instances.

Phase 2 changes:
  - CLI menu now includes MITM, SQL Injection, Lateral Movement (options 3-5)
  - DoS is option 6, Reconnaissance is option 7 (menu numbers shifted)
  - _show_mitm(), _show_sqli(), _show_lateral() display helpers added
  - _show_recs() extended with new attack types

Fix (v3):
  - JSON export now uses encoding='utf-8' and ensure_ascii=False so the
    arrow and box-drawing characters are written correctly on Windows
    instead of raising a UnicodeEncodeError with the charmap codec.

Usage:
    python main.py          -> web GUI + interactive CLI menu
    python main.py --demo   -> web GUI + auto-run all 7 attacks
"""

import json
import sys
import time
from typing import Optional

from network_model import VirtualNetwork
from logger import SimulatorLogger
import attack_engine
from gui import launch_gui

# ── ANSI colour helpers ──────────────────────────────────────────────
_R  = "\033[0m"
_B  = "\033[1m"
_G  = "\033[32m"
_Y  = "\033[33m"
_C  = "\033[36m"
_M  = "\033[35m"
_RD = "\033[31m"


# ── Display helpers ──────────────────────────────────────────────────

def _banner():
    print(f"""{_B}{_C}
\u2554{'='*62}\u2557
\u2551         NETWORK ATTACK SIMULATOR \u2014 SANDBOX EDITION          \u2551
\u2551              \u26a0  FOR EDUCATIONAL USE ONLY \u26a0                  \u2551
\u2551        All attacks are fully simulated. No real traffic.     \u2551
\u255a{'='*62}\u255d{_R}
""")


def _section(title: str):
    print(f"\n{_B}{_Y}{'\u2500'*60}\n  {title}\n{'\u2500'*60}{_R}")


def _risk_col(r: str) -> str:
    return {"Low": _G, "Medium": _Y, "High": _RD, "Critical": _M}.get(r, "")


def _print_network(network: VirtualNetwork):
    _section("VIRTUAL NETWORK MAP")
    for ip, node in network.nodes.items():
        fw  = f"{_G}\u2713 Firewall{_R}" if node.firewall_enabled else f"{_RD}\u2717 No Firewall{_R}"
        ids = f"{_G}\u2713 IDS{_R}"      if node.ids_enabled      else f"{_RD}\u2717 No IDS{_R}"
        print(f"\n  {_B}{_C}{ip}{_R}  ({node.hostname})  {fw}  {ids}")
        print(f"    OS: {node.os}")
        for s in node.services:
            vul = f"{_RD}[VULNERABLE]{_R}" if s.vulnerable else f"{_G}[Secure]{_R}"
            print(f"    \u251c\u2500 {s.port:5d}  {s.name:8s}  {s.version}  {vul}")


def _choose_target(network: VirtualNetwork) -> Optional[str]:
    ips = network.get_all_ips()
    _section("SELECT TARGET")
    for i, ip in enumerate(ips, 1):
        n = network.nodes[ip]
        print(f"  [{i}] {ip}  ({n.hostname}  |  {n.os})")
    print("  [0] Back")
    try:
        c = int(input(f"\n{_B}  Enter number: {_R}").strip())
        return None if c == 0 else ips[c - 1]
    except (ValueError, IndexError):
        print(f"{_RD}  Invalid choice.{_R}")
        return None


def _choose_attack() -> Optional[str]:
    opts = {
        "1": ("Port Scan",         "TCP SYN scan \u2014 discover open ports & services"),
        "2": ("Brute Force",       "Repeated login attempts until locked or cracked"),
        "3": ("MITM",              "ARP poisoning \u2014 intercept traffic between two nodes"),
        "4": ("SQL Injection",     "Payload battery against HTTP/MySQL \u2014 extract DB data"),
        "5": ("Lateral Movement",  "Pivot from a foothold to compromise adjacent nodes"),
        "6": ("DoS Attack",        "Traffic flood \u2014 degrade service availability"),
        "7": ("Reconnaissance",    "Network-wide host & service discovery"),
    }
    _section("SELECT ATTACK TYPE")
    for k, (name, desc) in opts.items():
        print(f"  [{k}] {_B}{name}{_R} \u2014 {desc}")
    print("  [0] Back")
    c = input(f"\n{_B}  Enter number: {_R}").strip()
    return None if c == "0" else (opts.get(c, (None,))[0])


def _show_scan(r: attack_engine.PortScanResult):
    _section(f"PORT SCAN RESULTS \u2014 {r.target_ip}")
    print(f"  OS Guess   : {r.os_guess}")
    print(f"  Risk Level : {_risk_col(r.risk_level)}{r.risk_level}{_R}\n")
    if r.open_ports:
        print(f"  {_B}OPEN PORTS:{_R}")
        for port, svc in r.open_ports:
            print(f"    {_G}\u25cf{_R} {port:5d}/tcp  {svc}")
    if r.filtered_ports[:5]:
        print(f"\n  {_B}FILTERED (first 5):{_R}")
        for p in r.filtered_ports[:5]:
            print(f"    {_Y}\u25cb{_R} {p:5d}/tcp  filtered")
    print(f"\n  Closed: {len(r.closed_ports)}")


def _show_brute(r: attack_engine.BruteForceResult):
    _section(f"BRUTE FORCE RESULTS \u2014 {r.target_ip} [{r.service}]")
    print(f"  Attempts   : {r.attempts}")
    print(f"  Risk Level : {_risk_col(r.risk_level)}{r.risk_level}{_R}")
    if r.success:
        print(f"\n  {_RD}{_B}CREDENTIALS CRACKED: {r.cracked_credential}{_R}")
    elif r.locked:
        print(f"\n  {_G}\u2713 Account locked (defence successful){_R}")
    else:
        print(f"\n  {_G}\u2713 Brute force failed \u2014 no breach{_R}")


def _show_dos(r: attack_engine.DoSResult):
    _section(f"DoS RESULTS \u2014 {r.target_ip}")
    print(f"  Packets Sent    : {r.packets_sent:,}")
    print(f"  Peak Response   : {r.peak_response_ms} ms")
    print(f"  Service Degraded: {(_RD if r.service_degraded else _G)}{'YES' if r.service_degraded else 'NO'}{_R}")
    print(f"  Service Down    : {(_RD if r.service_down else _G)}{'YES' if r.service_down else 'NO'}{_R}")
    print(f"  IDS Triggered   : {'YES' if r.ids_triggered else 'NO'}")
    print(f"  Risk Level      : {_risk_col(r.risk_level)}{r.risk_level}{_R}")


def _show_recon(r: attack_engine.ReconResult):
    _section("RECONNAISSANCE RESULTS")
    print(f"  Live Hosts: {len(r.live_hosts)}")
    for ip in r.live_hosts:
        info = r.host_info[ip]
        print(f"\n  {_B}{_C}{ip}{_R}  {info['hostname']}  ({info['os']})")
        print(f"    Firewall: {'Enabled' if info['firewall'] else _RD + 'DISABLED' + _R}")
        for s in info["services"]:
            print(f"    \u251c\u2500 {s['port']:5d}/{s['service']:8s}  {s['version']}")


def _show_mitm(r: attack_engine.MITMResult):
    _section(f"MITM RESULTS \u2014 {r.target_ip} (via {r.gateway_ip})")
    print(f"  Packets Intercepted : {r.intercepted_packets:,}")
    print(f"  ARP Detected        : {(_RD if r.arp_detected else _G)}{'YES' if r.arp_detected else 'NO'}{_R}")
    print(f"  HTTP Injections     : {r.injected_payloads}")
    print(f"  Risk Level          : {_risk_col(r.risk_level)}{r.risk_level}{_R}")
    if r.captured_credentials:
        print(f"\n  {_RD}{_B}CAPTURED CREDENTIALS:{_R}")
        for cred in r.captured_credentials:
            print(f"    {_RD}\u25cf{_R}  {cred}")
    else:
        print(f"\n  {_G}\u2713 No cleartext credentials captured{_R}")


def _show_sqli(r: attack_engine.SQLInjectionResult):
    _section(f"SQL INJECTION RESULTS \u2014 {r.target_ip} [{r.service}:{r.port}]")
    print(f"  Payloads Tried   : {r.payloads_tried}")
    print(f"  Vulnerable       : {(_RD if r.vulnerable else _G)}{'YES' if r.vulnerable else 'NO'}{_R}")
    if r.bypass_used:
        print(f"  WAF Bypass Used  : {_Y}{r.bypass_used}{_R}")
    print(f"  Records Extracted: {r.extracted_records:,}")
    print(f"  Risk Level       : {_risk_col(r.risk_level)}{r.risk_level}{_R}")
    if r.extracted_tables:
        print(f"\n  {_RD}{_B}EXFILTRATED TABLES:{_R}")
        for tbl in r.extracted_tables:
            print(f"    {_RD}\u25cf{_R}  {tbl}")
    else:
        print(f"\n  {_G}\u2713 No data extracted{_R}")


def _show_lateral(r: attack_engine.LateralMovementResult):
    _section(f"LATERAL MOVEMENT RESULTS \u2014 pivot: {r.pivot_ip}")
    print(f"  Reachable Hosts  : {len(r.reachable_ips)}")
    print(f"  Compromised Hosts: {(_RD if r.compromised_ips else _G)}{len(r.compromised_ips)}{_R}")
    print(f"  Risk Level       : {_risk_col(r.risk_level)}{r.risk_level}{_R}")
    print(f"\n  {_B}Movement path:{_R}  {' \u2192 '.join(r.movement_path)}")
    if r.compromised_ips:
        print(f"\n  {_RD}{_B}COMPROMISED NODES:{_R}")
        for ip, cred in r.credentials_used.items():
            print(f"    {_RD}\u25cf{_R}  {ip}  ({cred})")
    else:
        print(f"\n  {_G}\u2713 Lateral movement blocked on all nodes{_R}")


def _show_recs(attack: str):
    recs_map = {
        "Port Scan":        ["Close unused ports", "Enable a firewall",
                             "Use port knocking for SSH", "Audit ports regularly"],
        "Brute Force":      ["Lock after 5 failures", "Use MFA",
                             "Add CAPTCHA to login forms", "Enforce strong passwords"],
        "DoS Attack":       ["Rate-limit traffic", "Deploy a WAF",
                             "Use CDN with DDoS protection", "Alert on traffic spikes"],
        "Reconnaissance":   ["Enable firewall to hide banners", "Disable unused services",
                             "Suppress version info", "Use VLANs"],
        "MITM":             ["Use TLS/HTTPS everywhere", "Enable Dynamic ARP Inspection (DAI)",
                             "Deploy 802.1X port authentication", "Monitor ARP tables for anomalies"],
        "SQL Injection":    ["Use parameterised queries (never string-concat SQL)",
                             "Deploy a Web Application Firewall",
                             "Apply least-privilege DB accounts",
                             "Enable IDS signatures for SQLi patterns"],
        "Lateral Movement": ["Segment network with VLANs / micro-segmentation",
                             "Enforce unique credentials per service",
                             "Deploy Privileged Access Management (PAM)",
                             "Alert on internal lateral login attempts"],
    }
    _section("RECOMMENDATIONS")
    for i, r in enumerate(recs_map.get(attack, []), 1):
        print(f"  {i}. {r}")


# ── Demo runner ──────────────────────────────────────────────────────

def run_demo(network: VirtualNetwork, engine: attack_engine.AttackEngine):
    print(f"\n{_B}{_M}{'='*60}\n  AUTO DEMO \u2014 All 7 attacks\n{'='*60}{_R}\n")
    time.sleep(0.5)

    print(f"{_B}[1/7] Reconnaissance{_R}")
    _show_recon(engine.reconnaissance())
    _show_recs("Reconnaissance")
    time.sleep(0.5)

    print(f"\n{_B}[2/7] Port Scan \u2192 192.168.1.20 (no firewall){_R}")
    _show_scan(engine.port_scan("192.168.1.20", (1, 3500)))
    _show_recs("Port Scan")
    time.sleep(0.5)

    print(f"\n{_B}[3/7] Brute Force FTP \u2192 192.168.1.30{_R}")
    _show_brute(engine.brute_force("192.168.1.30", "FTP"))
    _show_recs("Brute Force")
    time.sleep(0.5)

    print(f"\n{_B}[4/7] DoS \u2192 192.168.1.40 (IoT printer){_R}")
    _show_dos(engine.dos_attack("192.168.1.40", duration_seconds=4, packets_per_second=800))
    _show_recs("DoS Attack")
    time.sleep(0.5)

    print(f"\n{_B}[5/7] MITM \u2192 target 192.168.1.30, gateway 192.168.1.10{_R}")
    _show_mitm(engine.mitm_attack("192.168.1.10", "192.168.1.30"))
    _show_recs("MITM")
    time.sleep(0.5)

    print(f"\n{_B}[6/7] SQL Injection \u2192 192.168.1.20 (HTTP){_R}")
    _show_sqli(engine.sql_injection("192.168.1.20", "HTTP"))
    _show_recs("SQL Injection")
    time.sleep(0.5)

    print(f"\n{_B}[7/7] Lateral Movement from 192.168.1.40 (printer foothold){_R}")
    _show_lateral(engine.lateral_movement("192.168.1.40"))
    _show_recs("Lateral Movement")


# ── Interactive CLI ──────────────────────────────────────────────────

def interactive_cli(network: VirtualNetwork, engine: attack_engine.AttackEngine,
                    logger: SimulatorLogger):
    while True:
        print(f"\n{_B}{'='*55}\n  MAIN MENU\n{'-'*55}{_R}")
        print("  [1] View Network Map")
        print("  [2] Launch Attack Simulation")
        print("  [3] View All Logs")
        print("  [4] Log Summary")
        print("  [5] Export Logs (JSON)")
        print("  [6] Run Full Demo")
        print("  [7] Reset Network State")
        print("  [0] Exit")
        print(f"{_B}{'='*55}{_R}")
        c = input(f"{_B}  Choice: {_R}").strip()

        if c == "0":
            print(f"\n{_G}  Exiting. No real network was harmed.{_R}\n")
            break
        elif c == "1":
            _print_network(network)
        elif c == "2":
            target = _choose_target(network)
            if not target:
                continue
            attack = _choose_attack()
            if not attack:
                continue
            print(f"\n{_Y}  Simulating {attack} on {target}\u2026{_R}\n")
            time.sleep(0.3)

            if attack == "Port Scan":
                _show_scan(engine.port_scan(target, (1, 1024)))

            elif attack == "Brute Force":
                node = network.get_node(target)
                svcs = [s.name for s in node.services if s.auth_required]
                print(f"  Services with auth: {', '.join(svcs)}")
                svc = input(f"{_B}  Service name: {_R}").strip().upper()
                if svc not in svcs:
                    print(f"{_RD}  Invalid.{_R}")
                    continue
                _show_brute(engine.brute_force(target, svc))

            elif attack == "MITM":
                others = [ip for ip in network.get_all_ips() if ip != target]
                print(f"\n  {_B}Select gateway (node to spoof):{_R}")
                for i, ip in enumerate(others, 1):
                    print(f"    [{i}] {ip}  ({network.nodes[ip].hostname})")
                try:
                    gw_idx = int(input(f"{_B}  Gateway number: {_R}").strip()) - 1
                    gateway = others[gw_idx]
                except (ValueError, IndexError):
                    print(f"{_RD}  Invalid.{_R}")
                    continue
                _show_mitm(engine.mitm_attack(gateway, target))

            elif attack == "SQL Injection":
                node = network.get_node(target)
                web_svcs = [s.name for s in node.services
                            if s.name in ("HTTP", "MySQL", "HTTPS")]
                if not web_svcs:
                    print(f"{_RD}  No web/DB services on {target}.{_R}")
                    continue
                print(f"  Eligible services: {', '.join(web_svcs)}")
                svc = input(f"{_B}  Service (default HTTP): {_R}").strip().upper() or "HTTP"
                if svc not in web_svcs:
                    print(f"{_RD}  Invalid.{_R}")
                    continue
                _show_sqli(engine.sql_injection(target, svc))

            elif attack == "Lateral Movement":
                _show_lateral(engine.lateral_movement(target))

            elif attack == "DoS Attack":
                _show_dos(engine.dos_attack(target))

            elif attack == "Reconnaissance":
                _show_recon(engine.reconnaissance())

            _show_recs(attack)

        elif c == "3":
            _section("FULL LOG")
            for e in logger.entries:
                print(e)
        elif c == "4":
            logger.summary()
        elif c == "5":
            fname = "sim_logs.json"
            # FIX: encoding='utf-8' prevents UnicodeEncodeError on Windows
            # (charmap codec can't handle the arrow/box-drawing characters).
            # ensure_ascii=False keeps them readable rather than \u-escaped.
            with open(fname, "w", encoding="utf-8") as f:
                json.dump(logger.get_all_dicts(), f, indent=2, ensure_ascii=False)
            print(f"\n{_G}  Logs exported \u2192 {fname}{_R}")
        elif c == "6":
            run_demo(network, engine)
            logger.summary()
        elif c == "7":
            network.reset_all()
            logger.info("SYSTEM", "SYSTEM",
                        "Network state reset — all nodes restored to initial state.")
            print(f"\n{_G}  Network reset complete.{_R}")
        else:
            print(f"{_RD}  Unknown option.{_R}")


# ── Entry point ──────────────────────────────────────────────────────

def main():
    _banner()

    network = VirtualNetwork()
    logger  = SimulatorLogger(log_file="simulator.log")
    engine  = attack_engine.AttackEngine(network, logger)

    logger.info("SYSTEM", "SYSTEM",
                "Network Attack Simulator initialised. Sandbox active.")
    print(f"{_G}  Sandbox ready \u2014 {len(network.nodes)} virtual nodes loaded.")
    print(f"  No real network traffic will be generated.{_R}\n")

    launch_gui(network, logger)
    print()

    if "--demo" in sys.argv:
        run_demo(network, engine)
        logger.summary()
    else:
        interactive_cli(network, engine, logger)


if __name__ == "__main__":
    main()