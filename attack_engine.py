"""
attack_engine.py
================
Seven attack simulators, all running entirely in-memory.
No packets are sent. No OS networking calls are made.

Original attacks:
    1. port_scan()        — TCP SYN scan simulation
    2. brute_force()      — repeated login attempts
    3. dos_attack()       — traffic flood / response degradation
    4. reconnaissance()   — host & service discovery

Phase 2 attacks:
    5. mitm_attack()      — ARP poisoning + traffic interception + HTTP injection
    6. sql_injection()    — SQLi payload battery + WAF bypass + data extraction
    7. lateral_movement() — credential-reuse pivot across compromised nodes

Fixes applied:
    brute_force():
      - success_at used randint(3, max-1) which raises ValueError when
        max_login_attempts <= 3.  Lower bound is now 1 and guarded so
        max_idx >= 1 before calling randint.
      - success_at was bounded by max_login_attempts-1, not by the actual
        password list length (15).  With max_login_attempts > 15 the loop
        would exhaust all passwords without triggering success on a
        vulnerable service.  Now clamped to min(max_attempts-1, len(COMMON_PASSWORDS)-1).
    dos_attack():
      - Adds a warning log when a node already has residual load from a
        prior run so the examiner understands why it degrades fast.
"""

import random
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from network_model import VirtualNetwork
from logger import SimulatorLogger
from config import (
    ATTACKER_IP,
    SCAN_DELAY, BRUTE_DELAY, DOS_WAVE_DELAY, RECON_DELAY,
    MITM_DELAY, MITM_CYCLES,
    SQLI_DELAY, SQLI_PAYLOADS, SQLI_BYPASS_PAYLOADS, SIMULATED_DB_TABLES,
    LATERAL_DELAY, LATERAL_CREDS,
    COMMON_PASSWORDS, WEAK_CREDENTIALS,
)


# ── Result dataclasses ───────────────────────────────────────────────

@dataclass
class PortScanResult:
    target_ip: str
    open_ports: List[Tuple[int, str]]
    closed_ports: List[int]
    filtered_ports: List[int]
    os_guess: str
    risk_level: str


@dataclass
class BruteForceResult:
    target_ip: str
    service: str
    port: int
    attempts: int
    success: bool
    locked: bool
    cracked_credential: str
    risk_level: str


@dataclass
class DoSResult:
    target_ip: str
    packets_sent: int
    peak_response_ms: int
    service_degraded: bool
    service_down: bool
    ids_triggered: bool
    risk_level: str


@dataclass
class ReconResult:
    live_hosts: List[str]
    host_info: Dict[str, dict]
    risk_level: str


@dataclass
class MITMResult:
    gateway_ip: str
    target_ip: str
    intercepted_packets: int
    captured_credentials: List[str]
    injected_payloads: int
    arp_detected: bool
    risk_level: str


@dataclass
class SQLInjectionResult:
    target_ip: str
    service: str
    port: int
    payloads_tried: int
    vulnerable: bool
    extracted_tables: List[str]
    extracted_records: int
    bypass_used: str
    risk_level: str


@dataclass
class LateralMovementResult:
    pivot_ip: str
    reachable_ips: List[str]
    compromised_ips: List[str]
    credentials_used: Dict[str, str]
    movement_path: List[str]
    risk_level: str


# ── Attack Engine ────────────────────────────────────────────────────

class AttackEngine:
    """
    All attack simulations operate purely on VirtualNetwork data.
    No OS/network calls are made anywhere in this class.
    """

    def __init__(self, network: VirtualNetwork, logger: SimulatorLogger):
        self.network = network
        self.logger  = logger

    # ── 1. Port Scan ────────────────────────────────────────────────
    def port_scan(self, target_ip: str,
                  port_range: Tuple[int, int] = (1, 1024)) -> PortScanResult:
        """
        Mimics a TCP SYN scan.
        Checks VirtualNode.services to decide open / filtered / closed.
        Firewall flag causes non-service ports to appear filtered.
        """
        node = self.network.get_node(target_ip)
        if not node or not node.is_online:
            self.logger.alert(ATTACKER_IP, target_ip, "Host unreachable.", "port_scan")
            return PortScanResult(target_ip, [], [], [], "Unknown", "Low")

        self.logger.info(ATTACKER_IP, target_ip,
                         f"Port scan initiated. Range: {port_range[0]}-{port_range[1]}",
                         "port_scan")

        open_ports:     List[Tuple[int, str]] = []
        closed_ports:   List[int] = []
        filtered_ports: List[int] = []
        open_set = {s.port: s.name for s in node.services}

        for port in range(port_range[0], port_range[1] + 1):
            time.sleep(SCAN_DELAY)
            if port in open_set:
                open_ports.append((port, open_set[port]))
                self.logger.info(ATTACKER_IP, target_ip,
                                 f"Port {port}/tcp OPEN  [{open_set[port]}]", "port_scan")
            elif node.firewall_enabled:
                filtered_ports.append(port)
            else:
                closed_ports.append(port)

        if node.ids_enabled and open_ports:
            self.logger.alert(target_ip, target_ip,
                              f"IDS ALERT: Port scan from {ATTACKER_IP}. "
                              f"{len(open_ports)} open ports found.", "port_scan")
        if node.firewall_enabled:
            self.logger.warning(target_ip, target_ip,
                                "Firewall filtered most ports — attacker has limited info.",
                                "port_scan")

        vuln_names = {s.name for s in node.services if s.vulnerable}
        open_names = {n for _, n in open_ports}
        risk = ("High"   if any(n in vuln_names for n in open_names) else
                "Medium" if len(open_ports) > 3 else "Low")

        self.logger.info(ATTACKER_IP, target_ip,
                         f"Scan complete. Open:{len(open_ports)} "
                         f"Filtered:{len(filtered_ports)} Closed:{len(closed_ports)}. Risk:{risk}",
                         "port_scan")
        return PortScanResult(target_ip, open_ports, closed_ports,
                              filtered_ports, node.os, risk)

    # ── 2. Brute Force ──────────────────────────────────────────────
    def brute_force(self, target_ip: str, service_name: str,
                    seed: Optional[int] = None) -> BruteForceResult:
        """
        Tries COMMON_PASSWORDS one by one.
        Locks the account after max_login_attempts failures.
        Succeeds early if the service is marked vulnerable.

        seed — optional integer for reproducible random outcomes (useful in tests)

        Fixes:
          1. success_at is now bounded by both max_login_attempts-1 AND
             len(COMMON_PASSWORDS)-1, preventing the case where success_at
             exceeds the password list and the crack never triggers.
          2. Lower bound of randint changed from 3 to 1 so services with
             small max_login_attempts values (<=3) no longer raise ValueError.
          3. Guard added so randint is only called when max_idx >= 1.
        """
        node = self.network.get_node(target_ip)
        if not node or not node.is_online:
            self.logger.alert(ATTACKER_IP, target_ip, "Target offline.", "brute_force")
            return BruteForceResult(target_ip, service_name, 0, 0, False, False, "", "Low")

        svc = next((s for s in node.services if s.name == service_name), None)
        if not svc:
            self.logger.warning(ATTACKER_IP, target_ip,
                                f"Service {service_name} not found.", "brute_force")
            return BruteForceResult(target_ip, service_name, 0, 0, False, False, "", "Low")

        self.logger.info(ATTACKER_IP, target_ip,
                         f"Brute force started: {service_name} (port {svc.port})", "brute_force")

        rng = random.Random(seed)
        weak_user, weak_pass = WEAK_CREDENTIALS.get(service_name, ("admin", "admin"))

        # FIX: clamp success_at to the actual password list length so it is
        # always a valid index even if max_login_attempts > len(COMMON_PASSWORDS).
        # Lower bound is 1 (was 3) so services with max_login_attempts <= 3
        # no longer raise ValueError from randint(3, value < 3).
        max_idx = min(svc.max_login_attempts - 1, len(COMMON_PASSWORDS) - 1)
        success_at = rng.randint(1, max_idx) if svc.vulnerable and max_idx >= 1 else -1

        attempts = 0
        success = locked = False
        cracked = ""

        for i, pwd in enumerate(COMMON_PASSWORDS):
            attempts += 1
            user = "root" if service_name in ("SSH", "FTP", "MySQL") else "admin"
            time.sleep(BRUTE_DELAY)
            self.logger.warning(ATTACKER_IP, target_ip,
                                f"Login attempt #{attempts}: {user}/{pwd} \u2192 FAILED",
                                "brute_force")

            key = f"{service_name}:{user}"
            node.locked_accounts[key] = node.locked_accounts.get(key, 0) + 1

            # SUCCESS check runs BEFORE lockout so that when both conditions
            # would trigger on the same iteration, the crack is recorded
            # rather than silently discarded by the lockout break.
            if svc.vulnerable and i == success_at:
                success = True
                cracked = f"{weak_user}:{weak_pass}"
                self.logger.critical(ATTACKER_IP, target_ip,
                                     f"CREDENTIAL COMPROMISED! {service_name}: {cracked}",
                                     "brute_force")
                break

            if node.locked_accounts[key] >= svc.max_login_attempts:
                locked = True
                self.logger.alert(target_ip, target_ip,
                                  f"Account '{user}' LOCKED on {service_name} after "
                                  f"{node.locked_accounts[key]} attempts.", "brute_force")
                if node.ids_enabled:
                    self.logger.alert(target_ip, target_ip,
                                      f"IDS ALERT: Brute force from {ATTACKER_IP}!", "brute_force")
                break

        risk = "Critical" if success else ("High" if locked else "Medium")
        self.logger.info(ATTACKER_IP, target_ip,
                         f"Brute force done. Attempts:{attempts} Success:{success} "
                         f"Locked:{locked}. Risk:{risk}", "brute_force")
        return BruteForceResult(target_ip, service_name, svc.port,
                                attempts, success, locked, cracked, risk)

    # ── 3. DoS Attack ───────────────────────────────────────────────
    def dos_attack(self, target_ip: str,
                   duration_seconds: int = 5,
                   packets_per_second: int = 500) -> DoSResult:
        """
        Increments node.dos_load and node.response_time_ms each wave.
        Triggers IDS alert above 40% load; marks service down at 90%.

        Fix: Logs a warning if the node already has residual dos_load from
        a prior attack so the examiner understands why degradation is fast.
        """
        node = self.network.get_node(target_ip)
        if not node or not node.is_online:
            self.logger.alert(ATTACKER_IP, target_ip, "Target offline.", "dos")
            return DoSResult(target_ip, 0, 0, False, False, False, "Low")

        # Warn if there is leftover load from a previous run so the
        # behaviour (fast ramp to 90%) is visible and explainable.
        if node.dos_load > 0:
            self.logger.warning(ATTACKER_IP, target_ip,
                                f"Node already at {node.dos_load:.0%} load from a prior "
                                f"attack — degradation will progress faster. "
                                f"Use 'Reset nodes' to restore baseline.", "dos")

        total = duration_seconds * packets_per_second
        self.logger.info(ATTACKER_IP, target_ip,
                         f"DoS started. Simulating {total:,} packets over {duration_seconds}s.",
                         "dos")

        peak = node.response_time_ms
        ids_hit = False
        rng = random.Random()

        for wave in range(1, duration_seconds + 1):
            time.sleep(DOS_WAVE_DELAY)
            inc = rng.uniform(0.15, 0.25)
            node.dos_load = min(node.dos_load + inc, 1.0)
            node.response_time_ms = int(node.response_time_ms * (1 + inc * 5))
            peak = max(peak, node.response_time_ms)
            self.logger.warning(ATTACKER_IP, target_ip,
                                f"Flood wave {wave}/{duration_seconds}: "
                                f"~{packets_per_second} pkt/s | Load:{node.dos_load:.0%} | "
                                f"Response:{node.response_time_ms}ms", "dos")

            if node.ids_enabled and node.dos_load > 0.4 and not ids_hit:
                ids_hit = True
                self.logger.alert(target_ip, target_ip,
                                  f"IDS ALERT: Possible DoS from {ATTACKER_IP}! "
                                  f"Activating throttling.", "dos")

            if node.dos_load >= 0.9:
                self.logger.critical(ATTACKER_IP, target_ip,
                                     f"SERVICE DOWN: {target_ip} unresponsive! "
                                     f"Response: {node.response_time_ms}ms", "dos")
                break

        degraded = node.dos_load > 0.3
        down     = node.dos_load >= 0.9
        risk = "Critical" if down else ("High" if degraded else "Medium")
        self.logger.info(ATTACKER_IP, target_ip,
                         f"DoS done. Packets:{total:,} Peak:{peak}ms Risk:{risk}", "dos")
        return DoSResult(target_ip, total, peak, degraded, down, ids_hit, risk)

    # ── 4. Reconnaissance ───────────────────────────────────────────
    def reconnaissance(self) -> ReconResult:
        """
        Network-wide host discovery + service fingerprinting.
        Firewall hides version strings and hostname from the attacker.
        """
        self.logger.info(ATTACKER_IP, "255.255.255.255",
                         "Reconnaissance started. Pinging all hosts...", "recon")
        live: List[str] = []
        info: Dict[str, dict] = {}

        for ip, node in self.network.nodes.items():
            time.sleep(RECON_DELAY)
            if node.is_online:
                live.append(ip)
                svcs = [
                    {"port": s.port, "service": s.name,
                     "version": s.version if not node.firewall_enabled else "Unknown"}
                    for s in node.services
                ]
                info[ip] = {
                    "hostname": node.hostname if not node.firewall_enabled else ip,
                    "os":       node.os       if not node.firewall_enabled else "Unknown",
                    "services": svcs,
                    "firewall": node.firewall_enabled,
                    "ids":      node.ids_enabled,
                }
                self.logger.info(ATTACKER_IP, ip,
                                 f"Host ALIVE: {ip} ({node.hostname}) — "
                                 f"{len(svcs)} services detected.", "recon")
            else:
                self.logger.info(ATTACKER_IP, ip, f"Host {ip} offline.", "recon")

        self.logger.info(ATTACKER_IP, "255.255.255.255",
                         f"Recon done. {len(live)}/{len(self.network.nodes)} hosts alive.", "recon")
        risk = "High" if len(live) > 2 else "Medium"
        return ReconResult(live, info, risk)

    # ── 5. MITM Attack ──────────────────────────────────────────────
    def mitm_attack(self, gateway_ip: str, target_ip: str) -> MITMResult:
        """
        Simulates a man-in-the-middle attack via ARP poisoning.

        Phase 1 — ARP poison: attacker announces itself as both the gateway
                  (to the target) and as the target (to the gateway), so all
                  traffic between them flows through the attacker.
        Phase 2 — Intercept: cycle through MITM_CYCLES packet capture rounds.
                  Unencrypted services (HTTP, FTP, TELNET, MySQL) leak cleartext
                  credentials; encrypted services (HTTPS, SSH) remain opaque.
        Phase 3 — Inject: if the target runs a vulnerable HTTP service, insert
                  a malicious redirect into an HTTP response.

        IDS on either node detects the anomalous ARP storm.
        """
        gateway = self.network.get_node(gateway_ip)
        target  = self.network.get_node(target_ip)

        if not gateway or not gateway.is_online:
            self.logger.alert(ATTACKER_IP, gateway_ip, "Gateway unreachable.", "mitm")
            return MITMResult(gateway_ip, target_ip, 0, [], 0, False, "Low")
        if not target or not target.is_online:
            self.logger.alert(ATTACKER_IP, target_ip, "Target unreachable.", "mitm")
            return MITMResult(gateway_ip, target_ip, 0, [], 0, False, "Low")

        self.logger.info(ATTACKER_IP, target_ip,
                         f"MITM attack started. Positioning between "
                         f"{target_ip} \u2194 {gateway_ip}", "mitm")

        # ── Phase 1: ARP Poisoning ───────────────────────────────────
        arp_detected = False
        time.sleep(MITM_DELAY)
        self.logger.warning(ATTACKER_IP, gateway_ip,
                            f"ARP POISON \u2192 {gateway_ip}: "
                            f"'{target_ip} is at {ATTACKER_IP}' (gratuitous ARP)", "mitm")
        time.sleep(MITM_DELAY)
        self.logger.warning(ATTACKER_IP, target_ip,
                            f"ARP POISON \u2192 {target_ip}: "
                            f"'{gateway_ip} is at {ATTACKER_IP}' (gratuitous ARP)", "mitm")

        if gateway.ids_enabled or target.ids_enabled:
            arp_detected = True
            detector = gateway_ip if gateway.ids_enabled else target_ip
            self.logger.alert(detector, detector,
                              f"IDS ALERT: Anomalous ARP traffic from {ATTACKER_IP}. "
                              f"Possible MITM / ARP spoofing detected.", "mitm")

        # ── Phase 2: Traffic Interception ────────────────────────────
        intercepted       = 0
        captured_creds: List[str] = []
        UNENCRYPTED = {"HTTP", "FTP", "TELNET", "MySQL", "SMB"}
        ENCRYPTED   = {"HTTPS", "SSH"}
        target_svc_names  = {s.name for s in target.services}
        rng = random.Random()

        for cycle in range(1, MITM_CYCLES + 1):
            time.sleep(MITM_DELAY)
            pkt_count   = rng.randint(40, 120)
            intercepted += pkt_count
            exposed   = target_svc_names & UNENCRYPTED
            encrypted = target_svc_names & ENCRYPTED

            if exposed:
                svc_name = rng.choice(sorted(exposed))
                self.logger.warning(ATTACKER_IP, target_ip,
                                    f"Cycle {cycle}/{MITM_CYCLES}: {pkt_count} pkts captured. "
                                    f"Cleartext {svc_name} traffic visible.", "mitm")
                if cycle == MITM_CYCLES // 2 and svc_name in WEAK_CREDENTIALS:
                    user, pwd = WEAK_CREDENTIALS[svc_name]
                    cred_str = f"{svc_name}:{user}:{pwd}" if pwd else f"{svc_name}:{user}"
                    captured_creds.append(cred_str)
                    self.logger.critical(ATTACKER_IP, target_ip,
                                         f"CREDENTIAL CAPTURED: {cred_str} "
                                         f"(cleartext {svc_name} session)", "mitm")
            elif encrypted:
                self.logger.info(ATTACKER_IP, target_ip,
                                 f"Cycle {cycle}/{MITM_CYCLES}: {pkt_count} pkts relayed. "
                                 f"Traffic TLS-encrypted — content unreadable.", "mitm")
            else:
                self.logger.warning(ATTACKER_IP, target_ip,
                                    f"Cycle {cycle}/{MITM_CYCLES}: {pkt_count} pkts relayed. "
                                    f"Non-auth protocol traffic.", "mitm")

        # ── Phase 3: HTTP Injection ──────────────────────────────────
        injected = 0
        http_svc = next(
            (s for s in target.services if s.name == "HTTP" and s.vulnerable), None
        )
        if http_svc:
            injected = 1
            self.logger.critical(ATTACKER_IP, target_ip,
                                 f"HTTP INJECTION: Malicious <script> payload inserted into "
                                 f"HTTP response (port {http_svc.port}). "
                                 f"Victim browser redirected to credential-harvesting page.",
                                 "mitm")

        risk = ("Critical" if captured_creds and injected else
                "High"     if captured_creds or injected   else
                "Medium"   if not arp_detected             else "Low")
        self.logger.info(ATTACKER_IP, target_ip,
                         f"MITM done. Packets:{intercepted} Creds:{len(captured_creds)} "
                         f"Injections:{injected} ARP-detected:{arp_detected}. Risk:{risk}",
                         "mitm")
        return MITMResult(gateway_ip, target_ip, intercepted,
                          captured_creds, injected, arp_detected, risk)

    # ── 6. SQL Injection ────────────────────────────────────────────
    def sql_injection(self, target_ip: str,
                      service_name: str = "HTTP") -> SQLInjectionResult:
        """
        Fires SQLI_PAYLOADS at an HTTP or MySQL service.

        Firewall acts as a WAF and blocks standard payloads; SQLI_BYPASS_PAYLOADS
        are attempted as a follow-up (60% bypass success rate).
        IDS triggers after the fourth malformed request.
        If the service is vulnerable (and not WAF-blocked), the attacker
        extracts a simulated schema: table names + approximate row counts.
        """
        node = self.network.get_node(target_ip)
        if not node or not node.is_online:
            self.logger.alert(ATTACKER_IP, target_ip, "Target offline.", "sqli")
            return SQLInjectionResult(target_ip, service_name, 0, 0,
                                      False, [], 0, "", "Low")

        svc = next((s for s in node.services if s.name == service_name), None)
        if not svc:
            self.logger.warning(ATTACKER_IP, target_ip,
                                f"Service '{service_name}' not found on {target_ip}.", "sqli")
            return SQLInjectionResult(target_ip, service_name, 0, 0,
                                      False, [], 0, "", "Low")

        self.logger.info(ATTACKER_IP, target_ip,
                         f"SQL Injection started: {service_name} (port {svc.port})", "sqli")

        waf_active    = node.firewall_enabled
        payloads_tried = 0
        ids_alerted   = False
        bypass_used   = ""
        exploited     = False

        # ── Standard payload battery ─────────────────────────────────
        for i, payload in enumerate(SQLI_PAYLOADS):
            time.sleep(SQLI_DELAY)
            payloads_tried += 1

            if waf_active:
                self.logger.warning(ATTACKER_IP, target_ip,
                                    f"Payload [{i+1:02d}] WAF BLOCKED: {payload[:45]}", "sqli")
            else:
                self.logger.info(ATTACKER_IP, target_ip,
                                 f"Payload [{i+1:02d}] injected: {payload[:45]}", "sqli")

            if node.ids_enabled and i == 3 and not ids_alerted:
                ids_alerted = True
                self.logger.alert(target_ip, target_ip,
                                  f"IDS ALERT: Repeated malformed SQL requests from "
                                  f"{ATTACKER_IP}. Possible injection attack.", "sqli")

            if svc.vulnerable and not waf_active and i >= 2:
                exploited = True
                self.logger.critical(ATTACKER_IP, target_ip,
                                     f"INJECTION SUCCESSFUL: {payload[:50]}", "sqli")
                break

        # ── WAF bypass attempt ───────────────────────────────────────
        if waf_active and svc.vulnerable and not exploited:
            self.logger.warning(ATTACKER_IP, target_ip,
                                "All standard payloads WAF-blocked. "
                                "Switching to encoding/comment bypass...", "sqli")
            rng = random.Random()
            for bp in SQLI_BYPASS_PAYLOADS:
                time.sleep(SQLI_DELAY)
                payloads_tried += 1
                self.logger.warning(ATTACKER_IP, target_ip,
                                    f"Bypass attempt: {bp}", "sqli")
                if rng.random() < 0.60:
                    bypass_used = bp
                    exploited   = True
                    self.logger.critical(ATTACKER_IP, target_ip,
                                         f"WAF BYPASSED with encoding: {bp}", "sqli")
                    break
            if not exploited:
                self.logger.info(ATTACKER_IP, target_ip,
                                 "WAF bypass unsuccessful — all payloads filtered.", "sqli")

        # ── Data extraction ──────────────────────────────────────────
        extracted_tables: List[str] = []
        extracted_records = 0
        if exploited:
            rng = random.Random()
            n_tables = rng.randint(3, len(SIMULATED_DB_TABLES))
            extracted_tables = rng.sample(SIMULATED_DB_TABLES, n_tables)
            extracted_records = rng.randint(500, 50_000)
            self.logger.critical(ATTACKER_IP, target_ip,
                                 f"DATABASE SCHEMA DUMPED: {n_tables} tables found.", "sqli")
            per_table = extracted_records // n_tables
            for tbl in extracted_tables:
                rows = rng.randint(max(1, per_table - 200), per_table + 200)
                self.logger.critical(ATTACKER_IP, target_ip,
                                     f"  TABLE '{tbl}': {rows:,} rows exfiltrated.", "sqli")

        risk = ("Critical" if exploited and extracted_records > 10_000 else
                "High"     if exploited                               else
                "Medium"   if ids_alerted                             else "Low")
        self.logger.info(ATTACKER_IP, target_ip,
                         f"SQLi done. Payloads:{payloads_tried} Exploited:{exploited} "
                         f"Records:{extracted_records:,}. Risk:{risk}", "sqli")
        return SQLInjectionResult(target_ip, service_name, svc.port,
                                  payloads_tried, exploited, extracted_tables,
                                  extracted_records, bypass_used, risk)

    # ── 7. Lateral Movement ─────────────────────────────────────────
    def lateral_movement(self, pivot_ip: str) -> LateralMovementResult:
        """
        Simulates credential-reuse pivoting from an already-compromised node.

        The attacker enumerates every other online node visible from the pivot
        and tries LATERAL_CREDS against each auth service.  A hop succeeds when
        the target service is both auth_required=True and vulnerable=True.

        Firewall presence reduces (but does not eliminate) lateral success:
        packets can still reach open service ports, but the firewall makes the
        attacker less likely to succeed by blocking lateral probing traffic.

        Newly compromised nodes are added to the pivot set so the path can
        chain across the network.
        """
        pivot_node = self.network.get_node(pivot_ip)
        if not pivot_node or not pivot_node.is_online:
            self.logger.alert(ATTACKER_IP, pivot_ip,
                              "Pivot node unreachable — cannot initiate lateral movement.",
                              "lateral")
            return LateralMovementResult(pivot_ip, [], [], {}, [pivot_ip], "Low")

        self.logger.info(ATTACKER_IP, pivot_ip,
                         f"Lateral movement initiated. Foothold: "
                         f"{pivot_ip} ({pivot_node.hostname})", "lateral")

        reachable:   List[str]       = []
        compromised: List[str]       = []
        creds_used:  Dict[str, str]  = {}
        path:        List[str]       = [pivot_ip]
        pivot_list   = [pivot_ip]
        rng          = random.Random()

        for ip, node in self.network.nodes.items():
            if ip in pivot_list or not node.is_online:
                continue

            time.sleep(LATERAL_DELAY)
            reachable.append(ip)
            current_pivot = pivot_list[-1]

            self.logger.info(current_pivot, ip,
                             f"Probing {ip} ({node.hostname}) "
                             f"from pivot [{current_pivot}]", "lateral")

            moved = False
            for svc in node.services:
                if not svc.auth_required or not svc.vulnerable:
                    continue
                cred = LATERAL_CREDS.get(svc.name)
                if not cred:
                    continue

                time.sleep(LATERAL_DELAY)
                user, pwd = cred
                pwd_display = pwd if pwd else "(empty)"
                self.logger.warning(current_pivot, ip,
                                    f"Trying {svc.name}:{svc.port} "
                                    f"with {user}/{pwd_display}", "lateral")

                if node.ids_enabled:
                    self.logger.alert(ip, ip,
                                      f"IDS ALERT: Lateral login attempt on "
                                      f"{svc.name} from {current_pivot}", "lateral")

                success = (not node.firewall_enabled) or (rng.random() < 0.55)
                if success:
                    cred_str = f"{svc.name}:{user}:{pwd}" if pwd else f"{svc.name}:{user}"
                    compromised.append(ip)
                    creds_used[ip] = cred_str
                    path.append(ip)
                    pivot_list.append(ip)
                    self.logger.critical(current_pivot, ip,
                                         f"LATERAL MOVE SUCCESS: {ip} ({node.hostname}) "
                                         f"compromised via {svc.name} — {cred_str}", "lateral")
                    moved = True
                    break
                else:
                    self.logger.info(current_pivot, ip,
                                     f"Firewall blocked lateral access to "
                                     f"{svc.name}:{svc.port}", "lateral")

            if not moved:
                self.logger.info(current_pivot, ip,
                                 f"Could not pivot to {ip} — no accessible "
                                 f"vulnerable auth services.", "lateral")

        risk = ("Critical" if len(compromised) >= 3 else
                "High"     if len(compromised) >= 1 else
                "Medium"   if reachable             else "Low")
        path_str = " \u2192 ".join(path)
        self.logger.info(ATTACKER_IP, pivot_ip,
                         f"Lateral movement complete. "
                         f"Reachable:{len(reachable)} Compromised:{len(compromised)} "
                         f"Path: {path_str}. Risk:{risk}", "lateral")
        return LateralMovementResult(pivot_ip, reachable, compromised,
                                     creds_used, path, risk)
