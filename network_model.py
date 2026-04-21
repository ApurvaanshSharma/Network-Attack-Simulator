"""
network_model.py
================
Virtual network topology — nodes, services, firewall & IDS state.
Everything lives in Python dicts and dataclasses.
No sockets, no OS networking calls.

Changes vs original:
  - VirtualNode.__post_init__ snapshots mutable runtime fields
    (now includes deep-copy of services list)
  - VirtualNode.reset() restores node to initial state
    (now also restores services via deep-copy)
  - VirtualNetwork.reset_all() resets every node at once
  - to_json() exposes auth, version, online, dos_load, response_ms
    so the web GUI can display live node health without a separate endpoint

Fix:
  - __post_init__ now deep-copies self.services so reset() can fully
    restore service state if any attack mutates a VirtualService attribute.
"""

import copy
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class VirtualService:
    """A single service running on a virtual node (e.g. SSH on port 22)."""
    name: str
    port: int
    version: str
    vulnerable: bool
    auth_required: bool = True
    max_login_attempts: int = 5


@dataclass
class VirtualNode:
    """
    A simulated machine in the virtual network.

    Runtime state (dos_load, locked_accounts, response_time_ms) is mutated
    during attack simulations.  Call reset() to restore the initial state.
    """
    ip: str
    hostname: str
    os: str
    services: List[VirtualService] = field(default_factory=list)
    firewall_enabled: bool = True
    ids_enabled: bool = True
    is_online: bool = True
    locked_accounts: Dict[str, int] = field(default_factory=dict)
    dos_load: float = 0.0
    response_time_ms: int = 20

    def __post_init__(self):
        # Snapshot the initial values of every field that attacks (or the
        # future node-editor) can mutate, so reset() restores them fully.
        self._init_dos_load    = self.dos_load
        self._init_response_ms = self.response_time_ms
        self._init_is_online   = self.is_online
        self._init_firewall    = self.firewall_enabled
        self._init_ids         = self.ids_enabled
        # Deep-copy services so reset() can restore them even if an attack
        # mutates a VirtualService attribute (e.g. patching a vulnerability).
        self._init_services    = copy.deepcopy(self.services)

    # ── State management ────────────────────────────────────────────

    def reset(self) -> None:
        """Restore all runtime state to initial values."""
        self.dos_load         = self._init_dos_load
        self.response_time_ms = self._init_response_ms
        self.is_online        = self._init_is_online
        self.firewall_enabled = self._init_firewall
        self.ids_enabled      = self._init_ids
        self.locked_accounts  = {}
        # Restore services to their original state via a fresh deep-copy
        # so successive resets each get an independent copy.
        self.services         = copy.deepcopy(self._init_services)

    # ── Helpers ─────────────────────────────────────────────────────

    def get_open_ports(self) -> List[int]:
        return [s.port for s in self.services]

    def get_service_on_port(self, port: int) -> Optional[VirtualService]:
        return next((s for s in self.services if s.port == port), None)

    def is_port_filtered(self, port: int) -> bool:
        return self.firewall_enabled and port not in self.get_open_ports()


class VirtualNetwork:
    """
    Complete in-memory network.  Nodes keyed by IP string.
    The default topology mimics a small corporate environment.
    """

    def __init__(self):
        self.nodes: Dict[str, VirtualNode] = {}
        self._build_default_network()

    def _build_default_network(self):
        # Linux web server — firewall ON, IDS ON
        self.nodes["192.168.1.10"] = VirtualNode(
            ip="192.168.1.10", hostname="web-server-01", os="Ubuntu 20.04 LTS",
            services=[
                VirtualService("SSH",   22,  "OpenSSH 7.9",         vulnerable=False),
                VirtualService("HTTP",  80,  "Apache 2.4.41",       vulnerable=True),
                VirtualService("HTTPS", 443, "Apache 2.4.41 (TLS)", vulnerable=False),
            ],
            firewall_enabled=True, ids_enabled=True,
        )
        # Windows file server — NO firewall (misconfigured)
        # HTTP moved to port 8081 to avoid conflict with GUI on 5000.
        self.nodes["192.168.1.20"] = VirtualNode(
            ip="192.168.1.20", hostname="file-server-01", os="Windows Server 2019",
            services=[
                VirtualService("SMB",  445,  "Samba 4.11",  vulnerable=True,  auth_required=True),
                VirtualService("RDP",  3389, "MS RDP 10.0", vulnerable=False, auth_required=True),
                VirtualService("HTTP", 8081, "IIS 10.0",    vulnerable=False, auth_required=False),
            ],
            firewall_enabled=False, ids_enabled=True,
        )
        # CentOS database server — NO IDS (bad practice)
        self.nodes["192.168.1.30"] = VirtualNode(
            ip="192.168.1.30", hostname="db-server-01", os="CentOS 8",
            services=[
                VirtualService("MySQL", 3306, "MySQL 8.0.21", vulnerable=True,  auth_required=True),
                VirtualService("SSH",   22,   "OpenSSH 8.0",  vulnerable=False, auth_required=True),
                VirtualService("FTP",   21,   "vsftpd 3.0.3", vulnerable=True,  auth_required=True),
            ],
            firewall_enabled=True, ids_enabled=False,
        )
        # IoT printer — no firewall, no IDS, multiple vulns
        self.nodes["192.168.1.40"] = VirtualNode(
            ip="192.168.1.40", hostname="office-printer", os="Embedded Linux (CUPS)",
            services=[
                VirtualService("HTTP",   80,  "HP Web JetAdmin", vulnerable=True,  auth_required=False),
                VirtualService("TELNET", 23,  "BusyBox telnetd", vulnerable=True,  auth_required=False),
                VirtualService("LPD",    515, "CUPS 2.3.1",      vulnerable=False, auth_required=False),
            ],
            firewall_enabled=False, ids_enabled=False,
        )

    # ── Network-level operations ─────────────────────────────────────

    def reset_all(self) -> None:
        """Reset every node to its initial runtime state."""
        for node in self.nodes.values():
            node.reset()

    def get_node(self, ip: str) -> Optional[VirtualNode]:
        return self.nodes.get(ip)

    def get_all_ips(self) -> List[str]:
        return list(self.nodes.keys())

    def add_node(self, node: VirtualNode) -> None:
        self.nodes[node.ip] = node

    def to_json(self) -> dict:
        """
        Serialise the full network for the web GUI's /api/nodes endpoint.
        Includes live runtime fields (dos_load, response_ms, online) so the
        dashboard can show node health without a separate polling endpoint.
        """
        result = {}
        for ip, node in self.nodes.items():
            result[ip] = {
                "host":        node.hostname,
                "os":          node.os,
                "fw":          node.firewall_enabled,
                "ids":         node.ids_enabled,
                "online":      node.is_online,
                "dos_load":    round(node.dos_load, 3),
                "response_ms": node.response_time_ms,
                "svcs": [
                    {
                        "port":    s.port,
                        "name":    s.name,
                        "version": s.version,
                        "vuln":    s.vulnerable,
                        "auth":    s.auth_required,
                    }
                    for s in node.services
                ],
            }
        return result
