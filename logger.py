"""
logger.py
=========
Timestamped, colour-coded event logging system.
Levels: INFO · WARNING · ALERT · CRITICAL

All entries are stored in memory for the session and can be
exported to JSON or printed as a summary via SimulatorLogger.

Changes vs original:
  - Added SimulatorLogger.clear() to wipe entries and reset the timer
    (used by the /api/reset endpoint in gui.py)

Fix (v2):
  - The log file is now opened once in __init__ and kept open for the
    lifetime of the logger, rather than being opened and closed on every
    single _log() call.  During a fast port scan (~1 024 ports at
    SCAN_DELAY=0.001 s) the old approach created ~1 024 file handles per
    second — wasteful and unnecessary.
  - Each write is followed by flush() so real-time tail / monitoring still
    works correctly.
  - clear() now truncates the open file handle instead of leaving stale
    content on disk that would be re-read by any external tail process.

Fix (v3):
  - stdout is reconfigured to UTF-8 at import time so the → arrow and
    other non-ASCII characters don't raise a UnicodeEncodeError on Windows
    (where the default console codec is 'charmap' / cp1252).
  - log file is now opened with encoding='utf-8' for the same reason.
"""

import sys
import time
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import List, Optional

# ── Ensure stdout speaks UTF-8 on Windows (no-op on Linux/macOS) ─────
# reconfigure() is available from Python 3.7+; the errors='replace'
# fallback means any unencodable glyph is printed as '?' rather than
# crashing the whole process.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


class LogLevel(Enum):
    INFO     = "INFO"
    WARNING  = "WARNING"
    ALERT    = "ALERT"
    CRITICAL = "CRITICAL"


# ANSI terminal colours
_COL = {
    LogLevel.INFO:     "\033[36m",   # cyan
    LogLevel.WARNING:  "\033[33m",   # yellow
    LogLevel.ALERT:    "\033[31m",   # red
    LogLevel.CRITICAL: "\033[35m",   # magenta
}
_RST  = "\033[0m"
_BOLD = "\033[1m"


@dataclass
class LogEntry:
    timestamp: str
    level: LogLevel
    source_ip: str
    target_ip: str
    message: str
    attack_type: str = ""

    def __str__(self):
        col = _COL.get(self.level, "")
        return (f"{_BOLD}[{self.timestamp}]{_RST} "
                f"{col}{_BOLD}[{self.level.value:8s}]{_RST} "
                f"({self.source_ip} \u2192 {self.target_ip}) {self.message}")

    def to_dict(self) -> dict:
        return {
            "timestamp":   self.timestamp,
            "level":       self.level.value,
            "source_ip":   self.source_ip,
            "target_ip":   self.target_ip,
            "message":     self.message,
            "attack_type": self.attack_type,
        }


class SimulatorLogger:
    """Central log store. Prints to terminal and optionally writes to a file.

    The underlying file (if any) is opened once at construction time and
    kept open until the process exits, avoiding repeated open/close cycles
    on every log call.
    """

    def __init__(self, log_file: Optional[str] = None):
        self.entries: List[LogEntry] = []
        self.log_file = log_file
        self._start = time.time()
        # Open the file once and keep the handle alive for the session.
        # encoding='utf-8' is explicit so the → arrow and other non-ASCII
        # characters in log messages never raise UnicodeEncodeError on
        # Windows, regardless of the system default code page.
        self._fh = open(log_file, "a", encoding="utf-8") if log_file else None

    # ── Internal helpers ──────────────────────────────────────────────

    def _now(self) -> str:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    def _log(self, level: LogLevel, src: str, tgt: str, msg: str, attack: str = "") -> None:
        entry = LogEntry(self._now(), level, src, tgt, msg, attack)
        self.entries.append(entry)
        print(str(entry))
        if self._fh:
            self._fh.write(
                f"[{entry.timestamp}] [{entry.level.value}] ({src} -> {tgt}) {msg}\n"
            )
            # Flush immediately so external readers (tail -f, etc.) see each
            # entry as it is written, not in large buffered batches.
            self._fh.flush()

    # ── Public logging API ────────────────────────────────────────────

    def info    (self, src, tgt, msg, atk=""): self._log(LogLevel.INFO,     src, tgt, msg, atk)
    def warning (self, src, tgt, msg, atk=""): self._log(LogLevel.WARNING,  src, tgt, msg, atk)
    def alert   (self, src, tgt, msg, atk=""): self._log(LogLevel.ALERT,    src, tgt, msg, atk)
    def critical(self, src, tgt, msg, atk=""): self._log(LogLevel.CRITICAL, src, tgt, msg, atk)

    # ── State management ──────────────────────────────────────────────

    def clear(self) -> None:
        """Wipe all in-memory log entries, reset the session timer, and
        truncate the on-disk log file so that a fresh reconnect or tail
        does not replay pre-reset entries."""
        self.entries.clear()
        self._start = time.time()
        if self._fh:
            self._fh.seek(0)
            self._fh.truncate()

    # ── Export / reporting ────────────────────────────────────────────

    def get_all_dicts(self) -> List[dict]:
        return [e.to_dict() for e in self.entries]

    def summary(self) -> None:
        counts = {lvl: 0 for lvl in LogLevel}
        for e in self.entries:
            counts[e.level] += 1
        print(f"\n{_BOLD}{'='*50}\n  LOG SUMMARY\n{'='*50}{_RST}")
        for lvl, cnt in counts.items():
            print(f"  {_COL[lvl]}{lvl.value:10s}{_RST}: {cnt} entries")
        print(f"{_BOLD}  TOTAL      : {len(self.entries)} entries")
        print(f"  Session    : {time.time() - self._start:.1f}s{_RST}")
        print(f"{_BOLD}{'='*50}{_RST}\n")