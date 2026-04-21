"""
gui.py
======
Self-contained web dashboard served by Python's built-in http.server.
Starts automatically in a daemon thread when the app launches.

Key changes vs original:
  - Uses ThreadedHTTPServer (ThreadingMixIn + HTTPServer) so SSE, attack
    execution, and normal GET requests never block each other.
  - GUI and Python engine are now unified: the frontend POSTs to
    /api/attack and the server runs the real AttackEngine method in a
    background thread.  The JS fake-simulation code is gone entirely.
  - GET /api/logs/stream  — Server-Sent Events endpoint.  Streams every
    new LogEntry as it is written, so the terminal updates in real-time.
    Uses Last-Event-ID to resume without re-sending old entries on
    browser reconnect.
  - GET /api/state        — Returns the current attack status + result.
    Frontend polls this at 500ms to detect completion and render results.
  - POST /api/attack      — Validates the request, rejects if busy (409),
    otherwise launches the attack in a daemon thread and returns immediately.
  - POST /api/reset       — Calls network.reset_all(), clears the logger
    (so reconnecting browsers don't replay stale logs), and writes a
    reset sentinel to the log so the live feed reflects it.
  - Service selector (brute force) shown dynamically based on target node.
  - Reset button added to the target bar.

Fixes applied:
  - /api/reset now calls _logger.clear() before writing the sentinel so
    a browser that reconnects after reset gets a clean log, not a replay
    of every entry from the previous session.
  - _state result and running flag are now written inside _state_lock in
    _run_attack to prevent a half-written dict being read by a concurrent
    /api/state poll (CPython GIL makes this safe in practice, but the
    lock makes the intent explicit and correct under any interpreter).
  - JS: selService and selGateway are explicitly nulled when switching to
    the recon attack type so a stale service name from a previous attack
    is never forwarded to the next run.

Endpoints:
    GET  /              -> dark-themed HTML dashboard (full SPA)
    GET  /api/nodes     -> virtual network topology as JSON
    GET  /api/state     -> current attack state + result
    GET  /api/logs/stream -> SSE log feed
    POST /api/attack    -> launch an attack simulation
    POST /api/reset     -> reset all node state
"""

import dataclasses
import json
import socketserver
import threading
import time
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

from network_model import VirtualNetwork
from logger import SimulatorLogger
from attack_engine import AttackEngine
from config import GUI_HOST, GUI_PORT

# ── Module-level shared state (set by launch_gui) ────────────────────
_network: VirtualNetwork  = None   # type: ignore[assignment]
_logger:  SimulatorLogger = None   # type: ignore[assignment]
_engine:  AttackEngine    = None   # type: ignore[assignment]

_state: dict = {
    "running": False,
    "attack":  None,
    "target":  None,
    "result":  None,
    "error":   None,
}
# Guards the check-and-start sequence in do_POST so two simultaneous
# /api/attack requests cannot both pass the `running` check before
# either background thread has set it to True (TOCTOU race).
# Also used to make result writes atomic (see _run_attack).
_state_lock: threading.Lock = threading.Lock()


# ── Threaded server ──────────────────────────────────────────────────

class _ThreadedHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    """Each request runs in its own thread — required for SSE + API concurrency."""
    daemon_threads = True


# ── Attack runner ────────────────────────────────────────────────────

def _result_to_dict(attack_type: str, result) -> dict:
    """Convert any result dataclass to a JSON-safe dict."""
    return {"type": attack_type, "data": dataclasses.asdict(result)}


def _run_attack(body: dict) -> None:
    """Run the requested attack in a background thread, update _state."""
    atk    = body.get("attack", "")
    target = body.get("target", "")
    opts   = body.get("options", {})

    _state.update({"attack": atk, "target": target, "result": None, "error": None})
    try:
        if atk == "scan":
            result = _engine.port_scan(target, tuple(opts.get("range", [1, 1024])))
        elif atk == "brute":
            result = _engine.brute_force(target, opts.get("service", "SSH"))
        elif atk == "dos":
            result = _engine.dos_attack(
                target,
                opts.get("duration", 5),
                opts.get("pps", 500),
            )
        elif atk == "recon":
            result = _engine.reconnaissance()
        elif atk == "mitm":
            gateway = opts.get("gateway", "")
            if not gateway:
                with _state_lock:
                    _state.update({"running": False, "error": "No gateway specified for MITM"})
                return
            result = _engine.mitm_attack(gateway, target)
        elif atk == "sqli":
            result = _engine.sql_injection(target, opts.get("service", "HTTP"))
        elif atk == "lateral":
            result = _engine.lateral_movement(target)
        else:
            with _state_lock:
                _state.update({"running": False, "error": f"Unknown attack: {atk}"})
            return

        # FIX: write result inside the lock so a concurrent /api/state poll
        # never reads a half-updated dict (important under non-CPython runtimes
        # and good practice regardless).
        with _state_lock:
            _state["result"] = _result_to_dict(atk, result)

    except Exception as exc:  # noqa: BLE001
        with _state_lock:
            _state["error"] = str(exc)
    finally:
        # FIX: set running=False inside the lock so the check-and-start
        # sequence in do_POST stays consistent.
        with _state_lock:
            _state["running"] = False


# ── Embedded HTML/CSS/JS ─────────────────────────────────────────────
_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Network Attack Simulator</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500&family=Syne:wght@400;500;700&display=swap');
  :root{
    --bg:#0d0f12;--bg2:#13161b;--bg3:#1a1e25;
    --border:#242830;--border2:#2e3340;
    --text:#e2e4e9;--muted:#636878;--dim:#3a3f4d;
    --green:#2dca72;--green-bg:#0e2318;
    --amber:#f5a623;--amber-bg:#221a08;
    --red:#e84040;--red-bg:#230d0d;
    --blue:#4a9eff;--blue-bg:#0d1e35;
    --purple:#b04aff;--purple-bg:#1d0d35;
    --mono:'JetBrains Mono',monospace;--sans:'Syne',sans-serif;
  }
  *{box-sizing:border-box;margin:0;padding:0}
  html,body{height:100%;background:var(--bg);color:var(--text);font-family:var(--mono)}
  .shell{display:grid;grid-template-rows:48px 1fr;grid-template-columns:260px 1fr;height:100vh;overflow:hidden}
  .topbar{grid-column:1/-1;display:flex;align-items:center;gap:14px;padding:0 20px;border-bottom:1px solid var(--border);background:var(--bg2)}
  .brand{font-family:var(--sans);font-size:14px;font-weight:700;letter-spacing:.04em}
  .brand-sub{font-size:11px;color:var(--muted);margin-left:2px}
  .pulse{width:7px;height:7px;border-radius:50%;background:var(--green);animation:pulse 2s infinite;flex-shrink:0}
  @keyframes pulse{0%{box-shadow:0 0 0 0 rgba(45,202,114,.5)}70%{box-shadow:0 0 0 6px rgba(45,202,114,0)}100%{box-shadow:0 0 0 0 rgba(45,202,114,0)}}
  .topbar-stats{margin-left:auto;display:flex;gap:20px}
  .tstat{display:flex;flex-direction:column;align-items:flex-end}
  .tstat-v{font-size:14px;font-weight:500}
  .tstat-l{font-size:9px;color:var(--muted);letter-spacing:.08em;margin-top:1px}
  .sidebar{background:var(--bg2);border-right:1px solid var(--border);overflow-y:auto;padding:14px 0}
  .sec-head{font-size:9px;letter-spacing:.1em;color:var(--muted);padding:0 16px 8px;text-transform:uppercase}
  .node-item{padding:10px 16px;cursor:pointer;border-left:2px solid transparent;transition:background .12s,border-color .12s;margin-bottom:2px}
  .node-item:hover{background:var(--bg3)}
  .node-item.active{background:var(--bg3);border-left-color:var(--blue)}
  .node-ip{font-size:12px;font-weight:500;color:var(--text)}
  .node-host{font-size:10px;color:var(--muted);margin-top:2px}
  .node-tags{display:flex;gap:4px;margin-top:6px;flex-wrap:wrap}
  .tag{font-size:9px;padding:2px 6px;border-radius:3px}
  .tok{background:var(--green-bg);color:var(--green);border:1px solid #1a4029}
  .tbad{background:var(--red-bg);color:var(--red);border:1px solid #3d1515}
  .tinfo{background:var(--blue-bg);color:var(--blue);border:1px solid #152a45}
  .twarn{background:var(--amber-bg);color:var(--amber);border:1px solid #3d2d10}
  .tdim{background:var(--bg3);color:var(--dim);border:1px solid var(--border)}
  .vuln-bar{height:2px;background:var(--border2);border-radius:1px;margin-top:6px}
  .vuln-fill{height:2px;border-radius:1px;background:var(--red)}
  .sep{height:1px;background:var(--border);margin:14px 0}
  .cfg{padding:0 16px;margin-bottom:16px}
  .cfg-lbl{font-size:9px;color:var(--muted);letter-spacing:.08em;text-transform:uppercase;margin-bottom:8px}
  .atk-radio{display:flex;flex-direction:column;gap:4px}
  .atk-radio label{display:flex;align-items:center;gap:8px;font-size:11px;color:var(--muted);cursor:pointer;padding:5px 8px;border-radius:5px;border:1px solid transparent;transition:all .12s}
  .atk-radio label:hover{background:var(--bg3);color:var(--text)}
  .atk-radio label.chosen{background:var(--bg3);color:var(--text);border-color:var(--border2)}
  .atk-radio input[type=radio]{accent-color:var(--blue)}
  .spd-row{display:flex;align-items:center;gap:8px}
  input[type=range]{flex:1;accent-color:var(--blue);cursor:pointer;-webkit-appearance:none;height:4px;background:var(--border2);border-radius:2px}
  input[type=range]::-webkit-slider-thumb{-webkit-appearance:none;width:14px;height:14px;border-radius:50%;background:var(--blue);cursor:pointer}
  .spd-val{font-size:10px;color:var(--muted);min-width:38px;text-align:right}
  select.svc-sel{width:100%;font-family:var(--mono);font-size:11px;background:var(--bg3);color:var(--text);border:1px solid var(--border2);border-radius:4px;padding:5px 8px;cursor:pointer;outline:none;appearance:none}
  select.svc-sel:focus{border-color:var(--blue)}
  .main{display:grid;grid-template-rows:auto 1fr auto;overflow:hidden;background:var(--bg)}
  .tgt-bar{display:flex;align-items:center;gap:10px;padding:10px 18px;border-bottom:1px solid var(--border);background:var(--bg2)}
  .tgt-lbl{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em}
  .tgt-ip{font-size:13px;font-weight:500;color:var(--blue)}
  .tgt-atk{font-size:11px;color:var(--muted)}
  .run-btn{margin-left:auto;font-family:var(--mono);font-size:11px;background:var(--blue);color:#fff;border:none;border-radius:5px;padding:6px 18px;cursor:pointer;transition:opacity .15s}
  .run-btn:hover{opacity:.85}
  .run-btn:disabled{opacity:.3;cursor:not-allowed}
  .clr-btn{font-family:var(--mono);font-size:11px;background:transparent;color:var(--muted);border:1px solid var(--border2);border-radius:5px;padding:6px 12px;cursor:pointer;transition:all .12s}
  .clr-btn:hover{color:var(--text);border-color:var(--dim)}
  .term-wrap{overflow:hidden;display:flex;flex-direction:column;border-bottom:1px solid var(--border)}
  .term-head{display:flex;align-items:center;gap:6px;padding:8px 18px;background:var(--bg2);border-bottom:1px solid var(--border);flex-shrink:0}
  .tdot{width:10px;height:10px;border-radius:50%}
  .term-title{font-size:10px;color:var(--muted);margin-left:6px;letter-spacing:.06em}
  .spin{margin-left:auto;width:10px;height:10px;border:1.5px solid var(--border2);border-top-color:var(--green);border-radius:50%;display:none;animation:spin .7s linear infinite}
  @keyframes spin{to{transform:rotate(360deg)}}
  .term-body{flex:1;overflow-y:auto;padding:12px 18px;font-size:11px;line-height:1.9;background:var(--bg)}
  .ll{display:flex;gap:10px}
  .lts{color:var(--dim);flex-shrink:0;font-size:10px}
  .llv{flex-shrink:0;font-weight:500;min-width:56px;font-size:10px}
  .llv.INFO{color:var(--blue)}.llv.WARN{color:var(--amber)}.llv.ALERT{color:var(--red)}.llv.CRIT{color:var(--purple)}
  .lm{color:#8b8fa8;font-size:11px}
  .lm .hi{color:var(--text)}.lm .hd{color:var(--red)}.lm .hg{color:var(--green)}
  .empty-term{color:var(--dim);text-align:center;padding:40px;font-size:12px}
  .sse-badge{font-size:9px;padding:1px 5px;border-radius:3px;margin-left:8px;background:var(--green-bg);color:var(--green);border:1px solid #1a4029}
  .sse-badge.off{background:var(--red-bg);color:var(--red);border-color:#3d1515}
  .results{padding:14px 18px;background:var(--bg2);border-top:1px solid var(--border);display:none}
  .results.show{display:block}
  .res-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
  .res-card{background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:12px 14px}
  .res-card-title{font-size:9px;color:var(--muted);letter-spacing:.08em;text-transform:uppercase;margin-bottom:10px}
  .port-grid{display:flex;flex-wrap:wrap;gap:5px}
  .ppill{font-size:10px;padding:3px 8px;border-radius:3px;border:1px solid}
  .p-open{background:var(--green-bg);color:var(--green);border-color:#1a4029}
  .p-filt{background:var(--amber-bg);color:var(--amber);border-color:#3d2d10}
  .p-vuln{background:var(--red-bg);color:var(--red);border-color:#3d1515}
  .pbar{height:4px;background:var(--border2);border-radius:2px;margin:4px 0}
  .pbar-f{height:4px;border-radius:2px;transition:width .6s}
  .rec-item{display:flex;gap:6px;font-size:11px;color:#6b6f80;padding:2px 0}
  .rec-item::before{content:"\203A";color:var(--dim)}
  .risk-pill{display:inline-block;font-size:10px;padding:2px 8px;border-radius:3px;font-weight:500;border:1px solid}
  .rL{background:var(--green-bg);color:var(--green);border-color:#1a4029}
  .rM{background:var(--amber-bg);color:var(--amber);border-color:#3d2d10}
  .rH{background:var(--red-bg);color:var(--red);border-color:#3d1515}
  .rC{background:var(--purple-bg);color:var(--purple);border-color:#3d1545}
  .metric-duo{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:8px}
  .mini-metric{background:var(--bg2);border-radius:5px;padding:8px 10px;border:1px solid var(--border)}
  .mini-label{font-size:9px;color:var(--dim);letter-spacing:.06em;margin-bottom:3px}
  .mini-val{font-size:18px;font-weight:500}
  .host-row{display:flex;align-items:center;gap:8px;font-size:11px;padding:5px 0;border-bottom:1px solid var(--border)}
  .host-row:last-child{border-bottom:none}
  ::-webkit-scrollbar{width:5px}
  ::-webkit-scrollbar-track{background:transparent}
  ::-webkit-scrollbar-thumb{background:var(--border2);border-radius:3px}
</style>
</head>
<body>
<div class="shell">
  <header class="topbar">
    <div class="pulse"></div>
    <div>
      <div class="brand">NetAttack Simulator</div>
      <div class="brand-sub">sandboxed · no real traffic · educational</div>
    </div>
    <div class="topbar-stats">
      <div class="tstat"><div class="tstat-v" id="ts-runs">0</div><div class="tstat-l">Runs</div></div>
      <div class="tstat"><div class="tstat-v" id="ts-logs">0</div><div class="tstat-l">Log lines</div></div>
      <div class="tstat"><div class="tstat-v" id="ts-alerts" style="color:var(--red)">0</div><div class="tstat-l">Alerts</div></div>
    </div>
  </header>
  <aside class="sidebar">
    <div class="sec-head">Virtual nodes</div>
    <div id="nodelist"></div>
    <div class="sep"></div>
    <div class="cfg">
      <div class="cfg-lbl">Attack type</div>
      <div class="atk-radio" id="atk-radio"></div>
    </div>
    <div class="cfg" id="svc-wrap" style="display:none">
      <div class="cfg-lbl">Service (brute force / sqli)</div>
      <select id="svc-select" class="svc-sel" onchange="selService=this.value"></select>
    </div>
    <div class="cfg" id="gw-wrap" style="display:none">
      <div class="cfg-lbl">Gateway to spoof (MITM)</div>
      <select id="gw-select" class="svc-sel" onchange="selGateway=this.value"></select>
    </div>
    <div class="cfg">
      <div class="cfg-lbl">Speed</div>
      <div class="spd-row">
        <input type="range" id="spd" min="1" max="3" step="1" value="2">
        <div class="spd-val" id="spd-lbl">normal</div>
      </div>
    </div>
  </aside>
  <main class="main">
    <div class="tgt-bar">
      <div class="tgt-lbl">Target</div>
      <div class="tgt-ip" id="tgt-ip">— none selected —</div>
      <div class="tgt-atk" id="tgt-atk"></div>
      <button class="clr-btn" onclick="resetNetwork()" title="Reset all nodes to initial state">Reset nodes</button>
      <button class="clr-btn" onclick="clearTerm()">Clear log</button>
      <button class="run-btn" id="run-btn" onclick="runSim()">Run simulation</button>
    </div>
    <div class="term-wrap">
      <div class="term-head">
        <div class="tdot" style="background:#e84040"></div>
        <div class="tdot" style="background:#f5a623"></div>
        <div class="tdot" style="background:#2dca72"></div>
        <div class="term-title">simulation log</div>
        <span class="sse-badge off" id="sse-badge">SSE</span>
        <div class="spin" id="spin"></div>
      </div>
      <div class="term-body" id="term">
        <div class="empty-term">Select a node &nbsp;&#8594;&nbsp; choose attack &nbsp;&#8594;&nbsp; click Run simulation</div>
      </div>
    </div>
    <div class="results" id="results">
      <div class="res-grid" id="res-grid"></div>
    </div>
  </main>
</div>
<script>
// ── Shared state ───────────────────────────────────────────────────
const NODES = {};
let selIP = null, selAtk = "scan", selService = null, selGateway = null;
let running = false, runs = 0, logs = 0, alerts = 0;
const ATK_IP = "10.0.0.99";
const RECS = {
  scan:    ["Close all unused ports","Enable a host-level firewall","Audit open ports regularly","Use port knocking for SSH"],
  brute:   ["Lock accounts after 5 failed attempts","Enable multi-factor authentication","Monitor logins with SIEM","Enforce strong password policy"],
  dos:     ["Rate-limit inbound connections","Deploy a Web Application Firewall","Use CDN with DDoS mitigation","Set IDS alerts on traffic spikes"],
  recon:   ["Firewall to suppress service banners","Disable unnecessary services","Remove version info from banners","Segment network with VLANs"],
  mitm:    ["Use TLS/HTTPS everywhere (HSTS)","Enable Dynamic ARP Inspection (DAI)","Deploy 802.1X port authentication","Monitor ARP tables for anomalies"],
  sqli:    ["Use parameterised queries — never concatenate SQL","Deploy a Web Application Firewall","Apply least-privilege DB accounts","Enable IDS signatures for SQLi patterns"],
  lateral: ["Segment network with VLANs / micro-segmentation","Enforce unique credentials per service","Deploy Privileged Access Management (PAM)","Alert on internal lateral login attempts"],
};

// ── Stats ──────────────────────────────────────────────────────────
function updateStats(){
  document.getElementById("ts-runs").textContent = runs;
  document.getElementById("ts-logs").textContent = logs;
  document.getElementById("ts-alerts").textContent = alerts;
}

// ── Terminal ───────────────────────────────────────────────────────
function hi(msg){
  return msg
    .replace(/(OPEN|ALIVE|SUCCESS|gained)/g,'<span class="hg">$1</span>')
    .replace(/(FAILED|LOCKED|DOWN|COMPROMISED|CRACKED|vulnerable)/gi,'<span class="hd">$1</span>');
}
function appendEntry(entry){
  const term = document.getElementById("term");
  const empty = term.querySelector(".empty-term");
  if(empty) empty.remove();
  const LVL = {INFO:"INFO",WARNING:"WARN",ALERT:"ALERT",CRITICAL:"CRIT"};
  const lvl = LVL[entry.level] || entry.level;
  const div = document.createElement("div");
  div.className = "ll";
  div.innerHTML =
    `<span class="lts">${entry.timestamp.slice(11,23)}</span>` +
    `<span class="llv ${lvl}">[${lvl}]</span>` +
    `<span class="lm"><span class="hi">${entry.source_ip}</span> ` +
    `<span style="color:var(--dim)">\u2192</span> ` +
    `<span class="hi">${entry.target_ip}</span>&nbsp;&nbsp;${hi(entry.message)}</span>`;
  term.appendChild(div);
  term.scrollTop = term.scrollHeight;
  logs++;
  if(lvl==="ALERT"||lvl==="CRIT") alerts++;
  updateStats();
}
function clearTerm(){
  document.getElementById("term").innerHTML = '<div class="empty-term">Log cleared</div>';
  logs = 0; alerts = 0; updateStats();
  document.getElementById("results").classList.remove("show");
}

// ── SSE — real-time log stream ─────────────────────────────────────
let _es = null;
function startSSE(){
  if(_es) _es.close();
  _es = new EventSource("/api/logs/stream");
  _es.onopen = function(){
    document.getElementById("sse-badge").className = "sse-badge";
    document.getElementById("sse-badge").textContent = "LIVE";
  };
  _es.onmessage = function(e){
    appendEntry(JSON.parse(e.data));
  };
  _es.onerror = function(){
    document.getElementById("sse-badge").className = "sse-badge off";
    document.getElementById("sse-badge").textContent = "SSE";
    setTimeout(startSSE, 2000);
  };
}

// ── Result helpers ─────────────────────────────────────────────────
function riskCls(r){return{Low:"rL",Medium:"rM",High:"rH",Critical:"rC"}[r]||""}
function recsHtml(k){return(RECS[k]||[]).map(r=>`<div class="rec-item">${r}</div>`).join("")}
function showResults(html){
  document.getElementById("res-grid").innerHTML = html;
  document.getElementById("results").classList.add("show");
}

// ── Result renderers ───────────────────────────────────────────────
function renderResult(result){
  if(!result) return;
  const {type, data} = result;
  const recs = recsHtml(type);
  let html = "";

  if(type === "mitm")    return renderMITM(data);
  if(type === "sqli")    return renderSQLi(data);
  if(type === "lateral") return renderLateral(data);

  if(type === "scan"){
    const open = data.open_ports || [];
    const filt = (data.filtered_ports || []).slice(0,5);
    html = `
      <div class="res-card">
        <div class="res-card-title">Open ports \u2014 ${data.target_ip}</div>
        <div class="port-grid">
          ${open.map(([p,n])=>`<span class="ppill p-open">${p}/${n}</span>`).join("")}
          ${filt.map(p=>`<span class="ppill p-filt">${p} filt.</span>`).join("")}
          ${!open.length?'<span style="color:var(--muted);font-size:11px">None found</span>':""}
        </div>
        <div style="margin-top:10px;font-size:11px">
          OS: ${data.os_guess}
          &nbsp;\u2014&nbsp; Closed: ${(data.closed_ports||[]).length}
          &nbsp;\u2014&nbsp; Risk: <span class="risk-pill ${riskCls(data.risk_level)}">${data.risk_level}</span>
        </div>
      </div>
      <div class="res-card"><div class="res-card-title">Recommendations</div>${recs}</div>`;
  }
  else if(type === "brute"){
    const pct = Math.min(Math.round(data.attempts / 15 * 100), 100);
    const bc  = data.success ? "var(--purple)" : data.locked ? "var(--red)" : "var(--amber)";
    const outcome = data.success
      ? `Cracked: <span style="color:var(--purple);font-weight:500">${data.cracked_credential}</span>`
      : data.locked
        ? '<span style="color:var(--green)">\u2713 Account locked \u2014 defence held</span>'
        : '<span style="color:var(--green)">\u2713 Brute force failed</span>';
    html = `
      <div class="res-card">
        <div class="res-card-title">Brute force \u2014 ${data.target_ip} [${data.service}:${data.port}]</div>
        <div style="font-size:11px;color:var(--muted);margin-bottom:6px">
          Attempts: <span style="color:var(--text);font-weight:500">${data.attempts}</span>
        </div>
        <div class="pbar"><div class="pbar-f" style="width:${pct}%;background:${bc}"></div></div>
        <div style="margin-top:8px;font-size:11px">
          ${outcome} &nbsp;\u2014&nbsp;
          Risk: <span class="risk-pill ${riskCls(data.risk_level)}">${data.risk_level}</span>
        </div>
      </div>
      <div class="res-card"><div class="res-card-title">Recommendations</div>${recs}</div>`;
  }
  else if(type === "dos"){
    html = `
      <div class="res-card">
        <div class="res-card-title">DoS impact \u2014 ${data.target_ip}</div>
        <div class="metric-duo">
          <div class="mini-metric">
            <div class="mini-label">Packets sent</div>
            <div class="mini-val">${(data.packets_sent||0).toLocaleString()}</div>
          </div>
          <div class="mini-metric">
            <div class="mini-label">Peak response</div>
            <div class="mini-val">${data.peak_response_ms}ms</div>
          </div>
        </div>
        <div class="metric-duo">
          <div class="mini-metric">
            <div class="mini-label">Degraded</div>
            <div class="mini-val" style="color:${data.service_degraded?'var(--red)':'var(--green)'}">
              ${data.service_degraded?"YES":"NO"}
            </div>
          </div>
          <div class="mini-metric">
            <div class="mini-label">Service down</div>
            <div class="mini-val" style="color:${data.service_down?'var(--red)':'var(--green)'}">
              ${data.service_down?"YES":"NO"}
            </div>
          </div>
        </div>
        <div style="font-size:11px">
          IDS triggered: ${data.ids_triggered?"YES":"NO"}
          &nbsp;\u2014&nbsp;
          Risk: <span class="risk-pill ${riskCls(data.risk_level)}">${data.risk_level}</span>
        </div>
      </div>
      <div class="res-card"><div class="res-card-title">Recommendations</div>${recs}</div>`;
  }
  else if(type === "recon"){
    const hostsHtml = (data.live_hosts||[]).map(ip=>{
      const info = data.host_info[ip];
      return `<div class="host-row">
        <span style="color:var(--blue)">${ip}</span>
        <span style="color:var(--muted)">${info.hostname}</span>
        <span style="margin-left:auto" class="risk-pill ${info.firewall?'rL':'rH'}">
          ${info.firewall?"FW":"no FW"}
        </span>
      </div>`;
    }).join("");
    html = `
      <div class="res-card">
        <div class="res-card-title">Live hosts \u2014 ${(data.live_hosts||[]).length} discovered</div>
        ${hostsHtml}
        <div style="margin-top:8px;font-size:11px">
          Risk: <span class="risk-pill ${riskCls(data.risk_level)}">${data.risk_level}</span>
        </div>
      </div>
      <div class="res-card"><div class="res-card-title">Recommendations</div>${recs}</div>`;
  }

  if(html) showResults(html);
}

// ── Phase 2 result renderers ────────────────────────────────────────
function renderMITM(data){
  const recs = recsHtml("mitm");
  const credHtml = data.captured_credentials && data.captured_credentials.length
    ? data.captured_credentials.map(c=>`<div style="font-size:10px;color:var(--purple);padding:2px 0">\u25cf ${c}</div>`).join("")
    : `<span style="color:var(--green);font-size:11px">\u2713 No cleartext credentials captured</span>`;
  showResults(`
    <div class="res-card">
      <div class="res-card-title">MITM \u2014 ${data.target_ip} via gateway ${data.gateway_ip}</div>
      <div class="metric-duo">
        <div class="mini-metric">
          <div class="mini-label">Packets intercepted</div>
          <div class="mini-val">${(data.intercepted_packets||0).toLocaleString()}</div>
        </div>
        <div class="mini-metric">
          <div class="mini-label">HTTP injections</div>
          <div class="mini-val" style="color:${data.injected_payloads?'var(--red)':'var(--green)'}">${data.injected_payloads}</div>
        </div>
      </div>
      <div style="font-size:11px;margin-bottom:8px">
        ARP detected: <span style="color:${data.arp_detected?'var(--green)':'var(--red)'}">
          ${data.arp_detected?"\u2713 YES (IDS caught it)":"\u2717 NO (undetected)"}
        </span>
        &nbsp;\u2014&nbsp; Risk: <span class="risk-pill ${riskCls(data.risk_level)}">${data.risk_level}</span>
      </div>
      <div class="res-card-title" style="margin-top:8px">Captured credentials</div>
      ${credHtml}
    </div>
    <div class="res-card"><div class="res-card-title">Recommendations</div>${recs}</div>`);
}

function renderSQLi(data){
  const recs = recsHtml("sqli");
  const tableHtml = data.extracted_tables && data.extracted_tables.length
    ? data.extracted_tables.map(t=>`<span class="ppill p-vuln">${t}</span>`).join("")
    : `<span style="color:var(--green);font-size:11px">\u2713 No data extracted</span>`;
  showResults(`
    <div class="res-card">
      <div class="res-card-title">SQL injection \u2014 ${data.target_ip} [${data.service}:${data.port}]</div>
      <div class="metric-duo">
        <div class="mini-metric">
          <div class="mini-label">Payloads tried</div>
          <div class="mini-val">${data.payloads_tried}</div>
        </div>
        <div class="mini-metric">
          <div class="mini-label">Records leaked</div>
          <div class="mini-val" style="color:${data.extracted_records?'var(--red)':'var(--green)'}">${(data.extracted_records||0).toLocaleString()}</div>
        </div>
      </div>
      <div style="font-size:11px;margin-bottom:10px">
        Vulnerable: <span style="color:${data.vulnerable?'var(--red)':'var(--green)'}">
          ${data.vulnerable?"\u2717 YES":"\u2713 NO"}
        </span>
        ${data.bypass_used?`&nbsp;\u2014&nbsp; WAF bypass: <span style="color:var(--amber)">${data.bypass_used}</span>`:""}
        &nbsp;\u2014&nbsp; Risk: <span class="risk-pill ${riskCls(data.risk_level)}">${data.risk_level}</span>
      </div>
      <div class="res-card-title">Exfiltrated tables</div>
      <div class="port-grid" style="margin-top:6px">${tableHtml}</div>
    </div>
    <div class="res-card"><div class="res-card-title">Recommendations</div>${recs}</div>`);
}

function renderLateral(data){
  const recs = recsHtml("lateral");
  const pathHtml = (data.movement_path||[]).join(" \u2192 ");
  const compHtml = data.compromised_ips && data.compromised_ips.length
    ? data.compromised_ips.map(ip=>{
        const cred = data.credentials_used[ip] || "";
        return `<div style="font-size:10px;color:var(--purple);padding:2px 0">\u25cf ${ip} &nbsp;<span style="color:var(--muted)">${cred}</span></div>`;
      }).join("")
    : `<span style="color:var(--green);font-size:11px">\u2713 Lateral movement blocked on all nodes</span>`;
  showResults(`
    <div class="res-card">
      <div class="res-card-title">Lateral movement \u2014 pivot: ${data.pivot_ip}</div>
      <div class="metric-duo">
        <div class="mini-metric">
          <div class="mini-label">Reachable hosts</div>
          <div class="mini-val">${(data.reachable_ips||[]).length}</div>
        </div>
        <div class="mini-metric">
          <div class="mini-label">Compromised</div>
          <div class="mini-val" style="color:${data.compromised_ips&&data.compromised_ips.length?'var(--red)':'var(--green)'}">${(data.compromised_ips||[]).length}</div>
        </div>
      </div>
      <div style="font-size:10px;color:var(--muted);margin-bottom:10px">Path: <span style="color:var(--text)">${pathHtml}</span></div>
      <div style="font-size:11px;margin-bottom:8px">
        Risk: <span class="risk-pill ${riskCls(data.risk_level)}">${data.risk_level}</span>
      </div>
      <div class="res-card-title">Compromised nodes</div>
      <div style="margin-top:6px">${compHtml}</div>
    </div>
    <div class="res-card"><div class="res-card-title">Recommendations</div>${recs}</div>`);
}

// ── Attack execution ───────────────────────────────────────────────
function setRunning(on){
  running = on;
  document.getElementById("run-btn").disabled = on;
  document.getElementById("spin").style.display = on ? "block" : "none";
}
function flash(msg){
  const b = document.getElementById("run-btn"), orig = b.textContent;
  b.textContent = msg; b.style.background = "var(--red)";
  setTimeout(()=>{b.textContent = orig; b.style.background = "";}, 1600);
}
async function pollState(){
  try{
    const s = await (await fetch("/api/state")).json();
    if(s.running){ setTimeout(pollState, 500); return; }
    if(s.result)  renderResult(s.result);
    if(s.error)   flash(s.error.slice(0,30));
  }catch(e){}
  setRunning(false);
}
async function runSim(){
  if(running) return;
  if(selAtk !== "recon" && !selIP){ flash("Select a target"); return; }
  if(selAtk === "brute" && !selService){ flash("Select a service"); return; }
  if(selAtk === "sqli"  && !selService){ flash("Select a service"); return; }
  if(selAtk === "mitm"  && !selGateway){ flash("Select a gateway"); return; }
  setRunning(true); runs++; updateStats();
  document.getElementById("results").classList.remove("show");
  const body = {attack: selAtk, target: selIP, options: {}};
  if(selAtk === "brute")   body.options.service  = selService;
  if(selAtk === "sqli")    body.options.service  = selService || "HTTP";
  if(selAtk === "scan")    body.options.range    = [1, 1024];
  if(selAtk === "dos")     body.options = {duration: 5, pps: 500};
  if(selAtk === "mitm")    body.options.gateway  = selGateway;
  if(selAtk === "lateral") body.target = selIP;
  try{
    const resp = await fetch("/api/attack",{
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify(body),
    });
    if(!resp.ok){ flash((await resp.json()).error || "Error"); setRunning(false); return; }
    pollState();
  }catch(e){ flash("Server error"); setRunning(false); }
}
async function resetNetwork(){
  if(running) return;
  await fetch("/api/reset",{method:"POST"});
  clearTerm();
}

// ── Service selector ───────────────────────────────────────────────
function updateSvcSelect(){
  const wrap   = document.getElementById("svc-wrap");
  const gwWrap = document.getElementById("gw-wrap");

  // FIX: always clear stale selections before re-evaluating so a previous
  // node's service/gateway is never silently forwarded to a new attack.
  selService = null;
  selGateway = null;

  wrap.style.display   = "none";
  gwWrap.style.display = "none";

  if(selAtk === "brute" && selIP && NODES[selIP]){
    const svcs = NODES[selIP].svcs.filter(s => s.auth);
    wrap.style.display = "block";
    document.querySelector("#svc-wrap .cfg-lbl").textContent = "Service (brute force)";
    const sel = document.getElementById("svc-select");
    if(svcs.length){
      sel.innerHTML = svcs.map(s => `<option value="${s.name}">${s.name}  :${s.port}</option>`).join("");
      selService = svcs[0].name;
    } else {
      sel.innerHTML = '<option disabled selected>No auth services on this node</option>';
    }
  } else if(selAtk === "sqli" && selIP && NODES[selIP]){
    const svcs = NODES[selIP].svcs.filter(s => ["HTTP","HTTPS","MySQL"].includes(s.name));
    wrap.style.display = "block";
    document.querySelector("#svc-wrap .cfg-lbl").textContent = "Service (SQL injection)";
    const sel = document.getElementById("svc-select");
    if(svcs.length){
      sel.innerHTML = svcs.map(s => `<option value="${s.name}">${s.name}  :${s.port}</option>`).join("");
      selService = svcs[0].name;
    } else {
      sel.innerHTML = '<option disabled selected>No eligible services on this node</option>';
    }
  } else if(selAtk === "mitm" && selIP){
    const others = Object.entries(NODES).filter(([ip]) => ip !== selIP);
    if(others.length){
      gwWrap.style.display = "block";
      const sel = document.getElementById("gw-select");
      sel.innerHTML = others.map(([ip,n]) => `<option value="${ip}">${ip} (${n.host})</option>`).join("");
      selGateway = others[0][0];
    }
  }
}

// ── Sidebar builder ────────────────────────────────────────────────
function selectNode(ip){
  selIP = ip;
  document.querySelectorAll(".node-item").forEach(el=>el.classList.toggle("active",el.dataset.ip===ip));
  document.getElementById("tgt-ip").textContent = ip;
  document.getElementById("tgt-atk").textContent = "("+NODES[ip].host+")";
  updateSvcSelect();
}
function buildSidebar(){
  const nl = document.getElementById("nodelist");
  nl.innerHTML = Object.entries(NODES).map(([ip,n])=>{
    const vc = n.svcs.filter(s=>s.vuln).length;
    const vp = n.svcs.length ? Math.round(vc/n.svcs.length*100) : 0;
    return `<div class="node-item" data-ip="${ip}" onclick="selectNode('${ip}')">
      <div class="node-ip">${ip}</div>
      <div class="node-host">${n.host} \u00b7 ${n.os}</div>
      <div class="node-tags">
        ${n.fw ?`<span class="tag tok">FW</span>`  :`<span class="tag tbad">no FW</span>`}
        ${n.ids?`<span class="tag tinfo">IDS</span>`:`<span class="tag twarn">no IDS</span>`}
        ${n.svcs.map(s=>`<span class="tag tdim">${s.name}</span>`).join("")}
      </div>
      ${vc>0?`<div class="vuln-bar"><div class="vuln-fill" style="width:${vp}%"></div></div>
      <div style="font-size:9px;color:var(--muted);margin-top:3px">${vc}/${n.svcs.length} services vulnerable</div>`:""}
    </div>`;
  }).join("");

  const ATKS = [
    {id:"scan",    label:"Port scan"},
    {id:"brute",   label:"Brute force"},
    {id:"mitm",    label:"MITM (ARP poison)"},
    {id:"sqli",    label:"SQL injection"},
    {id:"lateral", label:"Lateral movement"},
    {id:"dos",     label:"DoS attack"},
    {id:"recon",   label:"Reconnaissance"},
  ];
  document.getElementById("atk-radio").innerHTML = ATKS.map(a=>`
    <label class="${a.id===selAtk?"chosen":""}" id="lbl-${a.id}">
      <input type="radio" name="atk" value="${a.id}" ${a.id===selAtk?"checked":""}
        onchange="selAtk=this.value;
          document.querySelectorAll('.atk-radio label').forEach(l=>l.classList.remove('chosen'));
          document.getElementById('lbl-'+this.value).classList.add('chosen');
          if(selAtk==='recon'){
            selService=null; selGateway=null;
            document.getElementById('tgt-ip').textContent='all nodes';
            document.getElementById('tgt-atk').textContent='';
            document.getElementById('svc-wrap').style.display='none';
            document.getElementById('gw-wrap').style.display='none';
          } else if(selIP){ selectNode(selIP); } else { updateSvcSelect(); }">
      ${a.label}
    </label>`).join("");

  document.getElementById("spd").addEventListener("input",function(){
    document.getElementById("spd-lbl").textContent = ["","slow","normal","fast"][+this.value];
  });
}

// ── Init ───────────────────────────────────────────────────────────
fetch("/api/nodes").then(r=>r.json()).then(data=>{
  Object.assign(NODES, data);
  buildSidebar();
  startSSE();
}).catch(()=>{
  Object.assign(NODES,{
    "192.168.1.10":{host:"web-server-01",os:"Ubuntu 20.04",fw:true,ids:true,
      svcs:[{port:22,name:"SSH",vuln:false,auth:true},{port:80,name:"HTTP",vuln:true,auth:false},{port:443,name:"HTTPS",vuln:false,auth:false}]},
    "192.168.1.20":{host:"file-server-01",os:"Windows Srv 2019",fw:false,ids:true,
      svcs:[{port:445,name:"SMB",vuln:true,auth:true},{port:3389,name:"RDP",vuln:false,auth:true},{port:8081,name:"HTTP",vuln:false,auth:false}]},
    "192.168.1.30":{host:"db-server-01",os:"CentOS 8",fw:true,ids:false,
      svcs:[{port:3306,name:"MySQL",vuln:true,auth:true},{port:22,name:"SSH",vuln:false,auth:true},{port:21,name:"FTP",vuln:true,auth:true}]},
    "192.168.1.40":{host:"office-printer",os:"Embedded Linux",fw:false,ids:false,
      svcs:[{port:80,name:"HTTP",vuln:true,auth:false},{port:23,name:"TELNET",vuln:true,auth:false},{port:515,name:"LPD",vuln:false,auth:false}]},
  });
  buildSidebar();
  startSSE();
});
</script>
</body>
</html>"""


# ── HTTP handler ─────────────────────────────────────────────────────

class _Handler(BaseHTTPRequestHandler):
    """Routes all HTTP requests to the appropriate handler."""

    def log_message(self, fmt, *args):
        pass  # silence default access log

    def _send(self, code: int, ctype: str, body):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(data)

    def _json(self, code: int, payload: dict):
        self._send(code, "application/json", json.dumps(payload))

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    # ── GET ─────────────────────────────────────────────────────────

    def do_GET(self):
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            self._send(200, "text/html; charset=utf-8", _HTML)
        elif path == "/api/nodes":
            self._json(200, _network.to_json())
        elif path == "/api/state":
            self._json(200, _state)
        elif path == "/api/logs/stream":
            self._stream_logs()
        else:
            self._send(404, "text/plain", "Not found")

    def _stream_logs(self):
        """
        SSE endpoint.  Keeps the connection open and sends new log entries
        as they appear in _logger.entries.

        Uses the Last-Event-ID header to resume from the correct position
        on browser reconnect — no entries are duplicated or skipped.
        """
        last_id_hdr = self.headers.get("Last-Event-ID", "-1")
        try:
            sent = int(last_id_hdr) + 1
        except ValueError:
            sent = 0

        self.send_response(200)
        self.send_header("Content-Type",  "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Accel-Buffering", "no")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        try:
            while True:
                batch = _logger.entries[sent:]
                for i, entry in enumerate(batch):
                    idx  = sent + i
                    data = json.dumps(entry.to_dict())
                    self.wfile.write(f"id: {idx}\ndata: {data}\n\n".encode())
                    self.wfile.flush()
                sent += len(batch)
                time.sleep(0.3)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass  # client disconnected

    # ── POST ────────────────────────────────────────────────────────

    def do_POST(self):
        path   = urlparse(self.path).path
        length = int(self.headers.get("Content-Length", 0))
        body   = json.loads(self.rfile.read(length)) if length else {}

        if path == "/api/attack":
            with _state_lock:
                if _state["running"]:
                    self._json(409, {"error": "Attack already running"})
                    return
                # Claim the slot inside the lock so a second concurrent
                # request cannot sneak past the check before this thread
                # has a chance to mark it running.
                _state["running"] = True
            threading.Thread(target=_run_attack, args=(body,), daemon=True).start()
            self._json(200, {"status": "started"})

        elif path == "/api/reset":
            # FIX: clear the logger BEFORE writing the sentinel so that a
            # browser reconnecting after reset starts from a clean slate
            # and does not replay every entry from the previous session.
            _network.reset_all()
            _logger.clear()
            _state.update({"running": False, "attack": None, "target": None,
                           "result": None, "error": None})
            _logger.info("SYSTEM", "SYSTEM",
                         "Network state reset — all nodes restored to initial state.",
                         "reset")
            self._json(200, {"status": "ok"})

        else:
            self._send(404, "text/plain", "Not found")


# ── Public launcher ──────────────────────────────────────────────────

def launch_gui(network: VirtualNetwork,
               logger:  SimulatorLogger) -> _ThreadedHTTPServer:
    """
    Start the web GUI in a background daemon thread and open the browser.

    Accepts both network and logger so the GUI runs the real AttackEngine
    instead of a JS-only simulation.

    Returns the server instance (rarely needed by callers).
    The server shuts down automatically when the main thread exits.
    """
    global _network, _logger, _engine
    _network = network
    _logger  = logger
    _engine  = AttackEngine(network, logger)

    server = _ThreadedHTTPServer((GUI_HOST, GUI_PORT), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    url = f"http://localhost:{GUI_PORT}"
    print(f"\033[1m\033[36m  Web GUI  \u2192  {url}  (opening in browser)\033[0m")
    threading.Thread(
        target=lambda: (time.sleep(0.8), webbrowser.open(url)),
        daemon=True,
    ).start()
    return server
