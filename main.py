import asyncio
import logging
import os
import re
import socket
import smtplib
import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from email.mime.text import MIMEText
from typing import Optional

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

VALID_INTERVALS = {1, 2, 5, 10, 15, 30, 60}
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
MAX_SCAN_PORTS = 500


def parse_port_range(port_range: str) -> list[tuple[int, str]]:
    """Parse '1-1000' or '80,443,8080' into (port, label) tuples, max MAX_SCAN_PORTS."""
    ports: list[tuple[int, str]] = []
    seen: set[int] = set()
    for part in port_range.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                a, b = part.split("-", 1)
                start, end = max(1, int(a.strip())), min(65535, int(b.strip()))
                for p in range(start, end + 1):
                    if p not in seen:
                        seen.add(p)
                        ports.append((p, WELL_KNOWN_PORTS.get(p, "")))
                        if len(ports) >= MAX_SCAN_PORTS:
                            return ports
            except ValueError:
                continue
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535 and p not in seen:
                    seen.add(p)
                    ports.append((p, WELL_KNOWN_PORTS.get(p, "")))
            except ValueError:
                continue
    return ports

WELL_KNOWN_PORTS: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    587: "SMTP-TLS", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    9200: "Elasticsearch", 27017: "MongoDB",
}

DB_PATH = os.environ.get("DB_PATH", "portmonitor.db")

# ── Database ─────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            description TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id INTEGER REFERENCES groups(id) ON DELETE SET NULL,
            name TEXT NOT NULL,
            ip TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            port INTEGER NOT NULL,
            label TEXT DEFAULT '',
            check_interval INTEGER DEFAULT 5,
            alert_email TEXT DEFAULT '',
            last_status INTEGER DEFAULT -1,
            last_checked TEXT DEFAULT NULL
        );
        CREATE TABLE IF NOT EXISTS checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            port_id INTEGER NOT NULL REFERENCES ports(id) ON DELETE CASCADE,
            status INTEGER NOT NULL,
            response_ms INTEGER DEFAULT 0,
            checked_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        INSERT OR IGNORE INTO settings VALUES ('smtp_host','');
        INSERT OR IGNORE INTO settings VALUES ('smtp_port','587');
        INSERT OR IGNORE INTO settings VALUES ('smtp_user','');
        INSERT OR IGNORE INTO settings VALUES ('smtp_pass','');
        INSERT OR IGNORE INTO settings VALUES ('smtp_from','');
    """)
    conn.commit()
    conn.close()

# ── Port Check ────────────────────────────────────────────────────────────────

def check_port(ip: str, port: int, timeout: float = 3.0) -> tuple[bool, int]:
    start = datetime.now()
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            ms = int((datetime.now() - start).total_seconds() * 1000)
            return True, ms
    except (socket.timeout, TimeoutError):
        ms = int((datetime.now() - start).total_seconds() * 1000)
        return False, ms
    except (socket.gaierror, socket.herror) as e:
        logger.warning("DNS/host error for %s:%d – %s", ip, port, e)
        ms = int((datetime.now() - start).total_seconds() * 1000)
        return False, ms
    except OSError as e:
        logger.warning("Connection error for %s:%d – %s", ip, port, e)
        ms = int((datetime.now() - start).total_seconds() * 1000)
        return False, ms

def send_alert(email: str, host_name: str, ip: str, port: int, status: bool, settings: dict):
    if not email or not settings.get("smtp_host"):
        return
    subject = f"[PortMonitor] {'✅ UP' if status else '🔴 DOWN'}: {host_name}:{port}"
    body = (
        f"Port check result for {host_name} ({ip}):{port}\n\n"
        f"Status: {'OPEN (up)' if status else 'CLOSED (down)'}\n"
        f"Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC"
    )
    try:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = settings["smtp_from"] or settings["smtp_user"]
        msg["To"] = email
        with smtplib.SMTP(settings["smtp_host"], int(settings["smtp_port"])) as s:
            s.starttls()
            if settings["smtp_user"]:
                s.login(settings["smtp_user"], settings["smtp_pass"])
            s.send_message(msg)
    except smtplib.SMTPAuthenticationError as e:
        logger.error("SMTP auth failed: %s", e)
    except smtplib.SMTPException as e:
        logger.error("SMTP error sending alert to %s: %s", email, e)
    except (OSError, ValueError) as e:
        logger.error("Mail connection error: %s", e)

async def run_checks_for_interval(interval: int):
    conn = get_db()
    settings = {r["key"]: r["value"] for r in conn.execute("SELECT key, value FROM settings").fetchall()}
    ports = conn.execute("""
        SELECT p.*, h.ip, h.name as host_name
        FROM ports p JOIN hosts h ON h.id = p.host_id
        WHERE p.check_interval = ?
    """, (interval,)).fetchall()
    conn.close()

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    results = await asyncio.gather(
        *[asyncio.to_thread(check_port, p["ip"], p["port"]) for p in ports],
        return_exceptions=True,
    )

    conn = get_db()
    for p, result in zip(ports, results):
        if isinstance(result, Exception):
            logger.error("Unexpected error checking %s:%d – %s", p["ip"], p["port"], result)
            continue
        ok, ms = result
        status = 1 if ok else 0
        conn.execute("INSERT INTO checks (port_id, status, response_ms, checked_at) VALUES (?,?,?,?)",
                     (p["id"], status, ms, now))
        # Alert on state change
        if p["last_status"] != -1 and p["last_status"] != status and p["alert_email"]:
            send_alert(p["alert_email"], p["host_name"], p["ip"], p["port"], ok, settings)
        conn.execute("UPDATE ports SET last_status=?, last_checked=? WHERE id=?",
                     (status, now, p["id"]))
        # Keep only last 1000 checks per port
        conn.execute("""DELETE FROM checks WHERE port_id=? AND id NOT IN (
            SELECT id FROM checks WHERE port_id=? ORDER BY id DESC LIMIT 1000)""",
                     (p["id"], p["id"]))
    conn.commit()
    conn.close()

# ── Scheduler ─────────────────────────────────────────────────────────────────

scheduler = AsyncIOScheduler()

def setup_scheduler():
    for interval in [1, 2, 5, 10, 15, 30, 60]:
        scheduler.add_job(
            run_checks_for_interval, "interval", minutes=interval,
            args=[interval], id=f"check_{interval}", replace_existing=True,
            misfire_grace_time=30,
        )

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    setup_scheduler()
    scheduler.start()
    yield
    scheduler.shutdown()

# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(lifespan=lifespan)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# ── Helpers ───────────────────────────────────────────────────────────────────

def get_dashboard_data():
    conn = get_db()
    groups = conn.execute("SELECT * FROM groups ORDER BY name").fetchall()
    hosts = conn.execute("SELECT * FROM hosts ORDER BY name").fetchall()
    ports = conn.execute("""
        SELECT p.*, h.name as host_name, h.ip, h.group_id
        FROM ports p JOIN hosts h ON h.id = p.host_id
        ORDER BY h.name, p.port
    """).fetchall()

    # Uptime % last 24h per port
    uptime = {}
    for p in ports:
        rows = conn.execute("""
            SELECT COUNT(*) total,
                   SUM(CASE WHEN status=1 THEN 1 ELSE 0 END) up
            FROM checks WHERE port_id=? AND checked_at >= datetime('now','-1 day')
        """, (p["id"],)).fetchone()
        total, up = rows["total"], rows["up"] or 0
        uptime[p["id"]] = round((up / total * 100) if total > 0 else -1, 1)

    conn.close()
    return groups, hosts, ports, uptime

# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    groups, hosts, ports, uptime = get_dashboard_data()
    return templates.TemplateResponse("dashboard.html", {
        "request": request, "groups": groups, "hosts": hosts,
        "ports": ports, "uptime": uptime
    })

@app.get("/history/{port_id}", response_class=HTMLResponse)
async def history(request: Request, port_id: int):
    conn = get_db()
    port = conn.execute("""
        SELECT p.*, h.name as host_name, h.ip FROM ports p
        JOIN hosts h ON h.id=p.host_id WHERE p.id=?
    """, (port_id,)).fetchone()
    if not port:
        raise HTTPException(404)
    checks = conn.execute("""
        SELECT * FROM checks WHERE port_id=? ORDER BY id DESC LIMIT 200
    """, (port_id,)).fetchall()
    conn.close()
    return templates.TemplateResponse("history.html", {
        "request": request, "port": port, "checks": checks
    })

# Groups
@app.post("/groups/add")
async def add_group(name: str = Form(...), description: str = Form("")):
    name = name.strip()
    if not name:
        raise HTTPException(400, "Gruppenname darf nicht leer sein")
    conn = get_db()
    conn.execute("INSERT OR IGNORE INTO groups (name, description) VALUES (?,?)", (name, description.strip()))
    conn.commit(); conn.close()
    return RedirectResponse("/", 303)

@app.post("/groups/delete/{gid}")
async def delete_group(gid: int):
    conn = get_db()
    conn.execute("DELETE FROM groups WHERE id=?", (gid,))
    conn.commit(); conn.close()
    return RedirectResponse("/", 303)

# Hosts
@app.post("/hosts/add")
async def add_host(name: str = Form(...), ip: str = Form(...), group_id: str = Form("")):
    name = name.strip()
    ip = ip.strip()
    if not name:
        raise HTTPException(400, "Hostname darf nicht leer sein")
    if not ip:
        raise HTTPException(400, "IP/Hostname darf nicht leer sein")
    gid = int(group_id) if group_id.strip() else None
    conn = get_db()
    conn.execute("INSERT INTO hosts (name, ip, group_id) VALUES (?,?,?)", (name, ip, gid))
    conn.commit(); conn.close()
    return RedirectResponse("/", 303)

@app.post("/hosts/scan-add")
async def hosts_scan_add(ip: str = Form(...), name: str = Form(...),
                         group_id: str = Form(""), ports: list[int] = Form(default=[])):
    name = name.strip(); ip = ip.strip()
    if not name or not ip:
        raise HTTPException(400, "Name und IP dürfen nicht leer sein")
    gid = int(group_id) if group_id.strip() else None
    conn = get_db()
    cursor = conn.execute("INSERT INTO hosts (name, ip, group_id) VALUES (?,?,?)", (name, ip, gid))
    host_id = cursor.lastrowid
    for port in ports:
        label = WELL_KNOWN_PORTS.get(port, "")
        conn.execute("INSERT INTO ports (host_id, port, label, check_interval, alert_email) VALUES (?,?,?,?,?)",
                     (host_id, port, label, 5, ""))
    conn.commit(); conn.close()
    return RedirectResponse("/", 303)

@app.post("/hosts/delete/{hid}")
async def delete_host(hid: int):
    conn = get_db()
    conn.execute("DELETE FROM hosts WHERE id=?", (hid,))
    conn.commit(); conn.close()
    return RedirectResponse("/", 303)

# Ports
@app.post("/ports/add")
async def add_port(host_id: int = Form(...), port: int = Form(...),
                   label: str = Form(""), check_interval: int = Form(5),
                   alert_email: str = Form("")):
    if not (1 <= port <= 65535):
        raise HTTPException(400, "Port muss zwischen 1 und 65535 liegen")
    if check_interval not in VALID_INTERVALS:
        raise HTTPException(400, f"Ungültiges Intervall: {check_interval}")
    alert_email = alert_email.strip()
    if alert_email and not _EMAIL_RE.match(alert_email):
        raise HTTPException(400, "Ungültige E-Mail-Adresse")
    conn = get_db()
    conn.execute("""INSERT INTO ports (host_id, port, label, check_interval, alert_email)
                    VALUES (?,?,?,?,?)""", (host_id, port, label.strip(), check_interval, alert_email))
    conn.commit(); conn.close()
    return RedirectResponse("/", 303)

@app.post("/ports/delete/{pid}")
async def delete_port(pid: int):
    conn = get_db()
    conn.execute("DELETE FROM ports WHERE id=?", (pid,))
    conn.commit(); conn.close()
    return RedirectResponse("/", 303)

@app.post("/ports/check/{pid}", response_class=HTMLResponse)
async def manual_check(request: Request, pid: int):
    conn = get_db()
    p = conn.execute("SELECT p.*, h.ip, h.name as host_name FROM ports p JOIN hosts h ON h.id=p.host_id WHERE p.id=?", (pid,)).fetchone()
    if not p:
        raise HTTPException(404)
    ok, ms = await asyncio.to_thread(check_port, p["ip"], p["port"])
    status = 1 if ok else 0
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    conn.execute("INSERT INTO checks (port_id, status, response_ms, checked_at) VALUES (?,?,?,?)", (pid, status, ms, now))
    conn.execute("UPDATE ports SET last_status=?, last_checked=? WHERE id=?", (status, now, pid))
    conn.commit(); conn.close()
    return HTMLResponse(f'<span hx-swap-oob="true" id="status-{pid}">' +
                        ('<span class="badge up">UP</span>' if ok else '<span class="badge down">DOWN</span>') +
                        f'</span><span id="ms-{pid}">{ms}ms</span>')

# Settings
@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    conn = get_db()
    s = {r["key"]: r["value"] for r in conn.execute("SELECT * FROM settings").fetchall()}
    conn.close()
    return templates.TemplateResponse("settings.html", {"request": request, "settings": s})

@app.get("/stats", response_class=HTMLResponse)
async def stats(request: Request):
    conn = get_db()
    ports = conn.execute("SELECT * FROM ports").fetchall()
    hosts = conn.execute("SELECT * FROM hosts").fetchall()
    conn.close()
    return templates.TemplateResponse("stats_bar.html", {
        "request": request, "ports": ports, "hosts": hosts,
    })


@app.post("/scan", response_class=HTMLResponse)
async def scan_host(request: Request, ip: str = Form(...),
                    scan_mode: str = Form("wellknown"),
                    port_range: str = Form("")):
    ip = ip.strip()
    if not ip:
        raise HTTPException(400, "IP/Hostname darf nicht leer sein")
    if scan_mode == "custom" and port_range.strip():
        port_list = parse_port_range(port_range.strip())
        if not port_list:
            raise HTTPException(400, "Kein gültiger Port-Bereich angegeben")
    else:
        port_list = list(WELL_KNOWN_PORTS.items())
    results = await asyncio.gather(
        *[asyncio.to_thread(check_port, ip, p) for p, _ in port_list],
        return_exceptions=True,
    )
    open_ports = []
    for (port, label), result in zip(port_list, results):
        if isinstance(result, Exception):
            continue
        ok, ms = result
        if ok:
            open_ports.append({"port": port, "label": label, "ms": ms})
    conn = get_db()
    groups_data = conn.execute("SELECT * FROM groups ORDER BY name").fetchall()
    conn.close()
    return templates.TemplateResponse("scan_results.html", {
        "request": request, "ip": ip, "open_ports": open_ports,
        "total_scanned": len(port_list), "groups": groups_data,
    })

@app.post("/settings/save")
async def save_settings(smtp_host: str = Form(""), smtp_port: str = Form("587"),
                        smtp_user: str = Form(""), smtp_pass: str = Form(""),
                        smtp_from: str = Form("")):
    try:
        port_num = int(smtp_port)
        if not (1 <= port_num <= 65535):
            raise ValueError
    except ValueError:
        raise HTTPException(400, "SMTP-Port muss eine Zahl zwischen 1 und 65535 sein")
    conn = get_db()
    for k, v in [("smtp_host", smtp_host.strip()), ("smtp_port", smtp_port.strip()),
                 ("smtp_user", smtp_user.strip()), ("smtp_pass", smtp_pass),
                 ("smtp_from", smtp_from.strip())]:
        conn.execute("UPDATE settings SET value=? WHERE key=?", (v, k))
    conn.commit(); conn.close()
    return RedirectResponse("/settings", 303)
