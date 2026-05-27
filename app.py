"""Secure fail2ban dashboard.

This public template is safe-by-default:
- Basic Auth is required after first setup.
- No browser CDN, map tile, GeoIP or Shodan calls are enabled by default.
- Write actions and API/Swagger are explicit setup switches.
"""

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import subprocess
import urllib.request
from collections import Counter
from datetime import datetime
from functools import wraps

from flask import Flask, Response, jsonify, redirect, render_template, request, url_for

try:
    import sentry_sdk
    from sentry_sdk.integrations.flask import FlaskIntegration
except Exception:  # pragma: no cover - optional dependency
    sentry_sdk = None
    FlaskIntegration = None


app = Flask(__name__)


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except ValueError:
        return default


CONFIG_PATH = os.getenv("FAIL2BAN_UI_CONFIG_PATH", "/etc/fail2ban-ui/config.json")
STATE_PATH = os.getenv("FAIL2BAN_UI_STATE_PATH", "/var/lib/fail2ban-ui/state.json")
SETUP_TOKEN = os.getenv("FAIL2BAN_UI_SETUP_TOKEN", "")
PASSWORD_ITERATIONS = 240_000
DEFAULT_JAILS = ["sshd", "portscan", "sensible-ports", "recidive-48h", "blacklist-permanent"]
DEFAULT_JAIL_META = {
    "sshd": {
        "title": "SSH",
        "description": "Autenticaciones fallidas contra SSH.",
        "policy": "Ban 24h",
        "tone": "warning",
    },
    "portscan": {
        "title": "Portscan",
        "description": "Barridos de puertos detectados en kernel/journal.",
        "policy": "Ban 24h",
        "tone": "info",
    },
    "sensible-ports": {
        "title": "Puertos sensibles",
        "description": "Toques directos a puertos que no deben exponerse.",
        "policy": "Ban inmediato 24h",
        "tone": "danger",
    },
    "recidive-48h": {
        "title": "Reincidentes",
        "description": "IPs que repiten actividad maliciosa entre jails.",
        "policy": "Ban 48h",
        "tone": "danger",
    },
    "blacklist-permanent": {
        "title": "Blacklist permanente",
        "description": "Bloqueos manuales o persistentes.",
        "policy": "Permanente",
        "tone": "critical",
    },
}


def _hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("ascii"),
        PASSWORD_ITERATIONS,
    ).hex()
    return f"pbkdf2_sha256${PASSWORD_ITERATIONS}${salt}${digest}"


def _verify_password(password: str, stored: str) -> bool:
    try:
        algo, iterations, salt, digest = stored.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        candidate = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("ascii"),
            int(iterations),
        ).hex()
        return hmac.compare_digest(candidate, digest)
    except Exception:
        return False


def _default_auth_hash() -> str:
    password_hash = os.getenv("FAIL2BAN_UI_AUTH_PASSWORD_HASH", "")
    password = os.getenv("FAIL2BAN_UI_AUTH_PASSWORD", "")
    if password_hash:
        return password_hash
    if password:
        return _hash_password(password)
    return ""


def _split_csv(value, fallback=None) -> list[str]:
    if value is None:
        return list(fallback or [])
    if isinstance(value, str):
        items = value.split(",")
    elif isinstance(value, list):
        items = value
    else:
        items = []
    return [str(item).strip() for item in items if str(item).strip()]


def _default_config() -> dict:
    env_jails = _split_csv(os.getenv("FAIL2BAN_UI_JAILS"), DEFAULT_JAILS)
    return {
        "configured": os.getenv("FAIL2BAN_UI_CONFIGURED", "0") == "1",
        "app_name": os.getenv("FAIL2BAN_UI_APP_NAME", "Fail2ban UI"),
        "server_name": os.getenv("FAIL2BAN_UI_SERVER_NAME", "fail2ban-host"),
        "server_public_ip": os.getenv("FAIL2BAN_UI_SERVER_PUBLIC_IP", ""),
        "server_lat": _env_float("FAIL2BAN_UI_SERVER_LAT", 0.0),
        "server_lon": _env_float("FAIL2BAN_UI_SERVER_LON", 0.0),
        "bind_host": os.getenv("FAIL2BAN_UI_BIND_HOST", "127.0.0.1"),
        "bind_port": _env_int("FAIL2BAN_UI_BIND_PORT", 2020),
        "jail_local": os.getenv("FAIL2BAN_UI_JAIL_LOCAL", "/etc/fail2ban/jail.local"),
        "jails": env_jails,
        "jail_meta": {**DEFAULT_JAIL_META},
        "protected_whitelist": _split_csv(
            os.getenv("FAIL2BAN_UI_PROTECTED_WHITELIST"),
            ["127.0.0.0/8", "100.64.0.0/10"],
        ),
        "page_size": _env_int("FAIL2BAN_UI_PAGE_SIZE", 15),
        "auto_refresh_seconds": _env_int("FAIL2BAN_UI_AUTO_REFRESH_SECONDS", 30),
        "ui_density": os.getenv("FAIL2BAN_UI_DENSITY", "comfortable"),
        "auth": {
            "username": os.getenv("FAIL2BAN_UI_AUTH_USERNAME", "admin"),
            "password_hash": _default_auth_hash(),
        },
        "features": {
            "journal_inspection": True,
            "port_inventory": True,
            "write_actions": False,
            "api_enabled": True,
            "swagger_enabled": True,
            "external_enrichment": False,
            "external_links": False,
            "mask_ips": False,
        },
        "notch": {
            "enabled": os.getenv("FAIL2BAN_UI_NOTCH_ENABLED", "0") == "1",
            "webhook_url": os.getenv("FAIL2BAN_UI_NOTCH_WEBHOOK_URL", ""),
            "token": os.getenv("FAIL2BAN_UI_NOTCH_TOKEN", ""),
            "payload_mode": os.getenv("FAIL2BAN_UI_NOTCH_PAYLOAD_MODE", "masked"),
            "min_severity": os.getenv("FAIL2BAN_UI_NOTCH_MIN_SEVERITY", "warning"),
        },
        "decisions": {
            "enabled": os.getenv("FAIL2BAN_UI_DECISIONS_ENABLED", "0") == "1",
            "mode": os.getenv("FAIL2BAN_UI_DECISION_MODE", "recommend"),
            "threshold": _env_int("FAIL2BAN_UI_DECISION_THRESHOLD", 5),
            "action_jail": os.getenv("FAIL2BAN_UI_DECISION_ACTION_JAIL", "blacklist-permanent"),
            "notify_recommendations": os.getenv("FAIL2BAN_UI_DECISION_NOTIFY", "1") == "1",
        },
    }


def _merge_config(saved: dict | None = None) -> dict:
    config = _default_config()
    saved = saved or {}
    for key, value in saved.items():
        if key in {"auth", "features", "jail_meta", "notch", "decisions"}:
            continue
        config[key] = value
    config["auth"].update(saved.get("auth") or {})
    config["features"].update(saved.get("features") or {})
    config["notch"].update(saved.get("notch") or {})
    config["decisions"].update(saved.get("decisions") or {})
    config["jail_meta"].update(saved.get("jail_meta") or {})
    return config


def _load_config() -> dict:
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return _merge_config(json.load(f))
    except FileNotFoundError:
        return _merge_config()
    except Exception:
        return _merge_config()


CONFIG = _load_config()


def _save_config(config: dict) -> None:
    directory = os.path.dirname(CONFIG_PATH)
    if directory:
        os.makedirs(directory, mode=0o700, exist_ok=True)
    tmp_path = f"{CONFIG_PATH}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
        f.write("\n")
    os.chmod(tmp_path, 0o600)
    os.replace(tmp_path, CONFIG_PATH)


def _reload_config() -> dict:
    global CONFIG
    CONFIG = _load_config()
    return CONFIG


def cfg(key: str, default=None):
    return CONFIG.get(key, default)


def features() -> dict:
    return CONFIG.get("features", {})


def feature_enabled(name: str) -> bool:
    return bool(features().get(name))


def notch_config() -> dict:
    return CONFIG.get("notch", {})


def decisions_config() -> dict:
    return CONFIG.get("decisions", {})


def auth_ready() -> bool:
    auth = CONFIG.get("auth") or {}
    return bool(auth.get("username") and auth.get("password_hash"))


def configured() -> bool:
    return bool(CONFIG.get("configured") and auth_ready())


def _remote_is_setup_safe() -> bool:
    remote = request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()
    try:
        ip = ipaddress.ip_address(remote)
    except ValueError:
        return False
    tailscale = ipaddress.ip_network("100.64.0.0/10")
    return ip.is_loopback or ip.is_private or ip in tailscale


def _setup_token_ok(payload: dict | None = None) -> bool:
    if not SETUP_TOKEN:
        return _remote_is_setup_safe()
    payload = payload or {}
    supplied = (
        request.args.get("token")
        or request.headers.get("X-Setup-Token")
        or payload.get("setup_token")
        or ""
    )
    return hmac.compare_digest(supplied, SETUP_TOKEN)


def _load_state() -> dict:
    try:
        with open(STATE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"notified": [], "actions": []}


def _save_state(state: dict) -> None:
    directory = os.path.dirname(STATE_PATH)
    if directory:
        os.makedirs(directory, mode=0o700, exist_ok=True)
    state["notified"] = list(dict.fromkeys(state.get("notified", [])))[-1000:]
    state["actions"] = list(dict.fromkeys(state.get("actions", [])))[-1000:]
    tmp_path = f"{STATE_PATH}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, ensure_ascii=False)
        f.write("\n")
    os.chmod(tmp_path, 0o600)
    os.replace(tmp_path, STATE_PATH)


def _parse_basic_auth() -> tuple[str, str] | None:
    header = request.headers.get("Authorization", "")
    if not header.startswith("Basic "):
        return None
    try:
        raw = base64.b64decode(header.split(" ", 1)[1]).decode("utf-8")
        username, password = raw.split(":", 1)
        return username, password
    except Exception:
        return None


def _basic_auth_ok() -> bool:
    parsed = _parse_basic_auth()
    if not parsed:
        return False
    username, password = parsed
    auth = CONFIG.get("auth") or {}
    return hmac.compare_digest(username, auth.get("username", "")) and _verify_password(
        password,
        auth.get("password_hash", ""),
    )


def _auth_response(message: str = "Autenticacion requerida") -> Response:
    return Response(
        message,
        401,
        {"WWW-Authenticate": 'Basic realm="fail2ban-ui", charset="UTF-8"'},
    )


@app.before_request
def gatekeeper():
    if request.path == "/health":
        return None

    if not configured():
        if request.path.startswith("/setup") and _setup_token_ok(request.form.to_dict()):
            return None
        if request.path.startswith("/api"):
            return jsonify({"error": "setup_required"}), 428
        return redirect(url_for("setup", token=request.args.get("token", "")))

    if not _basic_auth_ok():
        return _auth_response()
    return None


@app.after_request
def secure_headers(response):
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Cache-Control", "no-store")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none';",
    )
    return response


def _before_send_transaction(event, hint):
    transaction = (event.get("transaction") or "").lower()
    if "/static/" in transaction or transaction.endswith("/health"):
        return None
    return event


_sentry_dsn = os.getenv("FAIL2BAN_UI_SENTRY_DSN", "")
if _sentry_dsn and sentry_sdk and FlaskIntegration:
    sentry_sdk.init(
        dsn=_sentry_dsn,
        environment=os.getenv("FAIL2BAN_UI_SENTRY_ENVIRONMENT", "production-fail2ban-ui"),
        server_name=os.getenv("FAIL2BAN_UI_SENTRY_SERVER_NAME", "fail2ban-ui"),
        traces_sample_rate=float(os.getenv("FAIL2BAN_UI_SENTRY_TRACE_SAMPLE_RATE", "0.0")),
        integrations=[FlaskIntegration()],
        before_send_transaction=_before_send_transaction,
        auto_session_tracking=False,
    )


_geo_cache: dict[str, dict] = {}
_shodan_cache: dict[str, dict] = {}


def _fetch_json(url: str, timeout: int = 3) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "fail2ban-ui/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def _empty_geo(ip: str = "") -> dict:
    return {
        "country": "--",
        "city": "",
        "region": "",
        "org": "enriquecimiento externo apagado",
        "lat": 0.0,
        "lon": 0.0,
        "ip": ip,
    }


def geoip(ip: str) -> dict:
    if not feature_enabled("external_enrichment"):
        return _empty_geo(ip)
    if ip in _geo_cache:
        return _geo_cache[ip]
    try:
        data = _fetch_json(f"https://ipinfo.io/{ip}/json")
        loc = data.get("loc", "0,0").split(",")
        result = {
            "country": data.get("country", "--"),
            "city": data.get("city", ""),
            "region": data.get("region", ""),
            "org": data.get("org", ""),
            "lat": float(loc[0]) if loc[0] else 0.0,
            "lon": float(loc[1]) if len(loc) > 1 else 0.0,
            "ip": ip,
        }
    except Exception:
        result = _empty_geo(ip)
    _geo_cache[ip] = result
    return result


def shodan_idb(ip: str) -> dict:
    if not feature_enabled("external_enrichment"):
        return {"ports": [], "hostnames": [], "tags": [], "vulns": [], "cpes": []}
    if ip in _shodan_cache:
        return _shodan_cache[ip]
    try:
        data = _fetch_json(f"https://internetdb.shodan.io/{ip}", timeout=4)
        result = {
            "ports": data.get("ports", []),
            "hostnames": data.get("hostnames", []),
            "tags": data.get("tags", []),
            "vulns": data.get("vulns", []),
            "cpes": data.get("cpes", []),
        }
    except Exception:
        result = {"ports": [], "hostnames": [], "tags": [], "vulns": [], "cpes": []}
    _shodan_cache[ip] = result
    return result


def f2b(cmd: list[str]) -> str:
    try:
        result = subprocess.run(
            ["fail2ban-client"] + cmd,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        return result.stdout.strip() or result.stderr.strip()
    except Exception as exc:
        return f"ERROR: {exc}"


def run_cmd(command: list[str]) -> str:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=8, check=False)
        return result.stdout.strip() or result.stderr.strip()
    except Exception as exc:
        return f"ERROR: {exc}"


def _mask_ip(ip: str) -> str:
    if not feature_enabled("mask_ips"):
        return ip
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if parsed.version == 4:
        parts = ip.split(".")
        return ".".join(parts[:3] + ["x"])
    groups = ip.split(":")
    return ":".join(groups[:4] + ["..."])


def _ip_is_safe_for_action(ip: str) -> bool:
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if parsed.is_loopback or parsed.is_private or parsed.is_reserved or parsed.is_multicast:
        return False
    for protected in cfg("protected_whitelist", []):
        try:
            if parsed in ipaddress.ip_network(protected, strict=False):
                return False
        except ValueError:
            continue
    return True


def _severity_allowed(severity: str) -> bool:
    levels = {"info": 0, "warning": 1, "critical": 2}
    min_level = notch_config().get("min_severity", "warning")
    return levels.get(severity, 0) >= levels.get(min_level, 1)


def _send_notch(event: dict) -> bool:
    notch = notch_config()
    if not notch.get("enabled") or not notch.get("webhook_url"):
        return False
    if not _severity_allowed(event.get("severity", "info")):
        return False

    payload = dict(event)
    if notch.get("payload_mode", "masked") == "masked":
        if "source_ip" in payload:
            payload["source_ip"] = _mask_ip(payload["source_ip"])
        payload.pop("raw", None)

    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    headers = {"Content-Type": "application/json", "User-Agent": "fail2ban-ui/1.0"}
    if notch.get("token"):
        headers["Authorization"] = f"Bearer {notch['token']}"
    try:
        req = urllib.request.Request(notch["webhook_url"], data=body, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=4) as response:
            return 200 <= response.status < 300
    except Exception:
        return False


def evaluate_decisions(attempts: list[dict], banned_ips: set[str]) -> list[dict]:
    decisions = []
    decision_cfg = decisions_config()
    if not decision_cfg.get("enabled"):
        return decisions

    state = _load_state()
    threshold = max(1, int(decision_cfg.get("threshold") or 5))
    mode = decision_cfg.get("mode", "recommend")
    action_jail = decision_cfg.get("action_jail") or "blacklist-permanent"
    counts: Counter[str] = Counter(a["source_ip"] for a in attempts if a.get("malicious"))

    for source_ip, hits in counts.most_common(20):
        if hits < threshold:
            continue
        safe_for_action = _ip_is_safe_for_action(source_ip)
        action = "notify"
        action_result = "pending"
        severity = "critical" if hits >= threshold * 2 else "warning"
        reason = f"{hits} eventos maliciosos recientes"

        if source_ip in banned_ips:
            action = "already-banned"
            action_result = "observed"
        elif mode == "auto" and feature_enabled("write_actions") and safe_for_action:
            action = "ban"
            action_key = f"ban:{action_jail}:{source_ip}"
            if action_key not in state.get("actions", []):
                f2b(["set", action_jail, "banip", source_ip])
                state.setdefault("actions", []).append(action_key)
                action_result = "executed"
            else:
                action_result = "already-executed"
        elif mode in {"recommend", "auto"}:
            action = "recommend-ban" if safe_for_action else "review"
            action_result = "recommended"

        decision = {
            "source_ip": source_ip,
            "display_ip": _mask_ip(source_ip),
            "hits": hits,
            "severity": severity,
            "reason": reason,
            "mode": mode,
            "action": action,
            "action_result": action_result,
            "action_jail": action_jail,
            "safe_for_action": safe_for_action,
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        decisions.append(decision)

        notify_key = f"{severity}:{action}:{source_ip}:{hits}"
        if decision_cfg.get("notify_recommendations") and notify_key not in state.get("notified", []):
            _send_notch(
                {
                    "type": "fail2ban-ui.decision",
                    "app": cfg("app_name", "Fail2ban UI"),
                    "server": cfg("server_name", "fail2ban-host"),
                    "severity": severity,
                    "source_ip": source_ip,
                    "hits": hits,
                    "reason": reason,
                    "mode": mode,
                    "action": action,
                    "action_result": action_result,
                    "safe_for_action": safe_for_action,
                }
            )
            state.setdefault("notified", []).append(notify_key)

    _save_state(state)
    return decisions


def parse_status(jail: str) -> dict:
    raw = f2b(["status", jail])
    meta = CONFIG.get("jail_meta", {}).get(
        jail,
        {"title": jail, "description": "Jail configurado en fail2ban.", "policy": "Activa", "tone": "neutral"},
    )
    if raw.startswith("ERROR") or "Sorry but the jail" in raw or "does not exist" in raw:
        return {
            "jail": jail,
            "meta": meta,
            "currently_failed": "0",
            "total_failed": "0",
            "currently_banned": "0",
            "total_banned": "0",
            "banned_ips": [],
            "enabled": False,
        }

    def extract(pattern, default="0"):
        match = re.search(pattern, raw)
        return match.group(1).strip() if match else default

    banned_line = extract(r"Banned IP list:\s*(.*)", "")
    banned_ips = [ip.strip() for ip in banned_line.split() if ip.strip()] if banned_line else []
    return {
        "jail": jail,
        "meta": meta,
        "currently_failed": extract(r"Currently failed:\s*(\d+)"),
        "total_failed": extract(r"Total failed:\s*(\d+)"),
        "currently_banned": extract(r"Currently banned:\s*(\d+)"),
        "total_banned": extract(r"Total banned:\s*(\d+)"),
        "banned_ips": banned_ips,
        "enabled": True,
    }


def get_listening_ports() -> list[dict]:
    if not feature_enabled("port_inventory"):
        return []
    raw = run_cmd(["ss", "-tlnpH"])
    ports = []
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        local = parts[3]
        process = " ".join(parts[5:]) if len(parts) > 5 else "-"
        port_match = re.search(r":(\d+)$", local)
        if not port_match:
            continue
        port = int(port_match.group(1))
        host = local[: local.rfind(":")]
        exposure = "public"
        if host.startswith("127.") or host == "::1":
            exposure = "loopback"
        elif host.startswith("100.") or host.startswith("fd7a:"):
            exposure = "tailscale"
        elif host.startswith("10.") or host.startswith("192.168."):
            exposure = "interna"
        ports.append({"port": port, "host": host, "process": process or "-", "exposure": exposure})
    return sorted(ports, key=lambda item: (item["exposure"], item["port"]))


def get_recent_attempts(limit: int = 60) -> tuple[list[dict], list[dict]]:
    if not feature_enabled("journal_inspection"):
        return [], []
    attempts = []
    port_counter: Counter[int] = Counter()

    kernel_raw = run_cmd(["journalctl", "-k", "--no-pager", "-n", "160"])
    for line in kernel_raw.splitlines():
        if "F2B-PORTSCAN:" not in line and "F2B-SENSITIVE:" not in line:
            continue
        src = re.search(r"SRC=([0-9a-fA-F:.]+)", line)
        dpt = re.search(r"DPT=(\d+)", line)
        proto = re.search(r"PROTO=([A-Z]+)", line)
        if not src or not dpt:
            continue
        port = int(dpt.group(1))
        kind = "sensible-ports" if "F2B-SENSITIVE:" in line else "portscan"
        port_counter[port] += 1
        attempts.append(
            {
                "at": line[:25].strip(),
                "source_ip": src.group(1),
                "display_ip": _mask_ip(src.group(1)),
                "target_port": port,
                "protocol": proto.group(1) if proto else "TCP",
                "kind": kind,
                "detail": f"Intento contra puerto {port}",
                "malicious": True,
            }
        )

    ssh_raw = run_cmd(["journalctl", "_COMM=sshd", "--no-pager", "-n", "160"])
    for line in ssh_raw.splitlines():
        failed = re.search(r"Failed password for (invalid user )?([^ ]+) from ([0-9a-fA-F:.]+) port (\d+)", line)
        if failed:
            username = failed.group(2)
            source_ip = failed.group(3)
            source_port = failed.group(4)
            port_counter[22] += 1
            attempts.append(
                {
                    "at": line[:25].strip(),
                    "source_ip": source_ip,
                    "display_ip": _mask_ip(source_ip),
                    "target_port": 22,
                    "protocol": "TCP",
                    "kind": "ssh-failed",
                    "detail": f"SSH fallido usuario {username}, puerto origen {source_port}",
                    "malicious": True,
                }
            )
            continue
        closed = re.search(r"Connection closed by (?:invalid user |authenticating user )?([^ ]+) ([0-9a-fA-F:.]+) port (\d+)", line)
        if closed:
            attempts.append(
                {
                    "at": line[:25].strip(),
                    "source_ip": closed.group(2),
                    "display_ip": _mask_ip(closed.group(2)),
                    "target_port": 22,
                    "protocol": "TCP",
                    "kind": "ssh-closed",
                    "detail": f"Conexion SSH cerrada para usuario {closed.group(1)}",
                    "malicious": False,
                }
            )

    attempts.sort(key=lambda item: item["at"], reverse=True)
    top_ports = [{"port": port, "hits": hits} for port, hits in port_counter.most_common(12)]
    return attempts[:limit], top_ports


def get_all_stats() -> dict:
    jails = []
    all_ips = []
    total_banned = 0
    total_failed = 0
    for jail_name in cfg("jails", DEFAULT_JAILS):
        status = parse_status(jail_name)
        total_banned += int(status["currently_banned"])
        total_failed += int(status["currently_failed"])
        all_ips.extend(status["banned_ips"])
        jails.append(status)

    ignoreip_raw = f2b(["get", cfg("jails", ["sshd"])[0], "ignoreip"])
    whitelist = [
        line.strip().lstrip("|-`").strip()
        for line in ignoreip_raw.splitlines()
        if "/" in line or re.search(r"\d{1,3}\.\d{1,3}", line)
    ]
    recent_attempts, top_ports = get_recent_attempts()
    listening_ports = get_listening_ports()
    decisions = evaluate_decisions(recent_attempts, set(all_ips))

    unique_ips = list({attempt["source_ip"] for attempt in recent_attempts if attempt["malicious"]})
    geo_map = {ip: geoip(ip) for ip in unique_ips[:40]} if feature_enabled("external_enrichment") else {}
    shodan_map = {ip: shodan_idb(ip) for ip in unique_ips[:40]} if feature_enabled("external_enrichment") else {}
    for attempt in recent_attempts:
        attempt["geo"] = geo_map.get(attempt["source_ip"], _empty_geo(attempt["source_ip"]))
        attempt["shodan"] = shodan_map.get(attempt["source_ip"], {"ports": [], "hostnames": [], "tags": [], "vulns": [], "cpes": []})

    for jail in jails:
        jail["banned_ips_geo"] = [
            {"ip": ip, "display_ip": _mask_ip(ip), **(geoip(ip) if feature_enabled("external_enrichment") else _empty_geo(ip))}
            for ip in jail["banned_ips"]
        ]

    map_points = []
    if feature_enabled("external_enrichment"):
        all_ip_set = set(all_ips)
        for attempt in recent_attempts:
            geo = attempt["geo"]
            if geo.get("lat") == 0.0 and geo.get("lon") == 0.0:
                continue
            shodan = attempt.get("shodan", {})
            map_points.append(
                {
                    "ip": attempt["display_ip"],
                    "lat": geo.get("lat"),
                    "lon": geo.get("lon"),
                    "country": geo.get("country"),
                    "city": geo.get("city"),
                    "org": geo.get("org"),
                    "banned": attempt["source_ip"] in all_ip_set,
                    "kind": attempt["kind"],
                    "ports": shodan.get("ports", []),
                    "vulns": shodan.get("vulns", []),
                }
            )

    return {
        "app": {"name": cfg("app_name"), "configured": configured()},
        "server": {
            "name": cfg("server_name"),
            "public_ip": cfg("server_public_ip"),
            "lat": cfg("server_lat"),
            "lon": cfg("server_lon"),
        },
        "features": features(),
        "ui": {
            "page_size": int(cfg("page_size", 15)),
            "auto_refresh_seconds": int(cfg("auto_refresh_seconds", 30)),
            "density": cfg("ui_density", "comfortable"),
        },
        "jails": jails,
        "summary": {
            "total_banned": total_banned,
            "total_failed": total_failed,
            "unique_ips": len(set(all_ips)),
        },
        "whitelist": whitelist,
        "protected_whitelist": cfg("protected_whitelist", []),
        "recent_attempts": recent_attempts,
        "decisions": decisions,
        "top_ports": top_ports,
        "listening_ports": listening_ports,
        "map_points": map_points,
        "updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


def _bool_from_form(form, name: str) -> bool:
    return form.get(name) in {"on", "true", "1", "yes"}


def _config_from_form(form, existing: dict) -> dict:
    jails = _split_csv(form.get("jails"), existing.get("jails", DEFAULT_JAILS))
    jail_meta = {}
    for jail in jails:
        base = existing.get("jail_meta", {}).get(jail, DEFAULT_JAIL_META.get(jail, {}))
        jail_meta[jail] = {
            "title": form.get(f"jail_title_{jail}") or base.get("title") or jail,
            "description": form.get(f"jail_description_{jail}") or base.get("description") or "",
            "policy": form.get(f"jail_policy_{jail}") or base.get("policy") or "Activa",
            "tone": form.get(f"jail_tone_{jail}") or base.get("tone") or "neutral",
        }

    config = _merge_config(existing)
    config.update(
        {
            "configured": True,
            "app_name": form.get("app_name", "Fail2ban UI").strip(),
            "server_name": form.get("server_name", "fail2ban-host").strip(),
            "server_public_ip": form.get("server_public_ip", "").strip(),
            "server_lat": float(form.get("server_lat") or 0.0),
            "server_lon": float(form.get("server_lon") or 0.0),
            "bind_host": form.get("bind_host", "127.0.0.1").strip(),
            "bind_port": max(1, min(65535, int(form.get("bind_port") or 2020))),
            "jail_local": form.get("jail_local", "/etc/fail2ban/jail.local").strip(),
            "jails": jails,
            "jail_meta": jail_meta,
            "protected_whitelist": _split_csv(form.get("protected_whitelist"), []),
            "page_size": max(5, min(100, int(form.get("page_size") or 15))),
            "auto_refresh_seconds": max(0, min(3600, int(form.get("auto_refresh_seconds") or 30))),
            "ui_density": form.get("ui_density", "comfortable"),
            "features": {
                "journal_inspection": _bool_from_form(form, "feature_journal_inspection"),
                "port_inventory": _bool_from_form(form, "feature_port_inventory"),
                "write_actions": _bool_from_form(form, "feature_write_actions"),
                "api_enabled": _bool_from_form(form, "feature_api_enabled"),
                "swagger_enabled": _bool_from_form(form, "feature_swagger_enabled"),
                "external_enrichment": _bool_from_form(form, "feature_external_enrichment"),
                "external_links": _bool_from_form(form, "feature_external_links"),
                "mask_ips": _bool_from_form(form, "feature_mask_ips"),
            },
            "notch": {
                "enabled": _bool_from_form(form, "notch_enabled"),
                "webhook_url": form.get("notch_webhook_url", "").strip(),
                "token": form.get("notch_token", "").strip()
                or (existing.get("notch") or {}).get("token", ""),
                "payload_mode": form.get("notch_payload_mode", "masked"),
                "min_severity": form.get("notch_min_severity", "warning"),
            },
            "decisions": {
                "enabled": _bool_from_form(form, "decisions_enabled"),
                "mode": form.get("decision_mode", "recommend"),
                "threshold": max(1, min(100, int(form.get("decision_threshold") or 5))),
                "action_jail": form.get("decision_action_jail", "blacklist-permanent").strip(),
                "notify_recommendations": _bool_from_form(form, "decision_notify_recommendations"),
            },
        }
    )

    username = form.get("auth_username", "admin").strip()
    password = form.get("auth_password", "")
    confirm = form.get("auth_password_confirm", "")
    existing_hash = (existing.get("auth") or {}).get("password_hash", "")
    if password:
        if len(password) < 12:
            raise ValueError("La clave debe tener al menos 12 caracteres.")
        if password != confirm:
            raise ValueError("La confirmacion de clave no coincide.")
        password_hash = _hash_password(password)
    elif existing_hash:
        password_hash = existing_hash
    else:
        raise ValueError("Configura una clave de acceso inicial.")

    config["auth"] = {"username": username, "password_hash": password_hash}
    return config


def require_api_enabled(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not feature_enabled("api_enabled"):
            return jsonify({"error": "api_disabled"}), 404
        return fn(*args, **kwargs)

    return wrapper


def require_write_actions(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not feature_enabled("write_actions"):
            return jsonify({"ok": False, "error": "write_actions_disabled"}), 403
        return fn(*args, **kwargs)

    return wrapper


@app.route("/health")
def health():
    return jsonify({"ok": True, "configured": configured()})


@app.route("/")
def index():
    return render_template("index.html", data=get_all_stats(), config=CONFIG)


@app.route("/setup", methods=["GET", "POST"])
@app.route("/settings", methods=["GET", "POST"])
def setup():
    current = _load_config()
    error = ""
    if request.method == "POST":
        try:
            new_config = _config_from_form(request.form, current)
            _save_config(new_config)
            _reload_config()
            return redirect(url_for("index"))
        except Exception as exc:
            error = str(exc)
    setup_mode = not configured()
    return render_template(
        "setup.html",
        config=current,
        setup_mode=setup_mode,
        setup_token_required=bool(SETUP_TOKEN),
        error=error,
    )


@app.route("/api/stats")
@require_api_enabled
def api_stats():
    return jsonify(get_all_stats())


@app.route("/api/unban/<ip>", methods=["POST"])
@require_api_enabled
@require_write_actions
def unban(ip: str):
    if not re.match(r"^[0-9a-fA-F:.]+$", ip):
        return jsonify({"ok": False, "error": "IP invalida"}), 400
    for jail in cfg("jails", DEFAULT_JAILS):
        f2b(["set", jail, "unbanip", ip])
    return jsonify({"ok": True, "ip": _mask_ip(ip)})


@app.route("/api/geoip/<ip>")
@require_api_enabled
def api_geoip(ip: str):
    if not feature_enabled("external_enrichment"):
        return jsonify({"error": "external_enrichment_disabled"}), 403
    if not re.match(r"^[0-9a-fA-F:.]+$", ip):
        return jsonify({"error": "IP invalida"}), 400
    return jsonify(geoip(ip))


@app.route("/api/shodan/<ip>")
@require_api_enabled
def api_shodan(ip: str):
    if not feature_enabled("external_enrichment"):
        return jsonify({"error": "external_enrichment_disabled"}), 403
    if not re.match(r"^[0-9a-fA-F:.]+$", ip):
        return jsonify({"error": "IP invalida"}), 400
    return jsonify({**geoip(ip), **shodan_idb(ip)})


def _read_jail_local() -> str:
    try:
        with open(cfg("jail_local", "/etc/fail2ban/jail.local"), "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return ""


def _write_jail_local(content: str) -> None:
    with open(cfg("jail_local", "/etc/fail2ban/jail.local"), "w", encoding="utf-8") as f:
        f.write(content)


def _parse_ignoreip(content: str) -> list[str]:
    match = re.search(r"(ignoreip\s*=\s*)([\s\S]*?)(?=\n\w|\Z)", content)
    if not match:
        return []
    entries = []
    for line in match.group(2).splitlines():
        value = line.strip()
        if value and not value.startswith("#"):
            entries.append(value)
    return entries


def _set_ignoreip(content: str, entries: list[str]) -> str:
    first = entries[0] if entries else ""
    rest = "\n".join(f"           {entry}" for entry in entries[1:])
    block = f"ignoreip = {first}\n{rest}" if rest else f"ignoreip = {first}"
    if "ignoreip" not in content:
        default_header = "[DEFAULT]\n" if "[DEFAULT]" not in content else ""
        return f"{content.rstrip()}\n\n{default_header}{block}\n"
    return re.sub(r"ignoreip\s*=\s*[\s\S]*?(?=\n\w|\Z)", block + "\n", content, count=1)


_IP_CIDR_RE = re.compile(r"^((\d{1,3}\.){3}\d{1,3}(/\d{1,2})?|([0-9a-fA-F:]+)(/\d{1,3})?)$")


@app.route("/api/whitelist", methods=["GET"])
@require_api_enabled
def wl_get():
    return jsonify({"entries": _parse_ignoreip(_read_jail_local())})


@app.route("/api/whitelist/add", methods=["POST"])
@require_api_enabled
@require_write_actions
def wl_add():
    data = request.get_json(force=True)
    entry = (data.get("entry") or "").strip()
    if not entry or not _IP_CIDR_RE.match(entry):
        return jsonify({"ok": False, "error": "Formato invalido"}), 400
    content = _read_jail_local()
    entries = _parse_ignoreip(content)
    if entry in entries:
        return jsonify({"ok": False, "error": "Ya existe en whitelist"}), 409
    entries.append(entry)
    _write_jail_local(_set_ignoreip(content, entries))
    for jail in cfg("jails", DEFAULT_JAILS):
        f2b(["set", jail, "addignoreip", entry])
    run_cmd(["ipset", "add", "whitelist", entry, "-exist"])
    return jsonify({"ok": True, "entry": entry})


@app.route("/api/whitelist/remove", methods=["POST"])
@require_api_enabled
@require_write_actions
def wl_remove():
    data = request.get_json(force=True)
    entry = (data.get("entry") or "").strip()
    if entry in set(cfg("protected_whitelist", [])):
        return jsonify({"ok": False, "error": "Entrada protegida"}), 403
    content = _read_jail_local()
    entries = _parse_ignoreip(content)
    if entry not in entries:
        return jsonify({"ok": False, "error": "No encontrado"}), 404
    entries.remove(entry)
    _write_jail_local(_set_ignoreip(content, entries))
    for jail in cfg("jails", DEFAULT_JAILS):
        f2b(["set", jail, "delignoreip", entry])
    run_cmd(["ipset", "del", "whitelist", entry, "-exist"])
    return jsonify({"ok": True, "entry": entry})


def openapi_spec() -> dict:
    return {
        "openapi": "3.0.3",
        "info": {
            "title": cfg("app_name", "Fail2ban UI"),
            "version": "1.0.0",
            "description": "API protegida por Basic Auth para consultar y operar fail2ban-ui.",
        },
        "components": {
            "securitySchemes": {
                "basicAuth": {"type": "http", "scheme": "basic"},
            }
        },
        "security": [{"basicAuth": []}],
        "paths": {
            "/health": {"get": {"summary": "Health check", "responses": {"200": {"description": "OK"}}}},
            "/api/stats": {"get": {"summary": "Dashboard stats", "responses": {"200": {"description": "Stats"}}}},
            "/api/unban/{ip}": {
                "post": {
                    "summary": "Unban IP from configured jails",
                    "parameters": [{"name": "ip", "in": "path", "required": True, "schema": {"type": "string"}}],
                    "responses": {"200": {"description": "Unbanned"}, "403": {"description": "Write actions disabled"}},
                }
            },
            "/api/whitelist": {"get": {"summary": "List whitelist", "responses": {"200": {"description": "Whitelist"}}}},
            "/api/whitelist/add": {
                "post": {
                    "summary": "Add whitelist entry",
                    "requestBody": {
                        "content": {"application/json": {"schema": {"type": "object", "properties": {"entry": {"type": "string"}}}}}
                    },
                    "responses": {"200": {"description": "Added"}},
                }
            },
            "/api/whitelist/remove": {
                "post": {
                    "summary": "Remove whitelist entry",
                    "requestBody": {
                        "content": {"application/json": {"schema": {"type": "object", "properties": {"entry": {"type": "string"}}}}}
                    },
                    "responses": {"200": {"description": "Removed"}},
                }
            },
            "/api/openapi.json": {"get": {"summary": "OpenAPI spec", "responses": {"200": {"description": "OpenAPI"}}}},
        },
    }


@app.route("/api/openapi.json")
def api_openapi():
    if not feature_enabled("swagger_enabled"):
        return jsonify({"error": "swagger_disabled"}), 404
    return jsonify(openapi_spec())


@app.route("/api/docs")
def api_docs():
    if not feature_enabled("swagger_enabled"):
        return jsonify({"error": "swagger_disabled"}), 404
    return render_template("docs.html", spec=openapi_spec(), config=CONFIG)


if __name__ == "__main__":
    app.run(host=str(cfg("bind_host", "127.0.0.1")), port=int(cfg("bind_port", 2020)), debug=False)
