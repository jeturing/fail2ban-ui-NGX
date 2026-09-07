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
MAIL_RELAY_HOST_SERVICE = "sajet-mail-egress-firewall.service"
MAIL_RELAY_PCT_SERVICE = "sajet-mail-inbound-firewall.service"
MAIL_RELAY_ALLOWED_PCT_IP = "10.10.20.206"
MAIL_RELAY_ALLOWED_DOCKER_CIDR = "172.18.0.0/16"
MAIL_RELAY_ALLOWED_POSTFIX_NETS = {
    "127.0.0.0/8",
    "172.18.0.7/32",
    "172.18.0.4/32",
    "172.18.0.3/32",
}
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
            "enabled": os.getenv("FAIL2BAN_UI_DECISIONS_ENABLED", "1") == "1",
            "mode": os.getenv("FAIL2BAN_UI_DECISION_MODE", "recommend"),
            "threshold": _env_int("FAIL2BAN_UI_DECISION_THRESHOLD", 5),
            "action_jail": os.getenv("FAIL2BAN_UI_DECISION_ACTION_JAIL", "blacklist-permanent"),
            "notify_recommendations": os.getenv("FAIL2BAN_UI_DECISION_NOTIFY", "1") == "1",
        },
        "enrichment": {
            # ipinfo.io — token gratis: https://ipinfo.io/signup (50k req/mes)
            "ipinfo_token": os.getenv("FAIL2BAN_UI_IPINFO_TOKEN", ""),
            # Shodan InternetDB — sin clave, pero se puede agregar en el futuro
            "shodan_key": os.getenv("FAIL2BAN_UI_SHODAN_KEY", ""),
        },
        "npm_sidecar": {
            # URL del sidecar npm-custom (ej: http://10.10.20.205:8888)
            "enabled": os.getenv("FAIL2BAN_UI_NPM_ENABLED", "0") == "1",
            "url": os.getenv("FAIL2BAN_UI_NPM_URL", ""),
            "api_key": os.getenv("FAIL2BAN_UI_NPM_API_KEY", ""),
            # Si True, al banear en fail2ban también bloquea en NPM access list
            "sync_bans": os.getenv("FAIL2BAN_UI_NPM_SYNC_BANS", "0") == "1",
            # Nombre de la access list en NPM donde se agregan las IPs baneadas
            "access_list_name": os.getenv("FAIL2BAN_UI_NPM_ACCESS_LIST", "fail2ban-blocked"),
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
    config["enrichment"].update(saved.get("enrichment") or {})
    config["npm_sidecar"].update(saved.get("npm_sidecar") or {})
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


def enrichment_config() -> dict:
    return CONFIG.get("enrichment", {})


def npm_sidecar_config() -> dict:
    return CONFIG.get("npm_sidecar", {})


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
    
    # Webhook receptor de notificaciones (sin autenticación)
    if request.path == "/api/fail2ban" and request.method == "POST":
        return None

    if not configured():
        if (request.path.startswith("/setup") or request.path.startswith("/settings")) and _setup_token_ok(request.form.to_dict()):
            return None
        if request.path.startswith("/api"):
            return jsonify({"error": "setup_required"}), 428
        setup_token = request.args.get("token") or SETUP_TOKEN
        return redirect(url_for("setup", token=setup_token))

    if not _basic_auth_ok():
        return _auth_response()
    return None


@app.after_request
def secure_headers(response):
    frame_ancestors = os.getenv(
        "FAIL2BAN_UI_FRAME_ANCESTORS",
        "'self' https://sajet.us https://www.sajet.us https://app.jeturing.com",
    )
    if frame_ancestors.strip() in {"'none'", "none"}:
        response.headers.setdefault("X-Frame-Options", "DENY")
    else:
        response.headers.pop("X-Frame-Options", None)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Cache-Control", "no-store")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; img-src 'self' data: https://tile.openstreetmap.org https://a.tile.openstreetmap.org https://b.tile.openstreetmap.org https://c.tile.openstreetmap.org https://*.tile.openstreetmap.de https://tile.openstreetmap.de https://*.openstreetmap.org; style-src 'self' 'unsafe-inline'; "
        f"script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors {frame_ancestors};",
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
        "org": "geo no disponible",
        "lat": 0.0,
        "lon": 0.0,
        "ip": ip,
    }


def _pseudo_geo_from_ip(ip: str) -> tuple[float, float]:
    """Coordenadas estimadas determinísticas para visualización cuando no hay GeoIP real."""
    try:
        digest = hashlib.sha256(ip.encode("utf-8")).hexdigest()
        lat_seed = int(digest[:8], 16)
        lon_seed = int(digest[8:16], 16)
        lat = (lat_seed / 0xFFFFFFFF) * 140 - 70
        lon = (lon_seed / 0xFFFFFFFF) * 340 - 170
        return round(lat, 4), round(lon, 4)
    except Exception:
        return 0.0, 0.0


def geoip(ip: str) -> dict:
    if not feature_enabled("external_enrichment"):
        return {**_empty_geo(ip), "org": "enriquecimiento externo apagado"}
    if ip in _geo_cache:
        return _geo_cache[ip]
    try:
        token = enrichment_config().get("ipinfo_token", "")
        url = f"https://ipinfo.io/{ip}/json?token={token}" if token else f"https://ipinfo.io/{ip}/json"
        data = _fetch_json(url)
        if data.get("status") == 429 or data.get("error"):
            raise RuntimeError("ipinfo_unavailable")
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
        try:
            data = _fetch_json(
                f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,lat,lon,isp,org,query",
                timeout=4,
            )
            if data.get("status") != "success":
                raise RuntimeError("ip_api_unavailable")
            result = {
                "country": data.get("countryCode") or data.get("country") or "--",
                "city": data.get("city", ""),
                "region": data.get("regionName", ""),
                "org": data.get("org") or data.get("isp") or "",
                "lat": float(data.get("lat") or 0.0),
                "lon": float(data.get("lon") or 0.0),
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


def shodan_idb_on_demand(ip: str) -> dict:
    """Consulta Shodan InternetDB aun con enrichment apagado, para drill-down manual."""
    try:
        parsed = ipaddress.ip_address(ip)
        if parsed.is_private or parsed.is_loopback or parsed.is_reserved or parsed.is_multicast:
            return {"ports": [], "hostnames": [], "tags": [], "vulns": [], "cpes": [], "note": "ip_no_publica"}
    except ValueError:
        return {"ports": [], "hostnames": [], "tags": [], "vulns": [], "cpes": [], "note": "ip_invalida"}
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
            "source": "shodan_internetdb",
        }
    except Exception:
        result = {"ports": [], "hostnames": [], "tags": [], "vulns": [], "cpes": [], "source": "shodan_internetdb"}
    _shodan_cache[ip] = result
    return result


# ─── NPM Sidecar integration ─────────────────────────────────────────────────

def _npm_headers() -> dict:
    key = npm_sidecar_config().get("api_key", "")
    headers = {"User-Agent": "fail2ban-ui/1.0", "Content-Type": "application/json"}
    if key:
        headers["x-api-key"] = key
    return headers


def npm_push_ban(ip: str) -> bool:
    """Agrega una IP a la access list de bloqueo en NPM vía sidecar."""
    npm = npm_sidecar_config()
    if not npm.get("enabled") or not npm.get("sync_bans") or not npm.get("url"):
        return False
    try:
        base = npm["url"].rstrip("/")
        # 1. Obtener o crear la access list
        req = urllib.request.Request(
            f"{base}/npm/access-lists",
            headers=_npm_headers(),
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            lists = json.loads(resp.read())
        target = next((lst for lst in lists if lst.get("name") == npm["access_list_name"]), None)
        if not target:
            # Crear la access list
            body = json.dumps({"name": npm["access_list_name"], "satisfy_any": True, "pass_auth": False}).encode()
            create_req = urllib.request.Request(
                f"{base}/npm/access-lists",
                data=body, headers=_npm_headers(), method="POST",
            )
            with urllib.request.urlopen(create_req, timeout=5) as resp:
                target = json.loads(resp.read())
        list_id = target.get("id")
        if not list_id:
            return False
        # 2. Añadir regla deny para la IP
        clients = target.get("clients") or []
        if not any(c.get("address") == ip for c in clients):
            clients.append({"address": ip, "directive": "deny"})
            update_body = json.dumps({
                "name": npm["access_list_name"],
                "satisfy_any": True,
                "pass_auth": False,
                "clients": clients,
            }).encode()
            update_req = urllib.request.Request(
                f"{base}/npm/access-lists/{list_id}",
                data=update_body, headers=_npm_headers(), method="PUT",
            )
            with urllib.request.urlopen(update_req, timeout=5):
                pass
        return True
    except Exception:
        return False


def npm_push_unban(ip: str) -> bool:
    """Elimina una IP de la access list de bloqueo en NPM vía sidecar."""
    npm = npm_sidecar_config()
    if not npm.get("enabled") or not npm.get("sync_bans") or not npm.get("url"):
        return False
    try:
        base = npm["url"].rstrip("/")
        req = urllib.request.Request(
            f"{base}/npm/access-lists",
            headers=_npm_headers(),
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            lists = json.loads(resp.read())
        target = next((lst for lst in lists if lst.get("name") == npm["access_list_name"]), None)
        if not target:
            return False
        list_id = target.get("id")
        clients = [c for c in (target.get("clients") or []) if c.get("address") != ip]
        update_body = json.dumps({
            "name": npm["access_list_name"],
            "satisfy_any": True,
            "pass_auth": False,
            "clients": clients,
        }).encode()
        update_req = urllib.request.Request(
            f"{base}/npm/access-lists/{list_id}",
            data=update_body, headers=_npm_headers(), method="PUT",
        )
        with urllib.request.urlopen(update_req, timeout=5):
            pass
        return True
    except Exception:
        return False


def npm_get_proxy_hosts() -> list[dict]:
    """Obtiene lista de proxy hosts activos del sidecar."""
    npm = npm_sidecar_config()
    if not npm.get("enabled") or not npm.get("url"):
        return []
    try:
        base = npm["url"].rstrip("/")
        req = urllib.request.Request(
            f"{base}/proxy-hosts",
            headers=_npm_headers(),
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            hosts = json.loads(resp.read())
        return [
            {
                "id": h.get("id"),
                "domains": h.get("domain_names", []),
                "forward": f"{h.get('forward_scheme','http')}://{h.get('forward_host')}:{h.get('forward_port')}",
                "enabled": h.get("enabled", True),
                "ssl": bool(h.get("certificate_id")),
            }
            for h in (hosts if isinstance(hosts, list) else [])
        ]
    except Exception:
        return []


# ──────────────────────────────────────────────────────────────────────────────

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


def run_cmd_result(command: list[str], timeout: int = 8) -> dict:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
        return {
            "ok": result.returncode == 0,
            "returncode": result.returncode,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "command": " ".join(command),
        }
    except Exception as exc:
        return {"ok": False, "returncode": -1, "stdout": "", "stderr": str(exc), "command": " ".join(command)}


def _line_has_all(line: str, tokens: list[str]) -> bool:
    return all(token in line for token in tokens)


def _mail_relay_firewall_status() -> dict:
    host_rules = run_cmd_result(["iptables", "-S", "FORWARD"])
    pct_rules = run_cmd_result(["pct", "exec", "206", "--", "iptables", "-S", "INPUT"])
    host_text = f"{host_rules.get('stdout','')}\n{host_rules.get('stderr','')}"
    pct_text = f"{pct_rules.get('stdout','')}\n{pct_rules.get('stderr','')}"

    checks = {
        "host_allows_only_mail_pct_25": _line_has_all(
            host_text,
            ["-A FORWARD", "-s 10.10.20.206/32", "--dport 25", "-j ACCEPT"],
        ),
        "host_blocks_before_mail_pct_range_25": _line_has_all(
            host_text,
            ["--src-range 10.10.20.0-10.10.20.205", "--dport 25", "-j REJECT"],
        ),
        "host_blocks_after_mail_pct_range_25": _line_has_all(
            host_text,
            ["--src-range 10.10.20.207-10.10.20.255", "--dport 25", "-j REJECT"],
        ),
        "pct_allows_loopback_25": _line_has_all(
            pct_text,
            ["-A INPUT", "-i lo", "--dport 25", "-j ACCEPT"],
        ),
        "pct_allows_postal_internal_25": _line_has_all(
            pct_text,
            ["-A INPUT", "-s 172.18.0.0/16", "--dport 25", "-j ACCEPT"],
        ),
        "pct_blocks_public_25": _line_has_all(
            pct_text,
            ["-A INPUT", "--dport 25", "-j DROP"],
        ),
    }
    host_service = run_cmd_result(["systemctl", "is-enabled", MAIL_RELAY_HOST_SERVICE])
    pct_service = run_cmd_result(["systemctl", "is-enabled", MAIL_RELAY_PCT_SERVICE])
    return {
        "ok": all(checks.values()),
        "checks": checks,
        "host_service_enabled": host_service.get("stdout") == "enabled",
        "pct_service_enabled": pct_service.get("stdout") == "enabled",
        "host_rules_error": "" if host_rules.get("ok") else host_rules.get("stderr"),
        "pct_rules_error": "" if pct_rules.get("ok") else pct_rules.get("stderr"),
    }


def _mail_relay_postfix_status() -> dict:
    conf = run_cmd_result(["pct", "exec", "206", "--", "postconf", "-n"])
    text = conf.get("stdout", "")
    mynetworks_line = ""
    relay_line = ""
    recipient_line = ""
    for line in text.splitlines():
        if line.startswith("mynetworks ="):
            mynetworks_line = line
        elif line.startswith("smtpd_relay_restrictions ="):
            relay_line = line
        elif line.startswith("smtpd_recipient_restrictions ="):
            recipient_line = line
    nets = {item.strip() for item in mynetworks_line.split("=", 1)[-1].split(",") if item.strip()} if mynetworks_line else set()
    return {
        "ok": (
            bool(mynetworks_line)
            and nets == MAIL_RELAY_ALLOWED_POSTFIX_NETS
            and "reject_unauth_destination" in relay_line
            and "reject_unauth_destination" in recipient_line
        ),
        "mynetworks": sorted(nets),
        "relay_restrictions": relay_line,
        "recipient_restrictions": recipient_line,
        "error": "" if conf.get("ok") else conf.get("stderr"),
    }


def get_mail_relay_guard_status() -> dict:
    firewall = _mail_relay_firewall_status()
    postfix = _mail_relay_postfix_status()
    return {
        "ok": bool(firewall.get("ok") and postfix.get("ok")),
        "firewall": firewall,
        "postfix": postfix,
        "public_smtp_25_policy": "bloqueado para Internet; permitido sólo al flujo Postal interno",
        "egress_smtp_25_policy": f"sólo {MAIL_RELAY_ALLOWED_PCT_IP} puede salir a puerto 25",
        "updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


def apply_mail_relay_guard() -> dict:
    commands = [
        ["systemctl", "enable", "--now", MAIL_RELAY_HOST_SERVICE],
        ["systemctl", "enable", "--now", MAIL_RELAY_PCT_SERVICE],
        [
            "pct", "exec", "206", "--", "postconf", "-e",
            "mynetworks = 127.0.0.0/8, 172.18.0.7/32, 172.18.0.4/32, 172.18.0.3/32",
        ],
        [
            "pct", "exec", "206", "--", "postconf", "-e",
            "smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination",
        ],
        [
            "pct", "exec", "206", "--", "postconf", "-e",
            "smtpd_recipient_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination, reject_invalid_hostname, reject_non_fqdn_hostname",
        ],
        [
            "pct", "exec", "206", "--", "postconf", "-e",
            "smtpd_sender_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unknown_sender_domain",
        ],
        ["pct", "exec", "206", "--", "postfix", "check"],
        ["pct", "exec", "206", "--", "systemctl", "reload", "postfix"],
    ]
    results = [run_cmd_result(command, timeout=20) for command in commands]
    return {"ok": all(item.get("ok") for item in results), "results": results, "status": get_mail_relay_guard_status()}


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
                npm_push_ban(source_ip)
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


def _classify_port_exposure(host: str) -> str:
    host = (host or "").strip("[]")
    if host in {"127.0.0.1", "::1"} or host.startswith("127."):
        return "loopback"
    if host.startswith("100.") or host.startswith("fd7a:"):
        return "tailscale"
    if host in {"0.0.0.0", "::", "*"}:
        return "public"
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_loopback:
            return "loopback"
        if ip.is_private:
            return "interna"
        return "public"
    except ValueError:
        return "public"


def _port_risk(port: int, exposure: str) -> str:
    if exposure != "public":
        return "low"
    high = {21, 23, 111, 135, 139, 445, 1433, 1521, 3306, 5432, 6379, 11211, 27017}
    medium = {22, 80, 443, 3389, 8080, 8443}
    if port in high:
        return "high"
    if port in medium:
        return "medium"
    return "medium"


def _source_scope(ip: str) -> str:
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return "desconocido"
    if parsed.is_loopback:
        return "loopback"
    if parsed.is_private:
        return "interna"
    if parsed.is_reserved or parsed.is_multicast:
        return "reservada"
    return "internet"


def get_listening_ports() -> list[dict]:
    if not feature_enabled("port_inventory"):
        return []
    raw = run_cmd(["ss", "-tulnpH"])
    ports = []
    for line in raw.splitlines():
        match = re.match(r"^(tcp|udp)\s+\S+\s+\d+\s+\d+\s+(\S+)\s+\S+(?:\s+(.*))?$", line)
        if not match:
            continue
        protocol = (match.group(1) or "tcp").upper()
        local = match.group(2)
        process = (match.group(3) or "-").strip()
        local = local.strip()
        if local.startswith("[") and "]" in local:
            host = local[1 : local.rfind("]")]
            tail = local[local.rfind("]") + 1 :]
            port_match = re.search(r":(\d+)$", tail)
        else:
            host = local.rsplit(":", 1)[0] if ":" in local else local
            port_match = re.search(r":(\d+)$", local)
        if not port_match:
            continue
        port = int(port_match.group(1))
        exposure = _classify_port_exposure(host)
        risk = _port_risk(port, exposure)
        ports.append(
            {
                "port": port,
                "protocol": protocol,
                "host": host,
                "process": process or "-",
                "exposure": exposure,
                "risk": risk,
            }
        )
    return sorted(ports, key=lambda item: (item["exposure"], item["risk"], item["port"], item["protocol"]))


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
                "source_scope": _source_scope(src.group(1)),
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
                    "source_scope": _source_scope(source_ip),
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
                    "source_scope": _source_scope(closed.group(2)),
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


def auto_blacklist_enforcement(events: list[dict]) -> None:
    """
    Implementa regla de blacklist automática:
    - Si una IP tiene 120+ eventos interneteros → blacklist 24h (fail2ban)
    - Si está EN blacklist 24h y vuelve a atacar 3+ veces más → blacklist permanente
    """
    try:
        # Cargar historial de blacklists desde state.json
        state_path = os.getenv("FAIL2BAN_UI_STATE_PATH", "/var/lib/fail2ban-ui/state.json")
        state = {}
        if os.path.exists(state_path):
            try:
                with open(state_path, "r", encoding="utf-8") as f:
                    state = json.load(f)
            except Exception:
                state = {}
        
        blacklist_24h_state = state.get("blacklist_24h_state", {})  # {ip: {count, first_seen}}
        already_permanent = state.get("blacklist_permanent_ips", set())
        
        # Contar eventos por IP (solo internet scope)
        internet_events = [e for e in events if e.get("source_scope") == "internet" and e.get("malicious")]
        ip_counts = Counter(e.get("source_ip") for e in internet_events if e.get("source_ip"))
        
        # Regla 1: 120+ eventos → blacklist 24h
        for ip, count in ip_counts.items():
            if count >= 120 and ip not in already_permanent:
                if ip not in blacklist_24h_state:
                    print(f"[AUTO-BLACKLIST] {ip}: {count} eventos, aplicando ban 24h")
                    for jail in cfg("jails", DEFAULT_JAILS):
                        f2b(["set", jail, "banip", ip])
                    blacklist_24h_state[ip] = {"count": count, "first_seen": datetime.now().isoformat()}
                    npm_push_ban(ip)
        
        # Regla 2: Si está en 24h y vuelve a atacar 3+ veces → permanente
        for ip in list(blacklist_24h_state.keys()):
            if ip not in already_permanent and ip in ip_counts:
                current_count = ip_counts[ip]
                prev_count = blacklist_24h_state[ip].get("count", 0)
                new_attacks = current_count - prev_count
                
                if new_attacks >= 3:
                    print(f"[AUTO-BLACKLIST] {ip}: ya estaba baneada, +{new_attacks} intentos nuevos, moviendo a PERMANENTE")
                    f2b(["set", "blacklist-permanent", "banip", ip])
                    already_permanent.add(ip)
                    del blacklist_24h_state[ip]
                    npm_push_ban(ip)
                else:
                    blacklist_24h_state[ip]["count"] = current_count
        
        # Guardar estado actualizado
        state["blacklist_24h_state"] = blacklist_24h_state
        state["blacklist_permanent_ips"] = list(already_permanent)
        state["auto_blacklist_last_run"] = datetime.now().isoformat()
        
        os.makedirs(os.path.dirname(state_path), exist_ok=True, mode=0o700)
        tmp_path = f"{state_path}.tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2, ensure_ascii=False)
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, state_path)
    except Exception as e:
        print(f"[AUTO-BLACKLIST] Error: {e}")


def get_fail2ban_events(limit: int = 120) -> list[dict]:
    raw = run_cmd(["tail", "-n", "600", "/var/log/fail2ban.log"])
    events: list[dict] = []
    for line in raw.splitlines():
        m_action = re.search(
            r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2},\d+)\s+fail2ban\.actions\s+\[[^\]]+\]:\s+NOTICE\s+\[(?P<jail>[^\]]+)\]\s+(?P<action>Ban|Unban)\s+(?P<ip>[0-9a-fA-F:.]+)",
            line,
        )
        if m_action:
            ip = m_action.group("ip")
            action = m_action.group("action").lower()
            jail = m_action.group("jail")
            events.append(
                {
                    "at": m_action.group(1),
                    "source_ip": ip,
                    "display_ip": _mask_ip(ip),
                    "source_scope": _source_scope(ip),
                    "target_port": "-",
                    "protocol": "-",
                    "kind": f"f2b-{action}",
                    "detail": f"{action.upper()} en jail {jail}",
                    "malicious": action == "ban",
                }
            )
            continue

        m_found = re.search(
            r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2},\d+)\s+fail2ban\.filter\s+\[[^\]]+\]:\s+INFO\s+\[(?P<jail>[^\]]+)\]\s+Found\s+(?P<ip>[0-9a-fA-F:.]+)",
            line,
        )
        if m_found:
            ip = m_found.group("ip")
            jail = m_found.group("jail")
            events.append(
                {
                    "at": m_found.group(1),
                    "source_ip": ip,
                    "display_ip": _mask_ip(ip),
                    "source_scope": _source_scope(ip),
                    "target_port": "-",
                    "protocol": "-",
                    "kind": "f2b-found",
                    "detail": f"Detectado por fail2ban en jail {jail}",
                    "malicious": True,
                }
            )

    events.reverse()
    return events[:limit]


def _event_sort_key(event: dict) -> datetime:
    raw = str(event.get("at") or "").strip()
    for fmt in ("%Y-%m-%d %H:%M:%S,%f", "%b %d %H:%M:%S"):
        try:
            parsed = datetime.strptime(raw, fmt)
            if fmt == "%b %d %H:%M:%S":
                parsed = parsed.replace(year=datetime.now().year)
            return parsed
        except ValueError:
            continue
    return datetime.min


def _compute_security_posture(
    listening_ports: list[dict],
    port_monitor: dict,
    summary: dict,
    feature_flags: dict,
    protected_whitelist: list[str],
) -> dict:
    score = 100
    findings: list[str] = []
    recommendations: list[str] = []

    public_total = int(port_monitor.get("public_total", 0))
    high_risk = port_monitor.get("high_risk_public", []) or []
    total_failed = int(summary.get("total_failed", 0))

    if public_total > 0:
        score -= min(20, public_total * 2)
        findings.append(f"{public_total} puertos expuestos en WAN")
        recommendations.append("Reducir puertos expuestos y mantener servicios de gestión solo por VPN/loopback")

    if high_risk:
        score -= min(30, len(high_risk) * 6)
        uniq = sorted({f"{p.get('port')}/{p.get('protocol')}" for p in high_risk})
        findings.append(f"Puertos de riesgo alto públicos: {', '.join(uniq[:6])}")
        recommendations.append("Filtrar puertos de riesgo alto en firewall de host")
        if any((p.get("port") in {111, 2049}) for p in high_risk):
            findings.append("Servicios RPC/NFS expuestos en WAN (riesgo para NAS)")
            recommendations.append("Mover NAS a red VPN privada y bloquear 111/2049 en IP pública")

    if total_failed > 0:
        score -= min(20, total_failed)
        findings.append(f"{total_failed} fallos activos en jails")

    if not feature_flags.get("write_actions"):
        score -= 8
        findings.append("Panel en modo solo lectura (sin acciones correctivas desde UI)")

    if not feature_flags.get("api_enabled"):
        score -= 3
        findings.append("API deshabilitada (limita integración y automatización)")

    if "216.106.182.26/32" not in set(protected_whitelist):
        score -= 15
        findings.append("IP pública del servidor no está en whitelist protegida")
        recommendations.append("Agregar 216.106.182.26/32 a protected_whitelist")

    has_ssh_public = any(
        p.get("port") == 22 and p.get("exposure") == "public" and p.get("protocol") == "TCP"
        for p in listening_ports
    )
    if has_ssh_public:
        score -= 8
        findings.append("SSH público detectado en WAN")
        recommendations.append("Restringir SSH por allowlist o mover acceso administrativo a VPN")

    score = max(0, min(100, score))
    if score >= 85:
        level = "alta"
        tone = "ok"
    elif score >= 65:
        level = "media"
        tone = "warn"
    else:
        level = "critica"
        tone = "danger"

    if not recommendations:
        recommendations.append("Mantener revisión periódica de puertos y eventos en jails")

    return {
        "score": score,
        "level": level,
        "tone": tone,
        "findings": findings[:6],
        "recommendations": recommendations[:6],
    }


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
    fail2ban_events = get_fail2ban_events()
    attack_events = sorted((recent_attempts + fail2ban_events), key=_event_sort_key, reverse=True)[:220]
    
    # Ejecutar auto-blacklist enforcement
    auto_blacklist_enforcement(attack_events)
    listening_ports = get_listening_ports()
    decisions = evaluate_decisions(attack_events, set(all_ips))

    unique_ips = list({attempt["source_ip"] for attempt in attack_events if attempt["malicious"]})
    geo_map = {ip: geoip(ip) for ip in unique_ips[:40]} if feature_enabled("external_enrichment") else {}
    shodan_map = {ip: shodan_idb(ip) for ip in unique_ips[:40]} if feature_enabled("external_enrichment") else {}
    for attempt in attack_events:
        attempt["geo"] = geo_map.get(attempt["source_ip"], _empty_geo(attempt["source_ip"]))
        attempt["shodan"] = shodan_map.get(attempt["source_ip"], {"ports": [], "hostnames": [], "tags": [], "vulns": [], "cpes": []})

    for jail in jails:
        jail["banned_ips_geo"] = [
            {"ip": ip, "display_ip": _mask_ip(ip), **(geoip(ip) if feature_enabled("external_enrichment") else _empty_geo(ip))}
            for ip in jail["banned_ips"]
        ]

    map_points = []
    all_ip_set = set(all_ips)
    for attempt in attack_events:
        source_ip = attempt.get("source_ip") or ""
        geo = attempt.get("geo") or _empty_geo(source_ip)
        lat = geo.get("lat") or 0.0
        lon = geo.get("lon") or 0.0
        estimated = False
        if lat == 0.0 and lon == 0.0:
            lat, lon = _pseudo_geo_from_ip(source_ip)
            estimated = True
        shodan = attempt.get("shodan", {})
        map_points.append(
            {
                "ip": attempt["display_ip"],
                "source_ip": source_ip,
                "source_scope": attempt.get("source_scope", "desconocido"),
                "lat": lat,
                "lon": lon,
                "country": geo.get("country", "--"),
                "city": geo.get("city", ""),
                "org": geo.get("org", ""),
                "estimated": estimated,
                "banned": source_ip in all_ip_set,
                "kind": attempt["kind"],
                "ports": shodan.get("ports", []),
                "vulns": shodan.get("vulns", []),
            }
        )

    public_ports = [p for p in listening_ports if p["exposure"] == "public"]
    high_risk_public = [p for p in public_ports if p["risk"] == "high"]
    if not map_points and cfg("server_public_ip"):
        host_ip = str(cfg("server_public_ip") or "").strip()
        if host_ip:
            lat = float(cfg("server_lat", 0.0) or 0.0)
            lon = float(cfg("server_lon", 0.0) or 0.0)
            estimated = False
            if lat == 0.0 and lon == 0.0:
                lat, lon = _pseudo_geo_from_ip(host_ip)
                estimated = True
            map_points.append(
                {
                    "ip": _mask_ip(host_ip),
                    "source_ip": host_ip,
                    "source_scope": "internet",
                    "lat": lat,
                    "lon": lon,
                    "country": "HOST",
                    "city": "Superficie pública",
                    "org": "servicio local",
                    "estimated": estimated,
                    "banned": False,
                    "kind": "host-surface",
                    "ports": [p.get("port") for p in public_ports[:10]],
                    "vulns": [],
                }
            )
    port_monitor = {
        "total": len(listening_ports),
        "public_total": len(public_ports),
        "tcp_total": sum(1 for p in listening_ports if p.get("protocol") == "TCP"),
        "udp_total": sum(1 for p in listening_ports if p.get("protocol") == "UDP"),
        "high_risk_public": high_risk_public[:20],
    }
    summary = {
        "total_banned": total_banned,
        "total_failed": total_failed,
        "unique_ips": len(set(all_ips)),
        "internet_events": sum(1 for a in attack_events if a.get("source_scope") == "internet" and a.get("malicious")),
        "internal_events": sum(1 for a in attack_events if a.get("source_scope") in {"interna", "loopback"} and a.get("malicious")),
        "logged_bans": sum(1 for a in attack_events if a.get("kind") == "f2b-ban"),
    }
    security_posture = _compute_security_posture(
        listening_ports,
        port_monitor,
        summary,
        features(),
        cfg("protected_whitelist", []),
    )
    
    # Cargar eventos webhook recibidos
    state = _load_state()
    webhook_events = state.get("webhook_events", [])

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
        "summary": summary,
        "security_posture": security_posture,
        "whitelist": whitelist,
        "protected_whitelist": cfg("protected_whitelist", []),
        "recent_attempts": recent_attempts,
        "fail2ban_events": fail2ban_events,
        "attack_events": attack_events,
        "decisions": decisions,
        "webhook_events": webhook_events[-20:],  # Últimos 20 eventos
        "top_ports": top_ports,
        "listening_ports": listening_ports,
        "port_monitor": port_monitor,
        "map_points": map_points,
        "npm": {
            "enabled": npm_sidecar_config().get("enabled", False),
            "proxy_hosts": npm_get_proxy_hosts(),
        },
        "mail_relay_guard": get_mail_relay_guard_status(),
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
            "enrichment": {
                "ipinfo_token": form.get("enrichment_ipinfo_token", "").strip()
                    or (existing.get("enrichment") or {}).get("ipinfo_token", ""),
                "shodan_key": form.get("enrichment_shodan_key", "").strip()
                    or (existing.get("enrichment") or {}).get("shodan_key", ""),
            },
            "npm_sidecar": {
                "enabled": _bool_from_form(form, "npm_enabled"),
                "url": form.get("npm_url", "").strip(),
                "api_key": form.get("npm_api_key", "").strip()
                    or (existing.get("npm_sidecar") or {}).get("api_key", ""),
                "sync_bans": _bool_from_form(form, "npm_sync_bans"),
                "access_list_name": form.get("npm_access_list_name", "fail2ban-blocked").strip(),
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
    return render_template("index.html", config=CONFIG)


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
    npm_push_unban(ip)
    return jsonify({"ok": True, "ip": _mask_ip(ip), "npm_sync": npm_sidecar_config().get("sync_bans", False)})


@app.route("/api/geoip/<ip>")
@require_api_enabled
def api_geoip(ip: str):
    if not feature_enabled("external_enrichment"):
        return jsonify({"error": "external_enrichment_disabled"}), 403
    if not re.match(r"^[0-9a-fA-F:.]+$", ip):
        return jsonify({"error": "IP invalida"}), 400
    return jsonify(geoip(ip))


@app.route("/api/npm/status")
@require_api_enabled
def api_npm_status():
    """Estado del sidecar NPM: proxy hosts activos y access list de bloqueo."""
    npm = npm_sidecar_config()
    if not npm.get("enabled"):
        return jsonify({"error": "npm_sidecar_disabled"}), 404
    try:
        base = npm["url"].rstrip("/")
        # Health del sidecar
        req = urllib.request.Request(f"{base}/health", headers=_npm_headers())
        with urllib.request.urlopen(req, timeout=4) as resp:
            health = json.loads(resp.read())
    except Exception as exc:
        health = {"ok": False, "error": str(exc)}
    return jsonify({
        "sidecar_url": npm["url"],
        "sync_bans": npm.get("sync_bans", False),
        "access_list_name": npm.get("access_list_name", "fail2ban-blocked"),
        "health": health,
        "proxy_hosts": npm_get_proxy_hosts(),
    })


@app.route("/api/mail-relay/status")
@require_api_enabled
def api_mail_relay_status():
    """Estado anti open-relay para el servidor de correo Sajet."""
    return jsonify(get_mail_relay_guard_status())


@app.route("/api/mail-relay/apply", methods=["POST"])
@require_api_enabled
@require_write_actions
def api_mail_relay_apply():
    """Aplica/repara las reglas anti open-relay públicas e internas."""
    return jsonify(apply_mail_relay_guard())


def _month_start() -> str:
    now = datetime.utcnow()
    return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0).strftime("%Y-%m-%d %H:%M:%S")


def _log_lines_from_command(command: list[str], source: str, limit: int = 500, timeout: int = 20) -> list[dict]:
    result = run_cmd_result(command, timeout=timeout)
    lines = (result.get("stdout") or result.get("stderr") or "").splitlines()
    return [{"source": source, "line": line} for line in lines[-limit:] if line.strip()]


def get_month_logs(limit: int = 800) -> dict:
    since = _month_start()
    sections = []
    sections.append({
        "name": "Postfix / Postal PCT 206",
        "items": _log_lines_from_command(
            ["pct", "exec", "206", "--", "journalctl", "--since", since, "--no-pager", "-u", "postfix", "-n", str(limit)],
            "mail-pct206",
            limit=limit,
        ),
    })
    sections.append({
        "name": "Mail log PCT 206",
        "items": _log_lines_from_command(
            ["pct", "exec", "206", "--", "bash", "-lc", f"grep -h \"$(date +%b)\" /var/log/mail.log /var/log/mail.log.* 2>/dev/null | tail -n {int(limit)}"],
            "mail-log-pct206",
            limit=limit,
        ),
    })
    sections.append({
        "name": "Fail2ban host",
        "items": _log_lines_from_command(
            ["journalctl", "--since", since, "--no-pager", "-u", "fail2ban", "-n", str(limit)],
            "fail2ban-host",
            limit=limit,
        ),
    })
    sections.append({
        "name": "Firewall anti open-relay",
        "items": _log_lines_from_command(
            [
                "journalctl",
                "--since",
                since,
                "--no-pager",
                "-u",
                MAIL_RELAY_HOST_SERVICE,
                "-u",
                MAIL_RELAY_PCT_SERVICE,
                "-n",
                str(limit),
            ],
            "mail-relay-firewall",
            limit=limit,
        ),
    })
    total = sum(len(section["items"]) for section in sections)
    return {
        "ok": True,
        "since": since,
        "limit": limit,
        "total": total,
        "sections": sections,
        "updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


@app.route("/api/month-logs")
@require_api_enabled
def api_month_logs():
    try:
        limit = max(50, min(2000, int(request.args.get("limit", "800"))))
    except ValueError:
        limit = 800
    return jsonify(get_month_logs(limit=limit))


def _parse_jail_status(name: str) -> dict:
    raw = f2b(["status", name])
    def number(pattern: str) -> int:
        match = re.search(pattern, raw)
        return int(match.group(1)) if match else 0
    banned_line = re.search(r"Banned IP list:\s*(.*)", raw)
    banned_ips = []
    if banned_line:
        banned_ips = [ip for ip in banned_line.group(1).split() if ip]
    meta = cfg("jail_meta", {}).get(name, DEFAULT_JAIL_META.get(name, {}))
    return {
        "name": name,
        "enabled": "ERROR:" not in raw and "Sorry but the jail" not in raw,
        "currently_failed": number(r"Currently failed:\s*(\d+)"),
        "total_failed": number(r"Total failed:\s*(\d+)"),
        "currently_banned": number(r"Currently banned:\s*(\d+)"),
        "total_banned": number(r"Total banned:\s*(\d+)"),
        "banned_ips": banned_ips[:60],
        "meta": meta,
    }


def get_fail2ban_lite() -> dict:
    jails = [_parse_jail_status(jail) for jail in cfg("jails", DEFAULT_JAILS)]
    attempts, top_ports = get_recent_attempts(limit=40)
    listening_ports = get_listening_ports()
    summary = {
        "total_banned": sum(jail.get("currently_banned", 0) for jail in jails),
        "logged_bans": sum(jail.get("total_banned", 0) for jail in jails),
        "internet_events": sum(1 for item in attempts if item.get("source_scope") == "internet"),
        "internal_events": sum(1 for item in attempts if item.get("source_scope") in {"interna", "loopback"}),
    }
    return {
        "ok": True,
        "summary": summary,
        "jails": jails,
        "attack_events": attempts,
        "top_ports": top_ports,
        "listening_ports": listening_ports,
        "updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


@app.route("/api/fail2ban-lite")
@require_api_enabled
def api_fail2ban_lite():
    return jsonify(get_fail2ban_lite())


def _geo_for_map(ip: str) -> dict:
    geo = geoip(ip)
    estimated = False
    if not geo.get("lat") or not geo.get("lon"):
        lat, lon = _pseudo_geo_from_ip(ip)
        geo = {**geo, "lat": lat, "lon": lon}
        estimated = True
    source = "ipinfo" if feature_enabled("external_enrichment") and not estimated else "estimado"
    return {**geo, "estimated": estimated, "source": source}


def _dsam_enrichment_for_ips(ips: list[str]) -> dict[str, dict]:
    """Best-effort DSAM bridge. Never blocks the local security dashboard."""
    base = os.getenv("FAIL2BAN_UI_DSAM_URL", "").rstrip("/")
    token = os.getenv("FAIL2BAN_UI_DSAM_TOKEN", "")
    if not base or not ips:
        return {}
    try:
        payload = json.dumps({"ips": ips[:250], "source": "fail2ban-ui"}).encode("utf-8")
        headers = {"Content-Type": "application/json", "User-Agent": "fail2ban-ui/1.0"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(f"{base}/api/dsam/fail2ban/enrich", data=payload, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=4) as resp:
            data = json.loads(resp.read())
        items = data.get("data") or data.get("items") or []
        return {str(item.get("ip")): item for item in items if item.get("ip")}
    except Exception:
        return {}


def get_enriched_blocked_ips(limit: int = 250) -> dict:
    jails = [_parse_jail_status(jail) for jail in cfg("jails", DEFAULT_JAILS)]
    attempts, top_ports = get_recent_attempts(limit=120)
    attempts_by_ip: dict[str, list[dict]] = {}
    for item in attempts:
        ip = item.get("source_ip")
        if ip:
            attempts_by_ip.setdefault(ip, []).append(item)
    by_ip: dict[str, dict] = {}
    for jail in jails:
        jail_name = jail.get("name")
        for ip in jail.get("banned_ips", []):
            by_ip.setdefault(
                ip,
                {
                    "ip": ip,
                    "display_ip": _mask_ip(ip),
                    "jails": [],
                    "currently_banned": True,
                    "events": [],
                },
            )
            by_ip[ip]["jails"].append(jail_name)
    for ip, items in attempts_by_ip.items():
        by_ip.setdefault(
            ip,
            {
                "ip": ip,
                "display_ip": _mask_ip(ip),
                "jails": [],
                "currently_banned": False,
                "events": [],
            },
        )
        by_ip[ip]["events"].extend(items[:12])

    dsam = _dsam_enrichment_for_ips(list(by_ip.keys()))
    enriched = []
    for ip, item in list(by_ip.items())[:limit]:
        geo = _geo_for_map(ip)
        dsam_item = dsam.get(ip) or {}
        if dsam_item.get("geo"):
            dsam_geo = dsam_item["geo"] or {}
            geo = {
                **geo,
                "country": dsam_geo.get("country") or geo.get("country"),
                "city": dsam_geo.get("city") or geo.get("city"),
                "region": dsam_geo.get("region") or geo.get("region"),
                "lat": dsam_geo.get("lat") or geo.get("lat"),
                "lon": dsam_geo.get("lon") or geo.get("lon"),
                "source": "dsam",
                "estimated": False,
            }
        item_events = item.get("events", [])
        enriched.append(
            {
                **item,
                "country": geo.get("country"),
                "city": geo.get("city"),
                "region": geo.get("region"),
                "org": geo.get("org"),
                "lat": geo.get("lat"),
                "lon": geo.get("lon"),
                "geo_source": geo.get("source"),
                "estimated": geo.get("estimated", False),
                "risk_level": dsam_item.get("risk_level") or ("high" if item.get("currently_banned") else "medium"),
                "risk_score": dsam_item.get("risk_score") or (90 if item.get("currently_banned") else 55),
                "tenant": dsam_item.get("tenant"),
                "case_id": dsam_item.get("case_id"),
                "last_event": item_events[0] if item_events else None,
                "event_count": len(item_events),
            }
        )
    enriched.sort(key=lambda x: (not x.get("currently_banned"), -(x.get("risk_score") or 0), x.get("ip") or ""))
    map_points = [
        {
            "ip": item["ip"],
            "display_ip": item["display_ip"],
            "lat": item.get("lat"),
            "lon": item.get("lon"),
            "country": item.get("country"),
            "city": item.get("city"),
            "risk_level": item.get("risk_level"),
            "risk_score": item.get("risk_score"),
            "banned": item.get("currently_banned"),
            "estimated": item.get("estimated"),
            "geo_source": item.get("geo_source"),
            "jails": item.get("jails", []),
        }
        for item in enriched
        if item.get("lat") and item.get("lon")
    ]
    return {
        "ok": True,
        "items": enriched,
        "map_points": map_points,
        "jails": jails,
        "top_ports": top_ports,
        "dsam": {"enabled": bool(os.getenv("FAIL2BAN_UI_DSAM_URL", "")), "matched": len(dsam)},
        "updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


@app.route("/api/enriched-blocked-ips")
@require_api_enabled
def api_enriched_blocked_ips():
    try:
        limit = max(20, min(500, int(request.args.get("limit", "250"))))
    except ValueError:
        limit = 250
    return jsonify(get_enriched_blocked_ips(limit=limit))


@app.route("/api/shodan/<ip>")
@require_api_enabled
def api_shodan(ip: str):
    if not re.match(r"^[0-9a-fA-F:.]+$", ip):
        return jsonify({"error": "IP invalida"}), 400
    geo_data = geoip(ip) if feature_enabled("external_enrichment") else _empty_geo(ip)
    return jsonify({**geo_data, **shodan_idb_on_demand(ip)})


@app.route("/api/intel/<ip>")
@require_api_enabled
def api_intel(ip: str):
    if not re.match(r"^[0-9a-fA-F:.]+$", ip):
        return jsonify({"error": "IP invalida"}), 400
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({"error": "IP invalida"}), 400
    public = not (parsed.is_private or parsed.is_loopback or parsed.is_reserved or parsed.is_multicast)
    geo_data = geoip(ip) if feature_enabled("external_enrichment") else _empty_geo(ip)
    if not feature_enabled("external_enrichment") and (geo_data.get("lat") == 0.0 and geo_data.get("lon") == 0.0):
        lat, lon = _pseudo_geo_from_ip(ip)
        geo_data = {**geo_data, "lat": lat, "lon": lon, "org": "geo estimada", "estimated": True}
    shodan_data = shodan_idb_on_demand(ip) if public else {"ports": [], "hostnames": [], "tags": [], "vulns": [], "cpes": [], "note": "ip_no_publica"}
    return jsonify(
        {
            "ip": ip,
            "display_ip": _mask_ip(ip),
            "is_public": public,
            "geo": geo_data,
            "shodan": shodan_data,
        }
    )


@app.route("/api/fail2ban", methods=["POST"])
def webhook_fail2ban():
    """
    Webhook receptor de notificaciones Notch (sin autenticación).
    Recibe eventos de fail2ban-ui y los integra en el dashboard.
    """
    try:
        payload = request.get_json(force=True)
        if not payload:
            return jsonify({"ok": False, "error": "empty_payload"}), 400
        
        # Validar estructura básica
        event_type = payload.get("type", "")
        if not event_type.startswith("fail2ban-ui"):
            return jsonify({"ok": False, "error": "invalid_event_type"}), 400
        
        # Cargar estado para registrar webhooks recibidos
        state = _load_state()
        if "webhook_events" not in state:
            state["webhook_events"] = []
        
        # Agregar evento recibido con timestamp
        event = {
            "received_at": datetime.now().isoformat(),
            "type": payload.get("type"),
            "severity": payload.get("severity", "info"),
            "source_ip": payload.get("source_ip", "unknown"),
            "hits": payload.get("hits", 0),
            "action": payload.get("action", "unknown"),
            "action_result": payload.get("action_result", "pending"),
        }
        state["webhook_events"].append(event)
        
        # Mantener últimos 100 eventos
        if len(state["webhook_events"]) > 100:
            state["webhook_events"] = state["webhook_events"][-100:]
        
        _save_state(state)
        
        # Log del webhook recibido
        print(f"[WEBHOOK] Recibido: {event['type']} | {event['severity']} | {event['source_ip']} | {event['action']}")
        
        return jsonify({
            "ok": True,
            "received": True,
            "event_type": event_type,
            "severity": event.get("severity"),
            "action": event.get("action"),
            "timestamp": event.get("received_at"),
        }), 202
    
    except Exception as e:
        print(f"[WEBHOOK] Error: {e}")
        return jsonify({"ok": False, "error": str(e)}), 400


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
