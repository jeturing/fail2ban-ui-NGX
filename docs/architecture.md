# 🛡️ Fail2ban UI — Arquitectura

[![Versión](https://img.shields.io/badge/versión-N%2FA-lightgrey)]()
[![Estado](https://img.shields.io/badge/estado-en%20uso-green)]()
[![Categoría](https://img.shields.io/badge/categoría-infraestructura%2Fseguridad-blue)]()
[![Autor](https://img.shields.io/badge/autor-SAJET%20%2F%20Jeturing%20Inc-informational)]()

Panel web y API JSON en Flask para administrar `fail2ban`: muestra jails, IPs bloqueadas, permite desbanear, integra estado de Nginx Proxy Manager (NPM), configuración de mail relay y enriquecimiento de amenazas (GeoIP/Shodan).

---

## 📋 Descripción

`app.py` es una aplicación Flask monolítica (~85 KB, un solo archivo) que sirve tanto el dashboard HTML (Jinja2, `templates/` + `static/`) como una API JSON bajo `/api/*`. Lee directamente los logs de jail de `fail2ban` y el estado del firewall (`iptables`) en el host donde corre. No usa base de datos propia visible en el código explorado.

---

## 🏗️ Arquitectura / Diagrama

Contexto del sistema: un administrador humano accede vía navegador al dashboard Flask. El backend lee estado de `fail2ban` (jails, bans) e `iptables` (reglas activas) del host, consulta el estado de NPM vía su API, aplica configuración opcional de mail relay, y enriquece IPs bloqueadas con lookups opcionales de GeoIP/Shodan.

Diagrama generado con `archify`: [`architecture-diagram.html`](./architecture-diagram.html)

Componentes principales:

| Componente | Rol |
|---|---|
| `app.py` (Flask) | Backend único: rutas HTML + API (`/api/stats`, `/api/unban/<ip>`, `/api/npm/status`, `/api/mail-relay/*`, `/api/geoip/<ip>`, `/api/shodan/<ip>`, `/api/intel/<ip>`) |
| `templates/` + `static/` | Renderizado del dashboard (Jinja2) |
| fail2ban (host) | Fuente de jails y logs de bans |
| iptables (host) | Estado del firewall; destino de comandos de unban |
| Nginx Proxy Manager | Consultado para estado de proxy (`/api/npm/status`) |
| Mail relay | Configuración opcional aplicada vía `/api/mail-relay/apply` |
| GeoIP / Shodan | Enriquecimiento opcional de inteligencia de amenazas por IP |

Decisiones de diseño relevantes:

- Aplicación de un solo proceso Flask, sin separación frontend/backend — reduce superficie operativa para una herramienta interna de administración.
- Las integraciones externas (NPM, GeoIP, Shodan, mail relay) son opcionales y no bloquean el flujo principal de lectura de jails/bans.
- El desbaneo (`/api/unban/<ip>`) actúa directamente sobre `iptables` del host — requiere que el proceso corra con privilegios suficientes (UNKNOWN el modelo exacto de privilegios desde el código revisado).

---

## 👥 Créditos

| Campo | Detalle |
|---|---|
| **Autor** | SAJET / Jeturing Inc |
