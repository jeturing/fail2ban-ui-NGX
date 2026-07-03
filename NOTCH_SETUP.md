# Notch - Sistema de Notificaciones Automáticas

## ✅ Estado Actual

**Notch está ACTIVO** y configurado con:
- ✓ Motor de decisiones automático
- ✓ Notificaciones de recomendaciones habilitadas
- ✓ Severidad mínima: **Warning**
- ✓ Payload: **Enmascarado** (protege IPs en webhook)

---

## 📋 Flujo de Eventos

### Cuando una IP alcanza el umbral:

1. **Evaluación**: Motor de decisiones analiza 120 últimos eventos/IP
2. **Scoring**: 
   - 3-5 eventos = ⚠️ **Warning**
   - 6+ eventos = 🔴 **Critical**
3. **Acción**:
   - Si score ≥ umbral → Ban automático en `blacklist-permanent`
   - **Webhook POST** enviado a URL configurada
4. **Sincronización**: Si NPM activo → se agrega a access-list

---

## 🔗 Configurar Webhook

### Opción 1: Usar webhook.site (testing rápido)

1. Accede a https://webhook.site
2. Copia la **Unique URL** que genera (ej: `https://webhook.site/a1b2c3d4-...`)
3. Ve a **Ajustes** (Settings) del panel fail2ban-ui
4. Pega en **Webhook URL**
5. Haz clic en toggle para activar **Notificaciones automáticas**
6. Guarda cambios

**Ventaja**: Inmediato, sin configuración.
**Desventaja**: Temporal, no persistente.

### Opción 2: Endpoint Custom (producción)

Reemplaza `https://webhook.site/unique-id` con tu endpoint:

```bash
# Ejemplo con servicio local (N8n, Make, Zapier)
https://tuservidor.com/api/webhooks/fail2ban

# Con Node.js simple:
http://10.10.20.202:5000/webhook

# Con Discord:
https://discord.com/api/webhooks/YOUR_WEBHOOK_ID/YOUR_WEBHOOK_TOKEN

# Con Slack:
https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

### Opción 3: Integración con Odoo/SAJET

Para enviar alertas a Odoo:

```bash
# Ir a Ajustes → Webhook URL
https://10.10.20.201:8069/api/fail2ban/webhook

# Con token bearer si Odoo requiere autenticación:
Authorization: Bearer <JWT_TOKEN>
```

---

## 📨 Payload del Webhook

### Modo Enmascarado (recomendado):

```json
{
  "type": "fail2ban-ui.decision",
  "app": "Fail2ban UI",
  "server": "fail2ban-host",
  "severity": "critical",
  "source_ip": "178.20.210.x",
  "hits": 16,
  "reason": "16 eventos maliciosos recientes",
  "mode": "auto",
  "action": "ban",
  "action_result": "executed",
  "safe_for_action": true
}
```

### Modo Completo (sin enmascarar):

```json
{
  "type": "fail2ban-ui.decision",
  "app": "Fail2ban UI",
  "server": "fail2ban-host",
  "severity": "critical",
  "source_ip": "178.20.210.208",  // ← IP completa visible
  "hits": 16,
  "reason": "16 eventos maliciosos recientes",
  "mode": "auto",
  "action": "ban",
  "action_result": "executed",
  "safe_for_action": true
}
```

---

## 🔐 Autenticación Bearer (Opcional)

Si tu webhook requiere token:

1. Ve a **Ajustes** → **Token Bearer**
2. Pega tu token (ej: JWT, API Key)
3. Se agregará header: `Authorization: Bearer <token>`

```bash
# Ejemplo con cURL
curl -X POST https://webhook.site/unique-id \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer tu_token_aqui" \
  -d '{"type": "fail2ban-ui.decision", ...}'
```

---

## ⚙️ Severidad Mínima

**Opciones**:
- 🟢 **Info**: Todos los eventos
- 🟡 **Warning** (default): Eventos moderados y críticos
- 🔴 **Critical**: Solo eventos críticos (6+ intentos)

---

## 📊 Ejemplo: Integración Discord

```bash
# 1. Crear webhook en Discord (Channel Settings → Webhooks)
# 2. Copiar URL (https://discord.com/api/webhooks/ABC123/XYZ789)
# 3. En Ajustes fail2ban-ui → pegar como Webhook URL
# 4. Actualizar configuración
```

**Resultado**: Mensajes en Discord como:
```
🚨 Fail2ban UI - fail2ban-host
Critical | 178.20.210.x | Ban automático ejecutado
Razón: 16 eventos maliciosos recientes
```

---

## 📊 Ejemplo: Integración Slack

```bash
# 1. Crear Webhook de Slack (api.slack.com → Apps → Create New App)
# 2. Copiar URL de Webhook Incoming (https://hooks.slack.com/...)
# 3. En Ajustes fail2ban-ui → pegar como Webhook URL
```

---

## 🧪 Prueba Manual

Para forzar una notificación:

```bash
# Generar eventos maliciosos contra SSH
for i in {1..20}; do
  ssh -o ConnectTimeout=1 invalid_user@127.0.0.1 < /dev/null
done

# Ver webhook.site para confirmar notificaciones
```

---

## 📍 Troubleshooting

### ❌ No se envían notificaciones

**Checklist**:
1. ¿Notch está **activo** en Ajustes?
2. ¿La URL de webhook es **válida y accesible**?
3. ¿El modo de decisiones es `auto` o `recommend`?
4. ¿notify_recommendations está **activo**?

**Validar manualmente**:
```bash
curl -X POST https://webhook.site/your-unique-id \
  -H "Content-Type: application/json" \
  -d '{"test": "ok"}'
```

### ⏱️ Latencia

Las notificaciones se envían cada vez que:
- API `/api/stats` es llamada (~30s auto-refresh)
- Un evento alcanza el umbral de decisión

---

## 🔄 Monitoreo en Tiempo Real

**Logs del servicio**:
```bash
journalctl -u fail2ban-ui -f
```

**Ver últimas decisiones**:
```bash
curl -u admin:Admin@2026!F2B \
  http://127.0.0.1:2020/api/stats | jq '.summary.decisions'
```

**Ver notificaciones enviadas (state.json)**:
```bash
cat /var/lib/fail2ban-ui/state.json | jq '.notified[-10:]'
```

---

## 📝 Configuración por Archivo

Alternativa a UI web:

```bash
cat > /etc/fail2ban-ui/config.json << 'EOF'
{
  "notch": {
    "enabled": true,
    "webhook_url": "https://webhook.site/your-unique-id",
    "token": "",
    "payload_mode": "masked",
    "min_severity": "warning"
  },
  "decisions": {
    "enabled": true,
    "notify_recommendations": true,
    "mode": "auto",
    "threshold": 3,
    "action_jail": "blacklist-permanent"
  }
}
EOF

systemctl restart fail2ban-ui
```

---

**Última actualización**: Julio 3, 2026
**Estado**: ✅ Producción
