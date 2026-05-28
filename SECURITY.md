# Security Policy

## Versiones soportadas

| Versión | Soporte de seguridad |
| ------- | -------------------- |
| 1.x     | ✅ Activa            |

## Reportar una vulnerabilidad

Si descubres una vulnerabilidad de seguridad en este proyecto, **no abras un Issue público**.

Repórtala de forma responsable:

- **Email:** <security@jeturing.com>
- **Asunto:** `[fail2ban-ui-NGX] Vulnerabilidad - <descripción breve>`

### Qué incluir en el reporte

1. Descripción clara del problema
2. Pasos para reproducirlo
3. Impacto potencial
4. Versión afectada
5. (Opcional) Propuesta de fix

### Tiempos de respuesta

| Acción | Plazo |
| ------ | ----- |
| Acuse de recibo | 48 horas |
| Evaluación inicial | 5 días hábiles |
| Parche o mitigación | 30 días |

## Consideraciones de seguridad del proyecto

Este panel está diseñado para operar **exclusivamente en redes privadas, VPN o Tailscale**.

⚠️ **No expongas este servicio directamente a Internet.**

- Acceso protegido por **Basic Auth + PBKDF2-SHA256**
- Sin dependencias de CDN externas
- Configuración con permisos `0600`
- Sin enriquecimiento externo por defecto (GeoIP, Shodan desactivados)
- El modo automático de decisiones requiere activación explícita de `write_actions`

## Licencia

Este proyecto se distribuye bajo la [GNU General Public License v3.0](LICENSE).
