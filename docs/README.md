# Documentación de fail2ban-ui-NGX

Índice maestro de la documentación de este repositorio. Cada historia que cierra suma su expediente y lo enlaza aquí; un documento sin índice es un documento perdido.

## Documentos en `docs/`

| Documento | Qué es |
|---|---|
| [architecture.md](architecture.md) | Arquitectura del panel: descripción, diagrama de contexto y cómo lee el estado de Fail2ban, el firewall y el gestor de proxy del host |
| [architecture-diagram.html](architecture-diagram.html) | Diagrama de arquitectura en HTML que acompaña a `architecture.md` |
| [operacion/NOTCH_SETUP.md](operacion/NOTCH_SETUP.md) | Guía de configuración de las alertas por webhook (Notch): campos, modos de carga y severidades |
| [assets/screenshot-dashboard.png](assets/screenshot-dashboard.png) | Captura del dashboard: jails y decisiones |
| [assets/screenshot-attempts.png](assets/screenshot-attempts.png) | Captura de intentos recientes y puertos en escucha (1 de 2) |
| [assets/screenshot-attempts-2.png](assets/screenshot-attempts-2.png) | Captura de intentos recientes (2 de 2) |
| [Este índice](README.md) | Índice maestro de la carpeta `docs/` |

## Documentos relacionados fuera de `docs/`

| Documento | Qué es |
|---|---|
| [README del repositorio](../README.md) | Presentación, capacidades con su estado, arquitectura, seguridad y despliegue del panel |
| [SECURITY.md](../SECURITY.md) | Política de seguridad del panel |
| [AGENTS.md](../AGENTS.md) | Notas de trabajo del repositorio |

## Cómo se mantiene esta carpeta

- Todo fichero dentro de `docs/` está enlazado desde este índice, con una línea honesta de qué contiene.
- El diseño vive en la raíz de `docs/` como documento previo asentado; la operación vive en `operacion/` y los activos en `assets/`.
- Disciplina de estado: **Construido** · **En desarrollo** · **Diseñado** · **Concepto** — los estados nunca se mezclan.
