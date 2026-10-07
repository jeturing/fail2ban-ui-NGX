# QA report fail2ban-ui-public — 20261007

Rama de diagnostico creada por project-pulse. NO mergear a main sin aprobacion del dueno.

## [C] ruff check (rc != 0)
```
 Exception:
     |            ^^^^^^^^^
2209 |         return {}
     |

DTZ005 `datetime.datetime.now()` called without a `tz` argument
    --> app.py:2322:20
     |
2320 |             "matched": len(dsam),
2321 |         },
2322 |         "updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
     |                    ^^^^^^^^^^^^^^
2323 |     }
     |
help: Pass a `datetime.timezone` object to the `tz` parameter

DTZ005 `datetime.datetime.now()` called without a `tz` argument
    --> app.py:2418:28
     |
2416 |         # Agregar evento recibido con timestamp
2417 |         event = {
2418 |             "received_at": datetime.now().isoformat(),
     |                            ^^^^^^^^^^^^^^
2419 |             "type": payload.get("type"),
2420 |             "severity": payload.get("severity", "info"),
     |
help: Pass a `datetime.timezone` object to the `tz` parameter

BLE001 Do not catch blind exception: `Exception`
    --> app.py:2450:12
     |
2448 |         ), 202
2449 |
2450 |     except Exception as e:
     |            ^^^^^^^^^
2451 |         print(f"[WEBHOOK] Error: {e}")
2452 |         return jsonify({"ok": False, "error": str(e)}), 400
     |

EXE001 Shebang is present but file is not executable
 --> scripts/fail2ban_ui_tick.py:1:1
  |
1 | #!/usr/bin/env python3
  | ^^^^^^^^^^^^^^^^^^^^^^
2 | """Run one decision/notification pass without serving HTTP."""
  |

Found 39 errors.
No fixes available (1 hidden fix can be enabled with the `--unsafe-fixes` option).

```

## [C] pytest (rc != 0)
```
herramienta no instalada
```

