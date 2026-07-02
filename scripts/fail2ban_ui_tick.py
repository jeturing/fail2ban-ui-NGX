#!/usr/bin/env python3
"""Run one decision/notification pass without serving HTTP."""

import os
import sys


def main() -> int:
    app_dir = os.getenv("FAIL2BAN_UI_APP_DIR", "/opt/fail2ban-ui")
    if app_dir not in sys.path:
        sys.path.insert(0, app_dir)

    import app as fail2ban_ui  # noqa: WPS433

    fail2ban_ui.get_all_stats()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
