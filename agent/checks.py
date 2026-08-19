"""
Posture checks and account inventory, dispatched per platform.

The collectors themselves live in os_linux, os_windows and os_darwin. This
module exists so the agent never has to know which OS it is on.
"""

import logging

import osdetect

log = logging.getLogger("nodewatch")


def collect_checks():
    """Never raise: a broken check must not stop the agent's main loop."""
    try:
        return osdetect.collect_checks()
    except Exception as e:
        log.warning("posture collection failed: %s", e)
        return [{
            "check_id": f"error-{osdetect.PLATFORM}",
            "title": "Posture checks ran",
            "category": "system",
            "severity": "low",
            "status": "error",
            "detail": str(e)[:200],
        }]


def collect_users():
    try:
        return osdetect.collect_users()
    except Exception as e:
        log.warning("account collection failed: %s", e)
        return []
