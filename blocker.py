"""
NetGuard v3 — Блокировка IP через iptables
"""

import subprocess
import logging
from journal import add_blocked_ip, remove_blocked_ip, is_blocked, get_blocked_ips

log = logging.getLogger("netguard.blocker")


def block_ip(ip: str, reason: str = "", auto: bool = False) -> bool:
    if is_blocked(ip):
        log.info(f"IP {ip} already blocked")
        return False
    try:
        subprocess.run(
            ["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"],
            check=True, capture_output=True
        )
        add_blocked_ip(ip, reason, auto)
        log.info(f"Blocked: {ip} | reason: {reason} | auto={auto}")
        return True
    except subprocess.CalledProcessError as e:
        log.error(f"Failed to block {ip}: {e.stderr.decode()}")
        return False
    except FileNotFoundError:
        log.error("iptables not found — run with NET_ADMIN capability")
        return False


def unblock_ip(ip: str) -> bool:
    try:
        subprocess.run(
            ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            check=True, capture_output=True
        )
        remove_blocked_ip(ip)
        log.info(f"Unblocked: {ip}")
        return True
    except subprocess.CalledProcessError as e:
        log.error(f"Failed to unblock {ip}: {e.stderr.decode()}")
        return False


def get_all_blocked() -> list[dict]:
    return get_blocked_ips()
