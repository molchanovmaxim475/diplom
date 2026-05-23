"""
NetGuard v3 — Генерация отчётов и статусов
"""

from datetime import datetime
from journal import get_stats, get_recent_events, get_blocked_ips


def _security_level(stats: dict) -> tuple[str, str]:
    today = stats.get("today", 0)
    blocked = stats.get("blocked_ips", 0)
    if today > 100 or blocked > 50:
        return "КРИТИЧЕСКИЙ", "[!!]"
    elif today > 20 or blocked > 10:
        return "ВЫСОКИЙ", "[!]"
    elif today > 5:
        return "СРЕДНИЙ", "[~]"
    else:
        return "НИЗКИЙ", "[OK]"


def status_message() -> str:
    stats = get_stats()
    level, icon = _security_level(stats)
    return (
        f"{icon} Статус защиты: {level}\n\n"
        f"Событий сегодня: {stats['today']}\n"
        f"Всего в журнале: {stats['total']}\n"
        f"Snort alerts: {stats['snort']}\n"
        f"iptables drops: {stats['iptables']}\n"
        f"Заблокировано IP: {stats['blocked_ips']}"
    )


def threats_message(limit: int = 10) -> str:
    events = get_recent_events(limit)
    if not events:
        return "Угроз не обнаружено."

    lines = [f"Последние {len(events)} событий:\n"]
    for e in events:
        ts = e["ts"][:16].replace("T", " ")
        src = e["src_ip"] or "?"
        port = e["dst_port"] or "?"
        blocked = " [БЛОК]" if e["blocked"] else ""
        lines.append(f"{ts}\n{e['type'].upper()}: {src} -> :{port}{blocked}\n")
    return "\n".join(lines)


def blocked_ips_message() -> str:
    ips = get_blocked_ips()
    if not ips:
        return "Список заблокированных IP пуст."
    lines = [f"Заблокировано IP: {len(ips)}\n"]
    for b in ips:
        auto = " (авто)" if b["auto"] else " (вручную)"
        ts = b["blocked_at"][:16].replace("T", " ")
        reason = b["reason"][:40] if b["reason"] else "-"
        lines.append(f"{b['ip']}{auto}\nПричина: {reason}\nВремя: {ts}\n")
    return "\n".join(lines)


def generate_report() -> str:
    stats = get_stats()
    events = get_recent_events(5)
    blocked = get_blocked_ips()[:5]
    level, icon = _security_level(stats)
    now = datetime.now().strftime("%d.%m.%Y %H:%M")

    lines = [
        "=" * 35,
        "  ОТЧЁТ ПО БЕЗОПАСНОСТИ",
        f"  {now}",
        "=" * 35,
        "",
        "СТАТИСТИКА СОБЫТИЙ:",
        f"  Всего в журнале : {stats['total']}",
        f"  За сегодня      : {stats['today']}",
        f"  Snort alerts    : {stats['snort']}",
        f"  iptables drops  : {stats['iptables']}",
        f"  Ручных блоков   : {stats['manual']}",
        f"  Заблок. IP      : {stats['blocked_ips']}",
        "",
        f"УРОВЕНЬ УГРОЗЫ: {icon} {level}",
        "",
    ]

    if events:
        lines.append("ПОСЛЕДНИЕ ИНЦИДЕНТЫ:")
        for e in events:
            ts = e["ts"][:16].replace("T", " ")
            lines.append(
                f"  {ts} | {e['type'].upper():8} | "
                f"{e['src_ip'] or '?':15} -> :{e['dst_port'] or '?'}"
            )
        lines.append("")

    if blocked:
        lines.append("ЗАБЛОКИРОВАННЫЕ IP:")
        for b in blocked:
            auto = "A" if b["auto"] else "M"
            lines.append(f"  [{auto}] {b['ip']:17} {b['reason'][:30]}")

    lines += ["", "=" * 35]
    return "\n".join(lines)
