"""
NetGuard v3 — Система мониторинга и реагирования на инциденты
Snort + iptables + блокировка IP + журнал + отчёты + VK бот
"""

import os
import re
import sys
import time
import asyncio
import logging
import signal
import platform
from pathlib import Path
from datetime import datetime

from journal  import init_db, log_event, get_ip_event_count, is_blocked, get_stats
from blocker  import block_ip, unblock_ip
from reporter import generate_report, status_message, threats_message, blocked_ips_message
from vk_bot   import VKBot

# ─── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("netguard")

# ─── Config ───────────────────────────────────────────────────────────────────
VK_TOKEN     = os.getenv("VK_TOKEN", "")
VK_GROUP_ID  = os.getenv("VK_GROUP_ID", "")
VK_ADMIN_ID  = int(os.getenv("VK_ADMIN_ID", "0"))

SNORT_ENABLED     = os.getenv("SNORT_ENABLED", "true").lower() == "true"
SNORT_ALERT_FILE  = os.getenv("SNORT_ALERT_FILE", "/var/log/snort/alert")
SNORT_PRIORITY    = int(os.getenv("SNORT_PRIORITY", "3"))

IPTABLES_ENABLED  = os.getenv("IPTABLES_ENABLED", "true").lower() == "true"
IPTABLES_LOG_FILE = os.getenv("IPTABLES_LOG_FILE", "/var/log/kern.log")

DEDUP_WINDOW         = int(os.getenv("DEDUP_WINDOW", "60"))
POLL_INTERVAL        = float(os.getenv("POLL_INTERVAL", "1.0"))
AUTO_BLOCK           = os.getenv("AUTO_BLOCK", "false").lower() == "true"
AUTO_BLOCK_THRESHOLD = int(os.getenv("AUTO_BLOCK_THRESHOLD", "10"))
AUTO_BLOCK_WINDOW    = int(os.getenv("AUTO_BLOCK_WINDOW", "300"))


# ─── Дедупликатор ─────────────────────────────────────────────────────────────
class Deduplicator:
    def __init__(self, window_sec: int = 60):
        self._seen: dict[str, float] = {}
        self.window = window_sec

    def is_new(self, key: str) -> bool:
        now = time.monotonic()
        if now - self._seen.get(key, 0) < self.window:
            return False
        self._seen[key] = now
        return True

    def cleanup(self):
        now = time.monotonic()
        self._seen = {k: v for k, v in self._seen.items() if now - v < self.window * 10}


# ─── Парсер Snort ─────────────────────────────────────────────────────────────
import re as _re

# Формат fast: TIMESTAMP [**] [SID] MSG [**] [Priority: N] {PROTO} SRC:SPORT -> DST:DPORT
RE_SNORT_FAST = _re.compile(
    r'(?P<ts>\d{2}/\d{2}-[\d:.]+)\s+\[\*\*\]\s+\[(?P<sid>[\d:]+)\]\s+(?P<msg>.+?)\s+\[\*\*\]\s*'
    r'(?:\[Priority:\s*(?P<priority>\d+)\])?\s*'
    r'(?:\{(?P<proto>\w+)\})?\s*'
    r'(?P<src>[\d.]+)(?::(?P<spt>\d+))?\s+->\s+(?P<dst>[\d.]+)(?::(?P<dpt>\d+))?'
)

class SnortParser:
    def __init__(self, filepath: str, threshold: int = 3):
        self.path = Path(filepath)
        self.threshold = threshold
        self._pos = 0

    def init(self):
        if self.path.exists():
            with open(self.path, "r", errors="replace") as f:
                f.seek(0, 2)
                self._pos = f.tell()
            log.info(f"Snort: watching {self.path}")
        else:
            log.warning(f"Snort: {self.path} not found, will watch when created")

    def read_new(self) -> list[dict]:
        if not self.path.exists():
            return []
        try:
            with open(self.path, "r", errors="replace") as f:
                f.seek(self._pos)
                data = f.read()
                self._pos = f.tell()
        except OSError:
            return []
        return [a for line in data.splitlines()
                if (a := self._parse(line)) is not None]

    def _parse(self, line: str) -> dict | None:
        line = line.strip()
        if not line:
            return None
        m = RE_SNORT_FAST.search(line)
        if not m:
            return None
        priority = int(m.group("priority") or 3)
        if priority > self.threshold:
            return None
        return dict(type="snort", sid=m.group("sid"), msg=m.group("msg"),
                    priority=priority,
                    src_ip=m.group("src") or "", dst_ip=m.group("dst") or "",
                    src_port=m.group("spt") or "", dst_port=m.group("dpt") or "",
                    ts=m.group("ts"))


# ─── Парсер iptables ──────────────────────────────────────────────────────────
RE_IPT = _re.compile(
    r'(?P<date>\w+\s+\d+\s+[\d:]+).*?kernel:\s+\[[\d.]+\]\s+\[(?P<tag>[^\]]+)\]'
    r'.*?SRC=(?P<src>[\d.]+).*?DST=(?P<dst>[\d.]+)'
    r'(?:.*?PROTO=(?P<proto>\w+))?'
    r'(?:.*?SPT=(?P<spt>\d+))?'
    r'(?:.*?DPT=(?P<dpt>\d+))?',
    _re.DOTALL
)
IPT_KEYWORDS = {"DROP", "REJECT", "BLOCK", "DENY", "BLOCKED"}

class IptablesParser:
    def __init__(self, filepath: str):
        self.path = Path(filepath)
        self._pos = 0

    def init(self):
        if self.path.exists():
            with open(self.path, "r", errors="replace") as f:
                f.seek(0, 2)
                self._pos = f.tell()
            log.info(f"iptables: watching {self.path}")
        else:
            log.warning(f"iptables: {self.path} not found, will watch when created")

    def read_new(self) -> list[dict]:
        if not self.path.exists():
            return []
        try:
            with open(self.path, "r", errors="replace") as f:
                f.seek(self._pos)
                data = f.read()
                self._pos = f.tell()
        except OSError:
            return []
        return [e for line in data.splitlines()
                if (e := self._parse(line)) is not None]

    def _parse(self, line: str) -> dict | None:
        if "kernel" not in line or "SRC=" not in line:
            return None
        m = RE_IPT.search(line)
        if not m:
            return None
        tag = m.group("tag").upper()
        if not any(kw in tag for kw in IPT_KEYWORDS):
            return None
        return dict(type="iptables", tag=m.group("tag"),
                    date=m.group("date"), src=m.group("src"), dst=m.group("dst"),
                    proto=m.group("proto") or "?",
                    spt=m.group("spt") or "?", dpt=m.group("dpt") or "?")


# ─── Обработчик команд VK ─────────────────────────────────────────────────────
async def handle_vk(bot: VKBot, peer_id: int, text: str):
    t = text.lower()

    # Ожидаем IP для блокировки
    if bot.pending_block.get(peer_id):
        if _re.match(r'^\d{1,3}(\.\d{1,3}){3}$', text.strip()):
            bot.pending_block.pop(peer_id)
            ip = text.strip()
            ok = block_ip(ip, reason="Ручная блокировка администратором")
            if ok:
                log_event("manual", ip, "", "", "", "Заблокирован администратором")
                await bot.send(peer_id, f"IP {ip} заблокирован.")
            else:
                await bot.send(peer_id, f"IP {ip} уже заблокирован или ошибка.")
            return
        else:
            bot.pending_block.pop(peer_id)
            await bot.send(peer_id, "Неверный формат IP. Введите снова или выберите действие.")
            return

    if any(x in t for x in ["проверить", "аудит", "check"]):
        stats = get_stats()
        msg = (
            "Аудит системы выполнен\n\n"
            f"Событий сегодня: {stats['today']}\n"
            f"Всего в журнале: {stats['total']}\n"
            f"Snort alerts:    {stats['snort']}\n"
            f"iptables drops:  {stats['iptables']}\n"
            f"Заблокировано:   {stats['blocked_ips']}\n\n"
            "Система работает."
        )
        await bot.send(peer_id, msg)

    elif any(x in t for x in ["угроз", "инцидент", "последн"]):
        await bot.send(peer_id, threats_message(10))

    elif any(x in t for x in ["статус", "защит"]):
        await bot.send(peer_id, status_message())

    elif any(x in t for x in ["заблокировать", "блокировать"]):
        bot.pending_block[peer_id] = True
        await bot.send(peer_id, "Введите IP-адрес для блокировки:", keyboard=None)

    elif any(x in t for x in ["заблокированные", "список"]):
        await bot.send(peer_id, blocked_ips_message())

    elif any(x in t for x in ["отчёт", "отчет", "report"]):
        await bot.send(peer_id, generate_report())

    elif any(x in t for x in ["настройки", "параметры"]):
        msg = (
            "Настройки системы:\n\n"
            f"Snort:          {'вкл' if SNORT_ENABLED else 'выкл'}\n"
            f"iptables:       {'вкл' if IPTABLES_ENABLED else 'выкл'}\n"
            f"Авто-блокировка:{'вкл' if AUTO_BLOCK else 'выкл'}\n"
            f"Порог авто-блок:{AUTO_BLOCK_THRESHOLD} событий / {AUTO_BLOCK_WINDOW}с\n"
            f"Дедупликация:   {DEDUP_WINDOW}с\n"
            f"Интервал опроса:{POLL_INTERVAL}с"
        )
        await bot.send(peer_id, msg)

    else:
        await bot.send(peer_id, "NetGuard v3\nВыберите действие:")


# ─── Авто-блокировка ──────────────────────────────────────────────────────────
async def maybe_auto_block(bot: VKBot, src_ip: str, descr: str):
    if not AUTO_BLOCK or not src_ip or is_blocked(src_ip):
        return
    count = get_ip_event_count(src_ip, AUTO_BLOCK_WINDOW)
    if count >= AUTO_BLOCK_THRESHOLD:
        ok = block_ip(src_ip, f"Авто-блок: {descr}", auto=True)
        if ok:
            log_event("manual", src_ip, "", "", "", f"Авто-заблокирован: {descr}", blocked=True)
            await bot.notify(
                VK_ADMIN_ID,
                f"[АВТО-БЛОК] {src_ip}\n"
                f"Событий: {count} за {AUTO_BLOCK_WINDOW}с\n"
                f"Причина: {descr}"
            )


# ─── Main ─────────────────────────────────────────────────────────────────────
async def main():
    if not VK_TOKEN or not VK_GROUP_ID or not VK_ADMIN_ID:
        log.error("VK_TOKEN, VK_GROUP_ID, VK_ADMIN_ID must be set in .env")
        sys.exit(1)

    init_db()
    log.info("NetGuard v3 starting...")
    log.info(f"Snort:    {'enabled -> ' + SNORT_ALERT_FILE if SNORT_ENABLED else 'disabled'}")
    log.info(f"iptables: {'enabled -> ' + IPTABLES_LOG_FILE if IPTABLES_ENABLED else 'disabled'}")
    log.info(f"Auto-block: {'ON threshold=' + str(AUTO_BLOCK_THRESHOLD) if AUTO_BLOCK else 'OFF'}")

    bot   = VKBot(VK_TOKEN, VK_GROUP_ID)
    dedup = Deduplicator(DEDUP_WINDOW)
    snort = SnortParser(SNORT_ALERT_FILE, SNORT_PRIORITY) if SNORT_ENABLED else None
    ipt   = IptablesParser(IPTABLES_LOG_FILE) if IPTABLES_ENABLED else None

    if snort: snort.init()
    if ipt:   ipt.init()

    # Graceful shutdown
    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop_event.set)

    # Запуск Long Poll
    asyncio.create_task(bot.run(handle_vk))
    await asyncio.sleep(2)

    # Стартовое уведомление
    stats = get_stats()
    await bot.send(
        VK_ADMIN_ID,
        f"NetGuard v3 запущен\n\n"
        f"Snort:    {'вкл' if snort else 'выкл'}\n"
        f"iptables: {'вкл' if ipt else 'выкл'}\n"
        f"Авто-блок:{'вкл' if AUTO_BLOCK else 'выкл'}\n"
        f"Событий в журнале: {stats['total']}\n"
        f"Хост: {platform.node()}"
    )

    log.info("Monitor loop running. Ctrl+C to stop.")
    dedup_tick = 0

    while not stop_event.is_set():
        try:
            # ── Snort ──
            if snort:
                for a in snort.read_new():
                    key = f"snort:{a['sid']}:{a['src_ip']}:{a['dst_ip']}"
                    if dedup.is_new(key):
                        descr = f"[{a['sid']}] {a['msg']} P{a['priority']}"
                        log_event("snort", a['src_ip'], a['dst_ip'],
                                  a['dst_port'], "TCP", descr)
                        log.info(f"Snort: {a['msg']} {a['src_ip']} -> {a['dst_ip']}")
                        await maybe_auto_block(bot, a['src_ip'], a['msg'])
                        await bot.notify(
                            VK_ADMIN_ID,
                            f"[SNORT] P{a['priority']}: {a['msg']}\n"
                            f"{a['src_ip']} -> {a['dst_ip']}:{a['dst_port']}\n"
                            f"SID: {a['sid']}"
                        )

            # ── iptables ──
            if ipt:
                for e in ipt.read_new():
                    key = f"ipt:{e['tag']}:{e['src']}:{e['dst']}:{e['dpt']}"
                    if dedup.is_new(key):
                        log_event("iptables", e['src'], e['dst'],
                                  e['dpt'], e['proto'], e['tag'])
                        log.info(f"iptables: {e['tag']} {e['src']} -> {e['dst']}:{e['dpt']}")
                        await maybe_auto_block(bot, e['src'], e['tag'])
                        await bot.notify(
                            VK_ADMIN_ID,
                            f"[IPTABLES] {e['tag']}\n"
                            f"{e['src']}:{e['spt']} -> {e['dst']}:{e['dpt']} {e['proto']}"
                        )

            dedup_tick += 1
            if dedup_tick >= 300:
                dedup.cleanup()
                dedup_tick = 0

        except Exception as e:
            log.error(f"Loop error: {e}")

        await asyncio.sleep(POLL_INTERVAL)

    await bot.notify(VK_ADMIN_ID, "NetGuard v3 остановлен.")
    log.info("Stopped.")


if __name__ == "__main__":
    asyncio.run(main())
