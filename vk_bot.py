"""
NetGuard v3 — VK бот с кнопками (Long Poll API)
"""

import asyncio
import json
import random
import logging

import httpx

log = logging.getLogger("netguard.vk")

# Клавиатура главного меню
MAIN_KEYBOARD = json.dumps({
    "one_time": False,
    "buttons": [
        [
            {"action": {"type": "text", "label": "Проверить систему"},  "color": "primary"},
            {"action": {"type": "text", "label": "Последние угрозы"},   "color": "negative"},
        ],
        [
            {"action": {"type": "text", "label": "Статус защиты"},      "color": "positive"},
            {"action": {"type": "text", "label": "Заблокировать IP"},   "color": "secondary"},
        ],
        [
            {"action": {"type": "text", "label": "Отчёт"},              "color": "primary"},
            {"action": {"type": "text", "label": "Заблокированные IP"}, "color": "secondary"},
        ],
        [
            {"action": {"type": "text", "label": "Настройки"},          "color": "secondary"},
        ],
    ],
}, ensure_ascii=False)


class VKBot:
    def __init__(self, token: str, group_id: str):
        self.token    = token
        self.group_id = group_id
        self.api_url  = "https://api.vk.com/method"
        self.v        = "5.131"
        # peer_id -> True : ожидаем IP для блокировки
        self.pending_block: dict[int, bool] = {}

    async def _call(self, method: str, **params) -> dict:
        params.update({"access_token": self.token, "v": self.v})
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.post(f"{self.api_url}/{method}", data=params)
            data = r.json()
            if "error" in data:
                log.error(f"VK API [{method}] error: {data['error']}")
                return {}
            return data.get("response", {})
        except Exception as e:
            log.error(f"VK API [{method}] exception: {e}")
            return {}

    async def send(self, peer_id: int, text: str, keyboard: str | None = MAIN_KEYBOARD) -> bool:
        """Отправить сообщение с клавиатурой."""
        params: dict = {
            "peer_id":   peer_id,
            "message":   text[:4096],
            "random_id": random.randint(0, 2 ** 31),
        }
        if keyboard is not None:
            params["keyboard"] = keyboard
        result = await self._call("messages.send", **params)
        return bool(result)

    async def notify(self, peer_id: int, text: str) -> bool:
        """Уведомление без клавиатуры (алерты)."""
        return await self.send(peer_id, text, keyboard=None)

    async def run(self, handler):
        """Запустить Long Poll цикл."""
        log.info("VK Long Poll starting...")
        while True:
            try:
                info = await self._call("groups.getLongPollServer", group_id=self.group_id)
                if not info:
                    log.warning("Failed to get Long Poll server, retry in 5s")
                    await asyncio.sleep(5)
                    continue

                server = info["server"]
                key    = info["key"]
                ts     = info["ts"]
                log.info("VK Long Poll connected")

                # VK иногда возвращает URL с протоколом, иногда без
                lp_url = server if server.startswith("http") else f"https://{server}"
                log.info(f"Long Poll URL: {lp_url}")

                async with httpx.AsyncClient(timeout=35) as client:
                    while True:
                        try:
                            r = await client.get(
                                lp_url,
                                params={"act": "a_check", "key": key,
                                        "ts": ts, "wait": 25}
                            )
                            data = r.json()
                        except Exception as e:
                            log.error(f"Long Poll request error: {e}")
                            await asyncio.sleep(3)
                            break

                        if "failed" in data:
                            log.warning(f"Long Poll failed={data.get('failed')}, reconnecting")
                            break

                        ts = data["ts"]
                        for upd in data.get("updates", []):
                            if upd.get("type") == "message_new":
                                msg     = upd["object"]["message"]
                                peer_id = msg["from_id"]
                                text    = msg.get("text", "").strip()
                                asyncio.create_task(handler(self, peer_id, text))

            except Exception as e:
                log.error(f"Long Poll loop error: {e}")
                await asyncio.sleep(5)
