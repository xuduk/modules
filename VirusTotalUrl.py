# -*- coding: utf-8 -*-

# meta developer: @xuduk
# This module checks links via VirusTotal API.

from .. import loader, utils
import requests
import logging

logger = logging.getLogger(__name__)

@loader.tds
class VirusTotalUrlMod(loader.Module):
    """Проверяет ссылки через VirusTotal API"""
    strings = {"name": "Virus Total URL"}

    async def client_ready(self, client, db):
        self.client = client
        self.db = db
        self.api_key = self.db.get("VirusTotal", "api_key", None)
        if not self.api_key:
            logger.warning("<emoji document_id=5210952531676504517>❌</emoji> API Key не установлен. Используйте команду .setvtotalkey")

    @loader.owner
    async def setvtotalkeycmd(self, message):
        """Устанавливает API-ключ VirusTotal\nИспользование: .setvtotalkey <API_KEY>"""
        args = utils.get_args_raw(message)
        if not args:
            await message.edit("Пожалуйста, укажите ваш API-ключ VirusTotal.\n"
                                "Получить можно на www.virustotal.com/gui/my-apikey</b>")
            return
        self.api_key = args.strip()
        self.db.set("VirusTotal", "api_key", self.api_key)
        await message.edit("<b>API-ключ сохранен.</b>")

    async def vtotalcmd(self, message):
        """Проверяет ссылку через VirusTotal\nИспользование: .vtotal <ссылка>"""
        if not self.api_key:
            await message.edit("<b><emoji document_id=5210952531676504517>❌</emoji> API Key не установлен.\nИспользуйте команду <code>.setvtotalkey</code><b>")
            return

        args = utils.get_args_raw(message)
        if not args:
            await message.edit("<b><emoji document_id=5210952531676504517>❌</emoji> Пожалуйста, укажите ссылку для проверки.</b>")
            return

        url = args.strip()

        await message.edit("<b>Проверяю ссылку...</b>")

        headers = {
            "Accept": "application/json",
            "x-apikey": self.api_key
        }

        scan_url = "https://www.virustotal.com/api/v3/urls"

        try:
            # Преобразуем URL в формат, принятый VirusTotal
            response = requests.post(scan_url, headers=headers, data={"url": url})
            if response.status_code != 200:
                await message.edit(f"<emoji document_id=5210952531676504517>❌</emoji> <b>Ошибка при отправке запроса: {response.text}</b>")
                return

            data = response.json()
            url_id = data["data"]["id"]

            # Получаем результаты анализа
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{url_id}"
            analysis_response = requests.get(analysis_url, headers=headers)

            if analysis_response.status_code != 200:
                await message.edit(f"<b><emoji document_id=5210952531676504517>❌</emoji> Ошибка при получении результатов: {analysis_response.text}</b>")
                return

            analysis_data = analysis_response.json()

            # Проверяем статус анализа
            status = analysis_data["data"]["attributes"]["status"]
            if status == "queued":
                await message.edit("<b><emoji document_id=5451646226975955576>⌛️</emoji> Ссылка поставлена в очередь на анализ. Пожалуйста, подождите несколько секунд и повторите попытку.</b>")
                return

            stats = analysis_data["data"]["attributes"]["stats"]

            harmless = stats.get("harmless", 0)
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            undetected = stats.get("undetected", 0)
            timeout = stats.get("timeout", 0)

            result_message = (
                f"<b>**Результаты проверки:**</b>\n"
                f"<b><emoji document_id=5352888345972187597>✅</emoji> Безопасно: {harmless}</b>\n"
                f"<b><emoji document_id=5364241851500997604>⚠️</emoji> Вредоносно: {malicious}</b>\n"
                f"<b><emoji document_id=5393144297048516784>🤨</emoji> Подозрительно: {suspicious}</b>\n"
                f"<b><emoji document_id=5435893060028345073>😐</emoji> Не обнаружено: {undetected}</b>\n"
                f"<b><emoji document_id=5451646226975955576>⌛️</emoji> Таймаут: {timeout}</b>"
            )

            await message.edit(result_message)

        except Exception as e:
            logger.error(e)
            await message.edit(f"<emoji document_id=5210952531676504517>❌</emoji> Произошла ошибка: {e}")