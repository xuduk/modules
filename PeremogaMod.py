#meta developer: @xuduk
"""
██████████████████████████████████████████████████████████████████████████████████
█░░░░░░░░██░░░░░░░░█░░░░░░██░░░░░░█░░░░░░░░░░░░███░░░░░░██░░░░░░█░░░░░░██░░░░░░░░█
█░░▄▀▄▀░░██░░▄▀▄▀░░█░░▄▀░░██░░▄▀░░█░░▄▀▄▀▄▀▄▀░░░░█░░▄▀░░██░░▄▀░░█░░▄▀░░██░░▄▀▄▀░░█
█░░░░▄▀░░██░░▄▀░░░░█░░▄▀░░██░░▄▀░░█░░▄▀░░░░▄▀▄▀░░█░░▄▀░░██░░▄▀░░█░░▄▀░░██░░▄▀░░░░█
███░░▄▀▄▀░░▄▀▄▀░░███░░▄▀░░██░░▄▀░░█░░▄▀░░██░░▄▀░░█░░▄▀░░██░░▄▀░░█░░▄▀░░██░░▄▀░░███
███░░░░▄▀▄▀▄▀░░░░███░░▄▀░░██░░▄▀░░█░░▄▀░░██░░▄▀░░█░░▄▀░░██░░▄▀░░█░░▄▀░░░░░░▄▀░░███
█████░░▄▀▄▀▄▀░░█████░░▄▀░░██░░▄▀░░█░░▄▀░░██░░▄▀░░█░░▄▀░░██░░▄▀░░█░░▄▀▄▀▄▀▄▀▄▀░░███
███░░░░▄▀▄▀▄▀░░░░███░░▄▀░░██░░▄▀░░█░░▄▀░░██░░▄▀░░█░░▄▀░░██░░▄▀░░█░░▄▀░░░░░░▄▀░░███
███░░▄▀▄▀░░▄▀▄▀░░███░░▄▀░░██░░▄▀░░█░░▄▀░░██░░▄▀░░█░░▄▀░░██░░▄▀░░█░░▄▀░░██░░▄▀░░███
█░░░░▄▀░░██░░▄▀░░░░█░░▄▀░░░░░░▄▀░░█░░▄▀░░░░▄▀▄▀░░█░░▄▀░░░░░░▄▀░░█░░▄▀░░██░░▄▀░░░░█
█░░▄▀▄▀░░██░░▄▀▄▀░░█░░▄▀▄▀▄▀▄▀▄▀░░█░░▄▀▄▀▄▀▄▀░░░░█░░▄▀▄▀▄▀▄▀▄▀░░█░░▄▀░░██░░▄▀▄▀░░█
█░░░░░░░░██░░░░░░░░█░░░░░░░░░░░░░░█░░░░░░░░░░░░███░░░░░░░░░░░░░░█░░░░░░██░░░░░░░░█
██████████████████████████████████████████████████████████████████████████████████
"""
from .. import loader, utils
from telethon.tl.types import Message

@loader.tds
class Peremoga(loader.Module):
    """Изменяет все гласные буквы на і.\nZOVMod, наша битва будет легендарной."""
    strings = {
        "name": "Перемога Мод"
    }

    async def client_ready(self, client, db):
        self.db = db
        self._client = client
        self.enabled = self.db.get("PeremogaMod", "enabled", False)

    async def peremogacmd(self, message: Message):
        """- включить/выключить переможное автоформатирование"""
        args = utils.get_args_raw(message)
        self.enabled = not self.enabled
        self.db.set("PeremogaMod", "enabled", self.enabled)

        if self.enabled:
            response = "<b>Перемога мод включен.\nПеремога буде <emoji document_id=5370870691140737817>🥳</emoji></b>"
        else:
            response = "<b>Перемога мод выключен.\nПеремоги не буде <emoji document_id=5370881342659631698>😢</emoji></b>"

        await utils.answer(message=message, response=response)

    async def watcher(self, message: Message):
        if self.enabled and message.out:
            # Заменяем буквы на указанные символы
            new_text = message.text.replace("а", "і").replace("А", "І").replace("е", "і").replace("Е", "І").replace("ё", "і").replace("Ё", "І").replace("є", "і").replace("Є", "І").replace("и", "і").replace("И", "І").replace("і", "і").replace("І", "І").replace("о", "і").replace("О", "І").replace("у", "і").replace("У", "І").replace("ы", "і").replace("Ы", "І")

            await self._client.edit_message(message.peer_id, message.id, new_text)
