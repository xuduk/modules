# meta developer: @xuduk
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

from hikkatl.types import Message
from .. import loader, utils

@loader.tds
class CustomFakePing(loader.Module):
    """Кастомный фейк пинг, советую заглянуть в конфиг."""

    strings = {
        "name": "Custom Fake Ping",
        "configtext": "Ваш кастомный текст\n"
        "Пинг: {ping}\n"
        "Аптайм: {uptime}",
        "ping_emoji": ""
    }

    def __init__(self):
        self.config = loader.ModuleConfig(
            loader.ConfigValue(
                "text",
                "🕐 Задержка юзербота: {ping}\n⏳ Аптайм: {uptime}",
                lambda: self.strings["configtext"],
                validator=loader.validators.String()
            ),
            loader.ConfigValue(
                "standart_ping",
                "1488",
                lambda: "Какой пинг использовать если он не будет указан",
                validator=loader.validators.String(),
            ),
            loader.ConfigValue(
                "ping_emoji",
                "🌘",
                lambda: "Эмодзи в начале сообщения",
                validator=loader.validators.String(),
            ),
            loader.ConfigValue(
                "custom_uptime",
                False,
                lambda: "Использовать ли кастомный аптайм",
                validator=loader.validators.Boolean()
            ),
            loader.ConfigValue(
                "uptime_text",
                "",
                lambda: "Текст для кастомного аптайма",
                validator=loader.validators.String(),
            ),
            loader.ConfigValue(
                "ms",
                True,
                lambda: "Добавлять ли ms к пингу",
                validator=loader.validators.Boolean()
            ),
        )

    @loader.command()
    async def cpinj(self, message: Message):
        """<ping> - Узнать фейковый пинг вашего юзербота"""
        args = utils.get_args_raw(message)
        message = await utils.answer(message, self.config["ping_emoji"])

        if not args:
            await utils.answer(
            message,
            self.config["text"].format(
                ping=self.config["standart_ping"] + " ms" if self.config["ms"] else self.config["standart_ping"],
                uptime=self.config["uptime_text"] if self.config["custom_uptime"] else utils.formatted_uptime(),
            ),
        )
            return

        await utils.answer(
            message,
            self.config["text"].format(
                ping=f"{args} ms" if self.config["ms"] else args,
                uptime=self.config["uptime_text"] if self.config["custom_uptime"] else utils.formatted_uptime(),
            ),
        )
