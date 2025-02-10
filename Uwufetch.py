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
# meta developer: @xuduk

from .. import loader, utils
import subprocess
import traceback
import shutil

@loader.tds
class UwufetchMod(loader.Module):
    strings = {
        "name": "Uwufetch"
    }

    @loader.command()
    async def uwufetchcmd(self, message):
        """- запустить uwufetch"""
        message = await utils.answer(message, "<emoji document_id=5352752036595116992>💗</emoji>")
        try:
            result = subprocess.run(["uwufetch"], capture_output=True, text=True)
            
            clean_result = subprocess.run(
                ["sed", "-E", r's/\x1B\[[0-9;]*[mK]//g; s/\x1B\[[0-9;]*[A-Z]//g'],
                input=result.stdout, capture_output=True, text=True
            )

            output = clean_result.stdout
            await utils.answer(message, f"<pre>{output}</pre>")

        except FileNotFoundError:
            await utils.answer(message, f"<emoji document_id=5210952531676504517>❌</emoji> Установи uwufetch через <code>{self.get_prefix()}installuwufetch</code>")

    @loader.command()
    async def installuwufetchcmd(self, message):
        """- установить uwufetch"""
        message = await utils.answer(message, "<emoji document_id=5326015457155620929>⏳</emoji>")
        try:
            install = (
                "git clone https://github.com/TheDarkBug/uwufetch.git && "
                "cd uwufetch && "
                "make build && "
                "sudo make install"
            )

            process = subprocess.run(
                install, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )

            if process.returncode == 0:
                await utils.answer(message, "<emoji document_id=5237699328843200968>✅</emoji> Uwufetch успешно установлен")
            else:
                await utils.answer(message, f"<emoji document_id=5210952531676504517>❌</emoji> Ошибка при установке Uwufetch\n<pre>{process.stderr}</pre>")

        except Exception as e:
            await utils.answer(message, f"<emoji document_id=5210952531676504517>❌</emoji> Ошибка при установке Uwufetch\n<pre>{str(e)}</pre>")

    @loader.command()
    async def uninstalluwufetchcmd(self, message):
        """- удалить uwufetch"""
        message = await utils.answer(message, "<emoji document_id=5326015457155620929>⏳</emoji>")
        try:
            uninstall = (
                "cd uwufetch && "
                "sudo make uninstall "
            )

            process = subprocess.run(
                uninstall, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )

            shutil.rmtree("uwufetch")

            if process.returncode == 0:
                await utils.answer(message, "<emoji document_id=5237699328843200968>✅</emoji> Uwufetch успешно удален")
            else:
                await utils.answer(message, f"<emoji document_id=5210952531676504517>❌</emoji> Ошибка при удалении Uwufetch\n<pre>{process.stderr}</pre>")

        except Exception as e:
            await utils.answer(message, f"<emoji document_id=5210952531676504517>❌</emoji> Ошибка при удалении Uwufetch\n<pre>{str(e)}</pre>")

