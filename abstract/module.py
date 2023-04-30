import abc
from typing import Optional

from core.logging import LoggableModule


class AbstractModule(abc.ABC, LoggableModule):
    @classmethod
    @abc.abstractmethod
    def execute(cls, target, *args, **kwargs) -> Optional:
        raise NotImplementedError()
