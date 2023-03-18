import abc
from typing import Optional


class AbstractModule(abc.ABC):
    @classmethod
    @abc.abstractmethod
    def execute(cls, target, *args, **kwargs) -> Optional:
        raise NotImplementedError()
