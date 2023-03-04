import abc

from htbpwn.core.target import Target


class AbstractModule(abc.ABC):

    @classmethod
    @abc.abstractmethod
    def execute(cls, target: Target, *args, **kwargs) -> bool:
        raise NotImplementedError()
