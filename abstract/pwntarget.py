import abc
from pwnlib.tubes.process import process
from pwnlib.gdb import Gdb


class PwnTarget(abc.ABC):
    @classmethod
    @abc.abstractmethod
    def main(cls, proc: process, payload: bytes, *args, **kwargs):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def input_handler(cls, proc: process, payload: bytes, *args, **kwargs):
        raise NotImplementedError()


class CustomOffsetFinderMixin(abc.ABC):
    @classmethod
    @abc.abstractmethod
    def find_offset(cls, proc: process, debugger: Gdb, max_offset: int, *args, **kwargs):
        raise NotImplementedError()


class StackCanaryFinderMixin(abc.ABC):
    @classmethod
    @abc.abstractmethod
    def find_canary(cls, proc: process, debugger: Gdb, max_offset: int, *args, **kwargs):
        raise NotImplementedError()
