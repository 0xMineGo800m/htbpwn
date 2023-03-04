import abc


class PwnTarget(abc.ABC):
    @classmethod
    @abc.abstractmethod
    def main(cls, process):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def input_handler(cls, process, payload: bytes):
        raise NotImplementedError()
