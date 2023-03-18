import enum
import threading
import typing
from typing import Optional
from abstract.module import AbstractModule
from core.targetbase import TargetBase
from loguru import logger


class Method(enum.Enum):
    SymbolTable = enum.auto()
    PLT = enum.auto()
    GOT = enum.auto()


class FindFunction(AbstractModule):
    @classmethod
    def execute(cls, target: TargetBase, function_name: typing.Union[typing.AnyStr, typing.List[typing.AnyStr]],
                method: Method = Method.SymbolTable, find_all: bool = False, *args, **kwargs) -> Optional:
        logger.info(f"Running {cls.__name__} module")
        if not isinstance(function_name, list):
            function_name = (function_name,)

        results = {}
        if find_all:
            for function in function_name:
                address = cls.execute(target, function, method)
                if address:
                    results[function] = address
            return results
        logger.info(f"Looking for function address. Possible functions: {function_name}")
        address = None
        if method == Method.SymbolTable:
            logger.info("Checking out the symbol table")
            container = target.file.symbols
        elif method == Method.PLT:
            logger.info("Checking out the procedure linkage table")
            container = target.file.plt
        elif method == Method.GOT:
            logger.info("Checking out the global offset table")
            container = target.file.got
        else:
            logger.critical(f"Method not supported")
            return address

        for name in function_name:
            try:
                address = container[name]
                logger.success(f"Found: {name}@{hex(address)}")
                return name, address
            except KeyError:
                pass
        logger.critical(f"No address for any functions provided found")
        return None
