from pwnlib.tubes.process import process
from abstract.pwntarget import PwnTarget


class CasinoPwn(PwnTarget):
    @classmethod
    def main(cls, proc: process, payload: bytes, pwn_target, *args, **kwargs):
        proc.clean(0.3)
        proc.sendline(payload)

    @classmethod
    def input_handler(cls, proc: process, payload: bytes, *args, **kwargs):
        return proc.recvline()
