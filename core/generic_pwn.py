from pwnlib.tubes.process import process
from abstract.pwntarget import PwnTarget


class GenericPwn(PwnTarget):
    @classmethod
    def main(cls, proc: process, payload: bytes, *args, **kwargs):
        proc.sendline(payload)

    @classmethod
    def input_handler(cls, proc: process, payload: bytes, *args, **kwargs):
        proc.recvline()
