import re
from pwnlib.tubes.process import process

from abstract.pwntarget import PwnTarget


class FortressJetPwn(PwnTarget):
    @classmethod
    def main(cls, proc: process, payload: bytes, *args, **kwargs):
        print(proc.clean(timeout=0.2).decode())
        proc.sendline(payload)

    @classmethod
    def input_handler(cls, proc: process, payload: bytes, *args, **kwargs):
        pass