import struct
from pwnlib.tubes.process import process
from abstract.pwntarget import PwnTarget


class SickROPPwn(PwnTarget):
    @classmethod
    def main(cls, proc: process, payload: bytes, pwn_target, *args, **kwargs):
        proc.send_raw(payload)

    @classmethod
    def input_handler(cls, proc: process, payload: bytes, *args, **kwargs):
        return proc.recv(len(payload))
