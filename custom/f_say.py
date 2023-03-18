import struct
from pwnlib.tubes.process import process
from abstract.pwntarget import PwnTarget


class WhatDoesTheFSayPwn(PwnTarget):
    @classmethod
    def main(cls, proc: process, payload: bytes, pwn_target, *args, **kwargs):
        print(proc.clean(timeout=0.2).decode())
        proc.sendline(b'1 2')
        print(proc.clean(timeout=0.2).decode())
        proc.sendline(payload)

    @classmethod
    def input_handler(cls, proc: process, payload: bytes, *args, **kwargs):
        return proc.recvline()
