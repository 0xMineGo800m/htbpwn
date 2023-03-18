from loguru import logger
from pwnlib.tubes.process import process

from abstract.pwntarget import PwnTarget


class RestaurantPwn(PwnTarget):
    @classmethod
    def main(cls, proc: process, payload: bytes, *args, **kwargs):
        print(proc.clean(timeout=0.5).decode())
        proc.sendline(b"1")
        print(proc.clean(timeout=0.3).decode())
        proc.send_raw(payload)

    @classmethod
    def input_handler(cls, proc: process, payload: bytes, *args, **kwargs):
        pos = payload.find(b'\0')
        expected = b'Enjoy your '
        if pos >= 0:
            expected += payload[:pos]
        else:
            expected += payload
        proc.recvline()
        data = proc.recv(len(expected))
        if data != expected:
            logger.warning("Input handler: received and expected data mismatch")
