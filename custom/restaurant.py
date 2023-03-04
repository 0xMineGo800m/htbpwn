from loguru import logger

from htbpwn.abstract.pwntarget import PwnTarget


class RestaurantPwn(PwnTarget):
    @classmethod
    def main(cls, process):
        print(process.clean(timeout=0.5).decode())
        process.sendline(b"1")
        print(process.clean(timeout=0.3).decode())

    @classmethod
    def input_handler(cls, process, payload: bytes):
        pos = payload.find(b'\0')
        expected = b'Enjoy your '
        if pos >= 0:
            expected += payload[:pos]
        else:
            expected += payload
        process.recvline()
        data = process.recv(len(expected))
        if data != expected:
            logger.warning("Input handler: received and expected data mismatch")



