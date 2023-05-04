import ipaddress
import pathlib

from core.gdb_wrapper import GdbWrapper
from core.generic_pwn import GenericPwn
from core.target_config import Config, Mode
from core.targetbase import TargetBase
from pwn import p64, u64


class FancyNamesPwn(GenericPwn):
    @classmethod
    def custom_name(cls, name: bytes):
        prompt_pre = ' \n[*] Are you sure you want to use the name \n'
        prompt_post = '(y/n):'
        default_prompt_len = len(prompt_pre) + len(name) + len(prompt_post)
        cls.logger.info(t.process.recvuntil(b'>').decode() + '1')
        t.process.sendline(b'1')
        cls.logger.info(t.process.recvuntil(b':').decode())
        cls.logger.info(name)
        t.process.send_raw(name)
        cls.logger.info(t.process.recvuntil(b':'))
        t.process.sendline(b'y')
        cls.logger.info(t.process.recvuntil(b':'))
        data = t.process.recvuntil(b'\x1B[1;34m')
        debug = t.process.clean(0.5)
        pass

    @classmethod
    def generate(cls):
        cls.logger.info(t.process.recvuntil(b'>').decode() + '2')
        t.process.sendline(b'2')
        cls.logger.info(t.process.recvuntil(b'>').decode() + '4')
        t.process.sendline(b'4')


if __name__ == '__main__':
    config = Config(
        rop=True,
        mode=Mode.remote,
        ip=ipaddress.IPv4Address("127.0.0.1"),
        port=1337,
        file=pathlib.Path('/home/lim8en1/htb/projects/fancynames/challenge/fancy_names'),
        no_offset=True
    )

    t = TargetBase(pwn_target=FancyNamesPwn, config=config)
    t.pwn_target.generate()
    t.pwn_target.custom_name(b'C001BABE1\x00')
